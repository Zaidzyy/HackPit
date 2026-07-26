"""Turn a finished run into state.

Called once per run, immediately after it completes. Reads two things:

  1. the run's STDOUT, parsed by the program that produced it (httpx/nuclei/ffuf/secretsdump);
  2. any file that APPEARED IN THE RUN'S LOOT DIRECTORY while it ran.

The second is what makes `nmap -oA scan` work with no special handling: the operator (or the
planner) writes output the way they normally would, and the XML is picked up because it is
newer than the moment the run started. It only works at all because Phase 1 mounted a loot
directory and set it as the working directory.

THREE RULES THIS MODULE OBEYS

* NEVER BREAK A RUN. Ingestion happens after the command has already finished. A parser
  bug, a malformed file, a locked database — none of them may propagate. Every entry point
  catches broadly and returns what it managed.
* NEVER EXECUTE. This module reads files and text. It has no subprocess, no network, no
  container access, and it must never gain any: it runs automatically after every command,
  which is exactly the position from which an execution path would bypass the approval gate.
* ONLY FILES THE RUN ITSELF PRODUCED. Loot directories persist across runs, so ingesting
  everything present would re-attribute an old scan's XML to whatever ran last, corrupting
  the `source_run_id` that makes state citable.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import parsers, store
from .parsers import Parsed

# A loot file bigger than this is not something a parser should pull into memory during an
# automatic post-run pass. Skipped rather than truncated: half an XML document parses to
# nothing useful anyway, and a partial parse would look like a complete one.
MAX_LOOT_FILE_BYTES = 25 * 1024 * 1024

# Files whose extension no parser claims are skipped without reading them at all.
_PARSEABLE_SUFFIXES = tuple(parsers.FILE_PARSERS)


def program_name(command: str) -> str:
    """The tool a command actually invoked, normalised for parser lookup.

    Read from the command itself, never from anything a model claimed — `/usr/bin/nmap`,
    `nmap.exe` and `nmap` are the same tool.
    """
    base = os.path.basename((command or "").strip())
    if base.lower().endswith(".exe"):
        base = base[:-4]
    return base.lower()


def new_loot_files(loot_dir: Path | None, since: float) -> list[Path]:
    """Files in ``loot_dir`` modified at or after ``since``. Empty on any problem."""
    if loot_dir is None:
        return []
    try:
        if not loot_dir.is_dir():
            return []
        out: list[Path] = []
        for entry in loot_dir.iterdir():
            try:
                if not entry.is_file() or not entry.name.lower().endswith(_PARSEABLE_SUFFIXES):
                    continue
                st = entry.stat()
                # A 1s slack: the run's start timestamp and the filesystem's mtime
                # resolution do not always agree, and missing the file a run just wrote
                # is a worse failure than occasionally re-reading one.
                if st.st_mtime + 1.0 < since:
                    continue
                if st.st_size > MAX_LOOT_FILE_BYTES:
                    continue
                out.append(entry)
            except OSError:
                continue
        return sorted(out)
    except OSError:
        return []


def parse_run(
    *,
    session_id: str,
    run_id: str | None,
    command: str,
    stdout: str,
    loot_dir: Path | None = None,
    started_at_epoch: float | None = None,
) -> Parsed:
    """Everything this run revealed, as unsaved records. Never raises."""
    found = Parsed()
    if not session_id:
        return found

    try:
        found.extend(
            parsers.parse_stdout(program_name(command), stdout or "", session_id, run_id)
        )
    except Exception:  # noqa: BLE001
        pass

    if loot_dir is not None and started_at_epoch is not None:
        for path in new_loot_files(loot_dir, started_at_epoch):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            try:
                found.extend(parsers.parse_file(path.name, text, session_id, run_id))
            except Exception:  # noqa: BLE001
                continue
    return found


def ingest_run(
    *,
    session_id: str,
    run_id: str | None,
    command: str,
    stdout: str,
    loot_dir: Path | None = None,
    started_at_epoch: float | None = None,
) -> dict[str, Any]:
    """Parse a finished run and persist whatever it revealed.

    Returns a count-per-kind dict so the caller can surface "this run added 12 services".
    Returns zeros on any failure — ingestion is additive enrichment, never a gate.
    """
    empty = {"hosts": 0, "services": 0, "endpoints": 0, "credentials": 0, "findings": 0}
    try:
        found = parse_run(
            session_id=session_id, run_id=run_id, command=command, stdout=stdout,
            loot_dir=loot_dir, started_at_epoch=started_at_epoch,
        )
        if found.is_empty():
            return empty
        return {
            "hosts": store.upsert_hosts(found.hosts),
            "services": store.upsert_services(found.services),
            "endpoints": store.upsert_endpoints(found.endpoints),
            "credentials": store.upsert_credentials(found.credentials),
            "findings": store.upsert_findings(found.findings),
        }
    except Exception:  # noqa: BLE001 - must never affect a run that already completed
        return empty
