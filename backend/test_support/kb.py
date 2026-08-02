"""The corpus the fingerprint regression locks iterate — live KB when present, fixture otherwise.

`/data/` is gitignored, so a clean checkout (CI, a fresh clone) has no `data/kb/entries.jsonl`.
Three locks iterate that corpus BY DESIGN — per backend/AGENTS.md §1 a safety test draws from
the real population, so that a fingerprint added tomorrow is covered without anyone remembering
to edit a test. On a clean checkout they used to crash.

The fix is not to skip them. `kb_fixture.jsonl` is the COMPLETE corpus projected onto the fields
`reasoning.retrieval` actually reads (see make_kb_fixture.py for why that is
information-preserving, and test_kb_fixture.py for the assertion that proves it). Every entry
and every structured fingerprint survives, so the locks run for real in CI.

WHICH SOURCE WAS USED IS ALWAYS REPORTED. A green run that quietly fell back to a stale fixture
would be exactly the failure `test_proof_honesty.py` exists to prevent on the proof harness: a
check that did not really run, reported as a pass. So `load()` returns the provenance with the
entries and every caller prints it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_KB = REPO_ROOT / "data" / "kb" / "entries.jsonl"
FIXTURE = Path(__file__).resolve().parent / "kb_fixture.jsonl"

# Reproduce a clean CI checkout on a machine that HAS the KB:
#   HACKPIT_FORCE_KB_FIXTURE=1 sh backend/run_safety_tests.sh
# Verification-only, and deliberately not silent: `load()` reports the forced fixture in its
# provenance string and every caller prints it, so this can never turn a live-KB run into a
# fixture run without saying so. It is read at call time, never cached.
FORCE_ENV = "HACKPIT_FORCE_KB_FIXTURE"


def _forced() -> bool:
    return os.environ.get(FORCE_ENV, "").strip().lower() in {"1", "true", "yes"}


def _read(path: Path) -> list[dict]:
    entries: list[dict] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def load() -> tuple[list[dict], str]:
    """``(entries, provenance)``. Prefers the live KB; falls back to the committed fixture.

    Raises rather than returning an empty corpus: a lock that iterates nothing passes
    vacuously, and a vacuous pass is the thing these tests exist to make impossible.
    """
    if LIVE_KB.exists() and not _forced():
        entries = _read(LIVE_KB)
        if entries:
            return entries, f"live KB ({len(entries)} entries, {LIVE_KB.relative_to(REPO_ROOT)})"
    if not FIXTURE.exists():
        raise SystemExit(
            f"FAIL  no corpus: neither {LIVE_KB} nor the committed fixture {FIXTURE} exists. "
            "Regenerate with backend/test_support/make_kb_fixture.py"
        )
    entries = _read(FIXTURE)
    if not entries:
        raise SystemExit(f"FAIL  the committed fixture {FIXTURE} parsed to zero entries")
    why = f"{FORCE_ENV} set" if _forced() else "live KB absent, e.g. CI"
    return entries, f"FIXTURE ({len(entries)} entries — {why})"


def fingerprint_count(entries: list[dict]) -> int:
    """How many entries carry a structured ``meta.fingerprint``. The number every fingerprint
    lock's coverage claim rests on, so it is asserted non-zero at the call site."""
    return sum(
        1
        for e in entries
        if isinstance(e.get("meta"), dict) and isinstance(e["meta"].get("fingerprint"), dict)
    )
