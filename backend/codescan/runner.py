"""SAST runner — bounded, read-only, STATIC.

The scanners (Semgrep, Bandit) PARSE source files. Nothing in this module executes the code
being scanned, imports it, or reaches the network on its behalf. That is the one guarantee
worth stating precisely, because it is what makes this feature orthogonal to everything else
in HackPit:

    the only programs this module ever launches are the SCANNERS themselves (:data:`_TOOLS`).
    The path under review is passed to them as an ARGUMENT and is never the executable.

:func:`_spawn` asserts exactly that before every subprocess call, and
``test_codescan_safety.py`` asserts it again from the outside.

This module is deliberately disconnected from the engagement/executor/target-lock/scope/
isolation model: no target, no network, no gates, no engagement id. A code scan cannot reach
any of it — it imports none of it (locked by an orthogonality test).

Bounding, because a scanner pointed at a huge tree is the only real failure mode here:
  * a hard wall-clock TIMEOUT (killed, reported as a clean timeout, never left running);
  * an output-size CAP applied to a spool FILE, so oversized output is never read into memory
    at all — the size is checked before the read;
  * PATH VALIDATION — must exist, must be a directory, resolved to an absolute real path.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# bounds
# --------------------------------------------------------------------------- #
DEFAULT_TIMEOUT_S = 120      # per scanner
MAX_TIMEOUT_S = 600          # hard ceiling, whatever the caller asks for
MAX_OUTPUT_BYTES = 16 << 20  # 16 MB of tool JSON; beyond this we refuse to parse
MAX_FILES = 20_000           # a tree bigger than this is refused up front, not scanned

# The ONLY executables this module may launch. The scanned path is always an argument to one
# of these, never a program itself.
_TOOLS = ("semgrep", "bandit")

# Bundled offline Semgrep ruleset (see rules/hackpit-security.yaml).
BUNDLED_RULES = Path(__file__).parent / "rules" / "hackpit-security.yaml"

# Directories never worth scanning — dependency and build trees dominate the runtime and the
# findings are not the reviewer's code.
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".next", ".nuxt", "dist", "build", "target", "vendor", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "site-packages", ".gradle", ".idea", ".vscode",
})


class ScanError(RuntimeError):
    """A scan could not be completed. The message is meant for the operator."""


class ScannerMissing(ScanError):
    """A scanner isn't installed. Carries the exact install command."""


class ScanTimeout(ScanError):
    """A scanner hit the wall-clock bound and was killed."""


# --------------------------------------------------------------------------- #
# path validation
# --------------------------------------------------------------------------- #
def resolve_target(raw: str) -> Path:
    """Validate + resolve a codebase path. Raises :class:`ScanError` with a plain reason.

    Read-only: this only resolves and stats. A file is rejected in favour of a directory so
    the caller's mental model ("point it at a codebase folder") matches what runs.
    """
    text = (raw or "").strip().strip('"').strip("'")
    if not text:
        raise ScanError("a codebase path is required")
    try:
        path = Path(text).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ScanError(f"path could not be resolved: {exc}") from exc
    if not path.exists():
        raise ScanError(f"path does not exist: {path}")
    if not path.is_dir():
        raise ScanError(
            f"not a directory: {path} — point the scan at a codebase FOLDER"
        )
    return path


def count_files(path: Path, cap: int = MAX_FILES) -> tuple[int, bool]:
    """(files counted, hit_cap). Walks once, skipping dependency/build trees, so an
    accidental scan of a huge root is refused before a scanner is ever launched."""
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        total += len(files)
        if total > cap:
            return total, True
    return total, False


def has_python(path: Path, probe_cap: int = 5000) -> bool:
    """True when the tree contains at least one .py file (decides whether Bandit runs)."""
    seen = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in files:
            if name.endswith(".py"):
                return True
            seen += 1
            if seen > probe_cap:
                return False
    return False


# --------------------------------------------------------------------------- #
# tool discovery
# --------------------------------------------------------------------------- #
def tool_path(tool: str) -> str | None:
    """Absolute path to a scanner, or None. Looks in the running interpreter's own
    Scripts/bin dir first (the backend venv, where `uv pip install` puts it) before PATH."""
    if tool not in _TOOLS:  # pragma: no cover - guarded by callers
        raise ValueError(f"unknown tool {tool!r}")
    bindir = Path(sys.executable).parent
    for name in (f"{tool}.exe", tool):
        candidate = bindir / name
        if candidate.is_file():
            return str(candidate)
    return shutil.which(tool)


def available() -> dict[str, str | None]:
    """{tool: path or None} — what the UI shows when a scanner is missing."""
    return {tool: tool_path(tool) for tool in _TOOLS}


def _require(tool: str) -> str:
    found = tool_path(tool)
    if not found:
        raise ScannerMissing(
            f"{tool} is not installed — install it into the backend environment:\n"
            f"    cd backend && uv pip install {tool}\n"
            f"(or `pip install {tool}` if you manage the venv with pip)"
        )
    return found


# --------------------------------------------------------------------------- #
# bounded subprocess
# --------------------------------------------------------------------------- #
def _spawn(argv: list[str], timeout_s: int, cwd: Path | None = None) -> tuple[str, float]:
    """Run a SCANNER with a hard timeout and a spooled, size-capped stdout.

    THE STATIC-ONLY INVARIANT: ``argv[0]`` must be one of the scanners in :data:`_TOOLS`.
    The scanned path only ever appears as a later argument, so no file from the codebase under
    review can become the program that runs. Asserted here, on every call.

    stdout is spooled to a temp file and its SIZE is checked before anything is read, so
    oversized tool output is refused rather than pulled into memory. ``shell=False`` always —
    argv is a list, so nothing in the path is ever interpreted by a shell.
    """
    if not argv:
        raise ScanError("empty scanner command")
    program = Path(argv[0]).name.lower()
    for suffix in (".exe", ".cmd", ".bat"):
        program = program[: -len(suffix)] if program.endswith(suffix) else program
    assert program in _TOOLS, (
        f"code scan tried to execute {program!r} — only {_TOOLS} may ever be launched; "
        "the scanned code is NEVER executed"
    )

    started = time.monotonic()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False, program asserted above
                argv,
                stdout=out,
                stderr=err,
                stdin=subprocess.DEVNULL,
                cwd=str(cwd) if cwd else None,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise ScannerMissing(f"scanner not found: {argv[0]}") from exc
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=15)
            raise ScanTimeout(
                f"{program} exceeded the {timeout_s}s limit and was stopped — scan a smaller "
                "subtree, or raise the timeout"
            ) from None
        duration = time.monotonic() - started

        size = out.tell()
        if size > MAX_OUTPUT_BYTES:
            raise ScanError(
                f"{program} produced {size >> 20} MB of output (cap "
                f"{MAX_OUTPUT_BYTES >> 20} MB) — scan a narrower path"
            )
        out.seek(0)
        stdout = out.read().decode("utf-8", "replace")
        if not stdout.strip():
            err.seek(0)
            detail = err.read().decode("utf-8", "replace").strip().splitlines()
            tail = detail[-1] if detail else f"exit code {proc.returncode}"
            raise ScanError(f"{program} produced no output ({tail[:300]})")
    return stdout, duration


def _parse_json(tool: str, text: str) -> dict[str, Any]:
    """Parse a scanner's JSON, with a clean error instead of a stack trace on garbage."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScanError(f"{tool} returned output that is not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ScanError(f"{tool} returned unexpected JSON (expected an object)")
    return data


# --------------------------------------------------------------------------- #
# the scanners
# --------------------------------------------------------------------------- #
def run_semgrep(
    path: Path, timeout_s: int = DEFAULT_TIMEOUT_S, config: str | None = None
) -> dict[str, Any]:
    """Semgrep over ``path``. Defaults to the BUNDLED offline ruleset — no network, no account.

    ``config`` may name a registry ruleset (e.g. ``p/security-audit``) when the operator wants
    the full catalogue; that form DOES require network access (documented, not silent).
    """
    exe = _require("semgrep")
    ruleset = config or str(BUNDLED_RULES)
    argv = [
        exe, "--json", "--quiet",
        "--config", ruleset,
        "--metrics", "off",             # no telemetry
        "--disable-version-check",      # no phone-home on start
        "--timeout", str(min(timeout_s, MAX_TIMEOUT_S)),
        "--max-target-bytes", "2000000",
        str(path),
    ]
    stdout, duration = _spawn(argv, min(timeout_s, MAX_TIMEOUT_S))
    data = _parse_json("semgrep", stdout)
    data["_duration_s"] = round(duration, 2)
    data["_ruleset"] = ruleset
    return data


def run_bandit(path: Path, timeout_s: int = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
    """Bandit over the Python in ``path``. Bandit exits 1 when it finds issues — that is a
    normal result, not an error, so the exit code is not treated as failure."""
    exe = _require("bandit")
    argv = [
        exe, "-r", str(path), "-f", "json", "-q",
        "--exclude", ",".join(f"*/{d}/*" for d in sorted(SKIP_DIRS)),
    ]
    stdout, duration = _spawn(argv, min(timeout_s, MAX_TIMEOUT_S))
    data = _parse_json("bandit", stdout)
    data["_duration_s"] = round(duration, 2)
    return data
