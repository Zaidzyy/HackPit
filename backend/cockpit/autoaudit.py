"""Append-only audit for AUTONOMOUS actions.

In modes 2 and 3 the machine fires without a per-command human sign-off, so the tamper-evident
record that replaces that sign-off is this: one JSON object per line, APPENDED, never updated or
deleted. Every auto-fire (assisted passive fire + every full-mode fire) writes one line —
timestamp, engagement, mode, tier, what ran, and the outcome.

SECRETS NEVER LAND HERE. Surface params can carry tokens/headers and a command's argv can carry
credentials, so the audit stores the surface NAME + its param KEYS (not values) and the command
with its argv REDACTED via secretargs — the same rule the run records follow.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .runstore import DB_PATH

_lock = threading.Lock()

#: Beside the run DB (gitignored). Module-global so a test can point it at a temp file.
_AUDIT_PATH = str(Path(DB_PATH).parent / "autorun-audit.jsonl")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def path() -> str:
    return _AUDIT_PATH


def _redact_args(command: str, args: list[str]) -> list[str]:
    """Argv with credential-shaped tokens masked, best-effort. Never raises."""
    try:
        from . import secretargs

        redactor = getattr(secretargs, "redact_args", None) or getattr(secretargs, "redact", None)
        if redactor is not None:
            out = redactor(command, list(args)) if _takes_two(redactor) else redactor(list(args))
            if isinstance(out, list):
                return [str(x) for x in out]
    except Exception:  # noqa: BLE001 — an audit line must never fail a run; degrade to no argv
        pass
    return []  # if we cannot prove the argv is clean, we record NONE of it, not the raw values


def _takes_two(fn: object) -> bool:
    import inspect

    try:
        return len(inspect.signature(fn).parameters) >= 2  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False


def record(*, engagement_id: str, session_id: str, mode: str, tier: str, action: str,
           proposal: dict, outcome: str, run_id: str = "", error: str = "") -> None:
    """Append one audit line for an auto-fired (or auto-queued) action. Secrets stripped. Never raises."""
    kind = str(proposal.get("kind", "command"))
    entry: dict[str, object] = {
        "at": _now(),
        "engagement_id": engagement_id or "",
        "session_id": session_id or "",
        "mode": mode,
        "tier": tier,
        "action": action,          # fire | queue | skip
        "kind": kind,
        "outcome": outcome,        # started | queued | error | skipped
        "run_id": run_id,
    }
    if kind == "surface":
        entry["surface"] = str(proposal.get("surface", ""))
        params = proposal.get("surface_params") or {}
        entry["param_keys"] = sorted(params.keys()) if isinstance(params, dict) else []
    else:
        cmd = str(proposal.get("command", ""))
        entry["command"] = cmd
        entry["args"] = _redact_args(cmd, list(proposal.get("args", []) or []))
        entry["dangerous_flags"] = list(proposal.get("dangerous_flags", []) or [])
    if error:
        entry["error"] = error[:500]

    line = json.dumps(entry, default=str, ensure_ascii=False)
    with _lock, open(_AUDIT_PATH, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def read_all() -> list[dict]:
    """Every audit line, oldest first. For a status view / a test. Missing file → empty."""
    p = Path(_AUDIT_PATH)
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out
