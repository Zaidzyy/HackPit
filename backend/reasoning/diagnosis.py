"""2.4 — failure diagnosis: when a step fails, diagnose it; do not blindly repeat it.

A shallow loop that sees "connection refused" tends to run the exact same command again. A
reasoning loop asks WHY it failed and proposes the check that would explain it — a reachability
probe before another exploit attempt, a DNS resolve before another HTTP fetch. This module reads
the last run's output, classifies the failure, and offers a diagnostic/alternative as a proposal.

Propose-only, like everything in this package. The diagnostic is a suggested next command a
human still approves; nothing here runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ledger import classify_run

# failure kind -> (marker substrings, human explanation, how to diagnose)
_KINDS: list[tuple[str, tuple[str, ...], str]] = [
    ("connection-refused", ("connection refused",),
     "the port is closed or nothing is listening there right now"),
    ("dns", ("could not resolve host", "name or service not known"),
     "the hostname does not resolve from the sandbox"),
    ("unreachable", ("no route to host", "network is unreachable", "unable to connect"),
     "the host is not reachable on the network"),
    ("timeout", ("connection timed out", "timed out", "timeout"),
     "the host did not answer in time — filtered, down, or rate-limiting"),
    ("auth", ("authentication failed", "login failed", "access denied", "401", "403"),
     "the credential or authorization was rejected"),
    ("permission", ("operation not permitted", "permission denied", "requires root"),
     "the sandbox profile blocked the operation (caps / no-new-privileges)"),
    ("missing-tool", ("command not found", "executable not found"),
     "the tool is not installed under that name in the sandbox"),
]


@dataclass
class Failure:
    kind: str
    explanation: str
    detail: str  # the raw marker / exit info from the ledger classifier


def detect_failure(run: dict[str, Any]) -> Failure | None:
    """Classify the failure in one run, or None if it did not fail."""
    if not run:
        return None
    outcome, detail = classify_run(run)
    if outcome != "failed":
        return None
    blob = ((run.get("stdout") or "") + "\n" + (run.get("stderr") or "")).lower()
    for kind, markers, explanation in _KINDS:
        if any(m in blob for m in markers):
            return Failure(kind, explanation, detail)
    return Failure("unknown", "the step failed but the reason is not one we pattern-match", detail)


def _host_token(args: list[str]) -> str:
    """A host/url-shaped token from the failed command, to point the diagnostic at."""
    for a in args:
        s = str(a)
        if s.startswith(("http://", "https://")):
            return s
        if "." in s and "/" not in s and not s.startswith("-"):
            return s
    return ""


def diagnostic_for(failure: Failure, command: str, args: list[str]) -> dict[str, Any] | None:
    """A concrete diagnostic/alternative for a failure — or None when a plain retry is right.

    Returns ``{command, args, hypothesis, rationale}`` shaped like a proposal fragment. The
    canonical case: connection-refused -> a reachability check (nmap -Pn against the port) BEFORE
    another attempt, so the loop learns whether the service is even there.
    """
    host = _host_token([str(a) for a in (args or [])])
    if failure.kind in ("connection-refused", "unreachable", "timeout") and host:
        bare = host.split("//")[-1].split("/")[0].split(":")[0]
        return {
            "command": "nmap",
            "args": ["-Pn", "-sV", bare],
            "hypothesis": f"before retrying, confirm whether {bare} is actually up and what is "
                          f"listening — {failure.explanation}",
            "rationale": "reachability check to distinguish a down/filtered host from a wrong "
                         "port, instead of repeating the failed command.",
        }
    if failure.kind == "dns" and host:
        bare = host.split("//")[-1].split("/")[0].split(":")[0]
        return {
            "command": "dig",
            "args": ["+short", bare],
            "hypothesis": f"resolve {bare} first — {failure.explanation}",
            "rationale": "a DNS resolution check explains the failure before another HTTP attempt.",
        }
    return None


def advice(runs: list[dict[str, Any]]) -> str:
    """A prompt hint appended when the MOST RECENT run failed: diagnose, do not repeat.

    "" when the last run did not fail, so a healthy loop's prompt is unchanged.
    """
    if not runs:
        return ""
    failure = detect_failure(runs[-1])
    if failure is None:
        return ""
    last = runs[-1]
    cmdline = " ".join([str(last.get("command") or ""), *[str(a) for a in (last.get("args") or [])]]).strip()
    lines = [
        "",
        f"LAST STEP FAILED ({failure.kind}): {failure.explanation}.",
        f"  $ {cmdline[:160]}",
        "Do NOT simply repeat it. Propose a DIAGNOSTIC that explains the failure (e.g. a "
        "reachability or resolution check), or a genuinely different alternative.",
    ]
    diag = diagnostic_for(failure, str(last.get("command") or ""),
                          [str(a) for a in (last.get("args") or [])])
    if diag:
        dl = " ".join([diag["command"], *diag["args"]])
        lines.append(f"  Suggested diagnostic: {dl}  — {diag['rationale']}")
    return "\n".join(lines)
