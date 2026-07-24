"""Command parsing, the dangerous-command heuristic, and best-effort target helpers.

THE ALLOWLIST GATE WAS REMOVED (Zaid's decision, 2026-07-24). The cockpit no longer
restricts WHICH binary may run: the human-approved agent may run ANY single command
(one binary + args) against the isolated lab. This module therefore no longer holds a
command allowlist or a per-tool flag schema. What survives:

* the flag PARSER (:func:`_is_flag_token`, :func:`flags_in_args`) — spots a flag in any
  form (bare, combined short, ``=``-joined); reused by the heuristic to detect an eval
  flag (``-c``/``-e``);
* :func:`dangerous_command_heuristic` — an OVER-INCLUSIVE, best-effort detector that
  drives the red-confirm (interpreters, reverse-shell/exec tools, frameworks). It is an
  ASSIST, not a guarantee: a false positive costs one extra confirm; a false negative is a
  missed warning. The HUMAN approval is the real gate, so gaps are expected by design;
* :func:`extract_hostish` — for the best-effort target-lock (host-shaped tokens must be
  the lab); note it CANNOT see hosts hidden inside arbitrary commands (e.g.
  ``python -c "...connect..."``) — isolation is the real bound on the lab;
* :data:`SUGGESTED_COMMANDS` — purely informational hints for the UI (not enforced).

The real safety bounds on the lab are ISOLATION (egress-less sandbox) + HUMAN APPROVAL,
plus this heuristic red-confirm. Execution stays argv-style (never a shell), so what is
approved is exactly what runs.
"""

from __future__ import annotations

import os

# Informational only — example commands the UI may surface. NOT an allowlist; anything
# may run. Kept so the manual cockpit surface has something to suggest.
SUGGESTED_COMMANDS: list[tuple[str, str]] = [
    ("nmap", "Port/service scan of the lab target."),
    ("curl", "Fetch a URL from the lab target."),
    ("whatweb", "Fingerprint the lab target's web stack."),
    ("sqlmap", "SQL-injection exploitation against the lab."),
    ("ffuf", "Web fuzzer against the lab."),
    ("nuclei", "Template scanner against the lab."),
    ("gobuster", "Directory/DNS brute-forcer."),
    ("nikto", "Web server scanner."),
]


def _is_flag_token(token: str) -> bool:
    """True if a token is flag-shaped (a leading '-' plus at least one more char).

    A lone ``-`` (stdin) is an operand, not a flag. Only used now by the heuristic to
    spot an eval flag — there is no flag rejection anymore.
    """
    return len(token) >= 2 and token[0] == "-"


def flags_in_args(args: list[str]) -> set[str]:
    """Best-effort set of flag identities present in ``args`` — whole single-dash/long
    tokens plus each letter of a short cluster, ``=``-joined names split on ``=``.

    Over-inclusive on purpose: the heuristic only needs to spot an eval flag like ``-c``
    (in ``-c``, ``-abc``, ``-c=…``) or ``--command``. Reuses the flag parser so the
    forms stay consistent with how the tools actually parse them.
    """
    found: set[str] = set()
    for tok in args:
        if not _is_flag_token(tok):
            continue
        base = tok.split("=", 1)[0]
        found.add(base)
        if not base.startswith("--"):  # short cluster: each letter is a flag
            for ch in base[1:]:
                found.add("-" + ch)
    return found


# --------------------------------------------------------------------------- #
# The dangerous-command heuristic (drives the red-confirm). OVER-INCLUSIVE by
# design — an ASSIST, not a guarantee. A false positive costs one extra confirm;
# a false negative is a missed warning (the HUMAN approval is the real gate).
# --------------------------------------------------------------------------- #

# Language interpreters — the binary itself is the tell (it can run arbitrary code).
_INTERPRETERS = frozenset({
    "python", "python2", "python3", "bash", "sh", "dash", "zsh", "ksh", "fish",
    "perl", "ruby", "php", "node", "nodejs", "lua", "tclsh", "expect",
    "pwsh", "powershell", "osascript", "groovy", "gawk", "awk",
})
# Raw network / exec tools commonly used for shells + exec.
_EXEC_TOOLS = frozenset({"nc", "ncat", "netcat", "socat", "telnet", "rlwrap"})
# Exploitation frameworks / payload generators.
_FRAMEWORKS = frozenset({
    "msfconsole", "msfvenom", "msfcli", "meterpreter", "empire", "sliver",
    "covenant", "cobaltstrike", "beacon", "chisel", "ligolo",
})
# Flags that mean "run this inline code / command".
_EVAL_FLAGS = frozenset({"-c", "-e", "--command", "--eval", "--exec", "-code"})
# Substrings anywhere in the args that signal a reverse shell / code exec shape.
_SHELL_MARKERS = (
    "/dev/tcp/", "/dev/udp/", "bash -i", "sh -i", "mkfifo", "/inet/tcp/",
    "pty.spawn", "os.system", "subprocess", "runtime.exec", "0>&1", ">&/dev/tcp",
    "exec 5<>", "socket(", "fsockopen", "sh >&", "cmd.exe", "-nlvp", "-e /bin",
    "curl | sh", "wget | sh", "| bash", "| sh", "base64 -d",
)


def dangerous_command_heuristic(command: str, args: list[str]) -> list[str]:
    """Return human-readable reasons this command looks dangerous (empty if it doesn't).

    Drives the red-confirm: when non-empty the executor's danger gate requires an explicit
    ``dangerous_ack`` before running (it NEVER blocks outright). Over-inclusive best-effort
    — the human approval is the real gate, so gaps are expected. Flags: language interpreters
    (esp. with an eval flag), reverse-shell/exec tools (esp. nc/ncat/socat -e/-c), exploitation
    frameworks, and reverse-shell/code-exec shapes anywhere in the args.
    """
    reasons: list[str] = []
    cmd = os.path.basename(str(command)).lower()  # handles /usr/bin/python3, ./x
    flags = flags_in_args(args)
    eval_flags = sorted(flags & _EVAL_FLAGS)

    if cmd in _INTERPRETERS:
        note = f" with {', '.join(eval_flags)} (inline code)" if eval_flags else ""
        reasons.append(f"{cmd}: language interpreter — runs arbitrary code{note}")
    if cmd in _EXEC_TOOLS:
        if flags & {"-e", "-c"}:
            reasons.append(f"{cmd} -e/-c: command execution / reverse shell")
        else:
            reasons.append(f"{cmd}: raw network tool — can carry a reverse shell")
    if cmd in _FRAMEWORKS:
        reasons.append(f"{cmd}: exploitation framework / payload generator")

    # scan the whole arg vector for reverse-shell / code-exec shapes (payloads, one-liners)
    blob = " ".join(str(a) for a in args).lower()
    for marker in _SHELL_MARKERS:
        if marker in blob:
            reasons.append(f"reverse-shell / code-exec pattern: {marker!r}")

    # de-dup, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def extract_hostish(args: list[str]) -> list[str]:
    """Return arg tokens that look like a host/URL operand (not flags).

    Used by the executor's best-effort target-lock: every hostish token must be the lab.
    Pure heuristic — flags (starting with '-') are skipped. It CANNOT see a host embedded
    inside an arbitrary command's payload; isolation is the real bound on the lab.
    """
    return [a for a in args if not a.startswith("-")]
