"""Build #10 DC PREREQUISITE PROBE — read-only inventory of the lab domain controller.

Answers "would the build #10 C2 path even have the pieces it needs?" BEFORE anyone runs a
proof: does the DC have a route to the published listener, is there DNS/HTTPS egress, is
tooling already staged, what is Defender's posture, what OS/PowerShell is this. Knowing
that up front is the difference between a proof that reports a real NOTRUN and an hour
spent debugging a tunnel that was never going to route.

*** THIS PROBE IS READ-ONLY AND MUST STAY READ-ONLY. ***

It runs NO offensive command, stages nothing, changes no setting, and starts no listener.
Every probe is an inventory question. That is not just a promise in a docstring — each
script is checked against a read-only cmdlet allow-list by ``assert_read_only()`` before it
is sent anywhere, and a probe added later with a mutating verb (Set-/New-/Start-/Remove-/
Invoke-...) makes this file raise instead of run. The guard fails CLOSED: an unrecognised
cmdlet is refused, not waved through, so the read-only claim cannot rot as probes are added.

It also authors no offensive strings, which is what keeps it separate from the four C2
proof scripts. Those hold their offensive commands as operator-filled slots and report
NOT-RUN while the slots are empty (locked by backend/test_proof_honesty.py). This file has
no such slots and never will.

Traffic goes over the SAME gated path everything else uses — POST /cockpit/exec against the
running backend with a Windows profile — so what it reports is what the shipped code sees.
Even so, every probe still carries the normal approval + acknowledgement flags: a read-only
probe is not a reason to route around the gate.

Usage (needs the backend up and a Windows profile already created):

    python docker/proof/dc_prereq_probe.py --profile win-xxxxxxxxxxxx
    python docker/proof/dc_prereq_probe.py --profile win-xxxxxxxxxxxx --base http://127.0.0.1:8000
    python docker/proof/dc_prereq_probe.py --list      # print the probes, contact nothing

Exit status: 0 every probe answered, 1 one or more failed to answer, 2 bad invocation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request

DEFAULT_BASE = "http://127.0.0.1:8000"

# --------------------------------------------------------------------------- #
# The read-only guard.
# --------------------------------------------------------------------------- #

# PowerShell verbs that only ever OBSERVE. `Test-*` is included because the Test-NetConnection
# / Test-Path used here are reachability and existence questions; neither writes anything.
READ_ONLY_VERBS = frozenset(
    {
        "Get",
        "Test",
        "Select",
        "Where",
        "ForEach",
        "Measure",
        "Sort",
        "Group",
        "Compare",
        "Format",
        "Resolve",
        "Out",
    }
)

# Refused by name even if some future verb list would admit them: these are the ways a
# "read-only" script stops being read-only without looking like it changed.
FORBIDDEN = (
    "Invoke-Expression",
    "Invoke-Command",
    "Invoke-WebRequest",
    "Invoke-RestMethod",
    "Start-Process",
    "iex",
    "downloadstring",
    "downloadfile",
)

_CMDLET = re.compile(r"\b([A-Z][a-z]+)-([A-Za-z][A-Za-z0-9]*)\b")


class NotReadOnly(Exception):
    """A probe script asked to do something other than observe."""


def assert_read_only(script: str) -> None:
    """Raise unless every cmdlet in ``script`` is an observation. Fails CLOSED.

    An unknown verb is a refusal, not a pass. That is the whole point: the next person to
    add a probe cannot quietly make this file mutate the DC, because a verb this list has
    never seen stops the run instead of being assumed harmless.
    """
    low = script.lower()
    for bad in FORBIDDEN:
        if bad.lower() in low:
            raise NotReadOnly(f"probe uses {bad!r} — this file is READ-ONLY")
    for verb, noun in _CMDLET.findall(script):
        if verb not in READ_ONLY_VERBS:
            raise NotReadOnly(
                f"probe uses {verb}-{noun!r}: verb {verb!r} is not a read-only verb "
                f"(allowed: {', '.join(sorted(READ_ONLY_VERBS))})"
            )


# --------------------------------------------------------------------------- #
# The probes. Inventory questions only — see the read-only guard above.
# --------------------------------------------------------------------------- #

PROBES: list[tuple[str, str]] = [
    (
        "TAP adapters present on the DC",
        "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status | "
        'ForEach-Object { "$($_.Name) | $($_.InterfaceDescription) | $($_.Status)" }',
    ),
    (
        "tunnel client already staged?",
        "if (Test-Path 'C:\\Tools\\iodine.exe') { 'PRESENT' } else { 'ABSENT' }",
    ),
    (
        "HTTPS egress from the DC (could it fetch tooling)",
        "(Test-NetConnection 8.8.8.8 -Port 443 -InformationLevel Quiet "
        "-WarningAction SilentlyContinue)",
    ),
    (
        "DNS egress from the DC (the UDP/53 path a tunnel would ride)",
        "(Test-NetConnection 8.8.8.8 -Port 53 -InformationLevel Quiet "
        "-WarningAction SilentlyContinue)",
    ),
    (
        "route to the host VMnet8 gateway (where the published listener lives)",
        "(Test-NetConnection 192.168.13.1 -InformationLevel Quiet "
        "-WarningAction SilentlyContinue)",
    ),
    (
        "Defender posture (real-time protection + tamper protection)",
        "$s = Get-MpComputerStatus; "
        '"RealTime=$($s.RealTimeProtectionEnabled) Tamper=$($s.IsTamperProtected) " + '
        '"AntiMalware=$($s.AMServiceEnabled)"',
    ),
    (
        "OS + PowerShell version",
        '"$((Get-CimInstance Win32_OperatingSystem).Caption) | PS $($PSVersionTable.PSVersion)"',
    ),
]


# --------------------------------------------------------------------------- #
# Transport — the real backend route, not a side channel.
# --------------------------------------------------------------------------- #


def _post(base: str, path: str, body: dict, timeout: int) -> tuple[int, str]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        base + path, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # connection refused, DNS, timeout — report, never crash
        return 0, str(exc)


def run_probe(base: str, profile: str, script: str, timeout: int = 120) -> tuple[int, str]:
    """Send one read-only probe through the gated exec route. Returns (exit_code, output)."""
    assert_read_only(script)  # belt and braces: also checked up front in main()
    status, raw = _post(
        base,
        "/cockpit/exec",
        {
            "command": script,
            "args": [],
            "approved": True,
            "dangerous_ack": True,
            "windows_profile_id": profile,
            "timeout_seconds": timeout,
        },
        timeout=timeout + 30,
    )
    if status != 200:
        return -1, f"HTTP {status}: {raw[:400]}"

    out: list[str] = []
    code: int | None = None
    for line in (raw or "").splitlines():
        if not line.startswith("data: "):
            continue
        try:
            event = json.loads(line[6:])
        except json.JSONDecodeError:
            continue
        if event.get("type") == "stdout":
            out.append(event.get("line", ""))
        elif event.get("type") == "exit":
            code = event.get("code")
    return (code if code is not None else -1), "\n".join(out).strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only prerequisite probe of the lab DC (runs nothing offensive)."
    )
    parser.add_argument(
        "--profile",
        help="Windows profile id the backend already holds (e.g. win-xxxxxxxxxxxx). "
        "Required unless --list is given; deliberately has NO default, so this never "
        "fires at whatever host a stale id happens to name.",
    )
    parser.add_argument("--base", default=DEFAULT_BASE, help=f"backend base URL (default {DEFAULT_BASE})")
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the probes and exit — contacts nothing, touches nothing",
    )
    args = parser.parse_args(argv)

    # Check EVERY probe before sending ANY. A mutating probe should stop the run at the
    # start, not after some of its siblings have already gone out.
    try:
        for _, script in PROBES:
            assert_read_only(script)
    except NotReadOnly as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    if args.list:
        print(f"{len(PROBES)} read-only probes (all verified read-only):\n")
        for label, script in PROBES:
            print(f"  [{label}]\n    {script}\n")
        return 0

    if not args.profile:
        parser.error("--profile is required (or use --list)")

    print(f"== DC prerequisite probe via {args.base} (profile {args.profile}) ==")
    print("== read-only: inventory questions only, nothing staged, nothing changed ==\n", flush=True)

    failures = 0
    for label, script in PROBES:
        code, out = run_probe(args.base, args.profile, script)
        if code != 0:
            failures += 1
        print(f"[{label}]", flush=True)
        print(f"  exit={code}", flush=True)
        for line in (out or "(no output)").splitlines():
            print(f"    {line}", flush=True)
        print(flush=True)

    answered = len(PROBES) - failures
    print(f"== {answered}/{len(PROBES)} probes answered ==")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
