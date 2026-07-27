"""Regression-lock for the PREVALIDATED path's belt-and-suspenders gate re-checks.

``executor.iter_run(request, prevalidated=True)`` SKIPS ``validate_request`` — the router
already ran it to decide the HTTP status, so re-running it would classify every command twice.
That shortcut is safe only for as long as every caller really does validate first, so the
load-bearing gates are re-checked INSIDE iter_run regardless:

  * approval — re-checked for engagement and windows since build #4 (never-auto-run is the sole
    floor on a real target).
  * danger   — re-checked for ALL THREE modes as of build #7. This is what this file adds.

THE ASYMMETRY THIS CLOSES. Before build #7 the prevalidated path re-checked approval but not
danger. Nothing was exposed — the single ``prevalidated=True`` caller (cockpit/router.py)
validates first — but "no caller does this today" is not an invariant, it is a coincidence that
holds until someone adds a second caller. A dangerous command with no red-confirm would have
run. The re-check makes the shortcut safe by construction instead of by convention.

PER-MODE CLASSIFIER. The re-check must use the SAME danger function ``validate_request`` uses
for that mode, not a single generic one:
  * windows        -> ``executor.windows_danger_reasons`` (the whole joined PowerShell script)
  * lab/engagement -> ``allowlist.dangerous_command_heuristic`` (the argv structure)
The windows case below is deliberately a command that ONLY the script classifier catches
(``Write-Host go ; Invoke-Mimikatz``) — the Critical-2 shape from the 2026-07-27 gate audit.
A re-check wired to the generic argv heuristic would let it through, and this file fails.

Hermetic: no Docker, no WinRM, no network. The process spawn and the WinRM transport are
monkeypatched by hand (this project has no pytest, so no fixtures).

Run:  backend/.venv/Scripts/python.exe backend/test_prevalidated_gates.py
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from cockpit import allowlist, executor as E, winprofiles, winrm_transport
from cockpit.models import EngagementRecord, ExecRequest

_LAB = "hackpit-lab-target"
_REAL = "scanme.nmap.org"

# A dangerous command in the ARGV-shaped sense: an interpreter with an eval flag. Flagged by
# allowlist.dangerous_command_heuristic, which is what lab and engagement mode use.
_ARGV_DANGER = ("python3", ["-c", "import os; os.system('id')"])

# A dangerous command in the WHOLE-SCRIPT sense ONLY. `Write-Host` with these args is not an
# interpreter invocation, so the argv heuristic sees nothing; the joined string
# "Write-Host go ; Invoke-Mimikatz" is a credential-dumping PowerShell program. This is the
# exact shape Critical 2 missed, and it is the reason the windows re-check may not be wired
# to the generic heuristic.
_SCRIPT_ONLY_DANGER = ("Write-Host", ["go", ";", "Invoke-Mimikatz"])


# --------------------------------------------------------------------------- #
# harness
# --------------------------------------------------------------------------- #
class _NoSpawn:
    """Records every attempt to spawn a process and lets none of them happen.

    Popen raising FileNotFoundError makes iter_run yield a single {"type": "error"} event and
    return cleanly, so a test that reaches the spawn still terminates — it just gets caught.
    ``calls`` is the evidence: an empty list means nothing was ever launched.
    """

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.winrm: list[str] = []

    def __enter__(self) -> "_NoSpawn":
        self._orig = (E.subprocess.Popen, E.runstore.save_run, E.state_ingest.ingest_run,
                      winrm_transport.run, E.winrm_transport.run)

        def fake_popen(argv, **kw):
            self.calls.append(list(argv))
            raise FileNotFoundError("test: no process may be spawned")

        def fake_winrm(profile, command, timeout):
            self.winrm.append(command)
            return winrm_transport.WinRMResult(0, "ok\n", "")

        E.subprocess.Popen = fake_popen
        E.runstore.save_run = lambda rec: None
        E.state_ingest.ingest_run = lambda **kw: {}
        winrm_transport.run = fake_winrm
        E.winrm_transport.run = fake_winrm
        return self

    def __exit__(self, *exc) -> None:
        (E.subprocess.Popen, E.runstore.save_run, E.state_ingest.ingest_run,
         winrm_transport.run, E.winrm_transport.run) = self._orig
        return False

    @property
    def launched(self) -> bool:
        """Did ANY execution surface get reached — docker exec or the WinRM transport?"""
        return bool(self.calls or self.winrm)


class _WinProfile:
    """A throwaway Windows profile DB, so a windows-mode request resolves."""

    def __enter__(self) -> dict:
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._orig = winprofiles.DB_PATH
        winprofiles.DB_PATH = Path(self._tmp.name) / "sessions.db"
        winprofiles.init_db()
        return winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")

    def __exit__(self, *exc) -> None:
        winprofiles.DB_PATH = self._orig
        self._tmp.cleanup()
        return False


def _engagement():
    """Make the executor resolve one active engagement; returns a restore fn."""
    rec = EngagementRecord(
        engagement_id="eng-preval0000", target=_REAL,
        authorization="authorized test target", active=True,
        entered_at="2026-07-27T00:00:00+00:00",
    )
    orig = E.engagement.get_active
    E.engagement.get_active = lambda eid: rec if eid == rec.engagement_id else None

    def restore():
        E.engagement.get_active = orig

    return restore


def _rejected_gate(events: list[dict]) -> str | None:
    if len(events) == 1 and events[0].get("type") == "rejected":
        return events[0].get("gate")
    return None


# --------------------------------------------------------------------------- #
# 0. the commands this file relies on really ARE dangerous
# --------------------------------------------------------------------------- #
def test_the_probe_commands_are_actually_flagged() -> None:
    """Guards against the vacuous-test failure mode: every assertion below is worthless if the
    command it fires at was never dangerous in the first place. Assert the classifiers
    themselves, and assert the ASYMMETRY that makes the windows case load-bearing."""
    cmd, args = _ARGV_DANGER
    assert allowlist.dangerous_command_heuristic(cmd, args), \
        f"{cmd} {args} must be flagged by the argv heuristic or the lab/engagement tests are vacuous"

    wcmd, wargs = _SCRIPT_ONLY_DANGER
    assert E.windows_danger_reasons(wcmd, wargs), \
        f"{wcmd} {wargs} must be flagged by the WINDOWS classifier"
    # THE POINT: the generic heuristic does NOT catch it. If this ever starts passing, the
    # windows test below stops proving that the re-check uses the per-mode classifier.
    assert not allowlist.dangerous_command_heuristic(wcmd, wargs), (
        f"{wcmd} {wargs} is now caught by the generic argv heuristic too — pick a new "
        "script-only probe, or the windows re-check is no longer proven to be per-mode")
    print("  probe commands are really dangerous, and the windows one is script-only: PASS")


# --------------------------------------------------------------------------- #
# 1. the re-check fires, in every mode
# --------------------------------------------------------------------------- #
def test_prevalidated_lab_danger_is_rejected() -> None:
    cmd, args = _ARGV_DANGER
    req = ExecRequest(command=cmd, args=[*args, _LAB], approved=True, dangerous_ack=False)
    with _NoSpawn() as spy:
        events = list(E.iter_run(req, prevalidated=True))
    assert _rejected_gate(events) == "danger", (
        "LAB: a prevalidated dangerous command with no ack must reject at the danger gate — "
        f"got {[e.get('type') + ':' + str(e.get('gate')) for e in events]}")
    assert not spy.launched, "LAB: nothing may be spawned when the danger gate refuses"
    print("  LAB: prevalidated + dangerous + no ack -> gate=danger, nothing spawned: PASS")


def test_prevalidated_engagement_danger_is_rejected() -> None:
    cmd, args = _ARGV_DANGER
    restore = _engagement()
    try:
        req = ExecRequest(command=cmd, args=[*args, _REAL], approved=True,
                          dangerous_ack=False, engagement_id="eng-preval0000")
        with _NoSpawn() as spy:
            events = list(E.iter_run(req, prevalidated=True))
    finally:
        restore()
    assert _rejected_gate(events) == "danger", (
        "ENGAGEMENT: a prevalidated dangerous command with no ack must reject at the danger "
        f"gate — got {[e.get('type') + ':' + str(e.get('gate')) for e in events]}")
    assert not spy.launched, "ENGAGEMENT: nothing may reach a real target when danger refuses"
    print("  ENGAGEMENT: prevalidated + dangerous + no ack -> gate=danger, nothing spawned: PASS")


def test_prevalidated_windows_danger_is_rejected() -> None:
    """The per-mode proof: this command is invisible to the generic argv heuristic and is
    caught only by windows_danger_reasons on the joined script."""
    cmd, args = _SCRIPT_ONLY_DANGER
    with _WinProfile() as p:
        req = ExecRequest(command=cmd, args=list(args), approved=True,
                          dangerous_ack=False, windows_profile_id=p["profile_id"])
        with _NoSpawn() as spy:
            events = list(E.iter_run(req, prevalidated=True))
    assert _rejected_gate(events) == "danger", (
        "WINDOWS: a prevalidated whole-script dangerous command with no ack must reject at the "
        f"danger gate — got {[e.get('type') + ':' + str(e.get('gate')) for e in events]}")
    assert not spy.winrm, "WINDOWS: nothing may reach the WinRM transport when danger refuses"
    print("  WINDOWS: prevalidated + script-only danger + no ack -> gate=danger, "
          "nothing sent: PASS")


# --------------------------------------------------------------------------- #
# 2. positive controls — the guard is additive, not a blanket refusal
# --------------------------------------------------------------------------- #
def test_the_same_request_with_the_ack_still_runs() -> None:
    """The red-confirm still WORKS. A guard that refuses even with the ack would pass every
    test above while breaking the feature."""
    cmd, args = _ARGV_DANGER
    checks = []

    req = ExecRequest(command=cmd, args=[*args, _LAB], approved=True, dangerous_ack=True)
    with _NoSpawn() as spy:
        list(E.iter_run(req, prevalidated=True))
    assert spy.calls, "LAB: an ACKED dangerous command must still reach the spawn"
    checks.append("lab")

    restore = _engagement()
    try:
        req = ExecRequest(command=cmd, args=[*args, _REAL], approved=True,
                          dangerous_ack=True, engagement_id="eng-preval0000")
        with _NoSpawn() as spy:
            list(E.iter_run(req, prevalidated=True))
        assert spy.calls, "ENGAGEMENT: an ACKED dangerous command must still reach the spawn"
        checks.append("engagement")
    finally:
        restore()

    wcmd, wargs = _SCRIPT_ONLY_DANGER
    with _WinProfile() as p:
        req = ExecRequest(command=wcmd, args=list(wargs), approved=True,
                          dangerous_ack=True, windows_profile_id=p["profile_id"])
        with _NoSpawn() as spy:
            list(E.iter_run(req, prevalidated=True))
        assert spy.winrm, "WINDOWS: an ACKED dangerous command must still reach the transport"
        checks.append("windows")

    print(f"  POSITIVE CONTROL: with the ack, all {len(checks)} modes still run "
          f"({', '.join(checks)}): PASS")


def test_a_benign_prevalidated_request_is_unaffected() -> None:
    """The re-check may only ADD a rejection for commands the classifier flags. A plain scan
    carries no ack and must be untouched in every mode."""
    checks = []

    req = ExecRequest(command="nmap", args=["-sV", _LAB], approved=True)
    with _NoSpawn() as spy:
        list(E.iter_run(req, prevalidated=True))
    assert spy.calls, "LAB: a benign command must run without any ack"
    checks.append("lab")

    restore = _engagement()
    try:
        req = ExecRequest(command="nmap", args=["-sV", _REAL], approved=True,
                          engagement_id="eng-preval0000")
        with _NoSpawn() as spy:
            list(E.iter_run(req, prevalidated=True))
        assert spy.calls, "ENGAGEMENT: a benign command must run without any ack"
        checks.append("engagement")
    finally:
        restore()

    with _WinProfile() as p:
        req = ExecRequest(command="whoami", approved=True, windows_profile_id=p["profile_id"])
        with _NoSpawn() as spy:
            list(E.iter_run(req, prevalidated=True))
        assert spy.winrm, "WINDOWS: a benign command must run without any ack"
        checks.append("windows")

    print(f"  benign prevalidated requests unaffected in all {len(checks)} modes "
          f"({', '.join(checks)}): PASS")


# --------------------------------------------------------------------------- #
# 3. approval still precedes danger (the existing re-check is not disturbed)
# --------------------------------------------------------------------------- #
def test_approval_still_precedes_danger_on_the_prevalidated_path() -> None:
    """A request failing BOTH re-checks is rejected at approval, matching validate_request's
    gate order. If danger were re-checked first, the two paths would disagree about which gate
    a request died at — and the audit record would name the wrong one."""
    cmd, args = _ARGV_DANGER
    restore = _engagement()
    try:
        req = ExecRequest(command=cmd, args=[*args, _REAL], approved=False,
                          dangerous_ack=False, engagement_id="eng-preval0000")
        with _NoSpawn() as spy:
            events = list(E.iter_run(req, prevalidated=True))
        assert _rejected_gate(events) == "approval", \
            f"approval must precede danger, got gate={_rejected_gate(events)}"
        assert not spy.launched
    finally:
        restore()

    wcmd, wargs = _SCRIPT_ONLY_DANGER
    with _WinProfile() as p:
        req = ExecRequest(command=wcmd, args=list(wargs), approved=False,
                          dangerous_ack=False, windows_profile_id=p["profile_id"])
        with _NoSpawn() as spy:
            events = list(E.iter_run(req, prevalidated=True))
        assert _rejected_gate(events) == "approval", \
            f"windows: approval must precede danger, got gate={_rejected_gate(events)}"
        assert not spy.winrm
    print("  gate ORDER preserved on the prevalidated path (approval before danger): PASS")


if __name__ == "__main__":
    test_the_probe_commands_are_actually_flagged()
    test_prevalidated_lab_danger_is_rejected()
    test_prevalidated_engagement_danger_is_rejected()
    test_prevalidated_windows_danger_is_rejected()
    test_the_same_request_with_the_ack_still_runs()
    test_a_benign_prevalidated_request_is_unaffected()
    test_approval_still_precedes_danger_on_the_prevalidated_path()
    print("ALL prevalidated-path gate re-check tests pass")
