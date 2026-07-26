"""Functional tests for the WinRM execution transport + Windows-target profiles.

HERMETIC. No pywinrm, no network, no Docker: the transport (winrm_transport.run) is
monkeypatched with a fake, the profile store points at a throwaway SQLite file, and
runstore/state-ingest are stubbed. This exercises the executor's WINDOWS mode end to end —
that an approved Windows-target ExecRequest routes to WinRM, records a run, and comes back
as the same event shape the docker path produces.

Run:  python test_winrm.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from cockpit import executor, winprofiles, winrm_transport
from cockpit.models import ExecRequest


class _Env:
    """Point the profile store at a temp DB and swap the WinRM transport + persistence for
    fakes. Captures what the transport was asked to run and what got recorded."""

    def __init__(self, *, result=None, error=None):
        # ignore_cleanup_errors: SQLite WAL handles (the codebase's `with _connect()` pattern
        # commits but does not close) keep the temp file locked on Windows at teardown.
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._db_orig = winprofiles.DB_PATH
        self.db = Path(self._tmp.name) / "sessions.db"
        self.result = result or winrm_transport.WinRMResult(0, "ok\n", "")
        self.error = error
        self.transport_calls: list[tuple[dict, str, int]] = []
        self.saved: list = []
        self.ingested: list = []
        self._orig = {}

    def __enter__(self):
        winprofiles.DB_PATH = self.db
        winprofiles.init_db()

        def fake_run(profile, command, timeout):
            self.transport_calls.append((profile, command, timeout))
            if self.error is not None:
                raise winrm_transport.WinRMError(self.error)
            return self.result

        self._orig["transport"] = winrm_transport.run
        self._orig["save"] = executor.runstore.save_run
        self._orig["ingest"] = executor.state_ingest.ingest_run
        self._orig["get"] = executor.runstore.get_run

        winrm_transport.run = fake_run
        executor.winrm_transport.run = fake_run
        executor.runstore.save_run = lambda rec: self.saved.append(rec)
        executor.runstore.get_run = lambda rid: next(
            (r for r in self.saved if r.run_id == rid), None
        )

        def fake_ingest(**kw):
            self.ingested.append(kw)
            return {}

        executor.state_ingest.ingest_run = fake_ingest
        return self

    def __exit__(self, *exc):
        winrm_transport.run = self._orig["transport"]
        executor.winrm_transport.run = self._orig["transport"]
        executor.runstore.save_run = self._orig["save"]
        executor.runstore.get_run = self._orig["get"]
        executor.state_ingest.ingest_run = self._orig["ingest"]
        winprofiles.DB_PATH = self._db_orig
        self._tmp.cleanup()
        return False


def _events(request):
    return list(executor.iter_run(request, prevalidated=True))


def test_profile_crud_masks_secret() -> None:
    """Create/list/get/update/delete a profile — and the secret is NEVER in a public view."""
    with _Env():
        p = winprofiles.create_profile(
            "DC01", "10.0.0.5", "administrator",
            auth_kind="password", secret="Sup3rSecret!", domain="corp.local",
        )
        assert p["host"] == "10.0.0.5" and p["username"] == "administrator"
        assert p["has_secret"] is True
        assert "secret" not in p, "public view must NOT carry the raw secret"

        listed = winprofiles.list_profiles()
        assert len(listed) == 1 and "secret" not in listed[0]

        # The raw secret is reachable ONLY through the transport-only accessor.
        assert winprofiles.get_secret(p["profile_id"]) == "Sup3rSecret!"

        # Update host, leave secret empty -> secret preserved.
        up = winprofiles.update_profile(p["profile_id"], host="10.0.0.6")
        assert up["host"] == "10.0.0.6"
        assert winprofiles.get_secret(p["profile_id"]) == "Sup3rSecret!"

        assert winprofiles.delete_profile(p["profile_id"]) is True
        assert winprofiles.list_profiles() == []
    print("  profile CRUD masks the secret in every public view: PASS")


def test_windows_exec_routes_to_winrm_and_records() -> None:
    """An approved Windows-target exec runs the command on the profile host over WinRM and
    records a run whose target is that host and whose mode is 'windows'."""
    with _Env(result=winrm_transport.WinRMResult(0, "corp\\administrator\n", "")) as env:
        p = winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")
        req = ExecRequest(
            command="whoami", windows_profile_id=p["profile_id"], approved=True,
            session_id="eng-1",
        )
        events = _events(req)
        types = [e["type"] for e in events]
        assert types[0] == "start" and types[-1] == "exit", types
        start = events[0]
        assert start["mode"] == "windows" and start["transport"] == "winrm"
        assert start["target"] == "10.0.0.5"
        assert any(e["type"] == "stdout" and "administrator" in e["line"] for e in events)

        # The transport was asked to run on the PROFILE host, with the rejoined command.
        assert len(env.transport_calls) == 1
        profile, command, _timeout = env.transport_calls[0]
        assert profile["host"] == "10.0.0.5"
        assert command == "whoami"

        rec = env.saved[0]
        assert rec.mode == "windows" and rec.target == "10.0.0.5"
        assert rec.approved is True and rec.exit_code == 0
        # State ingest was invoked for the session with the remote output.
        assert env.ingested and env.ingested[0]["session_id"] == "eng-1"
    print("  windows exec routes to WinRM, records mode=windows on the profile host: PASS")


def test_command_and_args_rejoined_as_one_string() -> None:
    """A command + args (e.g. a Rubeus invocation) is rejoined into one PowerShell string."""
    with _Env() as env:
        p = winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")
        req = ExecRequest(
            command="Rubeus.exe",
            args=["kerberoast", "/outfile:hashes.txt"],
            windows_profile_id=p["profile_id"],
            approved=True,
        )
        _events(req)
        _profile, command, _timeout = env.transport_calls[0]
        assert command == "Rubeus.exe kerberoast /outfile:hashes.txt"
    print("  command + args rejoined into one PowerShell string: PASS")


def test_transport_error_is_reported_not_raised() -> None:
    """A WinRM transport failure surfaces as an error event + a recorded run, never a crash."""
    with _Env(error="host unreachable") as env:
        p = winprofiles.create_profile("DC01", "10.0.0.9", "administrator", secret="pw")
        req = ExecRequest(command="whoami", windows_profile_id=p["profile_id"], approved=True)
        events = _events(req)
        assert any(e["type"] == "error" and "unreachable" in e["reason"] for e in events)
        assert events[-1]["type"] == "exit" and events[-1]["code"] is None
        assert env.saved, "even a failed WinRM run is recorded (audit)"
    print("  transport error is reported as an event + recorded, not raised: PASS")


def test_ntlm_hash_credential_is_lm_nt_formatted() -> None:
    """A pass-the-hash profile presents the NT hash to the transport in LM:NT form."""
    nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
    profile = {
        "host": "10.0.0.5", "port": 5985, "username": "administrator", "domain": "",
        "auth_kind": "ntlm-hash", "secret": nt,
    }
    cred = winrm_transport._credential(profile)
    assert cred == f"aad3b435b51404eeaad3b435b51404ee:{nt}", cred
    # An already-formed LM:NT pair is passed through unchanged.
    profile["secret"] = f"aad3b435b51404eeaad3b435b51404ee:{nt}"
    assert winrm_transport._credential(profile) == profile["secret"]
    # A password profile presents the password verbatim.
    assert winrm_transport._credential(
        {"auth_kind": "password", "secret": "hunter2"}
    ) == "hunter2"
    print("  ntlm-hash credential is LM:NT formatted; password passed verbatim: PASS")


if __name__ == "__main__":
    test_profile_crud_masks_secret()
    test_windows_exec_routes_to_winrm_and_records()
    test_command_and_args_rejoined_as_one_string()
    test_transport_error_is_reported_not_raised()
    test_ntlm_hash_credential_is_lm_nt_formatted()
    print("ALL WinRM functional tests pass")
