"""Unit tests for the Cockpit safety layers (allowlist + target lock + refusal).

These guard the three independent safety mechanisms (docs/cockpit-plan.md §c):
  1. allowlist — only known-safe commands, no shell metachars, per-command arg rules;
  2. target lock — every hostish operand must be the lab, nothing else;
  3. refusal — sandbox/executor entrypoints raise until wired (M1.2/M1.3), so no
     command can run before the isolation proof exists.

Self-contained (stdlib only, no live Docker). Run:  python test_cockpit.py
"""
from __future__ import annotations

from cockpit import allowlist as A
from cockpit import executor as E
from cockpit import sandbox as S
from cockpit.models import ExecRequest


def test_allowlist_validation() -> None:
    ok, _ = A.validate("nmap", ["-sV", "-T4", "hackpit-lab-target"])
    assert ok, "plain nmap recon must be allowed"

    ok, reason = A.validate("nmap", ["--script", "vuln", "hackpit-lab-target"])
    assert not ok and "script" in reason, "nmap scripting must be blocked in M1"

    ok, _ = A.validate("curl", ["-s", "http://hackpit-lab-target:3000"])
    assert ok, "simple curl must be allowed"

    ok, reason = A.validate("bash", ["-c", "id"])
    assert not ok and "allowlist" in reason, "non-allowlisted command must be blocked"

    ok, reason = A.validate("curl", ["http://x; rm -rf /"])
    assert not ok and "forbidden" in reason, "shell metachars must be blocked"

    ok, reason = A.validate("nmap", ["x"] * 99)
    assert not ok and "too many" in reason, "arg-count ceiling must be enforced"
    print("  allowlist validation: PASS")


def test_target_lock() -> None:
    for args in (
        ["-sV", "hackpit-lab-target"],
        ["http://hackpit-lab-target:3000/rest"],
        ["-s", "http://lab-target/"],
    ):
        ok, reason = E.check_target_lock(args)
        assert ok, f"lab target must be allowed: {args} ({reason})"

    for args in (
        ["scanme.nmap.org"],
        ["http://169.254.169.254/latest"],  # cloud metadata endpoint
        ["http://127.0.0.1:8000"],          # host loopback
    ):
        ok, reason = E.check_target_lock(args)
        assert not ok, f"non-lab target must be blocked: {args}"
    print("  target lock: PASS")


def test_execution_refuses_until_wired() -> None:
    for call in (S.is_sandbox_up, S.assert_isolation_proven):
        try:
            call()
        except NotImplementedError:
            pass
        else:
            raise AssertionError(f"{call.__name__} must refuse until wired")

    try:
        E.run_command(
            ExecRequest(command="nmap", args=["hackpit-lab-target"], approved=True)
        )
    except NotImplementedError:
        pass
    else:
        raise AssertionError("run_command must refuse until wired (M1.3)")
    print("  execution refuses until wired: PASS")


if __name__ == "__main__":
    test_allowlist_validation()
    test_target_lock()
    test_execution_refuses_until_wired()
    print("ALL cockpit safety-layer tests pass")
