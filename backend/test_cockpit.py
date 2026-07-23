"""Unit tests for the Cockpit safety layers (allowlist + target lock + gate order).

These guard the independent safety mechanisms (docs/cockpit-plan.md §c):
  1. allowlist — only known-safe commands, no shell metachars, per-command arg rules;
  2. target lock — the lab must be explicitly targeted; no other host may appear;
  3. gate order — validate_request rejects at allowlist → target → approval BEFORE it
     ever reaches the sandbox/isolation check (so an unsafe request never touches Docker).

Hermetic: the first three gates need no Docker. The live isolation gate + real exec are
exercised by the M1.5 integration demo, not here. Run:  python test_cockpit.py
"""
from __future__ import annotations

from cockpit import allowlist as A
from cockpit import executor as E
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


def test_gate_order_rejects_before_execution() -> None:
    # non-allowlisted command → rejected at the allowlist gate (no Docker touched)
    r = E.validate_request(ExecRequest(command="bash", args=["-c", "id"], approved=True))
    assert r is not None and r.gate == "allowlist", "non-allowlisted must reject at allowlist"

    # allowlisted + approved but a NON-lab target → rejected at the target gate
    r = E.validate_request(
        ExecRequest(command="nmap", args=["-sV", "scanme.nmap.org"], approved=True)
    )
    assert r is not None and r.gate == "target", "non-lab target must reject at target gate"

    # allowlisted + lab target but NOT approved → rejected at the approval gate
    r = E.validate_request(
        ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=False)
    )
    assert r is not None and r.gate == "approval", "unapproved must reject at approval gate"

    # a fully valid request must clear the first three gates: if it rejects at all,
    # it can ONLY be the sandbox/isolation gate (never allowlist/target/approval).
    r = E.validate_request(
        ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=True)
    )
    assert r is None or r.gate == "sandbox", (
        "valid approved lab request must pass allowlist/target/approval "
        f"(got gate={getattr(r, 'gate', None)})"
    )
    print("  gate order rejects before execution: PASS")


if __name__ == "__main__":
    test_allowlist_validation()
    test_target_lock()
    test_gate_order_rejects_before_execution()
    print("ALL cockpit safety-layer tests pass")
