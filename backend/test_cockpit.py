"""Regression-lock for the Cockpit safety invariants (docs/cockpit-plan.md §c).

These tests FAIL LOUDLY if anyone ever weakens the safety model. They guard the four
independent gates, in the order the executor enforces them:
  1. allowlist   — only known-safe commands, no shell metachars, per-command arg rules;
  2. target lock — the lab must be explicitly targeted; no other host may appear;
  3. approval    — approved must be explicitly True (no autonomous / approve-all path);
  4. isolation   — the running sandbox must be attached ONLY to internal networks; a
                   single non-internal (egress) network makes it refuse to execute.
Plus gate ORDER: a request that fails several gates is rejected at the FIRST one, and a
fully-valid request reaches (and only reaches) the isolation gate.

NOTE on gate names (the ExecRejected.gate literal, asserted below): the executor uses
``allowlist`` / ``target`` / ``approval`` / ``sandbox`` — i.e. the target-lock gate is
named ``target`` and the isolation gate is named ``sandbox``. Tests assert those exact
strings so a rename can't silently pass.

Hermetic: gates 1–3 need no Docker; the isolation gate (4) is exercised by simulating
docker inspect via monkeypatch (both the safe internal-only case and the unsafe
non-internal case), so no live daemon is required. Run:  python test_cockpit.py
"""
from __future__ import annotations

from cockpit import allowlist as A
from cockpit import executor as E
from cockpit import sandbox as S
from cockpit.models import ExecRequest
from cockpit.sandbox import SandboxError


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


def test_forbidden_metachars() -> None:
    """EVERY shell metacharacter we refuse must be rejected in an arg (defense in
    depth — we exec argv-style, but a metachar must never slip into the audit log)."""
    # one token per forbidden char, each must be refused
    for ch in [";", "|", "&", "$", "`", "\n", "\r", "<", ">", "\\", "!", "*"]:
        assert A.has_forbidden_chars(f"a{ch}b"), f"{ch!r} must be a forbidden char"
        ok, reason = A.validate("curl", [f"http://hackpit-lab-target/{ch}"])
        assert not ok and "forbidden" in reason, f"metachar {ch!r} must be rejected by validate"
    # a clean token is not falsely flagged
    assert not A.has_forbidden_chars("http://hackpit-lab-target:3000/rest/products")
    print("  forbidden metachars: PASS")


def test_per_command_arg_rules() -> None:
    """Each allowlisted command's own arg rules behave (the recon-only M1 scope)."""
    # nmap: script engine + aggressive scan are OUT of scope
    for bad in (["--script", "vuln", "hackpit-lab-target"],
                ["-sC", "hackpit-lab-target"],
                ["-A", "hackpit-lab-target"]):
        ok, reason = A.validate("nmap", bad)
        assert not ok and "script" in reason.lower(), f"nmap must block {bad}"
    # nmap: writing output to a file is out of scope
    for bad in (["-oN", "out.txt", "hackpit-lab-target"],
                ["-oX", "out.xml", "hackpit-lab-target"]):
        ok, reason = A.validate("nmap", bad)
        assert not ok and "file output" in reason.lower(), f"nmap must block {bad}"
    # nmap: a plain service/version scan is allowed
    ok, _ = A.validate("nmap", ["-sV", "-p", "80,443", "hackpit-lab-target"])
    assert ok, "plain nmap -sV must be allowed"

    # curl: tighter arg ceiling (12) than nmap
    ok, reason = A.validate("curl", ["x"] * 13)
    assert not ok and "too many" in reason, "curl arg ceiling (12) must be enforced"
    ok, _ = A.validate("curl", ["-s", "-I", "http://hackpit-lab-target:3000/"])
    assert ok, "simple curl HEAD must be allowed"

    # whatweb: tightest ceiling (8), plain fingerprint allowed
    ok, reason = A.validate("whatweb", ["x"] * 9)
    assert not ok and "too many" in reason, "whatweb arg ceiling (8) must be enforced"
    ok, _ = A.validate("whatweb", ["--color=never", "http://hackpit-lab-target:3000"])
    assert ok, "plain whatweb fingerprint must be allowed"

    # the allowlist is EXACTLY the recon-only M1 set — a regression that adds a
    # weaponised tool must trip this (update deliberately, with review, if it changes)
    assert set(A.ALLOWLIST) == {"nmap", "curl", "whatweb"}, (
        "allowlist changed — M1 is recon-only (nmap/curl/whatweb). Expanding it is a "
        "deliberate, reviewed change, not an accident."
    )
    print("  per-command arg rules: PASS")


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


def test_approval_gate() -> None:
    """approved MUST be explicitly True — there is no autonomous / approve-all path."""
    # allowlisted + lab target, but not approved → rejected at the approval gate
    r = E.validate_request(
        ExecRequest(command="curl", args=["-sI", "http://hackpit-lab-target:3000/"])
    )  # approved defaults to False
    assert r is not None and r.gate == "approval", "default (unapproved) must reject at approval"

    r = E.validate_request(
        ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=False)
    )
    assert r is not None and r.gate == "approval", "approved=False must reject at approval"
    print("  approval gate: PASS")


def test_first_failing_gate_wins() -> None:
    """A request that fails several gates is rejected at the FIRST failing gate, so an
    unsafe request never advances toward Docker on a technicality."""
    # non-allowlisted AND non-lab AND unapproved → must stop at the allowlist gate
    r = E.validate_request(
        ExecRequest(command="bash", args=["scanme.nmap.org"], approved=False)
    )
    assert r is not None and r.gate == "allowlist", "must reject at the FIRST gate (allowlist)"

    # allowlisted but non-lab AND unapproved → target beats approval (target is gate 2)
    r = E.validate_request(
        ExecRequest(command="nmap", args=["-sV", "scanme.nmap.org"], approved=False)
    )
    assert r is not None and r.gate == "target", "target-lock must fire before approval"
    print("  first-failing-gate wins: PASS")


def _patch_sandbox(up, networks, internal_map):
    """Swap sandbox's docker-inspect helpers for pure fakes; returns a restore fn."""
    orig = (S.is_sandbox_up, S._sandbox_networks, S._network_is_internal)
    S.is_sandbox_up = lambda: up
    S._sandbox_networks = lambda: list(networks)
    S._network_is_internal = lambda n: internal_map[n]

    def restore():
        S.is_sandbox_up, S._sandbox_networks, S._network_is_internal = orig

    return restore


def test_isolation_assert() -> None:
    """assert_isolation_proven refuses unless the sandbox is attached ONLY to internal
    networks. Simulated (no live Docker): both the safe and every unsafe shape."""
    # SAFE: running + a single internal-only network → must NOT raise
    restore = _patch_sandbox(True, ["hackpit_isolated"], {"hackpit_isolated": True})
    try:
        S.assert_isolation_proven()  # returns None on success
    finally:
        restore()

    # UNSAFE: an attached NON-internal network is an egress path → must raise
    restore = _patch_sandbox(
        True, ["hackpit_isolated", "bridge"],
        {"hackpit_isolated": True, "bridge": False},
    )
    try:
        raised = False
        try:
            S.assert_isolation_proven()
        except SandboxError as exc:
            raised = True
            assert "non-internal" in str(exc) and "bridge" in str(exc)
        assert raised, "a non-internal network MUST make isolation refuse"
    finally:
        restore()

    # UNSAFE: sandbox not running → must raise (can't prove isolation)
    restore = _patch_sandbox(False, [], {})
    try:
        raised = False
        try:
            S.assert_isolation_proven()
        except SandboxError as exc:
            raised = True
            assert "not running" in str(exc)
        assert raised, "a down sandbox MUST make isolation refuse"
    finally:
        restore()

    # UNSAFE: attached to NO network → cannot verify isolation → must raise
    restore = _patch_sandbox(True, [], {})
    try:
        raised = False
        try:
            S.assert_isolation_proven()
        except SandboxError as exc:
            raised = True
            assert "no network" in str(exc)
        assert raised, "no-network sandbox MUST make isolation refuse"
    finally:
        restore()
    print("  isolation assert (simulated): PASS")


def test_isolation_gate_in_validate() -> None:
    """The four-gate chain actually reaches the isolation gate: with gates 1–3 passed,
    a failing isolation check surfaces as gate=sandbox, and a passing one clears all."""
    orig = E.assert_isolation_proven

    def _raise():
        raise SandboxError("simulated: sandbox attached to non-internal network")

    try:
        E.assert_isolation_proven = _raise
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=True)
        )
        assert r is not None and r.gate == "sandbox", "isolation failure must be gate=sandbox"

        E.assert_isolation_proven = lambda: None
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=True)
        )
        assert r is None, "a fully valid, isolated request must clear all four gates"
    finally:
        E.assert_isolation_proven = orig
    print("  isolation gate reached in validate_request: PASS")


if __name__ == "__main__":
    test_allowlist_validation()
    test_forbidden_metachars()
    test_per_command_arg_rules()
    test_target_lock()
    test_gate_order_rejects_before_execution()
    test_approval_gate()
    test_first_failing_gate_wins()
    test_isolation_assert()
    test_isolation_gate_in_validate()
    print("ALL cockpit safety-layer tests pass")
