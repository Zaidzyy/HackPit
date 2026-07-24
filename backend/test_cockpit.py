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

    # nmap/curl/whatweb are the STRICT recon tools — a regression that loosens one of
    # them (or removes one) must trip this. Active tools are asserted separately below.
    assert {c for c in A.ALLOWLIST if not A.ALLOWLIST[c].active} == {"nmap", "curl", "whatweb"}, (
        "the strict recon set changed — nmap/curl/whatweb must stay strict; expanding or "
        "loosening it is a deliberate, reviewed change, not an accident."
    )
    print("  per-command arg rules: PASS")


def test_every_allowed_flag_passes() -> None:
    """Every flag on a command's allowed_flags must validate (recon usage stays working).

    Value-flags are given a benign value; all others are bare. This is the positive
    half of the strict gate — the negative half (un-listed flags rejected) is below.
    """
    sample_value = {"nmap": "80,443", "curl": "GET", "whatweb": "x"}
    for name, spec in A.ALLOWLIST.items():
        for flag in sorted(spec.allowed_flags):
            args = [flag]
            if flag in spec.value_flags:
                args.append(sample_value[name])
            ok, reason = A.validate(name, args)
            assert ok, f"allowed flag {flag!r} for {name} must validate — got: {reason}"
    print("  every allowed flag validates: PASS")


def test_unlisted_flags_rejected_and_named() -> None:
    """A flag NOT on a command's allowed_flags is rejected AT THE ALLOWLIST GATE, and the
    reason names the offending flag — in short, long, cluster, and =-joined forms."""
    # (command, args, substring the reason must contain)
    for cmd, args, needle in (
        ("nmap", ["-O", "hackpit-lab-target"], "-O"),                 # short: OS detect
        ("nmap", ["--min-rate", "1000", "hackpit-lab-target"], "--min-rate"),  # long
        ("curl", ["--data", "x", "http://hackpit-lab-target/"], "--data"),     # long
        ("curl", ["-sZ", "http://hackpit-lab-target/"], "-Z"),        # cluster: name the letter
        ("whatweb", ["--color=always", "http://hackpit-lab-target/"], "--color=always"),  # wrong pin
    ):
        ok, reason = A.validate(cmd, args)
        assert not ok, f"{cmd} {args} must be rejected by the strict flag gate"
        assert needle in reason, f"reason must NAME {needle!r} — got: {reason}"

    # and the rejection really is the ALLOWLIST gate (before target/approval/isolation),
    # so it stops an unsafe request at the first gate, exactly like a bad command does.
    r = E.validate_request(
        ExecRequest(command="nmap", args=["-O", "hackpit-lab-target"], approved=True)
    )
    assert r is not None and r.gate == "allowlist" and "-O" in r.reason, (
        "an un-listed flag must reject at the allowlist gate, naming the flag"
    )
    print("  un-listed flags rejected and named (at the allowlist gate): PASS")


def test_flag_parser_forms() -> None:
    """The flag parser is the load-bearing piece — it must classify EVERY form, and fail
    CLOSED on ambiguity. Tested against a synthetic spec so all forms are exercised
    deterministically, independent of which flags the recon commands happen to expose.

    ``_first_disallowed_flag(spec, args)`` returns None when all flags are permitted, or
    the offending flag token. Operands and value-flag VALUES are never misread as flags.
    """
    syn = A.CommandSpec(
        name="syn",
        description="synthetic — parser fixture",
        allowed_flags=frozenset({"-a", "-b", "-c", "-x", "--flag", "--opt", "--pin=on"}),
        value_flags=frozenset({"-x", "--opt"}),
    )

    def ok(args: list[str]) -> None:
        bad = A._first_disallowed_flag(syn, args)
        assert bad is None, f"{args} should be permitted — parser flagged {bad!r}"

    def bad(args: list[str], expected: str) -> None:
        got = A._first_disallowed_flag(syn, args)
        assert got == expected, f"{args} should reject {expected!r} — parser returned {got!r}"

    # combined short, each letter a flag (the '-sVn' shape)
    ok(["-abc"])
    bad(["-abz"], "-z")                       # one bad letter in a cluster is named
    # short value-flag: space form, and the value is NOT re-scanned as a flag
    ok(["-x", "val"])
    ok(["-x", "-z"])                          # flag-LIKE value not misread
    ok(["-x", "-5"])                          # negative-number value not misread
    # short value-flag: inline getopt form ('-xVALUE'), remainder is the value
    ok(["-xval"])
    ok(["-x-z"])                              # inline value that looks like a flag
    ok(["-abx", "val"])                       # cluster ending in a value-flag + space value
    # long forms: bool, unknown, =-joined pinned (exact value only), value-flag
    ok(["--flag"])
    bad(["--nope"], "--nope")
    ok(["--pin=on"])
    bad(["--pin=off"], "--pin=off")           # pinned flag: only the exact value passes
    ok(["--opt", "val"])
    ok(["--opt", "-z"])                       # long value-flag: flag-like value not misread
    ok(["--opt=anything"])                    # long value-flag: =-joined arbitrary value
    # operands are not flags; '--' is deliberately NOT an operand marker (fail closed)
    ok(["operand", "-", "hackpit-lab-target"])
    bad(["--"], "--")
    print("  flag parser forms (combined/joined/valued/flag-like) resolve correctly: PASS")


def test_flag_schema_frozen() -> None:
    """FREEZE the per-command flag schema. Widening (or narrowing) a command's
    allowed_flags / value_flags trips this ON PURPOSE — extending the strict schema is a
    deliberate, reviewed change, never an accident (mirrors the frozen command SET)."""
    frozen: dict[str, tuple[set[str], set[str]]] = {
        "nmap": ({"-sV", "-sT", "-sS", "-p", "-p-", "-T4", "-T3", "-Pn", "-n", "-oN-"}, {"-p"}),
        "curl": ({"-s", "-S", "-i", "-I", "-L", "-v", "-X"}, {"-X"}),
        "whatweb": ({"-a", "--color=never", "-v"}, set()),
    }
    # recon tools stay strict-frozen; the active tools (all-flags) are frozen separately
    # in test_active_tools_frozen. The command set is exactly recon ∪ active.
    assert set(A.ALLOWLIST) == set(frozen) | {"sqlmap", "ffuf", "nuclei"}, (
        "command set changed — adding/removing a tool is a deliberate, reviewed change."
    )
    for name, (flags, vflags) in frozen.items():
        spec = A.ALLOWLIST[name]
        assert spec.allowed_flags == frozenset(flags), (
            f"{name} allowed_flags changed to {set(spec.allowed_flags)} — widening the "
            f"strict flag schema is a deliberate, reviewed change, not an accident."
        )
        assert spec.value_flags == frozenset(vflags), (
            f"{name} value_flags changed to {set(spec.value_flags)} — reviewed change only."
        )
        assert spec.value_flags <= spec.allowed_flags, (
            f"{name} value_flags must be a subset of allowed_flags"
        )
    print("  flag schema frozen: PASS")


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


# --------------------------------------------------------------------------- #
# ACTIVE web-exploitation tools (all-flags + dangerous-flag detection + red-confirm)
# --------------------------------------------------------------------------- #

_LAB_URL = "http://hackpit-lab-target:3000/rest/products/search?q=1"


def test_active_tools_all_flags() -> None:
    """ACTIVE tools accept ALL flags (full capability), including dangerous + made-up ones,
    with NO flag-allowlist rejection. Recon tools still reject unlisted flags (the contrast)."""
    for cmd, args in (
        ("sqlmap", ["-u", _LAB_URL, "--os-shell", "--technique=BEUST"]),
        ("sqlmap", ["-u", _LAB_URL, "--a-totally-made-up-flag"]),
        ("ffuf", ["-u", "http://hackpit-lab-target/FUZZ", "-w", "list.txt", "-mc", "200,301"]),
        ("nuclei", ["-u", "http://hackpit-lab-target/", "-t", "cves/", "-code"]),
    ):
        ok, reason = A.validate(cmd, args)
        assert ok, f"active tool {cmd} must accept all flags — got: {reason}"
    # recon stays strict — an unlisted flag is still rejected + named
    ok, reason = A.validate("nmap", ["-O", "hackpit-lab-target"])
    assert not ok and "-O" in reason, "recon must still reject unlisted flags"
    print("  active tools accept all flags; recon stays strict: PASS")


def test_dangerous_flag_detection_every_form() -> None:
    """THE CRUX: every dangerous flag DETECTED in EVERY form — plain, =-joined, and the
    `--` trick — and marked dangerous (NOT blocked). A missed form is a silent dangerous
    approval, so this is the load-bearing safety test."""
    D = A.dangerous_flags_present
    for flag in sorted(A.ALLOWLIST["sqlmap"].dangerous_flags):
        forms = [
            ["-u", _LAB_URL, flag],            # plain
            ["-u", _LAB_URL, f"{flag}=x"],     # =-joined (value attached to the flag)
            ["--", "-u", _LAB_URL, flag],      # the -- trick must NOT hide it
        ]
        for args in forms:
            assert flag in D("sqlmap", args), f"sqlmap {flag!r} MISSED in form {args}"
            # detection marks dangerous — it is NOT blocked (validate still passes)
            ok, _ = A.validate("sqlmap", args)
            assert ok, f"a dangerous flag must be DETECTED, not blocked: {args}"
    # combined-short: -e hidden inside a cluster is still caught
    assert "-e" in D("sqlmap", ["-u", _LAB_URL, "-abe", "import os"]), "-e in a cluster must detect"
    # ffuf / nuclei single-dash long dangerous flags (whole-token candidate)
    assert "-config" in D("ffuf", ["-u", "http://hackpit-lab-target/FUZZ", "-config", "x.conf"])
    assert "-code" in D("nuclei", ["-u", "http://hackpit-lab-target/", "-code"])
    assert "-headless" in D("nuclei", ["-u", "http://hackpit-lab-target/", "-headless"])
    # benign active commands are NOT flagged (no false positives)
    assert D("sqlmap", ["-u", _LAB_URL, "--batch", "--dbs", "--technique=BEUST"]) == []
    assert D("ffuf", ["-u", "http://hackpit-lab-target/FUZZ", "-w", "w.txt", "-mc", "200", "-fc", "404"]) == []
    # recon tools are never dangerous
    assert D("nmap", ["-sV", "hackpit-lab-target"]) == []
    print("  dangerous-flag detection — every flag, every form (crux): PASS")


def test_active_target_lock() -> None:
    """Each active tool is bound to the lab via ITS OWN target flag; a non-lab target is
    rejected at the target gate, a wordlist is not mistaken for a target, and a missing
    target fails closed."""
    for cmd, args in (
        ("sqlmap", ["-u", _LAB_URL, "--batch"]),
        ("sqlmap", ["--url=" + _LAB_URL, "--dbs"]),
        ("ffuf", ["-u", "http://hackpit-lab-target/FUZZ", "-w", "wordlist.txt"]),  # .txt not a target
        ("nuclei", ["-target", "http://hackpit-lab-target/", "-t", "cves/"]),
    ):
        ok, reason = E.check_target_lock(args, cmd)
        assert ok, f"{cmd} against the lab must pass the target-lock — got: {reason}"
    for cmd, args in (
        ("sqlmap", ["-u", "http://evil.com/", "--dbs"]),
        ("ffuf", ["-u", "http://scanme.nmap.org/FUZZ", "-w", "w.txt"]),
        ("nuclei", ["-u", "http://169.254.169.254/"]),  # cloud metadata
    ):
        ok, reason = E.check_target_lock(args, cmd)
        assert not ok and "not the lab" in reason, f"{cmd} non-lab must be rejected: {args}"
    # missing target flag → fail closed
    ok, reason = E.check_target_lock(["-w", "w.txt", "-mc", "200"], "ffuf")
    assert not ok and "no lab target" in reason.lower(), "no target flag must fail closed"
    # end-to-end: a non-lab active target rejects at gate=target
    r = E.validate_request(
        ExecRequest(command="sqlmap", args=["-u", "http://evil.com/", "--dbs"], approved=True)
    )
    assert r is not None and r.gate == "target", "non-lab active target must reject at the target gate"
    print("  active per-tool target-lock (lab-bound, fail-closed): PASS")


def test_active_metachar_relaxation() -> None:
    """SURGICAL relaxation: active-tool VALUE args may carry metacharacters (payloads); a
    flag NAME may not; recon tools stay fully strict (metachars rejected everywhere)."""
    for cmd, args in (
        ("sqlmap", ["-u", "http://hackpit-lab-target/rest?q=1", "--data", "id=1*"]),   # *
        ("sqlmap", ["-u", "http://hackpit-lab-target/", "--data", "' OR 1=1-- -"]),     # sqli payload
        ("ffuf", ["-u", "http://hackpit-lab-target/FUZZ", "-w", "w.txt", "-H", "X-F: a|b&c"]),  # | &
    ):
        ok, reason = A.validate(cmd, args)
        assert ok, f"active value payload with metachars must be allowed — got: {reason}"
    # a flag NAME with a metachar is still refused (relaxation is values-only)
    ok, reason = A.validate("sqlmap", ["-u", "http://hackpit-lab-target/", "--os;shell"])
    assert not ok and "flag name" in reason, "a metachar in a flag NAME must be refused"
    # recon tools: metachars rejected everywhere (unchanged)
    ok, reason = A.validate("curl", ["http://hackpit-lab-target/;id"])
    assert not ok and "forbidden" in reason, "recon metachars stay strict"
    print("  active metachar relaxation is surgical (values yes, names no; recon strict): PASS")


def test_danger_confirm_gate() -> None:
    """A command carrying a dangerous flag is REFUSED unless dangerous_ack is explicitly
    true — approve alone is not enough. The confirm is required (test-locked)."""
    danger = ["-u", "http://hackpit-lab-target/rest", "--os-shell"]
    # approved but NOT confirmed → danger gate, flags named
    r = E.validate_request(ExecRequest(command="sqlmap", args=danger, approved=True))
    assert r is not None and r.gate == "danger" and "--os-shell" in r.dangerous_flags, (
        "a dangerous flag must refuse at the danger gate without the explicit confirm"
    )
    # approved AND confirmed → clears the danger gate (only isolation may remain)
    r = E.validate_request(
        ExecRequest(command="sqlmap", args=danger, approved=True, dangerous_ack=True)
    )
    assert r is None or r.gate == "sandbox", "the explicit confirm must clear the danger gate"
    # not approved → approval gate still wins (danger is checked AFTER approval)
    r = E.validate_request(
        ExecRequest(command="sqlmap", args=danger, approved=False, dangerous_ack=True)
    )
    assert r is not None and r.gate == "approval", "approval precedes the danger gate"
    # a benign active command needs no confirm
    r = E.validate_request(
        ExecRequest(command="sqlmap", args=["-u", "http://hackpit-lab-target/rest", "--dbs"], approved=True)
    )
    assert r is None or r.gate == "sandbox", "a benign active command needs no confirm"
    print("  danger gate: approve blocked without explicit confirm (test-locked): PASS")


def test_active_tools_frozen() -> None:
    """FREEZE the active tools + their dangerous-flag schemas. Adding an active tool or
    changing a dangerous-flag set trips this ON PURPOSE (a deliberate, reviewed change) —
    detection completeness depends on the set being exactly what was audited."""
    frozen_dangerous: dict[str, set[str]] = {
        "sqlmap": {
            "--os-shell", "--os-cmd", "--os-pwn", "--os-bof", "--os-smbrelay", "--sql-shell",
            "-e", "--eval", "--file-read", "--file-write", "--file-dest", "--tamper",
        },
        "ffuf": {"-config"},
        "nuclei": {"-code", "-headless"},
    }
    assert {c for c in A.ALLOWLIST if A.ALLOWLIST[c].active} == set(frozen_dangerous), (
        "the active-tool set changed — adding/removing an active tool is a reviewed change."
    )
    for name, dz in frozen_dangerous.items():
        spec = A.ALLOWLIST[name]
        assert spec.active, f"{name} must be active"
        assert spec.dangerous_flags == frozenset(dz), (
            f"{name} dangerous_flags changed to {set(spec.dangerous_flags)} — reviewed change only."
        )
        assert spec.target_flags, f"{name} must declare target_flags for the lab lock"
        assert spec.target_flags <= spec.value_flags, f"{name} target_flags must be value_flags"
        assert not spec.allowed_flags, (
            f"{name} is all-flags — allowed_flags must stay empty (not a strict list)"
        )
    print("  active tools + dangerous-flag schemas frozen: PASS")


if __name__ == "__main__":
    test_allowlist_validation()
    test_forbidden_metachars()
    test_per_command_arg_rules()
    test_every_allowed_flag_passes()
    test_unlisted_flags_rejected_and_named()
    test_flag_parser_forms()
    test_flag_schema_frozen()
    test_active_tools_all_flags()
    test_dangerous_flag_detection_every_form()
    test_active_target_lock()
    test_active_metachar_relaxation()
    test_danger_confirm_gate()
    test_active_tools_frozen()
    test_target_lock()
    test_gate_order_rejects_before_execution()
    test_approval_gate()
    test_first_failing_gate_wins()
    test_isolation_assert()
    test_isolation_gate_in_validate()
    print("ALL cockpit safety-layer tests pass")
