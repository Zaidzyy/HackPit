"""Regression-lock for SCOPE-AWARE engagement execution (target-lock + recon expansion).

Engagement mode is no longer locked to one exact host: it is locked to an authorized PROGRAM
SCOPE, and recon can expand the live allowed set WITHIN that scope. These tests fail loudly if
any of that widens past what the operator authorized:

  1. IN-SCOPE PASSES: an exact host, a *.wildcard subdomain and an in-CIDR IP all clear the
     engagement target-lock.
  2. OUT-OF-SCOPE IS REJECTED: an unrelated host, a wildcard near-miss (apex / suffix trick)
     and an EXCLUDED host are all refused at the target gate, before anything runs.
  3. EXPANSION ONLY ADDS IN-SCOPE HOSTS: hosts mined from a run's output are sorted by the
     scope — in-scope ones join the live allowed set, out-of-scope ones are recorded read-only
     and STILL fail the target-lock afterwards. Expansion never widens the scope.
  4. NEVER-AUTO-RUN SURVIVES EXPANSION: a command against a freshly-discovered, in-scope host
     with approved=False is still refused at the approval gate — discovery approves nothing.
  5. GATE ORDER unchanged: an out-of-scope host is refused at 'target' even when approved.
  6. LAB MODE UNTOUCHED: with no engagement, the lab target-lock is byte-for-byte the same
     (lab host passes, everything else refused with the lab wording).
  7. THE PROPOSER drafts against the engagement's SCOPE, never the lab — and the lab prompt is
     unchanged; the proposal pre-check uses the same matcher the executor does; and a proposal
     is only ever a DRAFT (the proposer never reaches an execution path, even off-scope).

Hermetic: no Docker, no LLM, no network. Scopes are built with resolve=False / explicit seed
IPs, and expansion runs against a throwaway temp DB. Run:  python test_engagement_scope.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from cockpit import engagement as ENG
from cockpit import executor as E
from cockpit import runstore
from cockpit.models import EngagementRecord, ExecRequest

_SCOPE = "example.com, *.example.com, 10.10.10.0/24, !admin.example.com"


def _eng(scope: str = _SCOPE, target: str = "example.com", **kw) -> EngagementRecord:
    return EngagementRecord(
        engagement_id="eng-scope000000",
        target=target,
        authorization="authorized program scope",
        active=True,
        entered_at="2026-07-25T00:00:00+00:00",
        scope=scope,
        scope_include=[p.strip() for p in scope.split(",") if not p.strip().startswith("!")],
        scope_exclude=[p.strip().lstrip("!") for p in scope.split(",") if p.strip().startswith("!")],
        allowed_hosts=kw.pop("allowed_hosts", ["example.com"]),
        **kw,
    )


def _lock(eng: EngagementRecord, args: list[str]) -> tuple[bool, str]:
    allowed, in_scope, label = E._engagement_lock(eng)
    return E.check_target_lock(args, "nmap", allowed=allowed, label=label, in_scope=in_scope)


def _patch_active(rec: EngagementRecord | None):
    orig = E.engagement.get_active
    E.engagement.get_active = lambda _id: rec  # type: ignore[assignment]
    return orig


# --------------------------------------------------------------------------- #
# 1. in-scope passes
# --------------------------------------------------------------------------- #
def test_in_scope_targets_pass() -> None:
    eng = _eng()
    for args in (
        ["-sV", "example.com"],                       # exact host include
        ["-sV", "api.example.com"],                   # *.wildcard subdomain
        ["-sV", "deep.api.example.com"],              # deep subdomain
        ["-p-", "10.10.10.7"],                        # inside the CIDR
        ["-u", "https://api.example.com/login?x=1"],  # URL form
        ["-u", "http://10.10.10.7:8080/"],            # IP:port URL form
    ):
        ok, reason = _lock(eng, args)
        assert ok, f"{args} is IN scope and must pass — got: {reason}"
    print("  in-scope host / wildcard subdomain / in-CIDR IP all pass the lock: PASS")


def test_seed_ip_of_an_exact_host_passes() -> None:
    eng = _eng(scope="scanme.nmap.org", target="scanme.nmap.org",
               allowed_hosts=["scanme.nmap.org"], scope_ips=["45.33.32.156"])
    ok, _ = _lock(eng, ["-sV", "45.33.32.156"])
    assert ok, "the address an in-scope host resolved to at entry must pass"
    ok, _ = _lock(eng, ["-sV", "45.33.32.157"])
    assert not ok, "a NEIGHBOURING address must NOT pass"
    print("  a resolved seed IP passes; its neighbour does not: PASS")


# --------------------------------------------------------------------------- #
# 2. out-of-scope is rejected
# --------------------------------------------------------------------------- #
def test_out_of_scope_targets_are_rejected() -> None:
    eng = _eng()
    for args in (
        ["-sV", "evil.com"],                    # unrelated host
        ["-sV", "example.com.evil.com"],        # suffix trick
        ["-sV", "notexample.com"],              # near-miss
        ["-p-", "10.10.11.7"],                  # outside the CIDR
        ["-sV", "admin.example.com"],           # EXCLUDED (an exclusion beats the wildcard)
        ["-u", "http://evil.com/x"],            # URL form
    ):
        ok, reason = _lock(eng, args)
        assert not ok, f"{args} is OUT of scope and must be refused"
        assert "scope" in reason, f"the refusal must name the scope — got: {reason}"
    print("  unrelated / suffix-trick / out-of-CIDR / EXCLUDED targets are refused: PASS")


def test_a_targetless_command_is_refused() -> None:
    ok, reason = _lock(_eng(), ["-sV", "--top-ports", "100"])
    assert not ok and "no target" in reason, reason
    print("  a command that references no in-scope target is refused: PASS")


# --------------------------------------------------------------------------- #
# 3. expansion only adds in-scope hosts
# --------------------------------------------------------------------------- #
def test_expansion_adds_only_in_scope_hosts() -> None:
    tmp = Path(tempfile.mkdtemp()) / "eng.db"
    orig_rs, orig_eng = runstore.DB_PATH, ENG.DB_PATH
    runstore.DB_PATH = ENG.DB_PATH = tmp
    try:
        ENG.init_db()
        rec = ENG.enter(
            "example.com", "authorized",
            scope_spec="example.com, *.example.com, 10.10.10.0/24, !admin.example.com",
        )
        out = (
            "Nmap scan report for api.example.com (10.10.10.7)\n"
            "found: admin.example.com, evil.com, 10.10.11.9, cdn.partner.net\n"
        )
        found = ENG.record_discoveries(rec, out, run_id="r-1")
        assert set(found["added"]) == {"api.example.com", "10.10.10.7"}, found
        assert set(found["out_of_scope"]) == {
            "admin.example.com", "evil.com", "10.10.11.9", "cdn.partner.net",
        }, found

        live = ENG.get_active(rec.engagement_id)
        assert live is not None
        assert "api.example.com" in live.allowed_hosts and "10.10.10.7" in live.allowed_hosts
        for host in ("admin.example.com", "evil.com", "10.10.11.9", "cdn.partner.net"):
            assert host not in live.allowed_hosts, f"{host} must NEVER be auto-added"
            ok, _ = _lock(live, ["-sV", host])
            assert not ok, f"a discovered OUT-OF-SCOPE host ({host}) must still be refused"
        ok, _ = _lock(live, ["-sV", "api.example.com"])
        assert ok, "a discovered IN-SCOPE host is targetable (it always was — scope covered it)"
        print("  expansion adds ONLY in-scope hosts; out-of-scope stays read-only: PASS")
    finally:
        runstore.DB_PATH, ENG.DB_PATH = orig_rs, orig_eng


def test_expansion_never_widens_the_scope() -> None:
    """The live allowed set can only ever contain hosts the SCOPE already covered — so an
    expansion round can never make a previously-refused target runnable."""
    tmp = Path(tempfile.mkdtemp()) / "eng2.db"
    orig_rs, orig_eng = runstore.DB_PATH, ENG.DB_PATH
    runstore.DB_PATH = ENG.DB_PATH = tmp
    try:
        ENG.init_db()
        rec = ENG.enter("scanme.nmap.org", "authorized", scope_spec="scanme.nmap.org")
        ENG.record_discoveries(rec, "also saw sub.scanme.nmap.org and evil.com", run_id="r-1")
        live = ENG.get_active(rec.engagement_id)
        assert live is not None
        assert live.allowed_hosts == ["scanme.nmap.org"], live.allowed_hosts
        for host in ("sub.scanme.nmap.org", "evil.com"):
            ok, _ = _lock(live, ["-sV", host])
            assert not ok, f"{host} is outside a single-host scope and must stay refused"
        print("  a single-host scope stays single-host after expansion: PASS")
    finally:
        runstore.DB_PATH, ENG.DB_PATH = orig_rs, orig_eng


# --------------------------------------------------------------------------- #
# 4-5. never-auto-run + gate order survive the scope model
# --------------------------------------------------------------------------- #
def test_never_auto_run_holds_for_a_discovered_host() -> None:
    eng = _eng(allowed_hosts=["example.com", "api.example.com"])
    orig = _patch_active(eng)
    try:
        req = ExecRequest(
            command="nmap", args=["-sV", "api.example.com"], approved=False,
            engagement_id=eng.engagement_id,
        )
        rej = E.validate_request(req)
        assert rej is not None and rej.gate == "approval", rej
        # …and the belt-and-suspenders path in iter_run refuses too, even prevalidated.
        events = list(E.iter_run(req, prevalidated=True))
        assert events and events[0]["type"] == "rejected" and events[0]["gate"] == "approval"
        print("  NEVER-AUTO-RUN: a discovered in-scope host still needs its own approval: PASS")
    finally:
        E.engagement.get_active = orig


def test_gate_order_target_before_approval() -> None:
    eng = _eng()
    orig = _patch_active(eng)
    try:
        rej = E.validate_request(ExecRequest(
            command="nmap", args=["-sV", "evil.com"], approved=True,
            engagement_id=eng.engagement_id,
        ))
        assert rej is not None and rej.gate == "target", rej
        print("  gate order: an out-of-scope target is refused at 'target' even if approved: PASS")
    finally:
        E.engagement.get_active = orig


# --------------------------------------------------------------------------- #
# 6. lab mode untouched
# --------------------------------------------------------------------------- #
def test_lab_target_lock_unchanged() -> None:
    ok, _ = E.check_target_lock(["-sV", "hackpit-lab-target"], "nmap")
    assert ok, "the lab host must still pass the unchanged lab lock"
    ok, reason = E.check_target_lock(["-sV", "example.com"], "nmap")
    assert not ok and reason == "target 'example.com' is not the lab — only the lab is allowed"
    ok, reason = E.check_target_lock(["-sV", "--top-ports", "100"], "nmap")
    assert not ok and reason == "no lab target specified — the command must reference the lab"
    print("  LAB target-lock wording + behaviour byte-for-byte unchanged: PASS")


# --------------------------------------------------------------------------- #
# 7. the PROPOSER drafts against the engagement scope, never the lab
# --------------------------------------------------------------------------- #
def _ctx():
    import orchestrator as O

    from cockpit import scope as SC

    matcher = SC.parse_scope(_SCOPE, resolve=False)
    return O.ScopeContext(
        target="example.com",
        scope=_SCOPE,
        include=("example.com", "*.example.com", "10.10.10.0/24"),
        exclude=("admin.example.com",),
        allowed_hosts=("example.com", "api.example.com"),
        out_of_scope_seen=("evil.com",),
        in_scope=matcher.in_scope,
    )


def test_proposer_targets_the_scope_not_the_lab() -> None:
    import orchestrator as O

    from cockpit import config

    ctx = _ctx()
    system, user = O._system_prompt(ctx), O.build_user_prompt({"goal": "g"}, [], [], ctx)
    both = system + "\n" + user
    assert config.LAB_TARGET_HOST not in both, "the LAB must never appear in a real-target prompt"
    assert "example.com" in system and "*.example.com" in user
    assert "admin.example.com" in both, "the exclusion must be stated to the model"
    assert "api.example.com" in user, "a discovered in-scope host must be offered as a pivot"
    assert "evil.com" in user, "an out-of-scope discovery must be listed as forbidden"
    print("  proposer drafts against the engagement scope, never the lab: PASS")


def test_lab_proposer_prompt_unchanged() -> None:
    import orchestrator as O

    from cockpit import config

    system, user = O._system_prompt(), O.build_user_prompt({"goal": "g"}, [], [])
    assert config.LAB_TARGET_HOST in system and f"LAB TARGET: {config.LAB_TARGET_HOST}" in user
    assert "The ONLY target is the lab host" in system
    assert "AUTHORIZED SCOPE" not in system + user, "no scope text may leak into the lab prompt"
    print("  LAB proposer prompt byte-for-byte unchanged: PASS")


def test_proposer_precheck_uses_the_scope() -> None:
    import orchestrator as O

    ctx = _ctx()
    ok, _ = O.precheck("nmap", ["-sV", "api.example.com"], ctx)
    assert ok, "an in-scope proposal must pre-check clean"
    ok, reason = O.precheck("nmap", ["-sV", "evil.com"], ctx)
    assert not ok and "scope" in reason, reason
    ok, _ = O.precheck("nmap", ["-sV", "admin.example.com"], ctx)
    assert not ok, "an EXCLUDED host must fail the pre-check"
    print("  the proposal pre-check uses the same scope matcher as the executor: PASS")


def test_loop_proposal_never_runs_anything() -> None:
    """NEVER-AUTO-RUN in the loop, on a REAL target: a proposal is a draft. propose_next must
    not reach the executor's run path, and an off-scope draft comes back flagged, not run."""
    import llm
    import orchestrator as O

    ctx = _ctx()
    fired: list[str] = []
    orig_chat, orig_iter, orig_run = llm.chat, E.iter_run, E.run_command
    llm.chat = lambda *a, **k: '{"done": false, "command": "nmap", "args": ["-sV", "evil.com"]}'
    E.iter_run = lambda *a, **k: fired.append("iter_run")  # type: ignore[assignment]
    E.run_command = lambda *a, **k: fired.append("run_command")  # type: ignore[assignment]
    try:
        res = O.propose_next({"goal": "g"}, [], {}, [], ctx)
        assert not fired, f"the proposer must never execute anything — called: {fired}"
        prop = res["proposal"]
        assert prop is not None and prop["gate_ok"] is False, prop
        assert "scope" in prop["gate_reason"], prop
        assert "approved" not in prop, "a proposal can never carry an approval"
    finally:
        llm.chat, E.iter_run, E.run_command = orig_chat, orig_iter, orig_run
    print("  NEVER-AUTO-RUN: a real-target proposal is a flagged draft, nothing ran: PASS")


if __name__ == "__main__":
    test_in_scope_targets_pass()
    test_seed_ip_of_an_exact_host_passes()
    test_out_of_scope_targets_are_rejected()
    test_a_targetless_command_is_refused()
    test_expansion_adds_only_in_scope_hosts()
    test_expansion_never_widens_the_scope()
    test_never_auto_run_holds_for_a_discovered_host()
    test_gate_order_target_before_approval()
    test_lab_target_lock_unchanged()
    test_proposer_targets_the_scope_not_the_lab()
    test_lab_proposer_prompt_unchanged()
    test_proposer_precheck_uses_the_scope()
    test_loop_proposal_never_runs_anything()
    print("ALL engagement-scope tests pass")
