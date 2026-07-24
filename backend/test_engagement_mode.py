"""Regression-lock for REAL-TARGET engagement mode (the SUPERVISED, highest-risk path).

Engagement mode removes the isolation floor AND Wall A: the cockpit execs against a human-named
REAL target through a FULLY-OPEN sandbox (internet + LAN + host + metadata — Zaid's informed
decision). The ENTIRE safety model then rests on human approval of every command. These tests
fail loudly if any surviving invariant is weakened:

  1. NEVER-AUTO-RUN: an engagement command with approved=False is refused at the approval gate —
     every command needs an INDIVIDUAL human approval; there is no batch/approve-all. (Now the
     ONLY bound on what runs — Wall A is gone — so it is more load-bearing than ever.)
  2. EXPLICIT ENTRY: an engagement_id that was never entered (or was exited) is refused at the
     engagement gate — engagement mode can never be reached by a bare exec, nor downgraded to
     lab. Entry requires a target + a non-empty authorization acknowledgement.
  3. TARGET-LOCK to the named target (best-effort DiD): a non-target host is refused; the named
     target (host or URL form) passes.
  4. HEURISTIC RED-CONFIRM still fires in engagement mode (interpreters/shells/frameworks need
     the extra confirm).
  5. GATE ORDER: engagement → target → approval → danger. (No wall_a gate — Wall A is down.)
  6. WALL A IS INTENTIONALLY GONE: there is no wall_a gate and no assert_wall_a_holds — locked
     so a broken Wall-A gate can't silently creep back.
  7. LAB MODE UNCHANGED: no engagement_id → the lab gates (isolation), unchanged.
  8. NO AUTONOMY ON REAL TARGETS + NO :kali PATH: the orchestrator/loop (the autonomy mechanic)
     has no engagement capability, and the executor still has zero :kali path.
  9. mode round-trips through the run store ('lab' default; 'engagement' preserved).

Hermetic: Docker + the LLM are never touched — engagement resolution is either monkeypatched
or driven through a throwaway temp DB. Run:  python test_engagement_mode.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from cockpit import config
from cockpit import engagement as ENG
from cockpit import executor as E
from cockpit import runstore
from cockpit import sandbox as S
from cockpit.models import EngagementRecord, ExecRequest
from cockpit.sandbox import SandboxError

_REAL = "scanme.nmap.org"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _fake_engagement(target=_REAL) -> EngagementRecord:
    return EngagementRecord(
        engagement_id="eng-test000000",
        target=target,
        authorization="authorized test target",
        active=True,
        entered_at="2026-07-24T00:00:00+00:00",
        resolved_scope=["45.33.32.156"],
        scope_kind="host",
    )


def _patch_active(rec: EngagementRecord | None, scope_ok: bool = True):
    """Make the executor resolve THIS engagement (or none), and stub the SCOPE-LOCK gate so the
    tests are hermetic (no Docker). ``scope_ok=True`` -> assert_scope_locked passes (the network
    floor is confirmed, so the OTHER gates can be exercised); ``scope_ok=False`` -> it raises, so
    the scope gate itself can be exercised."""
    orig_active = E.engagement.get_active
    orig_scope = E.assert_scope_locked
    E.engagement.get_active = lambda eid: rec if (rec and eid == rec.engagement_id) else None

    def _scope(resolved):
        if not scope_ok:
            raise SandboxError("scope-lock not confirmed (test)")

    E.assert_scope_locked = _scope

    def restore():
        E.engagement.get_active = orig_active
        E.assert_scope_locked = orig_scope

    return restore


# --------------------------------------------------------------------------- #
# 1–5. the engagement gate chain
# --------------------------------------------------------------------------- #
def test_never_auto_run_engagement() -> None:
    """The core real-target invariant (now the ONLY bound): approved=False is refused at
    approval. No batch/auto. An individually-approved command clears (no Wall-A gate)."""
    restore = _patch_active(_fake_engagement())
    try:
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id="eng-test000000")
        )
        assert r is not None and r.gate == "approval", "engagement + unapproved MUST reject at approval"
        assert "individual human approval" in r.reason or "hands-off" in r.reason
        # explicitly approved → clears all engagement gates (target ok, approved, not dangerous)
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id="eng-test000000", approved=True)
        )
        assert r is None, "an individually-approved engagement command clears the gates"
    finally:
        restore()
    print("  NEVER-AUTO-RUN: engagement needs an individual approval (no batch/auto): PASS")


def test_iter_run_prevalidated_still_needs_approval() -> None:
    """Belt-and-suspenders (ENGAGEMENT only): even in the PREVALIDATED path — which SKIPS
    validate_request — iter_run refuses an unapproved engagement command. With Wall A down,
    approval is the sole floor on a real target, so its enforcement must not depend on every
    future caller remembering to validate first. Exactly ONE rejected event (gate=approval);
    nothing runs (no start/stdout/stderr/exit — so no docker exec against the real target)."""
    restore = _patch_active(_fake_engagement(_REAL))
    try:
        req = ExecRequest(
            command="nmap", args=["-sV", _REAL],
            engagement_id="eng-test000000", approved=False,
        )
        # Fully consuming is safe: the guard yields the rejection and returns BEFORE any exec.
        events = list(E.iter_run(req, prevalidated=True))
        assert len(events) == 1, f"expected exactly one event, got {[e.get('type') for e in events]}"
        assert events[0]["type"] == "rejected" and events[0].get("gate") == "approval", \
            "prevalidated engagement + unapproved MUST reject at the approval gate"
        assert not any(
            e["type"] in ("start", "stdout", "stderr", "exit") for e in events
        ), "nothing may run — no command may reach the real target"
    finally:
        restore()
    print("  BELT-AND-SUSPENDERS: prevalidated engagement still refuses unapproved (gate=approval): PASS")


def test_explicit_entry_required() -> None:
    """An engagement_id that doesn't resolve to an ACTIVE engagement is refused — never run,
    never downgraded to lab."""
    restore = _patch_active(_fake_engagement())  # only 'eng-test000000' is active
    try:
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id="eng-unknown", approved=True)
        )
        assert r is not None and r.gate == "engagement", "an un-entered id MUST reject at engagement"
        assert "enter engagement mode first" in r.reason
    finally:
        restore()
    print("  EXPLICIT ENTRY: an un-entered / exited engagement id is refused (never lab): PASS")


def test_engagement_target_lock() -> None:
    restore = _patch_active(_fake_engagement(_REAL))
    try:
        # the named target passes in host + URL form
        for args in (["-sV", _REAL], [f"http://{_REAL}/"]):
            r = E.validate_request(
                ExecRequest(command="nmap", args=args, engagement_id="eng-test000000", approved=True)
            )
            assert r is None, f"the named target must pass: {args}"
        # a DIFFERENT host is rejected (locked to the named target)
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", "example.com"], engagement_id="eng-test000000", approved=True)
        )
        assert r is not None and r.gate == "target" and _REAL in r.reason, "a non-target host must reject at target"
        # a target-less command is rejected
        r = E.validate_request(
            ExecRequest(command="nmap", args=["--help"], engagement_id="eng-test000000", approved=True)
        )
        assert r is not None and r.gate == "target", "a target-less command must reject at target"
    finally:
        restore()
    print("  TARGET-LOCK: engagement locked to the named target (host/URL); others rejected: PASS")


def test_engagement_heuristic_red_confirm() -> None:
    restore = _patch_active(_fake_engagement(_REAL))
    try:
        flagged = ExecRequest(
            command="python3", args=["-c", "print(1)", _REAL], engagement_id="eng-test000000", approved=True
        )
        r = E.validate_request(flagged)
        assert r is not None and r.gate == "danger" and r.dangerous_flags, "interpreter must need the confirm"
        r = E.validate_request(
            ExecRequest(command="python3", args=["-c", "print(1)", _REAL],
                        engagement_id="eng-test000000", approved=True, dangerous_ack=True)
        )
        assert r is None, "the explicit confirm clears the danger gate"
    finally:
        restore()
    print("  HEURISTIC red-confirm still fires in engagement mode: PASS")


def test_scope_lock_gate() -> None:
    """SCOPE-LOCK is the engagement network floor: if assert_scope_locked refuses (rules not
    confirmed / don't match the resolved scope), the command is rejected at gate=scope BEFORE
    approval — even an approved, in-target command. This is what makes the loop safe on a real
    target: nothing runs unless egress is confirmed locked to scope. Fail-closed."""
    restore = _patch_active(_fake_engagement(_REAL), scope_ok=False)
    try:
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id="eng-test000000", approved=True)
        )
        assert r is not None and r.gate == "scope", "unconfirmed scope-lock MUST reject at gate=scope"
        assert "scope-lock" in r.reason
    finally:
        restore()
    # and with the scope-lock confirmed, an approved in-scope command clears every gate.
    restore = _patch_active(_fake_engagement(_REAL), scope_ok=True)
    try:
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id="eng-test000000", approved=True)
        )
        assert r is None, "confirmed scope-lock + approved in-scope command clears the gates"
    finally:
        restore()
    print("  SCOPE-LOCK: unconfirmed network floor refuses at gate=scope (fail-closed); confirmed clears: PASS")


def test_engagement_gate_order() -> None:
    """engagement → scope → target → approval → danger (first failing gate wins)."""
    # scope leads (before target/approval/danger) when the network floor is not confirmed.
    restore = _patch_active(_fake_engagement(_REAL), scope_ok=False)
    try:
        r = E.validate_request(
            ExecRequest(command="python3", args=["-c", "x", "example.com"], engagement_id="eng-test000000")
        )
        assert r.gate == "scope", "scope-lock leads (beats target/approval/danger)"
    finally:
        restore()
    restore = _patch_active(_fake_engagement(_REAL))  # scope_ok=True: exercise the rest of the order
    try:
        # unknown id + everything else wrong → engagement leads (before scope is even reached)
        r = E.validate_request(
            ExecRequest(command="python3", args=["-c", "x", "example.com"], engagement_id="nope")
        )
        assert r.gate == "engagement", "engagement (explicit entry) leads"
        # active id, scope ok, wrong target, unapproved, dangerous → target beats approval+danger
        r = E.validate_request(
            ExecRequest(command="python3", args=["-c", "x", "example.com"], engagement_id="eng-test000000")
        )
        assert r.gate == "target", "target beats approval/danger"
        # active id, scope ok, right target, unapproved, dangerous → approval beats danger
        r = E.validate_request(
            ExecRequest(command="python3", args=["-c", "x", _REAL], engagement_id="eng-test000000")
        )
        assert r.gate == "approval", "approval beats danger"
        # active id, scope ok, right target, approved, dangerous, no ack → danger (last gate)
        r = E.validate_request(
            ExecRequest(command="python3", args=["-c", "x", _REAL], engagement_id="eng-test000000", approved=True)
        )
        assert r.gate == "danger", "danger is the last engagement gate"
    finally:
        restore()
    print("  GATE ORDER: engagement -> scope -> target -> approval -> danger: PASS")


def test_no_wall_a_gate() -> None:
    """Wall A is UP as a per-target SCOPE-LOCK: engagement has a real, NETWORK-enforced floor
    (default-deny + allow-only-scope), wired as the 'scope' gate ahead of approval. Locked so
    the floor can't silently regress to fully-open. (The legacy 'wall_a' NAMING stays gone — the
    floor is the cleaner scope-lock; only the naming lock remains from the old model.)"""
    from cockpit.models import ExecRejected
    gate_args = getattr(ExecRejected.model_fields["gate"].annotation, "__args__", ())
    # the network floor exists: a 'scope' gate + assert_scope_locked + the firewall sidecar const
    assert "scope" in gate_args, "the ExecRejected.gate literal must include 'scope' (the floor)"
    assert hasattr(S, "assert_scope_locked"), "assert_scope_locked (the scope-lock gate) must exist"
    assert hasattr(config, "ENGAGE_FIREWALL_CONTAINER"), "the scope-lock firewall sidecar const must exist"
    # the legacy Wall-A naming stays gone (the floor is 'scope', not 'wall_a')
    assert "wall_a" not in gate_args, "the gate literal must not use the legacy 'wall_a' name"
    assert not hasattr(S, "assert_wall_a_holds"), "the legacy assert_wall_a_holds must stay gone"
    assert not hasattr(config, "WALL_A_BLOCKED"), "the legacy WALL_A_BLOCKED must stay gone"
    # a fully-valid approved engagement command clears once the scope-lock is confirmed
    restore = _patch_active(_fake_engagement(_REAL))
    try:
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id="eng-test000000", approved=True)
        )
        assert r is None, "an approved, in-scope engagement command clears once the floor is confirmed"
    finally:
        restore()
    print("  SCOPE-LOCK FLOOR present (scope gate + assert_scope_locked + sidecar; no legacy wall_a): PASS")


# --------------------------------------------------------------------------- #
# 2b. explicit entry / exit through the REAL registry (throwaway temp DB)
# --------------------------------------------------------------------------- #
def test_enter_exit_registry() -> None:
    tmp = Path(tempfile.mkdtemp()) / "eng.db"
    orig = (runstore.DB_PATH, ENG.DB_PATH)
    runstore.DB_PATH = tmp
    ENG.DB_PATH = tmp
    runstore.init_db()
    ENG.init_db()
    orig_scope = E.assert_scope_locked
    E.assert_scope_locked = lambda resolved: None  # this test exercises the REGISTRY, not the floor
    try:
        # entry requires a non-empty authorization ack (deliberate, warned entry)
        raised = False
        try:
            ENG.enter(_REAL, "   ")
        except ValueError:
            raised = True
        assert raised, "entry MUST require an authorization acknowledgement"

        rec = ENG.enter(_REAL, "I am authorized to test scanme.nmap.org")
        assert rec.active and rec.target == _REAL and rec.engagement_id.startswith("eng-")
        assert ENG.get_active(rec.engagement_id) is not None, "an entered engagement resolves"

        # the executor now runs against it (no Wall A to patch)
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id=rec.engagement_id, approved=True)
        )
        assert r is None, "an entered + approved command clears"

        assert ENG.exit_engagement(rec.engagement_id) is True, "exit ends the engagement"
        assert ENG.get_active(rec.engagement_id) is None, "an exited engagement no longer resolves"
        # and after exit the executor refuses (fail-closed) — via the REAL get_active
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id=rec.engagement_id, approved=True)
        )
        assert r is not None and r.gate == "engagement", "an exited engagement is refused at the gate"
    finally:
        runstore.DB_PATH, ENG.DB_PATH = orig
        E.assert_scope_locked = orig_scope
    print("  ENTER/EXIT registry: entry needs auth; exit fail-closes the executor: PASS")


# --------------------------------------------------------------------------- #
# 7. LAB MODE UNCHANGED — no engagement_id → lab gates (isolation)
# --------------------------------------------------------------------------- #
def test_lab_mode_unaffected() -> None:
    """A request with no engagement_id runs the LAB path unchanged: it reaches the ISOLATION
    gate (a passing check clears; a failing one surfaces as gate=sandbox)."""
    orig = E.assert_isolation_proven
    try:
        E.assert_isolation_proven = lambda: None
        r = E.validate_request(ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=True))
        assert r is None, "a valid lab command clears via the ISOLATION gate"

        E.assert_isolation_proven = lambda: (_ for _ in ()).throw(SandboxError("sim: not isolated"))
        r = E.validate_request(ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=True))
        assert r is not None and r.gate == "sandbox", "lab isolation failure surfaces as gate=sandbox"
    finally:
        E.assert_isolation_proven = orig
    print("  LAB MODE unchanged: lab path still uses the isolation gate: PASS")


# --------------------------------------------------------------------------- #
# 8. NO AUTONOMY ON REAL TARGETS + NO :kali PATH (source locks)
# --------------------------------------------------------------------------- #
def test_orchestrator_has_no_engagement_capability() -> None:
    """The guided loop / orchestrator (the autonomy mechanic) must NOT be able to drive a real
    target — never hands-off. It must not enter engagement mode, resolve one, or set an
    engagement_id on a proposal/exec. Scanned in source (the word 'engagement' may appear in a
    comment about the run store, so we forbid the CAPABILITY tokens, not the bare word)."""
    import orchestrator as O

    src = Path(O.__file__).read_text(encoding="utf-8")
    forbidden = [
        "engagement_id",       # cannot tag an exec/proposal for real-target mode
        "import engagement",
        "from .engagement",
        "cockpit.engagement",
        ".enter(",             # cannot enter engagement mode
        "get_active",          # cannot resolve an engagement
    ]
    hits = [f for f in forbidden if f in src]
    assert not hits, f"orchestrator/loop must have NO engagement capability — found: {hits}"
    print("  NO AUTONOMY on real targets: orchestrator/loop has no engagement capability: PASS")


def test_executor_still_has_no_kali_path() -> None:
    """The agent's exec path must still have ZERO path to the :kali open-egress shell, even
    though engagement mode now has its own fully-open sandbox."""
    assert not hasattr(E, "run_kali") and not hasattr(E, "kali"), "executor must not reference :kali"
    src = Path(E.__file__).read_text(encoding="utf-8")
    for tok in ("run_kali", "from .kali", "cockpit.kali", "KALI_OPEN_CONTAINER"):
        assert tok not in src, f"executor must not reference the :kali shell ({tok})"
    # the engagement module must not touch :kali either
    esrc = Path(ENG.__file__).read_text(encoding="utf-8")
    for tok in ("run_kali", "kali", "KALI_OPEN"):
        assert tok not in esrc, f"engagement module must not reference :kali ({tok})"
    print("  agent still has ZERO :kali path (executor + engagement module clean): PASS")


# --------------------------------------------------------------------------- #
# 9. mode round-trips through the run store
# --------------------------------------------------------------------------- #
def test_mode_round_trips() -> None:
    from cockpit.models import RunRecord

    tmp = Path(tempfile.mkdtemp()) / "runs.db"
    orig = runstore.DB_PATH
    runstore.DB_PATH = tmp
    runstore.init_db()
    try:
        base = dict(
            run_id="r1", command="nmap", args=["-sV", _REAL], target=_REAL, approved=True,
            started_at="2026-07-24T00:00:00+00:00", finished_at="2026-07-24T00:00:01+00:00",
            session_id="s1",
        )
        runstore.save_run(RunRecord(**base, mode="engagement"))
        runstore.save_run(RunRecord(run_id="r2", command="curl", args=["-sI", "http://hackpit-lab-target:3000/"],
                                    target="hackpit-lab-target", approved=True,
                                    started_at="2026-07-24T00:00:02+00:00", finished_at="2026-07-24T00:00:03+00:00",
                                    session_id="s1"))  # mode defaults to 'lab'
        got = {r.run_id: r for r in runstore.list_runs_for_session("s1")}
        assert got["r1"].mode == "engagement", "engagement mode must round-trip"
        assert got["r2"].mode == "lab", "a run with no explicit mode defaults to lab"
    finally:
        runstore.DB_PATH = orig
    print("  mode round-trips through the run store ('engagement' kept; default 'lab'): PASS")


if __name__ == "__main__":
    test_never_auto_run_engagement()
    test_iter_run_prevalidated_still_needs_approval()
    test_explicit_entry_required()
    test_engagement_target_lock()
    test_engagement_heuristic_red_confirm()
    test_scope_lock_gate()
    test_engagement_gate_order()
    test_no_wall_a_gate()
    test_enter_exit_registry()
    test_lab_mode_unaffected()
    test_orchestrator_has_no_engagement_capability()
    test_executor_still_has_no_kali_path()
    test_mode_round_trips()
    print("ALL engagement-mode tests pass")
