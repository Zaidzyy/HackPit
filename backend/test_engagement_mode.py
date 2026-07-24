"""Regression-lock for REAL-TARGET engagement mode (the SUPERVISED, highest-risk path).

Engagement mode removes the isolation floor: the cockpit execs against a human-named REAL
target through the Wall-A sandbox. The ENTIRE safety model then rests on a handful of
invariants — these tests fail loudly if any is weakened:

  1. WALL A (simulated inverted proof): assert_wall_a_holds refuses unless the firewall +
     sandbox are up, the sandbox SHARES the firewall netns, and the live ruleset DROPs every
     WALL_A_BLOCKED range. Any one missing → refuse (fail-closed).
  2. NEVER-AUTO-RUN: an engagement command with approved=False is refused at the approval
     gate — every command needs an INDIVIDUAL human approval; there is no batch/approve-all.
  3. EXPLICIT ENTRY: an engagement_id that was never entered (or was exited) is refused at the
     engagement gate — engagement mode can never be reached by a bare exec, nor downgraded to
     lab. Entry requires a target + a non-empty authorization acknowledgement.
  4. TARGET-LOCK to the named target (best-effort DiD): a non-target host is refused; the named
     target (host or URL form) passes.
  5. HEURISTIC RED-CONFIRM still fires in engagement mode (interpreters/shells/frameworks need
     the extra confirm).
  6. GATE ORDER: engagement → target → approval → danger → wall_a.
  7. LAB MODE UNCHANGED: no engagement_id → the lab gates (isolation), never Wall A.
  8. NO AUTONOMY ON REAL TARGETS + NO :kali PATH: the orchestrator/loop (the autonomy
     mechanic) has no engagement capability, and the executor still has zero :kali path.
  9. mode round-trips through the run store ('lab' default; 'engagement' preserved).

Hermetic: Docker + the LLM are never touched — assert_wall_a_holds' docker helpers are
monkeypatched, engagement resolution is either monkeypatched or driven through a throwaway
temp DB. Run:  python test_engagement_mode.py
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
def _full_ruleset(drop=config.WALL_A_BLOCKED) -> str:
    lines = ["-P OUTPUT ACCEPT", "-A OUTPUT -o lo -j ACCEPT"]
    lines += [f"-A OUTPUT -d {c} -j DROP" for c in drop]
    return "\n".join(lines)


def _patch_wall(*, running, netmode, ruleset, rc=0):
    """Swap sandbox's docker helpers for pure fakes; returns a restore fn."""
    fw = config.ENGAGE_FIREWALL_CONTAINER
    fw_id = "deadbeefcafe0000"
    orig = (S._running, S._inspect_field, S._docker)
    S._running = lambda name: running.get(name, False)

    def fake_inspect(name, fmt):
        if "NetworkMode" in fmt:
            return netmode.replace("{FWID}", fw_id)
        if ".Id" in fmt:
            return fw_id
        return ""

    S._inspect_field = fake_inspect
    S._docker = lambda args, timeout=10.0: (rc, ruleset, "" if rc == 0 else "boom")

    def restore():
        S._running, S._inspect_field, S._docker = orig

    return restore, fw


def _fake_engagement(target=_REAL) -> EngagementRecord:
    return EngagementRecord(
        engagement_id="eng-test000000",
        target=target,
        authorization="authorized test target",
        active=True,
        entered_at="2026-07-24T00:00:00+00:00",
    )


def _patch_active(rec: EngagementRecord | None):
    """Make executor resolve THIS engagement (or none), and no-op Wall A."""
    orig = (E.engagement.get_active, E.assert_wall_a_holds)
    E.engagement.get_active = lambda eid: rec if (rec and eid == rec.engagement_id) else None
    E.assert_wall_a_holds = lambda: None

    def restore():
        E.engagement.get_active, E.assert_wall_a_holds = orig

    return restore


# --------------------------------------------------------------------------- #
# 1. WALL A — simulated inverted proof
# --------------------------------------------------------------------------- #
def test_wall_a_holds_when_all_good() -> None:
    up = {config.ENGAGE_FIREWALL_CONTAINER: True, config.ENGAGE_SANDBOX_CONTAINER: True}
    restore, fw = _patch_wall(running=up, netmode="container:{FWID}", ruleset=_full_ruleset())
    try:
        S.assert_wall_a_holds()  # returns None on success
    finally:
        restore()
    print("  wall A holds when firewall+sandbox up, netns shared, all ranges dropped: PASS")


def test_wall_a_refuses_firewall_down() -> None:
    up = {config.ENGAGE_FIREWALL_CONTAINER: False, config.ENGAGE_SANDBOX_CONTAINER: True}
    restore, _ = _patch_wall(running=up, netmode="container:{FWID}", ruleset=_full_ruleset())
    try:
        raised = False
        try:
            S.assert_wall_a_holds()
        except SandboxError as exc:
            raised = True
            assert "firewall" in str(exc) and "not running" in str(exc)
        assert raised, "a down firewall MUST refuse (Wall A has no owner)"
    finally:
        restore()
    print("  wall A refuses when the firewall sidecar is down: PASS")


def test_wall_a_refuses_when_netns_not_shared() -> None:
    up = {config.ENGAGE_FIREWALL_CONTAINER: True, config.ENGAGE_SANDBOX_CONTAINER: True}
    # sandbox on its own bridge, NOT sharing the firewall's netns → Wall A wouldn't apply.
    restore, _ = _patch_wall(running=up, netmode="bridge", ruleset=_full_ruleset())
    try:
        raised = False
        try:
            S.assert_wall_a_holds()
        except SandboxError as exc:
            raised = True
            assert "netns" in str(exc) or "sharing" in str(exc)
        assert raised, "a sandbox not sharing the firewall netns MUST refuse"
    finally:
        restore()
    print("  wall A refuses when the sandbox does not share the firewall netns: PASS")


def test_wall_a_refuses_when_a_range_not_dropped() -> None:
    up = {config.ENGAGE_FIREWALL_CONTAINER: True, config.ENGAGE_SANDBOX_CONTAINER: True}
    # drop everything EXCEPT the metadata range — a hole Wall A must catch.
    partial = _full_ruleset(drop=[c for c in config.WALL_A_BLOCKED if c != "169.254.0.0/16"])
    restore, _ = _patch_wall(running=up, netmode="container:{FWID}", ruleset=partial)
    try:
        raised = False
        try:
            S.assert_wall_a_holds()
        except SandboxError as exc:
            raised = True
            assert "169.254.0.0/16" in str(exc) and "not dropping" in str(exc)
        assert raised, "a missing DROP (metadata reachable) MUST refuse"
    finally:
        restore()
    print("  wall A refuses when any WALL_A_BLOCKED range is not dropped: PASS")


def test_wall_a_refuses_on_docker_error() -> None:
    up = {config.ENGAGE_FIREWALL_CONTAINER: True, config.ENGAGE_SANDBOX_CONTAINER: True}
    restore, _ = _patch_wall(running=up, netmode="container:{FWID}", ruleset="", rc=1)
    try:
        raised = False
        try:
            S.assert_wall_a_holds()
        except SandboxError:
            raised = True
        assert raised, "an unreadable ruleset (docker error) MUST fail closed"
    finally:
        restore()
    print("  wall A fails closed when the ruleset cannot be read: PASS")


# --------------------------------------------------------------------------- #
# 2–6. the engagement gate chain (Wall A no-op'd; engagement resolved)
# --------------------------------------------------------------------------- #
def test_never_auto_run_engagement() -> None:
    """The core real-target invariant: approved=False is refused at approval. No batch/auto."""
    restore = _patch_active(_fake_engagement())
    try:
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id="eng-test000000")
        )
        assert r is not None and r.gate == "approval", "engagement + unapproved MUST reject at approval"
        assert "individual human approval" in r.reason or "hands-off" in r.reason
        # explicitly approved → clears (Wall A no-op'd) — one conscious command at a time
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id="eng-test000000", approved=True)
        )
        assert r is None, "an individually-approved engagement command clears the gates"
    finally:
        restore()
    print("  NEVER-AUTO-RUN: engagement needs an individual approval (no batch/auto): PASS")


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


def test_engagement_gate_order() -> None:
    """engagement → target → approval → danger → wall_a (first failing gate wins)."""
    restore = _patch_active(_fake_engagement(_REAL))
    try:
        # unknown id + everything else wrong → engagement leads
        r = E.validate_request(
            ExecRequest(command="python3", args=["-c", "x", "example.com"], engagement_id="nope")
        )
        assert r.gate == "engagement", "engagement (explicit entry) leads"
        # active id, wrong target, unapproved, dangerous → target beats approval+danger
        r = E.validate_request(
            ExecRequest(command="python3", args=["-c", "x", "example.com"], engagement_id="eng-test000000")
        )
        assert r.gate == "target", "target beats approval/danger"
        # active id, right target, unapproved, dangerous → approval beats danger
        r = E.validate_request(
            ExecRequest(command="python3", args=["-c", "x", _REAL], engagement_id="eng-test000000")
        )
        assert r.gate == "approval", "approval beats danger"
        # active id, right target, approved, dangerous, no ack → danger (wall_a is last, no-op'd)
        r = E.validate_request(
            ExecRequest(command="python3", args=["-c", "x", _REAL], engagement_id="eng-test000000", approved=True)
        )
        assert r.gate == "danger", "danger precedes wall_a"
    finally:
        restore()
    print("  GATE ORDER: engagement -> target -> approval -> danger -> wall_a: PASS")


def test_wall_a_is_reached_last() -> None:
    """With target/approval/danger all passed, a failing Wall A surfaces as gate=wall_a; a
    passing one clears. (Here we DON'T no-op Wall A — we patch it directly.)"""
    rec = _fake_engagement(_REAL)
    orig = (E.engagement.get_active, E.assert_wall_a_holds)
    E.engagement.get_active = lambda eid: rec if eid == rec.engagement_id else None
    try:
        E.assert_wall_a_holds = lambda: (_ for _ in ()).throw(SandboxError("sim: Wall A breached"))
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id=rec.engagement_id, approved=True)
        )
        assert r is not None and r.gate == "wall_a", "a Wall-A failure must surface as gate=wall_a"

        E.assert_wall_a_holds = lambda: None
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id=rec.engagement_id, approved=True)
        )
        assert r is None, "a fully valid engagement command clears all gates"
    finally:
        E.engagement.get_active, E.assert_wall_a_holds = orig
    print("  WALL A is the last engagement gate (reached in validate_request): PASS")


# --------------------------------------------------------------------------- #
# 3b. explicit entry / exit through the REAL registry (throwaway temp DB)
# --------------------------------------------------------------------------- #
def test_enter_exit_registry() -> None:
    tmp = Path(tempfile.mkdtemp()) / "eng.db"
    orig = (runstore.DB_PATH, ENG.DB_PATH)
    runstore.DB_PATH = tmp
    ENG.DB_PATH = tmp
    runstore.init_db()
    ENG.init_db()
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

        # the executor now runs against it (Wall A no-op'd)
        restore = _patch_active(rec)
        try:
            r = E.validate_request(
                ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id=rec.engagement_id, approved=True)
            )
            assert r is None, "an entered + approved command clears"
        finally:
            restore()

        assert ENG.exit_engagement(rec.engagement_id) is True, "exit ends the engagement"
        assert ENG.get_active(rec.engagement_id) is None, "an exited engagement no longer resolves"
        # and after exit the executor refuses (fail-closed) — via the REAL get_active
        r = E.validate_request(
            ExecRequest(command="nmap", args=["-sV", _REAL], engagement_id=rec.engagement_id, approved=True)
        )
        assert r is not None and r.gate == "engagement", "an exited engagement is refused at the gate"
    finally:
        runstore.DB_PATH, ENG.DB_PATH = orig
    print("  ENTER/EXIT registry: entry needs auth; exit fail-closes the executor: PASS")


# --------------------------------------------------------------------------- #
# 7. LAB MODE UNCHANGED — no engagement_id → lab gates, not Wall A
# --------------------------------------------------------------------------- #
def test_lab_mode_unaffected() -> None:
    """A request with no engagement_id runs the LAB path: it never consults engagement or Wall
    A, and reaches the ISOLATION gate. Verified by making Wall A blow up if it were ever called
    and isolation the thing that decides."""
    orig = (E.assert_isolation_proven, E.assert_wall_a_holds)

    def boom():
        raise AssertionError("Wall A must NOT be called in lab mode")

    try:
        E.assert_wall_a_holds = boom
        E.assert_isolation_proven = lambda: None
        r = E.validate_request(ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=True))
        assert r is None, "a valid lab command clears via the ISOLATION gate (not Wall A)"

        E.assert_isolation_proven = lambda: (_ for _ in ()).throw(SandboxError("sim: not isolated"))
        r = E.validate_request(ExecRequest(command="nmap", args=["-sV", "hackpit-lab-target"], approved=True))
        assert r is not None and r.gate == "sandbox", "lab isolation failure surfaces as gate=sandbox"
    finally:
        E.assert_isolation_proven, E.assert_wall_a_holds = orig
    print("  LAB MODE unchanged: lab path uses isolation, never Wall A: PASS")


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
        "assert_wall_a_holds",
    ]
    hits = [f for f in forbidden if f in src]
    assert not hits, f"orchestrator/loop must have NO engagement capability — found: {hits}"
    # and the loop proposal it emits carries no engagement field (structure lock)
    assert "engagement" not in " ".join(
        # the proposal dict keys built in propose_next
        ["command", "args", "rationale", "step_id", "gate_ok", "gate_reason", "dangerous_flags"]
    )
    print("  NO AUTONOMY on real targets: orchestrator/loop has no engagement capability: PASS")


def test_executor_still_has_no_kali_path() -> None:
    """The agent's exec path must still have ZERO path to the :kali open-egress shell, even
    though engagement mode now has its own egress sandbox."""
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
    test_wall_a_holds_when_all_good()
    test_wall_a_refuses_firewall_down()
    test_wall_a_refuses_when_netns_not_shared()
    test_wall_a_refuses_when_a_range_not_dropped()
    test_wall_a_refuses_on_docker_error()
    test_never_auto_run_engagement()
    test_explicit_entry_required()
    test_engagement_target_lock()
    test_engagement_heuristic_red_confirm()
    test_engagement_gate_order()
    test_wall_a_is_reached_last()
    test_enter_exit_registry()
    test_lab_mode_unaffected()
    test_orchestrator_has_no_engagement_capability()
    test_executor_still_has_no_kali_path()
    test_mode_round_trips()
    print("ALL engagement-mode tests pass")
