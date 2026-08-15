"""SAFETY invariants for the AUTO-RUNNER decision + fire path (modes 2/3).

The auto-runner is the one place HackPit fires without a per-command human approval. Its safety
rests on two things, both locked here:

  1. THE DECISION POLICY. manual fires NOTHING. assisted fires ONLY passive — exploitation and
     human_only are QUEUED for the operator, never fired. full fires passive AND exploitation,
     but human_only STILL queues (the repeater and an 'ask' never auto-fire in any mode).
  2. THE FIRE PATH IS AUDITED AND ROUTES CORRECTLY. A surface fire goes through the same
     self-approving _run_surface the operator's MCP path uses; a command fire goes through the
     executor with approved+dangerous_ack. Every fire appends ONE line to an append-only audit
     that grows and is never rewritten.

The teeth: a simulated loop over a mixed batch in ASSISTED mode must never let an
exploitation-class action reach the fire hands.

Hermetic (fire is monkeypatched — nothing actually runs). Run:  python test_autorun_safety.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import autoaudit, autorun, autotier  # noqa: E402

P, X, H = autotier.PASSIVE, autotier.EXPLOITATION, autotier.HUMAN_ONLY


def _surf(name: str, **params) -> dict:
    return {"kind": "surface", "surface": name, "surface_params": params}


# --------------------------------------------------------------------------- #
# 1. the decision policy — the whole matrix
# --------------------------------------------------------------------------- #
def test_manual_fires_nothing() -> None:
    for prop in (_surf("nuclei"), _surf("intruder"), _surf("repeater"),
                 {"kind": "command", "command": "httpx"}):
        d = autorun.decide(prop, "manual")
        assert d.action == "skip", f"manual mode decided {d.action} for {prop}"
    print("  manual mode fires nothing — the human drives every step: PASS")


def test_assisted_fires_passive_only_queues_the_rest() -> None:
    assert autorun.decide(_surf("nuclei"), "assisted").action == "fire"
    assert autorun.decide(_surf("discover"), "assisted").action == "fire"
    assert autorun.decide(_surf("recon", mode="passive"), "assisted").action == "fire"
    # exploitation -> queue, NEVER fire
    for name in ("intruder", "race", "credentials", "tokens", "c2", "tunnels", "capture"):
        d = autorun.decide(_surf(name), "assisted")
        assert d.action == "queue", f"assisted FIRED exploitation surface {name}: {d}"
    assert autorun.decide(_surf("smuggle", stage="confirm"), "assisted").action == "queue"
    assert autorun.decide(_surf("recon", mode="active"), "assisted").action == "queue"
    # human_only -> queue
    assert autorun.decide(_surf("repeater"), "assisted").action == "queue"
    assert autorun.decide({"kind": "ask"}, "assisted").action == "queue"
    print("  assisted fires ONLY passive; exploitation + human_only are queued: PASS")


def test_full_fires_passive_and_exploitation_but_never_human_only() -> None:
    assert autorun.decide(_surf("nuclei"), "full").action == "fire"
    assert autorun.decide(_surf("intruder"), "full").action == "fire"
    assert autorun.decide(_surf("smuggle", stage="confirm"), "full").action == "fire"
    assert autorun.decide(_surf("credentials", mode="spray"), "full").action == "fire"
    # human_only STILL queues, even in full
    assert autorun.decide(_surf("repeater"), "full").action == "queue"
    assert autorun.decide({"kind": "ask"}, "full").action == "queue"
    print("  full fires passive + exploitation; the repeater / 'ask' still queue: PASS")


def test_an_unknown_mode_is_treated_as_manual() -> None:
    for mode in ("", "yolo", None, "AUTO"):
        assert autorun.decide(_surf("nuclei"), mode).action == "skip", f"mode {mode!r} was not manual"
    print("  an unknown/empty mode fails safe to manual: PASS")


# --------------------------------------------------------------------------- #
# 2. THE TEETH — a simulated assisted loop never fires an exploitation action
# --------------------------------------------------------------------------- #
def test_a_simulated_assisted_loop_never_fires_exploitation() -> None:
    fired: list[str] = []

    def _spy(name, params, sid, eid):  # stands in for mcp_tools._run_surface
        fired.append(name)
        return {"run_id": f"r-{name}"}

    import mcp_tools

    orig = mcp_tools._run_surface
    mcp_tools._run_surface = _spy  # type: ignore[assignment]
    try:
        batch = [
            _surf("nuclei"), _surf("discover"), _surf("intruder"), _surf("race"),
            _surf("credentials", mode="spray"), _surf("repeater"),
            _surf("cache", stage="confirm"), _surf("recon", mode="passive"),
        ]
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            autoaudit._AUDIT_PATH = str(Path(td) / "audit.jsonl")
            for prop in batch:
                d = autorun.decide(prop, "assisted")
                if d.action == "fire":
                    autorun.fire(prop, "s1", "e1", mode="assisted", tier=d.tier)
                else:
                    autorun.note_non_fire(d, prop, "s1", "e1", "assisted")
        # ONLY the passive surfaces were fired
        assert set(fired) == {"nuclei", "discover", "recon"}, f"assisted fired: {fired}"
        for danger in ("intruder", "race", "credentials", "repeater", "cache"):
            assert danger not in fired, f"assisted FIRED {danger}"
    finally:
        mcp_tools._run_surface = orig  # type: ignore[assignment]
    print("  a full assisted loop over a mixed batch fires only the passive surfaces: PASS")


# --------------------------------------------------------------------------- #
# 3. the fire path routes correctly and is audited
# --------------------------------------------------------------------------- #
def test_fire_routes_surface_and_command_and_audits_append_only() -> None:
    import mcp_tools
    from cockpit import executor

    surf_calls: list[str] = []
    cmd_calls: list[str] = []

    def _spy_surface(name, params, sid, eid):
        surf_calls.append(name)
        return {"run_id": "surf-1"}

    class _Rec:
        def model_dump(self):
            return {"run_id": "cmd-1"}

    def _spy_cmd(req):
        cmd_calls.append(req.command)
        assert req.approved and req.dangerous_ack, "a fired command must self-approve both gates"
        return _Rec()

    o_surf, o_cmd = mcp_tools._run_surface, executor.run_command
    mcp_tools._run_surface = _spy_surface  # type: ignore[assignment]
    executor.run_command = _spy_cmd  # type: ignore[assignment]
    try:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
            autoaudit._AUDIT_PATH = str(Path(td) / "audit.jsonl")
            autorun.fire(_surf("nuclei", targets=["x"]), "s1", "e1", mode="full", tier=P)
            autorun.fire({"kind": "command", "command": "httpx", "args": ["-u", "x"]},
                         "s1", "e1", mode="full", tier=P)
            lines = Path(autoaudit._AUDIT_PATH).read_text(encoding="utf-8").splitlines()
            assert len(lines) == 2, f"expected 2 append-only audit lines, got {len(lines)}"
            audit = autoaudit.read_all()
            # the surface line records the surface NAME + param KEYS, never values
            assert audit[0]["surface"] == "nuclei" and audit[0]["param_keys"] == ["targets"]
            assert "targets" not in str(audit[0].get("args", "")), "a surface param value leaked"
            assert audit[0]["outcome"] == "started" and audit[0]["run_id"] == "surf-1"
            assert audit[1]["command"] == "httpx" and audit[1]["outcome"] == "started"
            # a THIRD fire only grows the file — nothing is rewritten
            autorun.fire(_surf("discover"), "s1", "e1", mode="full", tier=P)
            grown = Path(autoaudit._AUDIT_PATH).read_text(encoding="utf-8").splitlines()
            assert grown[:2] == lines, "the audit was rewritten, not appended to"
            assert len(grown) == 3
        assert surf_calls == ["nuclei", "discover"] and cmd_calls == ["httpx"]
    finally:
        mcp_tools._run_surface, executor.run_command = o_surf, o_cmd  # type: ignore[assignment]
    print("  fire routes surface/command correctly and appends (never rewrites) the audit: PASS")


if __name__ == "__main__":
    test_manual_fires_nothing()
    test_assisted_fires_passive_only_queues_the_rest()
    test_full_fires_passive_and_exploitation_but_never_human_only()
    test_an_unknown_mode_is_treated_as_manual()
    test_a_simulated_assisted_loop_never_fires_exploitation()
    test_fire_routes_surface_and_command_and_audits_append_only()
    print("ALL auto-runner safety invariants hold")
