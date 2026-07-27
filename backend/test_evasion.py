"""Functional tests for the bespoke evasion engine (build #4, item C).

Hermetic: no Docker, no network, no real subprocess. Everything that would leave the process
is monkeypatched by manual save/restore (this project has no pytest, so no fixtures).

Run:  backend/.venv/Scripts/python.exe backend/test_evasion.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import config, executor as EX, loot, runstore  # noqa: E402
from cockpit.models import EngagementRecord  # noqa: E402
from evasion import engine as G  # noqa: E402


class _Spy:
    """Save/restore monkeypatch for everything the engine can reach outside itself."""

    def __init__(self, *, returncode: int = 0, stdout: str = "ok", stderr: str = "") -> None:
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr
        self.run_argv: list[list[str]] = []
        self.saved: list = []
        self.loot_calls: list = []

    def __enter__(self) -> "_Spy":
        self._orig = (G.subprocess.run, runstore.save_run, loot.workdir_for,
                      EX.assert_isolation_proven)

        def fake_run(argv, **kw):
            self.run_argv.append(list(argv))
            return subprocess.CompletedProcess(argv, self.returncode, self.stdout, self.stderr)

        def fake_workdir(mode, engagement_id):
            self.loot_calls.append((mode, engagement_id))
            return f"/loot/{engagement_id}" if mode == "engagement" and engagement_id else None

        G.subprocess.run = fake_run
        runstore.save_run = lambda rec: self.saved.append(rec)
        loot.workdir_for = fake_workdir
        # The lab's ISOLATION gate shells out to docker to prove the sandbox is egress-less.
        # Stubbed so the suite stays hermetic — the gate ORDER is still exercised, and the
        # isolation gate itself is covered by the live proof run (run_safety_tests.sh
        # --with-proof), not by a unit test.
        EX.assert_isolation_proven = lambda *a, **k: None
        return self

    def __exit__(self, *exc) -> None:
        (G.subprocess.run, runstore.save_run, loot.workdir_for,
         EX.assert_isolation_proven) = self._orig


def _req(**kw) -> G.EvasionRequest:
    base = dict(payload_path="/loot/in.exe", target_os="windows",
                techniques=["donut-pack"], approved=True, dangerous_ack=True)
    base.update(kw)
    return G.EvasionRequest(**base)


# --------------------------------------------------------------------------- #
def test_generate_emits_artifact_and_mandatory_honest_footprint() -> None:
    with _Spy() as spy:
        res = G.generate(_req())
    assert res.artifact_path, "an artifact must be produced"
    assert res.footprint and res.footprint.get("activity"), "blue-view footprint is mandatory"
    assert res.opsec_note and res.opsec_note["still_recorded"].strip(), \
        "every generation must carry a still_recorded honesty marker"
    # The footprint must be the one that DESCRIBES this technique, not a near-miss.
    assert res.footprint["spec_key"] == "evasion_packed_loader", res.footprint.get("spec_key")
    assert len(spy.saved) == 1, "the generation must be audited"
    print("  every artifact carries a blue footprint + a still_recorded note: PASS")


def test_the_footprint_cannot_be_suppressed() -> None:
    """There is no flag, field or argument that turns the honest half off."""
    fields = set(G.EvasionRequest.model_fields)
    for off_switch in ("include_footprint", "footprint", "quiet", "no_footprint", "opsec"):
        assert off_switch not in fields, f"EvasionRequest must not expose {off_switch!r}"
    assert "footprint" in G.EvasionResult.model_fields
    assert "opsec_note" in G.EvasionResult.model_fields
    # Both are REQUIRED on the result model — no default means it cannot be omitted.
    assert G.EvasionResult.model_fields["footprint"].is_required()
    assert G.EvasionResult.model_fields["opsec_note"].is_required()
    print("  the honest half is structurally non-optional: PASS")


def test_a_technique_with_no_detection_spec_refuses_to_build() -> None:
    """If the engine cannot describe what a defender sees, it does not get to build."""
    orig = G.TECHNIQUES.copy()
    try:
        G.TECHNIQUES["donut-pack"] = "no_such_spec_key"
        with _Spy() as spy:
            try:
                G.generate(_req())
                assert False, "a technique with no detection spec must refuse"
            except G.EvasionError as exc:
                assert "no detection spec" in str(exc), exc
        assert not spy.run_argv, "nothing may be generated when the honest half is unavailable"
        assert not spy.saved, "a refused build records nothing"
    finally:
        G.TECHNIQUES.clear()
        G.TECHNIQUES.update(orig)
    print("  no detection spec -> refuses to emit, generates nothing: PASS")


def test_generate_never_runs_the_payload_or_the_artifact() -> None:
    """The ONLY thing exec'd is the generator. The artifact is never argv[0]."""
    with _Spy() as spy:
        res = G.generate(_req())
    assert len(spy.run_argv) == 1, spy.run_argv
    argv = spy.run_argv[0]
    assert argv[:2] == ["docker", "exec"], argv
    generator = argv[3]
    assert generator in ("donut", "ScareCrow"), generator
    # Neither the input payload nor the produced artifact is ever the executed program.
    assert argv[3] != res.artifact_path and res.artifact_path not in argv[:4]
    assert "/loot/in.exe" not in argv[:4], "the payload is an ARGUMENT, never the program"
    print("  only the generator is exec'd; payload and artifact are never run: PASS")


def test_no_shell_and_the_container_is_never_a_request_field() -> None:
    assert "container" not in G.EvasionRequest.model_fields
    src = Path(G.__file__).read_text(encoding="utf-8")
    for token in ("shell=True", "os.system", "os.popen", "/bin/sh", "subprocess.call("):
        assert token not in src, f"the engine must not use {token!r}"
    with _Spy() as spy:
        G.generate(_req(engagement_id=None))
    argv = spy.run_argv[0]
    assert argv[2] in (config.SANDBOX_CONTAINER, config.ENGAGE_SANDBOX_CONTAINER), argv[2]
    print("  no shell; the container comes from the resolved mode, not the request: PASS")


def test_generation_is_gated() -> None:
    """approved=False and dangerous_ack=False are both refused, and nothing runs."""
    for kw, expect in (({"approved": False}, "approval"), ({"dangerous_ack": False}, "danger")):
        with _Spy() as spy:
            try:
                G.generate(_req(**kw))
                assert False, f"{kw} must be refused"
            except G.EvasionRefused as exc:
                assert exc.gate, "a refusal must name its gate"
            assert not spy.run_argv, f"{kw}: nothing may run when a gate refuses"
            assert not spy.saved, f"{kw}: a refused generation records nothing"
    print("  generation is gated: unapproved and un-acked are refused, nothing runs: PASS")


def test_stub_techniques_render_text_and_exec_nothing() -> None:
    for technique in ("amsi-patch", "etw-blind"):
        with _Spy() as spy:
            res = G.generate(_req(techniques=[technique]))
        assert not spy.run_argv, f"{technique}: a stub technique must exec nothing"
        assert res.stub.strip(), f"{technique}: stub must render"
        assert res.artifact_path.endswith(".ps1"), res.artifact_path
        # The honesty header travels WITH the artifact, so it survives being copied out.
        low = res.stub.lower()
        assert "still sees" in low, f"{technique}: the stub must name what still records it"
        assert len(spy.saved) == 1, f"{technique}: the generation must be audited"
    print("  stub techniques render text, exec nothing, and carry the honesty header: PASS")


def test_render_stub_is_pure_and_rejects_a_non_stub_technique() -> None:
    a, b = G.render_stub("amsi-patch"), G.render_stub("amsi-patch")
    assert a == b and a.strip(), "render_stub must be deterministic"
    try:
        G.render_stub("donut-pack")
        assert False, "a compiled technique has no stub"
    except G.EvasionError:
        pass
    print("  render_stub is pure and refuses a non-stub technique: PASS")


def test_a_failed_build_is_recorded_not_raised() -> None:
    """A generator that exits non-zero is a FAILED BUILD, not a containment event."""
    with _Spy(returncode=2, stderr="donut: bad input") as spy:
        res = G.generate(_req())
    assert res.exit_code == 2 and "bad input" in res.stderr
    assert len(spy.saved) == 1 and spy.saved[0].exit_code == 2
    # ...and it STILL carries the honest half.
    assert res.footprint.get("activity") and res.opsec_note["still_recorded"].strip()
    print("  a failed build is recorded with its exit code, still honest: PASS")


def test_unknown_technique_is_rejected_at_the_model() -> None:
    for bad in (["not-a-technique"], []):
        try:
            G.EvasionRequest(payload_path="/loot/in.exe", techniques=bad)
            assert False, f"{bad!r} must be rejected"
        except Exception:
            pass
    try:
        G.EvasionRequest(payload_path="-oJ", techniques=["donut-pack"])
        assert False, "a payload_path that leads with '-' must be rejected"
    except Exception:
        pass
    print("  unknown/empty techniques and flag-lookalike paths are rejected: PASS")


def test_lab_mode_gets_a_bare_filename_and_engagement_gets_the_loot_dir() -> None:
    """Placement is delegated to the same helper executor.iter_run uses."""
    with _Spy() as spy:
        lab = G.generate(_req())
    assert "/loot" not in lab.artifact_path, lab.artifact_path
    assert lab.mode == "lab"

    eng = EngagementRecord(engagement_id="eng-1", target="10.0.0.5", scope="10.0.0.5",
                           authorization="authorized", active=True, entered_at="now")
    orig = (EX.resolve_mode, EX._engagement_for)
    try:
        EX.resolve_mode = lambda r: EX.ResolvedMode(
            mode="engagement", container=config.ENGAGE_SANDBOX_CONTAINER,
            target="10.0.0.5", engagement=eng)
        EX._engagement_for = lambda r: eng
        with _Spy() as spy2:
            res = G.generate(_req(engagement_id="eng-1", target="10.0.0.5"))
    finally:
        EX.resolve_mode, EX._engagement_for = orig
    assert res.artifact_path.startswith("/loot/eng-1/"), res.artifact_path
    assert spy2.run_argv[0][2] == config.ENGAGE_SANDBOX_CONTAINER
    print("  lab gets a bare filename; engagement lands in the loot dir: PASS")


if __name__ == "__main__":
    test_generate_emits_artifact_and_mandatory_honest_footprint()
    test_the_footprint_cannot_be_suppressed()
    test_a_technique_with_no_detection_spec_refuses_to_build()
    test_generate_never_runs_the_payload_or_the_artifact()
    test_no_shell_and_the_container_is_never_a_request_field()
    test_generation_is_gated()
    test_stub_techniques_render_text_and_exec_nothing()
    test_render_stub_is_pure_and_rejects_a_non_stub_technique()
    test_a_failed_build_is_recorded_not_raised()
    test_unknown_technique_is_rejected_at_the_model()
    test_lab_mode_gets_a_bare_filename_and_engagement_gets_the_loot_dir()
    print("ALL evasion functional tests pass")
