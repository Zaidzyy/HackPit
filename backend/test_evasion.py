"""Functional tests for the bespoke evasion engine (build #4, item C).

Hermetic: no Docker, no network, no real subprocess. Everything that would leave the process
is monkeypatched by manual save/restore (this project has no pytest, so no fixtures).

Run:  backend/.venv/Scripts/python.exe backend/test_evasion.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import config, executor as EX, loot, runstore  # noqa: E402
from cockpit.models import EngagementRecord  # noqa: E402
from detection import attck, catalog  # noqa: E402
from evasion import engine as G  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = Path(G.__file__).resolve().parent / "templates"


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
    base = dict(payload_path="/loot/in.exe",
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


# --------------------------------------------------------------------------- #
# Regression locks for the Tasks 8-13 review findings. Each of these FAILS on the
# code as it was before the corresponding fix.
# --------------------------------------------------------------------------- #
def test_a_mixed_technique_request_is_refused_not_half_honoured() -> None:
    """I1. `techniques` is a list, but only techniques[0] was ever described.

    Before the fix, ["amsi-patch", "scarecrow-loader"] BUILT the ScareCrow loader (because
    `_needs_generator` reads the whole list) and returned it carrying the AMSI-patch footprint
    (because `_honest_footprint` reads only the first entry) — a real artifact described by a
    technique it does not implement. Two stub techniques silently dropped the second. There was
    no multi-technique test at all, which is why it shipped.
    """
    for combo in (["amsi-patch", "scarecrow-loader"],   # built one thing, described another
                  ["donut-pack", "amsi-patch"],          # stub silently dropped
                  ["amsi-patch", "etw-blind"],           # second stub silently dropped
                  ["donut-pack", "donut-pack"]):         # even a duplicate is ambiguous
        try:
            G.EvasionRequest(payload_path="/loot/in.exe", techniques=combo)
            assert False, f"{combo!r} must be refused — it cannot be described honestly"
        except ValueError:
            pass

    # ...and every single-technique build still resolves to ITS OWN spec, not a near-miss.
    for technique, spec_key in G.TECHNIQUES.items():
        with _Spy():
            res = G.generate(_req(techniques=[technique]))
        assert res.footprint["spec_key"] == spec_key, \
            f"{technique}: described as {res.footprint.get('spec_key')!r}, expected {spec_key!r}"
        assert res.techniques == [technique]
    print("  a multi-technique build is refused; each single build gets its own spec: PASS")


def test_the_evasion_specs_cite_the_right_attck_techniques() -> None:
    """I2. `evasion_etw_blind` cited T1690, which is about shell history, not sensors.

    Checked against upstream's own revoked-by graph: T1562.001 (Disable or Modify Tools) AND
    T1562.006 (Indicator Blocking) BOTH revoke into T1685; T1690 is the successor of T1562.003
    (Impair Command History Logging). `pipeline/detection_sources.py --verify` cannot catch
    this — it checks that a cited id's name/tactic/log sources match upstream, not that the
    technique is the right one for the activity, so it reported 0 problems throughout.
    """
    assert attck.TECHNIQUES["T1690"].name == "Prevent Command History Logging", \
        "upstream renamed T1690 — recheck which technique the sensor-tamper specs should cite"
    assert attck.TECHNIQUES["T1685"].name == "Disable or Modify Tools"

    for key in ("evasion_amsi_patch", "evasion_etw_blind"):
        ids = catalog.SPECS[key].techniques
        assert "T1690" not in ids, (
            f"{key} cites T1690 ({attck.TECHNIQUES['T1690'].name}) — that is command-history "
            "tampering, not sensor tampering. Sensor tampering is T1685.")
        assert "T1685" in ids, f"{key} must cite T1685 (Disable or Modify Tools), got {ids}"

    # T1690 stays where it belongs: the log/history-tampering arg signal.
    log_tamper = next(s for s in catalog.ARG_SIGNALS if s.id == "log_tamper")
    assert "T1690" in log_tamper.techniques, "T1690 belongs on the history-tampering signal"

    # And the packed-loader spec is an obfuscation technique, not a tamper one.
    assert "T1027" in catalog.SPECS["evasion_packed_loader"].techniques
    print("  the 3 evasion specs cite the correct ATT&CK techniques: PASS")


def test_the_stub_headers_match_what_the_stubs_actually_do() -> None:
    """I3. The stubs are managed-reflection bypasses; the headers described memory patching.

    The headers and the catalog copy have to move TOGETHER — the header is the honesty contract
    that travels inside the artifact, the spec is the one the panel renders, and they describe
    the same thing. Before the fix both claimed Sysmon 8/10, 'a write into amsi.dll' and 'the
    ntdll handle access', none of which this code performs, while omitting the detection that
    does fire: the script is scanned and script-block logged before it takes effect.
    """
    for name, spec_key in (("amsi_patch.ps1.tmpl", "evasion_amsi_patch"),
                           ("etw_blind.ps1.tmpl", "evasion_etw_blind")):
        low = (TEMPLATES / name).read_text(encoding="utf-8").lower()

        # It really is the reflection variant — if that ever changes, recheck the header.
        assert "getfield(" in low and "setvalue(" in low, \
            f"{name}: expected a managed-reflection stub"
        for api in ("openprocess", "writeprocessmemory", "virtualprotect", "ntprotectvirtual"):
            assert api not in low, \
                f"{name}: no longer a pure reflection stub ({api}) — the header must be rechecked"

        # So it must not claim memory-patch telemetry it cannot generate.
        for claim in ("write into amsi.dll", "ntdll handle access", "memory-write telemetry"):
            assert claim not in low, f"{name}: claims {claim!r}, which this stub never produces"
        assert not re.search(r"eventcode[^\n.]*\b(?:8|10)\b", low), \
            f"{name}: cites Sysmon 8/10, which a reflection stub does not trigger"

        # ...and it must name the detection that DOES fire, in the header and in the spec.
        assert "4104" in low, f"{name}: must name script-block logging (4104)"
        telemetry = " ".join(catalog.SPECS[spec_key].telemetry).lower()
        assert "4104" in telemetry, f"{spec_key}: telemetry must name script-block logging"
        assert "eventcode=1, 7, 8" not in telemetry and "7, 10" not in telemetry, \
            f"{spec_key}: still cites memory-patch Sysmon codes"
        blue = catalog.SPECS[spec_key].blue_view.lower()
        for claim in ("write into amsi.dll", "ntdll image load", "handle access"):
            assert claim not in blue, f"{spec_key}: blue_view claims {claim!r}"
    print("  both stub headers and their specs describe the reflection variant: PASS")


def test_engagement_mode_with_no_target_is_permitted_by_design() -> None:
    """I5. Pins the behaviour `_gate_request`'s comment now describes.

    The comment used to claim an empty target in engagement mode 'falls through to the scope
    gate and is refused'. It does not: outside lab mode `check_target_lock` deliberately allows
    a command that names no host. Nothing network-facing can reach a generate, so that is
    correct — but the comment was wrong, and a wrong comment about a gate is how the next
    reader gets misled. This test fails if either the comment's claim or the gate changes.
    """
    eng = EngagementRecord(engagement_id="eng-1", target="10.0.0.5", scope="10.0.0.5",
                           authorization="authorized", active=True, entered_at="now")
    import cockpit.engagement as CE
    orig = CE.get_active
    try:
        CE.get_active = lambda i: eng
        req = _req(target="", engagement_id="eng-1")
        assert G._gate_request(req).args == [], "no target means no args reach the gate"
        assert G.validate_build(req) is None, \
            "engagement + empty target is PERMITTED — if this now refuses, fix the comment in " \
            "_gate_request that says so"
        # ...but a target that IS named is still scope-checked — it WARNS at the scope gate
        # (handrail, override-able), so an out-of-scope build is still refused without the override.
        bad = _req(target="evil.example.com", engagement_id="eng-1")
        rejected = G.validate_build(bad)
        assert rejected is not None and rejected.gate == "scope", \
            f"an out-of-scope target must still be refused (at the scope gate), got {rejected}"
    finally:
        CE.get_active = orig
    print("  engagement + no target is allowed by design; a named target is still gated: PASS")


def test_a_failed_build_claims_no_artifact_path() -> None:
    """M7. A non-zero exit or a timeout produced no file, so no path may be claimed."""
    with _Spy(returncode=3, stderr="donut: bad input"):
        failed = G.generate(_req())
    assert failed.exit_code == 3
    assert failed.artifact_path == "", \
        "a failed build must not hand back a path to a file that was never written"
    # ...and it is still honest about what the technique would have looked like.
    assert failed.footprint.get("activity") and failed.opsec_note["still_recorded"].strip()
    with _Spy() as spy:
        ok = G.generate(_req())
    assert ok.artifact_path and spy.run_argv, "a successful build still reports its path"
    print("  a failed build reports no artifact path, and stays honest: PASS")


# --------------------------------------------------------------------------- #
# The image layer (docker/Dockerfile.sandbox). No Docker needed — these read the
# recipe. M1: a smoke test that cannot fail is not a smoke test.
# --------------------------------------------------------------------------- #
_DOCKERFILE = REPO / "docker" / "Dockerfile.sandbox"
# The binaries the build-#4 layer advertises and claims to smoke-test.
_BUILD4_BINARIES = ("sliver-server", "sliver-client", "dnscat2-client", "dnscat2-server",
                    "iodine", "iodined", "donut", "ScareCrow", "osslsigncode")


def test_the_image_smoke_tests_carry_a_status() -> None:
    """M1. `tool -h | head -1` and `|| true` both discard the exit status.

    A pipeline's status is its LAST command's, so `head` returns 0 for a tool that is missing,
    empty or dies on its first line — and `|| true` is the same failure with the intent written
    down. ScareCrow was checked with BOTH, making it the one advertised binary whose brokenness
    could not fail the build, in a layer whose own comment says each tool is really invoked.
    """
    lines = _DOCKERFILE.read_text(encoding="utf-8").splitlines()
    offenders = []
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        if not any(b in line for b in _BUILD4_BINARIES):
            continue
        if "|| true" in line or "| head" in line:
            offenders.append(f"{i}: {line.strip()}")
    assert not offenders, (
        "these build-#4 smoke tests discard the tool's exit status, so a broken tool would "
        "still produce a green build:\n  " + "\n  ".join(offenders))

    # Positive control: the checks really are there to be discarded in the first place.
    body = "\n".join(lines)
    assert body.count("grep -qi") >= 8, \
        "the consolidated smoke test no longer asserts each tool's output"
    print(f"  all {len(_BUILD4_BINARIES)} build-#4 smoke tests carry a real exit status: PASS")


def test_the_image_layer_pins_every_build4_install() -> None:
    """M2, CLOSED in build #7. Every build-#4 install is now pinned to an exact upstream value.

    The earlier form of this test tolerated three unpinned installs and only asserted the gap
    stayed *documented*, because pinning needs values resolved from the network
    (docker/pin-build4-versions.sh). Those values are now in the Dockerfile, so the claim this
    test makes is the stronger one: no build-#4 install resolves to "whatever is current".

    Each entry carries BOTH forms deliberately. Asserting only that the pinned form is present
    would pass on a half-applied pin that left the floating clone in place next to it — the
    exact shape a re-run of the pin script against a drifted Dockerfile could produce.
    """
    body = _DOCKERFILE.read_text(encoding="utf-8")

    # ARG-carried version pins. DNSCAT2_COMMIT joins the two release-binary pins: dnscat2 has
    # no release tags at all, so a commit SHA is the only thing there is to pin it to.
    for arg in ("SLIVER_VERSION", "SCARECROW_VERSION", "DNSCAT2_COMMIT"):
        assert re.search(rf"^ARG {arg}=\S+", body, re.M), f"{arg} must stay pinned to a version"

    # The SHA has to be a real 40-char object id, not a branch name someone typed into the ARG.
    sha = re.search(r"^ARG DNSCAT2_COMMIT=(\S+)", body, re.M).group(1)
    assert re.fullmatch(r"[0-9a-f]{40}", sha), \
        f"DNSCAT2_COMMIT must be a full 40-char commit sha, got {sha!r}"

    # (what, the floating form that must be GONE, the pinned form that must be PRESENT)
    pinned = {
        "dnscat2": ("git clone --depth 1 https://github.com/iagox86", "checkout --detach"),
        "gems": ("gem install --no-document trollop salsa20 sha3 ecdsa", "trollop:"),
        "donut-shellcode": ("-q donut-shellcode;", "donut-shellcode=="),
    }
    for what, (floating_form, pinned_form) in pinned.items():
        assert pinned_form in body, f"{what}: the pin is gone — this install floats again"
        assert floating_form not in body, \
            f"{what}: pinned and floating forms are BOTH present — a half-applied pin"

    # Every pinned gem carries an explicit version, not just a colon.
    gems = re.search(r"gem install --no-document (\S+ \S+ \S+ \S+);", body).group(1)
    for spec in gems.split():
        name, _, version = spec.partition(":")
        assert version, f"gem {name} is not pinned to a version"

    # The pin script stays reachable — it is how these values move forward.
    assert (REPO / "docker" / "pin-build4-versions.sh").is_file(), \
        "the pin script named in the Dockerfile does not exist"

    print(f"  all {len(pinned)} build-#4 installs pinned + 3 ARG version pins, "
          f"0 floating: PASS")


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
    # Tasks 8-13 review regression locks
    test_a_mixed_technique_request_is_refused_not_half_honoured()
    test_the_evasion_specs_cite_the_right_attck_techniques()
    test_the_stub_headers_match_what_the_stubs_actually_do()
    test_engagement_mode_with_no_target_is_permitted_by_design()
    test_a_failed_build_claims_no_artifact_path()
    test_the_image_smoke_tests_carry_a_status()
    test_the_image_layer_pins_every_build4_install()
    print("ALL evasion functional tests pass")
