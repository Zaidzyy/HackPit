"""Bespoke evasion engine (build #4, item C) — GENERATES ONLY, never runs or deploys.

CONTAINMENT (mirrors cockpit/repeater.py and cockpit/sliver.py):

* :func:`generate` runs the generators (donut / ScareCrow) as argv-only ``docker exec`` inside
  a container resolved from the execution MODE. The container is a code constant, never a
  request field, and no shell parses any request value.
* It GENERATES an artifact into the loot directory. It NEVER runs or deploys the artifact —
  the produced path is never argv[0] of anything, and there is no deploy function here.
* HUMAN-invoked through the main.py endpoint only. The orchestrator / agent / loop modules
  have ZERO code path here (AST-asserted by test_evasion_safety.py).
* GATED: every generate builds an ExecRequest and runs the SAME gates a one-shot command run
  does — ``executor.validate_request`` (approval + scope + red-confirm via ``dangerous_ack``).
* AUDITED: every generate is recorded through ``runstore.save_run``.

FORCED HONESTY (build #4, D-guard). This is the load-bearing part of the design, and the
reason the OPSEC channel's sensor-tamper ban was lifted in Task 1. Every result carries BOTH:

  1. the blue-view detection footprint for the artifact's technique, and
  2. an OPSEC note whose ``still_recorded`` names what catches it anyway.

A result missing either is a bug, not a degraded mode: :func:`generate` RAISES rather than
return a footprint-less artifact. The footprint is never suppressible — there is no flag to
turn it off, and the HTTP layer returns it in the same object as the artifact path. An
evasion tool that told you only how to be quieter, and never what still sees you, would be an
evasion how-to; this is the thing that keeps it a purple-team tool.
"""
from __future__ import annotations

import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from cockpit import config, executor, loot, runstore
from cockpit.models import ExecRequest, RunRecord
from detection import resolver as det

_TEMPLATES = Path(__file__).resolve().parent / "templates"

# Every technique this engine can emit, and the DETECTION SPEC that describes what a defender
# sees when the resulting artifact runs. These spec keys are curated in detection/catalog.py
# (build #4) precisely so this table resolves to a real footprint rather than a near-miss —
# `_honest_footprint` fails loudly if a key here stops resolving.
TECHNIQUES: dict[str, str] = {
    "donut-pack": "evasion_packed_loader",
    "scarecrow-loader": "evasion_packed_loader",
    "amsi-patch": "evasion_amsi_patch",
    "etw-blind": "evasion_etw_blind",
}

# Techniques that produce a text stub rather than a compiled artifact.
_STUB_TECHNIQUES = {"amsi-patch": "amsi_patch.ps1.tmpl", "etw-blind": "etw_blind.ps1.tmpl"}

_MAX_OUTPUT = 20_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class EvasionError(RuntimeError):
    """The engine could not honour its own contract. Never raised for a merely failed build."""


class EvasionRefused(RuntimeError):
    """A gate refused the generation. ``gate`` names which one, mirroring SliverRefused."""

    def __init__(self, reason: str, gate: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.gate = gate


class EvasionRequest(BaseModel):
    """One generate request. ``techniques`` drives both the argv and the honest footprint."""

    # There is deliberately no `target_os`. One was accepted and surfaced as a panel dropdown
    # but never read by any code here — donut emits Windows PE shellcode and `_scarecrow_argv`
    # hardcodes a Windows `-Loader binary`, so the field could only ever have misled. If a
    # cross-compile target is wanted later it has to actually reach the argv.
    payload_path: str = ""
    techniques: list[str] = Field(default_factory=list)
    target: str = ""
    engagement_id: str | None = None
    session_id: str | None = None
    step_id: str | None = None
    approved: bool = False
    dangerous_ack: bool = False

    @field_validator("techniques")
    @classmethod
    def _known_techniques(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("at least one technique is required")
        unknown = [t for t in v if t not in TECHNIQUES]
        if unknown:
            raise ValueError(f"unknown technique(s): {', '.join(unknown)}")
        # EXACTLY ONE — this is a forced-honesty rule, not a convenience.
        #
        # Every describing helper below reads techniques[0] and only techniques[0]
        # (`_honest_footprint`, `render_stub`, `_artifact_name`), while `_needs_generator`
        # reads the WHOLE list. A mixed request therefore used to BUILD one thing and
        # DESCRIBE another: ["amsi-patch", "scarecrow-loader"] ran ScareCrow and handed the
        # resulting loader back carrying the AMSI-patch footprint. Two stub techniques
        # silently dropped the second. Both are the contract in the module docstring failing
        # quietly, which is worse than refusing.
        #
        # A list stays the wire shape (the result echoes it, and one day a build may legitimately
        # compose techniques) — but until the honest half can describe a COMBINATION, more than
        # one entry is refused rather than half-honoured.
        if len(v) > 1:
            raise ValueError(
                "exactly one technique per build — a build carries the footprint of ONE "
                f"technique, so it may not name {len(v)}: {', '.join(v)}"
            )
        return v

    @field_validator("payload_path")
    @classmethod
    def _no_flag_lookalike(cls, v: str) -> str:
        # A value that leads with '-' would be read as an option by the generator.
        if v.startswith("-"):
            raise ValueError("payload_path must not start with '-'")
        return v


class EvasionResult(BaseModel):
    """An artifact plus, MANDATORILY, the defender's view of it.

    ``footprint`` and ``opsec_note`` are not optional and are not suppressible. See the module
    docstring: a result carrying an artifact but no honest footprint is a bug.
    """

    run_id: str
    artifact_path: str
    techniques: list[str]
    mode: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    footprint: dict[str, Any]
    opsec_note: dict[str, Any]
    stub: str = ""


# --------------------------------------------------------------------------- #
# PURE helpers — argv construction and template rendering. No execution, no I/O
# beyond reading the packaged templates. Safe for the UI/preview path.
# --------------------------------------------------------------------------- #
def _artifact_name(run_id: str, techniques: list[str]) -> str:
    return f"evasive-{run_id}.bin" if _needs_generator(techniques) else f"evasive-{run_id}.ps1"


def _needs_generator(techniques: list[str]) -> bool:
    """True when a technique needs donut/ScareCrow rather than a text stub."""
    return any(t not in _STUB_TECHNIQUES for t in techniques)


def _donut_argv(req: EvasionRequest, out_path: str) -> list[str]:
    return ["donut", "-i", req.payload_path, "-o", out_path]


def _scarecrow_argv(req: EvasionRequest, out_path: str) -> list[str]:
    return ["ScareCrow", "-I", req.payload_path, "-Loader", "binary", "-O", out_path]


def _generator_argv(req: EvasionRequest, out_path: str) -> list[str]:
    """PURE: the generator invocation. Never includes the produced artifact as argv[0]."""
    if "scarecrow-loader" in req.techniques:
        return _scarecrow_argv(req, out_path)
    return _donut_argv(req, out_path)


def render_stub(technique: str) -> str:
    """The text stub for a stub technique. PURE apart from reading the packaged template.

    Every template carries a header naming what still records the technique — the same
    honesty invariant the OPSEC channel enforces, applied to the artifact itself so it
    survives being copied out of HackPit.
    """
    name = _STUB_TECHNIQUES.get(technique)
    if name is None:
        raise EvasionError(f"{technique!r} does not produce a stub")
    return (_TEMPLATES / name).read_text(encoding="utf-8")


def _gate_request(req: EvasionRequest) -> ExecRequest:
    """The ExecRequest the real gates run against.

    Surface: the GENERATOR NAME (which drives the danger heuristic — both `donut` and
    `scarecrow` are in allowlist._FRAMEWORKS, so a build always demands the red-confirm) plus
    the DECLARED TARGET (which the scope gate checks).

    Local file paths are deliberately NOT in the gate surface. They are not scope objects,
    and feeding them in is actively harmful: the target extractor reads any dotted token as a
    hostname, so `-o evasive-<id>.bin` was refused as an out-of-scope "host". Nothing is
    weakened by leaving them out — the only network-facing value a generate can carry is
    ``target``, and it is gated.
    """
    target = req.target
    if not target and not req.engagement_id:
        # LAB. Building an artifact has no network target, but the lab's target-lock requires
        # the command to name the lab. Naming it explicitly is the honest way to satisfy that:
        # it does not widen anything, because the lab host is the ONLY value the lock accepts.
        #
        # ENGAGEMENT mode is deliberately NOT symmetrical here, and the earlier claim that an
        # empty target "falls through to the scope gate and is refused" was WRONG: outside lab
        # mode `executor.check_target_lock` permits a command that names no host at all (see its
        # docstring — `nmap -iL targets.txt` hides its hosts in a file, so refusing on absence
        # protected nothing). With no target the ExecRequest carries empty args and the scope
        # gate has nothing to check, so it passes. Nothing is weakened by that: a generate
        # reaches no host, `target` feeds only the audit record, and the one value that COULD
        # be network-facing is `req.target` — which, when present, is gated exactly as it
        # should be. Regression-locked in test_evasion.py.
        target = config.LAB_TARGET_HOST
    return ExecRequest(
        command=_generator_argv(req, "")[0],
        args=[target] if target else [],
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
        session_id=req.session_id,
        step_id=req.step_id,
    )


def validate_build(req: EvasionRequest):
    """The gate verdict for this request, without generating anything. PURE."""
    return executor.validate_request(_gate_request(req))


# --------------------------------------------------------------------------- #
# the forced-honesty half
# --------------------------------------------------------------------------- #
def _honest_footprint(techniques: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    """The blue footprint + OPSEC note for the artifact. Raises if either is unavailable.

    Deliberately built with ``allow_llm=False``: the honest half of this engine must come from
    the curated map, not from a model that might be unreachable or might hedge.
    """
    spec_key = TECHNIQUES[techniques[0]]
    from detection import catalog

    spec = catalog.SPECS.get(spec_key)
    if spec is None:  # a TECHNIQUES entry that no longer resolves is a wiring bug
        raise EvasionError(f"no detection spec for {spec_key!r}; refusing to emit an artifact")

    match = catalog.Match(spec=spec, signals=(), matched_on="evasion-technique")
    fp = det._grounded(techniques[0], [], match)
    opsec = det._opsec_grounded(spec_key)

    if not (fp and fp.get("activity")):
        raise EvasionError("refusing to emit an artifact without a blue-view footprint")
    if not (opsec and str(opsec.get("still_recorded") or "").strip()):
        raise EvasionError(
            "refusing to emit an artifact without an OPSEC note naming what still records it"
        )
    # The channel's own guard, applied to our own data. A curated note that lost its honesty
    # marker is a data bug and must fail the build, not ship.
    det.assert_opsec_is_separate(opsec, f"evasion generate ({spec_key})")
    return fp, opsec


# --------------------------------------------------------------------------- #
# the entry point
# --------------------------------------------------------------------------- #
def generate(req: EvasionRequest) -> EvasionResult:
    """Produce ONE evasion artifact. Gated, scope-checked, audited, and honest.

    Never runs or deploys what it builds. Raises :class:`EvasionRefused` when a gate refuses,
    and :class:`EvasionError` when the engine cannot honour its forced-honesty contract. A
    generator that merely EXITS NON-ZERO is a failed build, not a refusal: it is recorded and
    returned with its exit code, the same way cockpit/sliver.py treats a failed implant build.
    """
    # The honest half is computed FIRST. If the engine cannot describe what a defender would
    # see, it does not get to build the artifact at all.
    footprint, opsec = _honest_footprint(req.techniques)

    rejected = validate_build(req)
    if rejected is not None:
        raise EvasionRefused(rejected.reason, gate=getattr(rejected, "gate", ""))

    # The engagement can exit between the gate and the resolve. `resolve_mode` refuses rather
    # than silently falling back to LAB (that is the point of EngagementInactive), but it
    # signals that by raising — so catch it and refuse the same way every other gate does,
    # instead of letting it surface as a 500. Mirrors executor.iter_run's handling.
    try:
        resolved = executor.resolve_mode(_gate_request(req))
    except executor.EngagementInactive as exc:
        raise EvasionRefused(str(exc), gate="engagement") from exc
    run_id = uuid.uuid4().hex[:12]
    out_name = _artifact_name(run_id, req.techniques)

    # Placement is delegated to the SAME helper executor.iter_run uses, so this engine can
    # never disagree with the cockpit about where loot goes (and lab, which has no /loot
    # mount, correctly gets a bare filename).
    workdir = loot.workdir_for(resolved.mode, req.engagement_id)
    out_path = f"{workdir}/{out_name}" if workdir else out_name

    started = _now()
    stub = ""
    exit_code: int | None = None
    stdout = stderr = ""

    if _needs_generator(req.techniques):
        argv = ["docker", "exec", resolved.container, *_generator_argv(req, out_path)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=300)
            exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            exit_code, stderr = None, "the generator timed out"
        except OSError as exc:
            exit_code, stderr = None, f"could not start the generator: {exc}"
    else:
        # A stub technique produces text, not a compiled artifact. It is WRITTEN, never run.
        stub = render_stub(req.techniques[0])
        exit_code = 0

    runstore.save_run(
        RunRecord(
            run_id=run_id,
            command="evasion-generate",
            args=list(req.techniques),
            target=req.target or resolved.target,
            approved=True,
            mode=resolved.mode,
            exit_code=exit_code,
            stdout=stdout[:_MAX_OUTPUT],
            stderr=stderr[:_MAX_OUTPUT],
            started_at=started,
            finished_at=_now(),
            session_id=req.session_id,
            step_id=req.step_id,
        )
    )

    return EvasionResult(
        run_id=run_id,
        # Only claim a path when something was actually written. A non-zero exit or a timeout
        # means the generator produced nothing, and handing back a path to a file that does not
        # exist reads as a successful build in the panel (it even offered a copy button for it).
        artifact_path=out_path if exit_code == 0 else "",
        techniques=list(req.techniques),
        mode=resolved.mode,
        exit_code=exit_code,
        stdout=stdout[:_MAX_OUTPUT],
        stderr=stderr[:_MAX_OUTPUT],
        footprint=footprint,
        opsec_note=opsec,
        stub=stub,
    )
