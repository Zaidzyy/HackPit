"""FastAPI routes for the :code scan (static AppSec) panel.

Read-only analysis. These routes launch a SCANNER over a path the operator names and return
what it found. They execute none of the scanned code, take no target, open no socket on the
codebase's behalf, and touch nothing in the engagement / executor / target-lock / scope /
isolation model — this router imports none of it.

The KB tie-in is injected by main.py (:func:`set_kb`), the same pattern
``adgraph.router.set_grounder`` and ``detection.router.set_run_lookup`` use, so the package
keeps no import cycle with the app layer and works with no KB at all.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field

from . import ai_audit
from . import findings as fmod
from . import kb_link
from . import report as report_mod
from . import runner
from . import web3_tools
from . import workflows as wfmod

router = APIRouter(prefix="/codescan", tags=["codescan"])

# Injected by main.py: (by_id, search_fn, is_eligible, is_focused). All optional — with no KB
# the scan runs identically, just without technique links.
_KB: dict[str, Any] = {"by_id": {}, "search": None, "eligible": None, "focused": None}

# Cross-cutting seams for the AI audit, injected by main.py so codescan stays orthogonal (it
# imports no state / executor / git of its own — the callbacks carry the capability in as DATA):
#   _FINDINGS_SINK(session_id, [finding-dict, ...]) -> int   persists audit findings to state
#   _DIFF_PROVIDER(root: Path, ref: str) -> set[str] | None  repo-relative paths changed since ref
_FINDINGS_SINK: Callable[[str, list[dict]], int] | None = None
_DIFF_PROVIDER: Callable[[Any, str], set | None] | None = None


def set_kb(
    by_id: dict[str, dict] | None = None,
    search_fn: Callable[[str, int, str], list[dict]] | None = None,
    eligible: Callable[[dict], bool] | None = None,
    focused: Callable[[dict], bool] | None = None,
) -> None:
    _KB.update(
        by_id=by_id or {}, search=search_fn, eligible=eligible, focused=focused
    )


def set_findings_sink(fn: Callable[[str, list[dict]], int] | None) -> None:
    """Wire (or clear) the engagement-state sink the AI audit persists findings through.

    Mirrors ``set_kb``: codescan never imports ``state`` — main.py hands in a callback that
    builds the ``Finding`` records and upserts them, so the audit can land in engagement state
    without codescan gaining any coupling to it."""
    global _FINDINGS_SINK
    _FINDINGS_SINK = fn


def set_diff_provider(fn: Callable[[Any, str], set | None] | None) -> None:
    """Wire the ``patched-since`` diff provider (a git-backed helper in main.py). None disables
    patched-since here — codescan runs no subprocess of its own (static-only invariant)."""
    global _DIFF_PROVIDER
    _DIFF_PROVIDER = fn


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class ToolStatus(BaseModel):
    name: str
    installed: bool
    path: str | None = Field(default=None, description="Resolved executable path.")
    install_hint: str = Field(description="Exact command to install it.")


class RulesetOption(BaseModel):
    key: str
    label: str


class ToolsOut(BaseModel):
    tools: list[ToolStatus]
    ready: bool = Field(description="True when at least Semgrep is available.")
    ruleset: str = Field(description="The default (resolved) Semgrep ruleset path.")
    rulesets: list[RulesetOption] = Field(
        default_factory=list, description="Offline rulesets the scan picker offers."
    )


class ScanIn(BaseModel):
    path: str = Field(min_length=1, description="Codebase FOLDER to analyse (read-only).")
    timeout_s: int = Field(
        default=runner.DEFAULT_TIMEOUT_S, ge=5, le=runner.MAX_TIMEOUT_S,
        description="Per-scanner wall-clock bound; the scanner is killed at this point.",
    )
    semgrep_config: str | None = Field(
        default=None,
        description="Ruleset to run. A picker key ('bundled' = all offline languages [default], "
        "'python-js-ts', 'languages' = Java/Go/PHP/Ruby/C#) or a registry ruleset "
        "(e.g. 'p/security-audit'). Registry rulesets REQUIRE network; the bundled ones do not.",
    )
    use_bandit: bool = Field(
        default=True, description="Also run Bandit when the tree contains Python."
    )


class FindingOut(BaseModel):
    rule_id: str
    tool: str = Field(description="'semgrep' | 'bandit' | 'bandit+semgrep' (corroborated).")
    severity: str = Field(description="critical | high | medium | low | info.")
    file: str
    line: int
    message: str
    category: str
    cwe: str | None = None
    owasp: str | None = None
    confidence: str | None = None
    tool_severity: str | None = Field(
        default=None, description="The scanner's own severity word, before mapping."
    )
    tools: list[str] = Field(default_factory=list)
    kb_entry_id: str | None = Field(
        default=None, description="KB technique behind this defect; null when none matched."
    )
    kb_title: str | None = None


class ScanOut(BaseModel):
    path: str
    files_scanned: int
    duration_s: float
    tools_run: list[str]
    ruleset: str
    summary: dict[str, Any]
    findings: list[FindingOut]
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal notes: a scanner skipped, rule errors, partial results.",
    )
    static_only: bool = Field(
        default=True,
        description="Always true — the scanned code is parsed, never executed.",
    )


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #
@router.get("/tools", response_model=ToolsOut)
def codescan_tools() -> dict[str, Any]:
    """Which scanners are installed. The UI uses this to show an install hint instead of
    failing a scan that was never going to work."""
    found = runner.available()
    tools = [
        ToolStatus(
            name=name,
            installed=bool(path),
            path=path,
            install_hint=f"cd backend && uv pip install {name}",
        )
        for name, path in found.items()
    ]
    return {
        "tools": tools,
        "ready": bool(found.get("semgrep")),
        "ruleset": runner.resolve_ruleset(None),
        "rulesets": runner.list_rulesets(),
    }


@router.post("/scan", response_model=ScanOut)
def codescan_scan(req: ScanIn = Body(...)) -> dict[str, Any]:
    """Run the scanners over a codebase path and return normalized findings.

    STATIC ONLY: the scanners parse the files. Nothing here executes, imports or evaluates
    the code under review (``runner._spawn`` asserts that only a scanner is ever launched).
    """
    started = time.monotonic()
    try:
        target = runner.resolve_target(req.path)
    except runner.ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    file_count, too_big = runner.count_files(target)
    if too_big:
        raise HTTPException(
            status_code=400,
            detail=f"that tree has more than {runner.MAX_FILES:,} files — point the scan at a "
            "subdirectory (a whole drive is not a codebase)",
        )

    warnings: list[str] = []
    tools_run: list[str] = []
    all_findings: list[fmod.Finding] = []
    ruleset = runner.resolve_ruleset(req.semgrep_config)

    # --- Semgrep (the multi-language half) ------------------------------------
    # A crash on ONE unscannable file must NOT sink the whole scan. Semgrep is all-or-nothing
    # on `--json` (a fatal parse/IO error yields empty stdout → ScanError), and some
    # environments crash on a specific language (e.g. semgrep hitting an OSError on a .php file
    # on Windows). So a ScanError degrades to a WARNING and the scan continues with whatever
    # else ran — exactly like bandit. Only a truly ABSENT scanner (setup error) or a TIMEOUT
    # (actionable: scan smaller) stays hard, because those are operational states, not a crash.
    try:
        raw = runner.run_semgrep(target, req.timeout_s, req.semgrep_config)
        all_findings.extend(fmod.from_semgrep(raw, target))
        tools_run.append("semgrep")
        errors = raw.get("errors") or []
        if errors:
            warnings.append(
                f"semgrep reported {len(errors)} rule/parse error(s) — results may be partial"
            )
    except runner.ScannerMissing as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except runner.ScanTimeout as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except runner.ScanError as exc:
        warnings.append(
            f"semgrep did not complete: {exc} — findings may be missing (e.g. semgrep can "
            "crash on a specific file/language on some platforms). Other scanners still ran."
        )

    # --- Bandit (Python only, and never fatal) --------------------------------
    if req.use_bandit and runner.has_python(target):
        try:
            raw_b = runner.run_bandit(target, req.timeout_s)
            all_findings.extend(fmod.from_bandit(raw_b, target))
            tools_run.append("bandit")
        except runner.ScannerMissing:
            warnings.append("bandit is not installed — Python-specific checks were skipped")
        except runner.ScanTimeout:
            warnings.append(f"bandit exceeded {req.timeout_s}s and was stopped — results are "
                            "semgrep-only")
        except runner.ScanError as exc:
            warnings.append(f"bandit did not complete: {exc}")

    merged = fmod.merge(all_findings)
    kb_link.link(merged, _KB["by_id"], _KB["search"], _KB["eligible"], _KB["focused"])

    return {
        "path": str(target),
        "files_scanned": file_count,
        "duration_s": round(time.monotonic() - started, 2),
        "tools_run": tools_run,
        "ruleset": ruleset,
        "summary": fmod.summarize(merged),
        "findings": [f.to_dict() for f in merged],
        "warnings": warnings,
        "static_only": True,
    }


class ReportOut(BaseModel):
    markdown: str
    filename: str = Field(description="Suggested download name.")


@router.post("/report", response_model=ReportOut)
def codescan_report(result: ScanOut = Body(...)) -> dict[str, Any]:
    """Render a scan result as a Markdown report.

    Takes the scan payload back rather than re-scanning, so the report is exactly the run
    the operator is looking at — same findings, same counts, no drift between the screen and
    the document, and no second pass over the tree.
    """
    payload = result.model_dump()
    stem = (payload.get("path") or "codebase").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    safe = "".join(ch if (ch.isalnum() or ch in "-_.") else "-" for ch in stem) or "codebase"
    return {
        "markdown": report_mod.render_markdown(payload),
        "filename": f"code-scan-{safe}.md",
    }


# --------------------------------------------------------------------------- #
# AI-agent code audit (see ai_audit.py) — the context-saving fan-out
# --------------------------------------------------------------------------- #
class AiAuditIn(BaseModel):
    path: str = Field(min_length=1, description="Codebase FOLDER to audit (read-only).")
    patched_since: str | None = Field(
        default=None,
        description="Git ref (branch/tag/SHA). When set and a diff provider is wired, the audit "
        "is restricted to the files changed since this ref — the 'patched-since' mode.",
    )
    playbook: str = Field(
        default="external-flow-analysis",
        description="The built-in audit playbook: 'external-flow-analysis' (web app) or a web3 "
        "playbook — 'evm-external-flow' (Solidity), 'cosmos-abci-halt' (Go), 'anchor-solana' "
        "(Rust). A web3 playbook maps only its language's files and hunts its chain's bug classes.",
    )
    session_id: str | None = Field(
        default=None,
        description="Engagement session to persist the ranked findings into. Optional — with "
        "none, the audit runs and returns results but writes nothing to engagement state.",
    )
    mode: str = Field(
        default="auto",
        description="'auto' (LLM agents, falling back to the heuristic analyst if the LLM layer "
        "is unavailable) | 'ai' (same) | 'heuristic' (deterministic, no LLM).",
    )


def _run_ai_audit(req: AiAuditIn) -> dict[str, Any]:
    """Shared by the POST route: resolve diff scope, pick the engine, persist, return the result.

    ONE approved job (the ZAP/nuclei justification): the operator's single action fans out into
    many analysis tasks. It executes nothing against a target — it reads source and calls the LLM
    layer — so it adds NO new gate, exactly like the rule-mode scan next to it.
    """
    try:
        root = runner.resolve_target(req.path)
    except runner.ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    extra_warnings: list[str] = []
    changed: set | None = None
    if req.patched_since:
        if _DIFF_PROVIDER is None:
            extra_warnings.append(
                "patched-since was requested but no diff provider is wired — audited the whole "
                "tree instead"
            )
        else:
            try:
                changed = _DIFF_PROVIDER(root, req.patched_since)
            except Exception as exc:  # noqa: BLE001 — a git miss degrades to a full audit
                extra_warnings.append(f"could not diff against {req.patched_since} ({exc}) — "
                                      "audited the whole tree")
            if changed is not None and not changed:
                extra_warnings.append(f"nothing changed since {req.patched_since}")

    mode = (req.mode or "auto").lower()
    try:
        if mode == "heuristic":
            result = ai_audit.run_heuristic_audit(
                root, kb_search=_KB["search"], changed_paths=changed,
                patched_since=req.patched_since, playbook=req.playbook)
        else:
            try:
                routine, hard = ai_audit.default_agents()
                result = ai_audit.run_audit(
                    root, routine, verify_agent=hard, kb_search=_KB["search"],
                    changed_paths=changed, patched_since=req.patched_since, playbook=req.playbook)
            except ai_audit.AuditError as exc:
                # graceful degradation: no LLM reachable -> the deterministic analyst still runs
                result = ai_audit.run_heuristic_audit(
                    root, kb_search=_KB["search"], changed_paths=changed,
                    patched_since=req.patched_since, playbook=req.playbook)
                result.setdefault("warnings", []).insert(
                    0, f"LLM agents unavailable ({exc}) — ran the deterministic heuristic analyst")
    except ai_audit.AuditError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result.setdefault("warnings", [])[:0] = extra_warnings

    # persist ranked findings to engagement state, if a session + sink are in play
    persisted = 0
    if req.session_id and _FINDINGS_SINK is not None and result.get("findings"):
        # rebuild the state payload from the ranked verdicts (concrete findings only)
        from .ai_audit import Verdict

        verdicts = [
            Verdict(flow_id="", finding=True, title=f["title"], vuln_class=f.get("vuln_class", ""),
                    severity=f.get("severity", "medium"), attacker_path=f.get("attacker_path", ""),
                    source_refs=f.get("source_refs", []), impact=f.get("impact", ""),
                    cwe=f.get("cwe"))
            for f in result["findings"]
        ]
        payload = ai_audit.to_state_findings(req.session_id, verdicts, result["repo"])
        try:
            persisted = int(_FINDINGS_SINK(req.session_id, payload) or 0)
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            result["warnings"].append(f"could not persist findings to engagement state ({exc})")
    result["persisted"] = persisted
    return result


@router.post("/ai-audit")
def codescan_ai_audit(req: AiAuditIn = Body(...)) -> dict[str, Any]:
    """Run the AI-agent code audit over a repo (see ai_audit.py). Returns the entrypoint map,
    the flow frontier, the per-flow verdicts, and the deduped + severity-ranked findings.

    No response_model on purpose: the audit shape is nested and still settling, and a
    response_model would silently strip any field the frontend later reads."""
    return _run_ai_audit(req)


# the bundled synthetic sample repo for each playbook (never a real client's source). The web3
# playbooks point at the deliberately-vulnerable fixture set under sample_web3/.
_SAMPLE_DIRS: dict[str, str] = {
    "external-flow-analysis": "sample_app",
    "evm-external-flow": "sample_web3/evm",
    "cosmos-abci-halt": "sample_web3/cosmos",
    "anchor-solana": "sample_web3/anchor",
}


@router.get("/ai-audit/sample")
def codescan_ai_audit_sample(playbook: str = "external-flow-analysis") -> dict[str, Any]:
    """A deterministic audit of the BUNDLED synthetic sample repo (never a real client's source).

    Runs the heuristic analyst so the /code-scan AI view renders the full enumerate -> flows ->
    ranked-findings surface with no LLM and no operator input — the offline demo the screenshot
    uses, and a live example of the pipeline's output shape. ``playbook`` selects which bundled
    fixture is mapped: the web app, or one of the web3 fixtures (Solidity / Cosmos-Go / Anchor)."""
    from pathlib import Path

    pb = ai_audit.resolve_playbook(playbook)
    sub = _SAMPLE_DIRS.get(pb.key, "sample_app")
    sample = Path(__file__).parent / sub
    result = ai_audit.run_heuristic_audit(sample, kb_search=_KB["search"], playbook=pb.key)
    result["is_sample"] = True
    return result


@router.get("/playbooks")
def codescan_playbooks() -> dict[str, Any]:
    """The built-in audit playbooks the /code-scan AI view offers (web app + the three web3 ones)."""
    return {"playbooks": ai_audit.list_playbooks()}


# --------------------------------------------------------------------------- #
# web3 tool pass (see web3_tools.py) — PROPOSE-ONLY. Nothing here executes a scanner: the audit
# stays static-only, and a tool pass is a command STRING the operator runs approve-each through
# the existing gated executor, exactly like a finding's PoC. Parsing pasted output normalizes it.
# --------------------------------------------------------------------------- #
class ToolPassIn(BaseModel):
    path: str = Field(min_length=1, description="Contract file or project dir the tool pass targets.")
    chain: str | None = Field(
        default=None, description="evm | cosmos | solana. If omitted, derived from `playbook`."
    )
    playbook: str | None = Field(
        default=None, description="A web3 playbook key; its chain selects the tool set."
    )
    tool: str | None = Field(
        default=None, description="A single tool to propose (slither/mythril/echidna/forge/...). "
        "Omit to propose the whole tool pass for the chain."
    )
    contract: str | None = Field(
        default=None, description="Contract name (echidna needs it to pick the fuzz target)."
    )


@router.post("/tool-pass")
def codescan_tool_pass(req: ToolPassIn = Body(...)) -> dict[str, Any]:
    """PROPOSE (never run) a slither/mythril/echidna/forge tool pass over a contract path.

    Returns command STRINGS the operator confirms approve-each in the :kali sandbox. This route
    launches nothing — it only builds the proposal, the tool-pass analogue of a finding's PoC."""
    chain = (req.chain or "").strip()
    if not chain and req.playbook:
        chain = ai_audit.resolve_playbook(req.playbook).chain
    if req.tool:
        proposals = [web3_tools.propose(req.tool, req.path, req.contract)]
    else:
        proposals = web3_tools.propose_pass(chain, req.path, req.contract)
    return {"path": req.path, "chain": chain, "proposals": proposals,
            "approve_each": True, "static_only": True}


class ToolParseIn(BaseModel):
    tool: str = Field(min_length=1, description="Which tool produced the output (slither/mythril/echidna).")
    output: str = Field(description="The tool's raw JSON/text output, pasted back after the run.")


@router.post("/tool-pass/parse")
def codescan_tool_pass_parse(req: ToolParseIn = Body(...)) -> dict[str, Any]:
    """Parse a tool's pasted output into normalized findings — closes the approve-each loop.

    The operator runs a proposed command in the sandbox, pastes the output here, and it is turned
    into the same finding shape the audit uses. Pure parsing — no execution."""
    findings = web3_tools.parse_output(req.tool, req.output)
    return {"tool": req.tool.strip().lower(), "count": len(findings), "findings": findings}


# --------------------------------------------------------------------------- #
# reusable prompt-workflow builder (see workflows.py) — AUTHORING EXECUTES NOTHING.
#
# CRUD/import/export only read and write a JSON store; they launch no agent and touch no target.
# RUNNING a workflow is the SAME "one approved job" the AI audit is — the fan-out justification —
# and it adds NO new gate: it renders each step's prompt, calls the injected LLM agent (the audit's
# ``default_agents``), threads outputs downstream, and persists ranked findings through the same
# injected sink. A ``command`` step is a proposal (approve-each), never run. An IMPORTED workflow
# is stored + surfaced for inspection and is never auto-run.
# --------------------------------------------------------------------------- #
# The operator's authored/imported workflows persist here (gitignored runtime data); the built-ins
# are always seeded from code. One store per process is enough — authoring is low-volume.
_WF_STORE = wfmod.WorkflowStore(Path(__file__).parent.parent / "data" / "workflows.json")


def _wf_bounds() -> dict[str, int]:
    return {
        "max_steps": wfmod.MAX_STEPS, "max_siblings": wfmod.MAX_SIBLINGS,
        "max_depth": wfmod.MAX_DEPTH, "max_batch_items": wfmod.MAX_BATCH_ITEMS,
        "max_tasks": wfmod.MAX_TASKS,
    }


@router.get("/workflows")
def codescan_workflows_list() -> dict[str, Any]:
    """Every workflow the operator can compose from: the seeded built-ins first, then their own
    authored/imported ones. Also returns the built-in variable catalog (for the editor's
    autocomplete) and the fan-out bounds. Reads the store — executes nothing."""
    return {
        "workflows": [w.to_dict() for w in _WF_STORE.list()],
        "builtin_variables": wfmod.BUILTIN_VARIABLES,
        "field_types": list(wfmod.FIELD_TYPES),
        "step_kinds": list(wfmod.STEP_KINDS),
        "bounds": _wf_bounds(),
    }


@router.post("/workflows")
def codescan_workflows_create(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Create a workflow from an authored definition. Persists it and returns it — it runs
    nothing. Authoring is orthogonal to any target or gate."""
    try:
        wf = _WF_STORE.create(body)
    except wfmod.WorkflowError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return wf.to_dict()


@router.get("/workflows/{wid}")
def codescan_workflows_get(wid: str) -> dict[str, Any]:
    try:
        return _WF_STORE.get(wid).to_dict()
    except wfmod.WorkflowError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/workflows/{wid}")
def codescan_workflows_update(wid: str, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Edit a workflow (PATCH, not PUT — the governance panel hit a CORS wall on PUT). Carries an
    optional ``expected_version`` optimistic lock so two editors cannot silently clobber each
    other. Built-ins are read-only. Executes nothing."""
    expected = body.pop("expected_version", None)
    try:
        wf = _WF_STORE.update(wid, body, expected_version=expected)
    except wfmod.WorkflowError as exc:
        code = 404 if "no workflow" in str(exc) else 409 if "stale" in str(exc) else 400
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    return wf.to_dict()


@router.delete("/workflows/{wid}")
def codescan_workflows_delete(wid: str) -> dict[str, Any]:
    try:
        _WF_STORE.delete(wid)
    except wfmod.WorkflowError as exc:
        code = 404 if "no workflow" in str(exc) else 400
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    return {"deleted": wid}


@router.get("/workflows/{wid}/export")
def codescan_workflows_export(wid: str) -> dict[str, Any]:
    """Serialize a workflow to the portable JSON an operator shares. Pure serialization."""
    try:
        return wfmod.to_portable(_WF_STORE.get(wid))
    except wfmod.WorkflowError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/workflows/import")
def codescan_workflows_import(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Import a portable workflow JSON. It is PARSED and STORED, flagged inspect-before-run — it is
    NEVER auto-run. The response carries the parsed steps so the operator reviews the prompt text
    before choosing to run it."""
    try:
        wf = _WF_STORE.import_workflow(body)
    except wfmod.WorkflowError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"workflow": wf.to_dict(), "imported": True, "inspect_before_run": True,
            "note": "Imported workflow stored, not run. Review the step prompts, then run it."}


@router.post("/workflows/{wid}/plan")
def codescan_workflows_plan(wid: str, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """The STATIC fan-out shape of a workflow (steps × items × siblings × depth), computed without
    running anything — the builder's preview."""
    try:
        wf = _WF_STORE.get(wid)
    except wfmod.WorkflowError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return wfmod.plan(wf, (body or {}).get("extra_vars"))


class WorkflowRunIn(BaseModel):
    path: str = Field(min_length=1, description="Codebase FOLDER the workflow runs over (read-only).")
    session_id: str | None = Field(
        default=None, description="Engagement session to persist ranked findings into (optional).")
    ref: str | None = Field(
        default=None, description="Git ref for the {{ref}} variable / patched-since on a "
        "playbook-backed heuristic run.")
    mode: str = Field(
        default="auto", description="'auto' (LLM agents, degrading to a playbook heuristic if the "
        "LLM layer is down and the workflow declares one) | 'heuristic' (no LLM; requires a "
        "playbook-backed workflow).")
    extra_vars: dict[str, Any] = Field(
        default_factory=dict, description="Per-run 'extra' variables the prompts can reference.")


def _heuristic_wf_result(wf: "wfmod.Workflow", root: Any, req: WorkflowRunIn,
                         changed: set | None) -> dict[str, Any]:
    """Run a playbook-backed workflow with NO LLM by delegating to the audit's deterministic
    analyst for its playbook — the offline demo path and the graceful-degradation path. A workflow
    with no playbook has no offline decomposition, so this refuses rather than faking one."""
    if not wf.playbook:
        raise HTTPException(
            status_code=400,
            detail="this workflow declares no playbook, so it has no offline (no-LLM) run — "
                   "wire an LLM and run it in 'auto' mode")
    audit = ai_audit.run_heuristic_audit(
        root, kb_search=_KB["search"], changed_paths=changed,
        patched_since=req.ref, playbook=wf.playbook)
    steps = [{"step_id": s.id, "title": s.title, "kind": s.kind, "tasks": 0, "outputs": [],
              "proposals": [], "warnings": []} for s in wf.steps]
    return {
        "workflow": wf.id, "name": wf.name, "repo": audit.get("repo"), "ref": req.ref,
        "mode": "heuristic", "imported": wf.imported, "via_playbook": wf.playbook,
        "steps": steps, "proposals": [], "findings": audit.get("findings", []),
        "tasks_run": 0, "duration_s": audit.get("duration_s", 0.0),
        "summary": audit.get("summary", {}),
        "warnings": (audit.get("warnings", []) or []) + [
            "ran the deterministic analyst for this workflow's playbook (no LLM) — the per-step "
            "prompts are not exercised in heuristic mode"],
    }


def _persist_wf_findings(session_id: str, result: dict[str, Any]) -> int:
    """Upsert a run's ranked findings through the injected sink (best-effort), exactly as the AI
    audit does — codescan never imports state; the sink builds the records."""
    if not (session_id and _FINDINGS_SINK is not None and result.get("findings")):
        return 0
    verdicts = [
        ai_audit.Verdict(
            flow_id="", finding=True, title=f["title"], vuln_class=f.get("vuln_class", ""),
            severity=f.get("severity", "medium"), attacker_path=f.get("attacker_path", ""),
            source_refs=f.get("source_refs", []), impact=f.get("impact", ""), cwe=f.get("cwe"))
        for f in result["findings"]
    ]
    payload = ai_audit.to_state_findings(session_id, verdicts, str(result.get("repo") or ""))
    try:
        return int(_FINDINGS_SINK(session_id, payload) or 0)
    except Exception as exc:  # noqa: BLE001 — persistence is best-effort
        result.setdefault("warnings", []).append(
            f"could not persist findings to engagement state ({exc})")
        return 0


@router.post("/workflows/{wid}/run")
def codescan_workflows_run(wid: str, req: WorkflowRunIn = Body(...)) -> dict[str, Any]:
    """Run a workflow over a source tree — the "one approved job" (the AI-audit justification, NO
    new gate). Renders each step, calls the injected LLM agent, threads outputs downstream, and
    de-dups + severity-ranks the findings. Command steps come back as approve-each proposals; they
    are never executed here. Persists ranked findings if a session is named."""
    try:
        wf = _WF_STORE.get(wid)
    except wfmod.WorkflowError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    try:
        root = runner.resolve_target(req.path)
    except runner.ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # patched-since scope (only meaningful on the playbook-backed heuristic delegation)
    changed: set | None = None
    if req.ref and _DIFF_PROVIDER is not None:
        try:
            changed = _DIFF_PROVIDER(root, req.ref)
        except Exception:  # noqa: BLE001 — a git miss degrades to a full run
            changed = None

    mode = (req.mode or "auto").lower()
    if mode == "heuristic":
        result = _heuristic_wf_result(wf, root, req, changed)
    else:
        try:
            _routine, hard = ai_audit.default_agents()
            result = wfmod.run_workflow(
                wf, repo=str(root), agent=hard, kb_search=_KB["search"],
                ref=req.ref or "", extra_vars=req.extra_vars)
        except ai_audit.AuditError as exc:
            # no LLM reachable -> a playbook-backed workflow still demos deterministically
            result = _heuristic_wf_result(wf, root, req, changed)
            result.setdefault("warnings", []).insert(
                0, f"LLM agents unavailable ({exc}) — ran the playbook heuristic instead")

    result["persisted"] = _persist_wf_findings(req.session_id or "", result)
    return result


@router.get("/workflows/{wid}/sample")
def codescan_workflows_sample(wid: str) -> dict[str, Any]:
    """A deterministic, no-LLM run of a BUILT-IN workflow over its bundled synthetic fixture — the
    offline example the builder shows and the screenshot uses. Uses the playbook heuristic, so a
    non-playbook workflow returns an empty example."""
    try:
        wf = _WF_STORE.get(wid)
    except wfmod.WorkflowError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not wf.playbook:
        return {"workflow": wf.id, "name": wf.name, "mode": "heuristic", "findings": [],
                "steps": [{"step_id": s.id, "title": s.title, "kind": s.kind} for s in wf.steps],
                "note": "no offline sample — this workflow declares no playbook"}
    pb = ai_audit.resolve_playbook(wf.playbook)
    sub = _SAMPLE_DIRS.get(pb.key, "sample_app")
    sample = Path(__file__).parent / sub
    audit = ai_audit.run_heuristic_audit(sample, kb_search=_KB["search"], playbook=pb.key)
    return {
        "workflow": wf.id, "name": wf.name, "mode": "heuristic", "via_playbook": pb.key,
        "is_sample": True, "repo": audit.get("repo"),
        "steps": [{"step_id": s.id, "title": s.title, "kind": s.kind,
                   "batch_over": s.batch_over, "siblings": s.siblings, "depth": s.depth}
                  for s in wf.steps],
        "findings": audit.get("findings", []), "summary": audit.get("summary", {}),
        "proposals": [],
    }
