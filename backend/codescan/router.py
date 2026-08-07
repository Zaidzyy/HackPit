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
from typing import Any, Callable

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field

from . import ai_audit
from . import findings as fmod
from . import kb_link
from . import report as report_mod
from . import runner

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
        description="The built-in audit playbook to run.",
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


@router.get("/ai-audit/sample")
def codescan_ai_audit_sample() -> dict[str, Any]:
    """A deterministic audit of the BUNDLED synthetic sample repo (never a real client's source).

    Runs the heuristic analyst so the /code-scan AI view renders the full enumerate -> flows ->
    ranked-findings surface with no LLM and no operator input — the offline demo the screenshot
    uses, and a live example of the pipeline's output shape."""
    from pathlib import Path

    sample = Path(__file__).parent / "sample_app"
    result = ai_audit.run_heuristic_audit(sample, kb_search=_KB["search"])
    result["is_sample"] = True
    return result
