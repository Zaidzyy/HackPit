"""Post-scripts — open·kritt's ``postScripts.js`` + ``postScriptLocks.js``, ported and GATED.

WHAT THIS IS
A **post-script** is an operator-authored step that runs AFTER a finding lands, to do one of:

  * **validate** — re-check the finding is real (composes with HackPit's existing validation
    gates; does not replace them). DATA — runs in-process, executes nothing.
  * **report**   — render a written writeup from the finding, to feed ``report-writer``. DATA.
  * **poc**      — build a proof-of-concept COMMAND. This is the one that could execute — so it
    NEVER does here. It returns the command as an **approve-each proposal**; the operator fires
    it through the existing gated executor + kali sandbox, exactly like a drafted web exploit.

THE INVARIANT (spec §0, do not weaken)
This module adds NO gate and executes NOTHING. A data post-script reshapes a dict. A command
post-script returns a *string* plus ``needs_approval: true`` — it is a proposal, never a run. The
coupling to the gated executor lives in the app layer (main.py), so this package imports no
cockpit / executor / state module. ``postScriptLocks`` prevent a concurrent double-run of the
same post-script on the same finding.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from .schema import normalize_severity

# post-script kinds and modes.
KINDS = ("validate", "report", "poc")
MODES = ("data", "command")


@dataclass
class PostScript:
    """One post-finding step. ``mode`` decides how a run resolves: 'data' in-process, 'command'
    an approve-each proposal. ``template`` is the command template for a 'command' post-script —
    ``{target}`` / ``{ref}`` / ``{loc}`` are filled from the finding; nothing else is."""

    id: str
    label: str
    kind: str
    mode: str
    description: str
    template: str = ""

    def meta(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "kind": self.kind, "mode": self.mode,
                "description": self.description,
                "needs_approval": self.mode == "command"}


# --------------------------------------------------------------------------- #
# built-in post-scripts
# --------------------------------------------------------------------------- #
BUILTIN_POSTSCRIPTS: dict[str, PostScript] = {
    "validate-concrete": PostScript(
        id="validate-concrete", label="Validate — concreteness check", kind="validate",
        mode="data",
        description="Re-check the finding is actionable: a severity, an attacker path, and at "
                    "least one concrete location. Composes with the validation gates; runs "
                    "in-process and executes nothing.",
    ),
    "render-report": PostScript(
        id="render-report", label="Report — draft writeup", kind="report", mode="data",
        description="Render a Markdown finding writeup (title, severity, attacker path, evidence, "
                    "references) to hand to report-writer. In-process; executes nothing.",
    ),
    "poc-curl": PostScript(
        id="poc-curl", label="PoC — curl the endpoint", kind="poc", mode="command",
        description="Build a curl command that exercises the finding's target for the operator to "
                    "run APPROVE-EACH through the executor. Returns a proposal, never runs it.",
        template="curl -sS -i '{target}'",
    ),
    "poc-nuclei-retest": PostScript(
        id="poc-nuclei-retest", label="PoC — nuclei re-test by template", kind="poc",
        mode="command",
        description="Build a nuclei re-test for the finding's template id/reference — an "
                    "approve-each executor run in the kali sandbox. Returns a proposal.",
        template="nuclei -u '{target}' -id '{ref}'",
    ),
}


def list_postscripts() -> list[dict[str, Any]]:
    return [ps.meta() for ps in BUILTIN_POSTSCRIPTS.values()]


def get_postscript(ps_id: str | None) -> PostScript | None:
    return BUILTIN_POSTSCRIPTS.get((ps_id or "").strip())


# --------------------------------------------------------------------------- #
# locks — postScriptLocks.js. A concurrent double-run of the same post-script on
# the same finding is refused. In-process (single FastAPI worker), thread-safe.
# --------------------------------------------------------------------------- #
class PostScriptLocked(RuntimeError):
    """Raised when a post-script is already running for a (session, finding, script) key."""


class PostScriptLocks:
    def __init__(self) -> None:
        self._held: set[tuple] = set()
        self._mutex = threading.Lock()

    def _key(self, session_id: str, fingerprint: str, ps_id: str) -> tuple:
        return (session_id, fingerprint, ps_id)

    def is_held(self, session_id: str, fingerprint: str, ps_id: str) -> bool:
        with self._mutex:
            return self._key(session_id, fingerprint, ps_id) in self._held

    @contextmanager
    def guard(self, session_id: str, fingerprint: str, ps_id: str) -> Iterator[None]:
        key = self._key(session_id, fingerprint, ps_id)
        with self._mutex:
            if key in self._held:
                raise PostScriptLocked(
                    f"post-script '{ps_id}' is already running for this finding")
            self._held.add(key)
        try:
            yield
        finally:
            with self._mutex:
                self._held.discard(key)


# a process-wide lock table for the app layer to share.
LOCKS = PostScriptLocks()


# --------------------------------------------------------------------------- #
# data post-scripts (in-process, execute nothing)
# --------------------------------------------------------------------------- #
def _primary_location(finding: dict[str, Any]) -> str:
    refs = finding.get("source_refs") or []
    if isinstance(refs, list) and refs:
        return str(refs[0])
    return str(finding.get("target") or "")


def validate_concrete(finding: dict[str, Any]) -> dict[str, Any]:
    """The 'validate' post-script: is this finding actionable? Pure checks over the fields.

    Mirrors the concreteness bar the AI code-audit gate uses — a claim with no attacker path or
    no location is not something to act on. Reports, never mutates.
    """
    problems: list[str] = []
    if not str(finding.get("title") or "").strip():
        problems.append("no title")
    if normalize_severity(finding.get("severity")) == "info" and not str(
            finding.get("attacker_path") or "").strip():
        problems.append("informational with no attacker path")
    if not str(finding.get("attacker_path") or "").strip():
        problems.append("no attacker path stated")
    if not _primary_location(finding).strip():
        problems.append("no concrete location (source ref or target)")
    ok = not problems
    return {"kind": "validate", "mode": "data", "ok": ok,
            "problems": problems,
            "summary": "actionable" if ok else "needs more evidence: " + "; ".join(problems)}


def render_report(finding: dict[str, Any]) -> dict[str, Any]:
    """The 'report' post-script: a Markdown writeup for report-writer. String assembly only."""
    title = str(finding.get("title") or "Untitled finding")
    sev = normalize_severity(finding.get("severity")).upper()
    refs = finding.get("source_refs") or []
    lines = [f"## {title}", "", f"**Severity:** {sev}"]
    if finding.get("vuln_class"):
        lines.append(f"**Class:** {finding['vuln_class']}")
    if finding.get("cvss"):
        lines.append(f"**CVSS:** {finding['cvss']}")
    if finding.get("target"):
        lines.append(f"**Target:** {finding['target']}")
    lines += ["", "### Attacker path", str(finding.get("attacker_path") or "_not stated_")]
    if finding.get("evidence"):
        lines += ["", "### Evidence", "```", str(finding["evidence"]), "```"]
    if refs:
        lines += ["", "### Source references"] + [f"- `{r}`" for r in refs]
    extra = finding.get("extra") or {}
    if isinstance(extra, dict) and extra:
        lines += ["", "### Additional fields"] + [
            f"- **{k}:** {v}" for k, v in extra.items() if k != "ranker_note"]
    md = "\n".join(lines).rstrip() + "\n"
    return {"kind": "report", "mode": "data", "markdown": md,
            "summary": "drafted a report section — hand it to report-writer"}


# --------------------------------------------------------------------------- #
# command post-scripts (approve-each PROPOSAL — never executed here)
# --------------------------------------------------------------------------- #
def build_command(script: PostScript, finding: dict[str, Any]) -> dict[str, Any]:
    """Fill a command post-script's template from the finding and return it as a PROPOSAL.

    This NEVER runs anything. The returned command carries ``needs_approval: true``; the app
    layer routes it to the gated executor where scope + approval + danger are checked and the
    operator fires it approve-each. Placeholders that cannot be filled are left visible so an
    under-specified finding produces an obviously-incomplete command, not a silently wrong one.
    """
    refs = finding.get("source_refs") or []
    loc = str(refs[0]) if isinstance(refs, list) and refs else ""
    command = (script.template or "").format_map(_SafeDict({
        "target": str(finding.get("target") or "").strip(),
        "ref": str(finding.get("reference") or "").strip(),
        "loc": loc,
    }))
    return {
        "kind": script.kind, "mode": "command", "command": command,
        "needs_approval": True, "executed": False,
        "summary": "proposed a PoC command — run it APPROVE-EACH through the executor; "
                   "nothing was executed here",
    }


class _SafeDict(dict):
    """str.format_map helper: a missing key stays as ``{key}`` rather than raising."""

    def __missing__(self, key: str) -> str:  # noqa: D401
        return "{" + key + "}"


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #
def run(script: PostScript, finding: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a post-script over a finding. DATA modes return their in-process result; the
    COMMAND mode returns an approve-each proposal. Executes nothing either way."""
    if script.mode == "command":
        return build_command(script, finding)
    if script.id == "validate-concrete" or script.kind == "validate":
        return validate_concrete(finding)
    if script.id == "render-report" or script.kind == "report":
        return render_report(finding)
    # an unknown data post-script degrades to the concreteness check rather than failing
    return validate_concrete(finding)
