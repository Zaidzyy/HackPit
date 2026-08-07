"""Reusable prompt-workflow builder — author playbooks over the AI code-audit fan-out.

WHAT THIS IS
`ai_audit.py` ships two proven decompositions (the web-app and the three web3 playbooks) as
hard-coded stage prompts. This is the authoring layer on top of that engine: an operator composes
their OWN ordered set of prompt **steps** — each with variables, a batch/depth/siblings fan-out
shape and an output schema — saves it, exports/imports it as a portable JSON, and RUNS it. Ported
from open·kritt's workflow builder (`workflows.js` / `steps.js` / `defaultWorkflows.js` and the
`{{var}}` / `resolve_ref` / `render_prompt` model in `prompting.py`), adapted to HackPit's stack.

THE ONE INVARIANT (do not weaken — §0 of the spec)
This module **executes nothing.** Authoring (create/edit/import/export) touches no agent and no
target — it only reads and writes a JSON store. RUNNING a workflow is the SAME "one approved job"
the AI audit already is (the fan-out justification), and it adds **no new gate**: it renders each
step's prompt, calls the INJECTED agent runner (reading source, never launching a scanner), and
threads outputs downstream. A ``command`` step is a *proposal* — a command STRING the operator
runs approve-each through the existing gated executor — this module never runs it. An IMPORTED
workflow is stored and surfaced for inspection; it is never auto-run. ``test_workflows_safety.py``
locks all of this from the outside; ``test_codescan_safety.py`` locks the wider no-exec /
orthogonality invariant over every ``codescan/*.py`` file, this one included.

SHAPE
  Variable model   resolve_ref (dotted) + render_prompt ({{ref}})   — port of prompting.py
  Step             a focused prompt + output schema + fan-out controls
  Batch            a step fanning out one task per item of a list variable
  Depth & siblings depth = how many generations a step's list output re-expands;
                   siblings = parallel branches per task
  Import / export  to_portable / from_portable — a round-tripping portable JSON
  Runner           run_workflow — compiles the steps onto the ai_audit agent + dedup/rank
  Store            WorkflowStore — JSON-backed CRUD with a version lock (workflowLocks.js)

Nothing here imports state / a git driver / the gated launcher: like ``ai_audit``, the run-time
capabilities (the agent, KB grounding, the findings sink) arrive as INJECTED callables/data.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import ai_audit  # reuse: Verdict, dedup_and_rank, gate_finding, AgentRunner, IMPACT_LEVELS

# --------------------------------------------------------------------------- #
# bounds — the fan-out is bounded, never unbounded (same posture as ai_audit)
# --------------------------------------------------------------------------- #
MAX_STEPS = 24            # steps in one workflow
MAX_SIBLINGS = 8          # parallel branches per task
MAX_DEPTH = 4             # generations a self-expanding batch step may recurse
MAX_BATCH_ITEMS = 64      # items one batch step fans out over
MAX_TASKS = 400           # total agent tasks a single run may spawn (context + credits ceiling)

SCHEMA_VERSION = 1        # bumped if the portable JSON shape ever changes

STEP_KINDS = ("analyze", "batch", "command")
#   analyze  — one agent call; its parsed output is validated against the step schema
#   batch    — fan out one agent call per item of `batch_over` (a list variable)
#   command  — PROPOSE a command string (approve-each). Never executed here.

# the field types a step's output schema may declare (open·kritt's dynamic output_format)
FIELD_TYPES = ("string", "text", "list", "refs", "number", "bool", "severity")

# a file:line reference, reused from the audit gate so a step's "concrete finding" means the same
_LOC_RE = re.compile(r"[^\s:]+:\d+")
# a {{ ref }} token — dotted refs allowed, whitespace tolerated
_REF_RE = re.compile(r"\{\{\s*([a-zA-Z_][\w.\-]*)\s*\}\}")


class WorkflowError(ValueError):
    """A workflow could not be built, parsed, saved or run. Operator-facing."""


# --------------------------------------------------------------------------- #
# the variable model — {{var}} render + dotted resolve_ref (port of prompting.py)
# --------------------------------------------------------------------------- #
# The built-in variables every workflow can reference without declaring them. Operator-defined and
# per-run "extra" variables land in the same flat namespace; a prior step's parsed output is
# reachable by the dotted ref ``steps.<step-id>.output`` (or the first-branch shorthand ``<id>``).
BUILTIN_VARIABLES: list[dict[str, str]] = [
    {"name": "repo", "desc": "the source tree the run targets (path or name)"},
    {"name": "ref", "desc": "the git ref for patched-since mode (empty for a full audit)"},
    {"name": "playbook", "desc": "the audit playbook key this workflow steers"},
    {"name": "item", "desc": "inside a batch step: the current item being processed"},
    {"name": "branch", "desc": "inside a step with siblings>1: the 0-based branch index"},
    {"name": "steps.<id>.output", "desc": "a prior step's parsed output list (dotted ref)"},
]


def resolve_ref(context: dict[str, Any], dotted: str) -> Any:
    """Resolve a dotted reference (``a.b.c``) against a nested context, or ``None`` if any hop is
    missing. Ported from open·kritt's ``resolve_ref``: list indices are numeric hops, dict keys are
    string hops, and a missing hop yields ``None`` rather than raising (a template renders the
    empty string for it). Pure lookup — it never calls anything."""
    cur: Any = context
    for hop in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(hop)
        elif isinstance(cur, (list, tuple)):
            try:
                cur = cur[int(hop)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if cur is None:
            return None
    return cur


def _stringify(value: Any) -> str:
    """Render a resolved value into prompt text. Scalars stringify directly; lists/dicts render as
    compact JSON so a whole prior-step output can be dropped into a downstream prompt verbatim."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def render_prompt(template: str, context: dict[str, Any]) -> str:
    """Substitute every ``{{ ref }}`` in ``template`` with its resolved value. An unresolved ref
    renders the empty string (open·kritt's behaviour) — a step never emits a literal ``{{x}}`` to
    an agent. Pure string work: no eval, no format(), no code path for the substituted text."""
    def _sub(m: "re.Match[str]") -> str:
        return _stringify(resolve_ref(context, m.group(1)))
    return _REF_RE.sub(_sub, template)


def referenced_vars(template: str) -> list[str]:
    """Every distinct ref a template mentions, in first-seen order — feeds the editor's linter."""
    seen: list[str] = []
    for m in _REF_RE.finditer(template):
        if m.group(1) not in seen:
            seen.append(m.group(1))
    return seen


# --------------------------------------------------------------------------- #
# records — Step + Workflow, with a strict from-dict that keeps import honest
# --------------------------------------------------------------------------- #
@dataclass
class OutputField:
    """One field of a step's output schema (open·kritt's dynamic ``output_format``)."""

    name: str
    type: str = "string"
    required: bool = False
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.type, "required": self.required,
                "label": self.label or self.name}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "OutputField":
        name = str(d.get("name") or "").strip()
        if not name:
            raise WorkflowError("an output field needs a name")
        ftype = str(d.get("type") or "string").strip().lower()
        if ftype not in FIELD_TYPES:
            raise WorkflowError(f"unknown output field type {ftype!r} "
                                f"(one of {', '.join(FIELD_TYPES)})")
        return cls(name=name, type=ftype, required=bool(d.get("required")),
                   label=str(d.get("label") or "").strip())


@dataclass
class Step:
    """One prompt step: a focused prompt, an output schema and a fan-out shape."""

    id: str
    title: str
    prompt: str
    kind: str = "analyze"
    batch_over: str = ""           # dotted ref to a list variable (batch step)
    item_var: str = "item"         # the name the current batch item binds to
    siblings: int = 1              # parallel branches per task (1..MAX_SIBLINGS)
    depth: int = 0                 # generations a batch step re-expands over its OWN output
    output_format: list[OutputField] = field(default_factory=list)  # [] -> finding-or-stub schema
    grounded: bool = False         # KB-ground the prompt (if a search is injected)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "prompt": self.prompt, "kind": self.kind,
            "batch_over": self.batch_over, "item_var": self.item_var,
            "siblings": self.siblings, "depth": self.depth,
            "output_format": [f.to_dict() for f in self.output_format],
            "grounded": self.grounded, "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Step":
        sid = str(d.get("id") or "").strip()
        if not re.fullmatch(r"[a-zA-Z_][\w\-]*", sid or ""):
            raise WorkflowError(f"step id {sid!r} must be a bare identifier (letters/digits/_/-)")
        kind = str(d.get("kind") or "analyze").strip().lower()
        if kind not in STEP_KINDS:
            raise WorkflowError(f"unknown step kind {kind!r} (one of {', '.join(STEP_KINDS)})")
        prompt = str(d.get("prompt") or "")
        if not prompt.strip():
            raise WorkflowError(f"step {sid!r} has an empty prompt")
        siblings = _clamp(int(d.get("siblings") or 1), 1, MAX_SIBLINGS)
        depth = _clamp(int(d.get("depth") or 0), 0, MAX_DEPTH)
        fields = [OutputField.from_dict(f) for f in (d.get("output_format") or [])
                  if isinstance(f, dict)]
        return cls(
            id=sid, title=str(d.get("title") or sid).strip(), prompt=prompt, kind=kind,
            batch_over=str(d.get("batch_over") or "").strip(),
            item_var=str(d.get("item_var") or "item").strip() or "item",
            siblings=siblings, depth=depth, output_format=fields,
            grounded=bool(d.get("grounded")), note=str(d.get("note") or "").strip(),
        )


@dataclass
class Workflow:
    """An ordered set of steps, plus authoring metadata. `playbook` is an optional hint: when set,
    a heuristic (no-LLM) run and the offline sample delegate to that built-in decomposition, so a
    workflow derived from a proven playbook still demos with no model wired."""

    id: str
    name: str
    description: str = ""
    steps: list[Step] = field(default_factory=list)
    playbook: str = ""             # optional ai_audit playbook key this workflow steers
    builtin: bool = False          # a seeded built-in (read-only in the store)
    imported: bool = False         # loaded from an external JSON — INSPECT BEFORE RUNNING
    version: int = 1               # bumped on every save; the store's optimistic lock
    updated_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "steps": [s.to_dict() for s in self.steps], "playbook": self.playbook,
            "builtin": self.builtin, "imported": self.imported,
            "version": self.version, "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Workflow":
        wid = str(d.get("id") or "").strip()
        if not re.fullmatch(r"[a-zA-Z0-9][\w\-]*", wid or ""):
            raise WorkflowError("a workflow needs an id (letters/digits/_/-)")
        name = str(d.get("name") or "").strip()
        if not name:
            raise WorkflowError("a workflow needs a name")
        raw_steps = d.get("steps") or []
        if not isinstance(raw_steps, list) or not raw_steps:
            raise WorkflowError("a workflow needs at least one step")
        if len(raw_steps) > MAX_STEPS:
            raise WorkflowError(f"a workflow may have at most {MAX_STEPS} steps")
        steps = [Step.from_dict(s) for s in raw_steps if isinstance(s, dict)]
        ids = [s.id for s in steps]
        if len(ids) != len(set(ids)):
            raise WorkflowError("step ids must be unique within a workflow")
        wf = cls(
            id=wid, name=name, description=str(d.get("description") or "").strip(),
            steps=steps, playbook=str(d.get("playbook") or "").strip(),
            builtin=bool(d.get("builtin")), imported=bool(d.get("imported")),
            version=int(d.get("version") or 1), updated_at=float(d.get("updated_at") or 0.0),
        )
        _check_batch_refs(wf)
        return wf


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))


def _check_batch_refs(wf: Workflow) -> None:
    """A batch step's ``batch_over`` may reference a builtin list (``item`` isn't one), an extra
    variable, or a PRIOR step's output (``steps.<id>.output`` / ``<id>``). Referencing a later or
    unknown step is a build error — caught here, not at run time. Advisory only for extra vars,
    which are supplied per-run and cannot be checked statically."""
    seen: set[str] = set()
    for st in wf.steps:
        if st.kind == "batch" and st.batch_over:
            head = st.batch_over.split(".")[0]
            known = head in seen or head in {"steps", "extra"} or head == st.item_var
            # `steps.<id>` must name an EARLIER step
            if head == "steps":
                parts = st.batch_over.split(".")
                ref_id = parts[1] if len(parts) > 1 else ""
                if ref_id and ref_id not in seen:
                    raise WorkflowError(
                        f"step {st.id!r} batches over {st.batch_over!r} but no earlier step "
                        f"is named {ref_id!r}")
            elif head in seen:
                pass  # <id> shorthand for an earlier step
            elif not known:
                # not a prior step and not the steps/extra namespaces — allow (an extra var), but
                # only if it is not the name of a LATER step
                later = {s.id for s in wf.steps} - seen - {st.id}
                if head in later:
                    raise WorkflowError(
                        f"step {st.id!r} batches over {head!r}, a step that runs AFTER it")
        seen.add(st.id)


# --------------------------------------------------------------------------- #
# output-schema validation — a step's output validates against its schema
# --------------------------------------------------------------------------- #
_TYPE_CHECK: dict[str, Callable[[Any], bool]] = {
    "string": lambda v: isinstance(v, str),
    "text": lambda v: isinstance(v, str),
    "severity": lambda v: isinstance(v, str) and v.lower() in ai_audit.IMPACT_LEVELS,
    "list": lambda v: isinstance(v, list),
    "refs": lambda v: isinstance(v, list),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "bool": lambda v: isinstance(v, bool),
}


def validate_step_output(payload: Any, step: Step) -> tuple[bool, list[str]]:
    """Shape-check a parsed step output against the step's schema. (ok, problems).

    A step with no declared ``output_format`` uses the finding-or-stub schema the audit engine
    uses (``ai_audit.validate_payload`` + the concrete-or-stub gate), so a custom workflow inherits
    the same 'a claimed finding must be concrete' discipline. A step WITH a declared schema is
    checked field-by-field: every required field present and every field the declared type."""
    if not step.output_format:
        ok, problems = ai_audit.validate_payload(payload)
        return ok, problems
    if not isinstance(payload, dict):
        return False, ["output must be a JSON object"]
    problems: list[str] = []
    for f in step.output_format:
        if f.name not in payload:
            if f.required:
                problems.append(f"missing required field {f.name!r}")
            continue
        check = _TYPE_CHECK.get(f.type, lambda v: True)
        if not check(payload[f.name]):
            problems.append(f"field {f.name!r} is not a {f.type}")
    return (not problems), problems


# --------------------------------------------------------------------------- #
# import / export — a round-tripping portable JSON (inspect-before-run on import)
# --------------------------------------------------------------------------- #
def to_portable(wf: Workflow) -> dict[str, Any]:
    """Serialize a workflow to a portable JSON dict: the schema version + the whole definition,
    with the store-local fields (version/updated_at/builtin) dropped so a re-import is a fresh
    authored copy, never a silent overwrite of a built-in."""
    body = wf.to_dict()
    for k in ("version", "updated_at", "builtin"):
        body.pop(k, None)
    return {"kritt_workflow_schema": SCHEMA_VERSION, "workflow": body}


def from_portable(data: dict[str, Any]) -> Workflow:
    """Parse a portable JSON dict back into a Workflow, flagged ``imported=True`` so the surface
    marks it INSPECT-BEFORE-RUN. Rejects a wrong/absent schema version loudly. Executes nothing —
    it parses, it does not run."""
    if not isinstance(data, dict):
        raise WorkflowError("an imported workflow must be a JSON object")
    ver = data.get("kritt_workflow_schema")
    if ver is None:
        raise WorkflowError("not a workflow export (no `kritt_workflow_schema` key)")
    if int(ver) != SCHEMA_VERSION:
        raise WorkflowError(f"unsupported workflow schema version {ver} "
                            f"(this build reads v{SCHEMA_VERSION})")
    body = data.get("workflow")
    if not isinstance(body, dict):
        raise WorkflowError("the export has no `workflow` body")
    body = dict(body)
    body["imported"] = True
    body["builtin"] = False
    wf = Workflow.from_dict(body)
    return wf


# --------------------------------------------------------------------------- #
# the runner — compile the steps onto the ai_audit agent, thread outputs downstream
# --------------------------------------------------------------------------- #
def _base_context(repo: str, ref: str, playbook: str,
                  extra_vars: dict[str, Any] | None) -> dict[str, Any]:
    """The variable namespace a run starts with: built-ins + operator/per-run extras. Extras land
    both flat (so ``{{customer}}`` works) and under ``extra.*`` (open·kritt's 'extra variable')."""
    ctx: dict[str, Any] = {
        "repo": repo, "ref": ref or "", "playbook": playbook or "",
        "steps": {}, "extra": dict(extra_vars or {}),
    }
    for k, v in (extra_vars or {}).items():
        if k not in ctx:            # never let an extra shadow a built-in
            ctx[k] = v
    return ctx


def _parse_output(raw: str) -> Any:
    """Parse an agent's raw text into a payload, tolerating a ```json fence and leading prose —
    delegated to the audit engine's parser so both surfaces read a model the same way."""
    return ai_audit._parse(raw)


def _step_system(step: Step) -> str:
    """The system framing for a step: return ONE JSON object, and — for the default schema — the
    concrete-or-stub contract the audit already enforces."""
    if step.output_format:
        names = ", ".join(f.name for f in step.output_format)
        return ("You are a focused code-audit step. Read the source you are given and return ONE "
                f"JSON object with these fields: {names}. Return only the JSON object.")
    return ("You are a focused code-audit step. Return ONE JSON object: either a concrete finding "
            "{finding:true, title, severity, attacker_path, source_refs:[\"file:line\"], impact} "
            "or an honest stub {finding:false, reason}. Return only the JSON object.")


@dataclass
class StepResult:
    step_id: str
    kind: str
    tasks: int
    outputs: list[Any] = field(default_factory=list)     # validated payloads (analyze/batch)
    proposals: list[str] = field(default_factory=list)    # command strings (command step)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"step_id": self.step_id, "kind": self.kind, "tasks": self.tasks,
                "outputs": self.outputs, "proposals": self.proposals,
                "warnings": self.warnings}


def _resolve_items(step: Step, context: dict[str, Any]) -> list[Any]:
    """The items a batch step fans out over. A non-list ref degrades to a single-item run over the
    resolved value (never a crash); an empty/absent list yields nothing (the step no-ops)."""
    if step.kind != "batch" or not step.batch_over:
        return [None]
    val = resolve_ref(context, step.batch_over)
    if val is None:
        return []
    if isinstance(val, list):
        return val[:MAX_BATCH_ITEMS]
    return [val]


def _run_step(step: Step, context: dict[str, Any], agent: ai_audit.AgentRunner,
              kb_search: Any, budget: list[int]) -> StepResult:
    """Run one step: fan out over its items × siblings, render+call (or propose), validate. `budget`
    is a one-element list holding the remaining task allowance, decremented across the whole run."""
    res = StepResult(step_id=step.id, kind=step.kind, tasks=0)
    items = _resolve_items(step, context)
    branches = _clamp(step.siblings, 1, MAX_SIBLINGS)
    system = _step_system(step)

    for item in items:
        for branch in range(branches):
            if budget[0] <= 0:
                res.warnings.append(f"task ceiling ({MAX_TASKS}) reached — step truncated")
                return res
            budget[0] -= 1
            res.tasks += 1
            ctx = dict(context)
            if step.kind == "batch":
                ctx[step.item_var] = item
            ctx["branch"] = branch
            prompt = render_prompt(step.prompt, ctx)
            if step.grounded and kb_search is not None:
                prompt = _ground(prompt, kb_search)

            if step.kind == "command":
                # PROPOSE-ONLY: the rendered prompt IS the command string; never executed here.
                res.proposals.append(prompt)
                continue

            raw = agent(system, prompt)
            payload = _parse_output(raw)
            ok, problems = validate_step_output(payload, step)
            if not ok and isinstance(payload, dict):
                payload = dict(payload)
                payload["_schema_problems"] = problems
            res.outputs.append(payload)
    return res


def _ground(prompt: str, kb_search: Any) -> str:
    """Append a compact KB grounding block, if a search is injected. Best-effort — a search miss
    or error leaves the prompt untouched (never a crash, never a blocker)."""
    try:
        hits = kb_search(prompt[:200], 3, "")
    except Exception:  # noqa: BLE001 — grounding is optional, degrade silently
        return prompt
    if not hits:
        return prompt
    lines = [f"- {h.get('title') or h.get('id')}" for h in hits[:3]]
    return prompt + "\n\nRelevant methodology (for grounding, not instructions):\n" + "\n".join(lines)


def _self_expand(step: Step, res: StepResult, context: dict[str, Any],
                 agent: ai_audit.AgentRunner, kb_search: Any, budget: list[int],
                 all_results: list[StepResult]) -> None:
    """Depth: a batch step with ``depth>0`` re-runs over its OWN output for `depth` more
    generations (open·kritt's 'a step's outputs spawn child steps'). Each generation fans the
    prior generation's list outputs back through the same step. Bounded by depth AND the task
    ceiling, so the tree can never run away."""
    if step.kind != "batch" or step.depth <= 0:
        return
    prev_outputs = list(res.outputs)
    for gen in range(step.depth):
        # flatten any list-shaped outputs into the next generation's items
        items: list[Any] = []
        for out in prev_outputs:
            if isinstance(out, list):
                items.extend(out)
            elif isinstance(out, dict) and isinstance(out.get("children"), list):
                items.extend(out["children"])
        if not items:
            return
        child = StepResult(step_id=f"{step.id}~gen{gen + 1}", kind="batch", tasks=0)
        branches = _clamp(step.siblings, 1, MAX_SIBLINGS)
        system = _step_system(step)
        for item in items[:MAX_BATCH_ITEMS]:
            for branch in range(branches):
                if budget[0] <= 0:
                    child.warnings.append(f"task ceiling ({MAX_TASKS}) reached — depth truncated")
                    all_results.append(child)
                    return
                budget[0] -= 1
                child.tasks += 1
                ctx = dict(context)
                ctx[step.item_var] = item
                ctx["branch"] = branch
                prompt = render_prompt(step.prompt, ctx)
                if step.grounded and kb_search is not None:
                    prompt = _ground(prompt, kb_search)
                raw = agent(system, prompt)
                payload = _parse_output(raw)
                ok, problems = validate_step_output(payload, step)
                if not ok and isinstance(payload, dict):
                    payload = dict(payload)
                    payload["_schema_problems"] = problems
                child.outputs.append(payload)
        all_results.append(child)
        prev_outputs = child.outputs


def _to_verdict(payload: Any) -> ai_audit.Verdict | None:
    """A step output that is a concrete finding becomes a Verdict for the shared dedup+rank pass.
    A stub, a non-dict, or a claim that fails the concrete-or-stub gate is not a finding."""
    if not isinstance(payload, dict) or not payload.get("finding"):
        return None
    ok, _ = ai_audit.gate_finding(payload)
    if not ok:
        return None
    sev = str(payload.get("severity") or "medium").lower()
    if sev not in ai_audit.IMPACT_LEVELS:
        sev = "medium"
    return ai_audit.Verdict(
        flow_id=str(payload.get("flow_id") or ""), finding=True,
        title=str(payload.get("title") or ""), vuln_class=str(payload.get("vuln_class") or ""),
        severity=sev, attacker_path=str(payload.get("attacker_path") or ""),
        source_refs=[str(r) for r in (payload.get("source_refs") or [])],
        impact=str(payload.get("impact") or ""), cwe=payload.get("cwe"),
        chain=str(payload.get("chain") or ""), contract=str(payload.get("contract") or ""),
        function=str(payload.get("function") or ""),
    )


def run_workflow(wf: Workflow, *, repo: str, agent: ai_audit.AgentRunner,
                 kb_search: Any = None, ref: str = "",
                 extra_vars: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compile a workflow onto the injected agent and run it — the "one approved job".

    Each step renders its prompt with the resolved variables, runs (single, batched, or a proposal
    for a command step) through ``agent``, validates the output against the step schema, and stores
    its outputs so downstream steps can reference them by ``{{steps.<id>.output}}``. Concrete
    findings across all steps are de-duplicated and severity-ranked by the SHARED audit pass. This
    executes nothing against a target: it reads source through the agent and threads text. Command
    steps only ever PROPOSE — their strings come back under ``proposals``, approve-each."""
    started = time.monotonic()
    context = _base_context(repo, ref, wf.playbook, extra_vars)
    budget = [MAX_TASKS]
    results: list[StepResult] = []
    proposals: list[dict[str, str]] = []

    for step in wf.steps:
        res = _run_step(step, context, agent, kb_search, budget)
        results.append(res)
        _self_expand(step, res, context, agent, kb_search, budget, results)
        # publish this step's outputs into the namespace downstream steps read
        context["steps"][step.id] = {"output": res.outputs, "proposals": res.proposals}
        context.setdefault(step.id, {})["output"] = res.outputs
        for cmd in res.proposals:
            proposals.append({"step": step.id, "command": cmd,
                              "approve_each": True, "executed": False})

    verdicts = [v for r in results for p in r.outputs if (v := _to_verdict(p)) is not None]
    ranked = ai_audit.dedup_and_rank(verdicts)
    findings = [v.to_dict() for v in ranked]

    by_sev = {s: 0 for s in ai_audit.IMPACT_LEVELS}
    for v in ranked:
        by_sev[v.severity] = by_sev.get(v.severity, 0) + 1

    return {
        "workflow": wf.id, "name": wf.name, "repo": repo, "ref": ref or None,
        "mode": "workflow", "imported": wf.imported,
        "steps": [r.to_dict() for r in results],
        "proposals": proposals,               # command-step proposals — approve-each, never run
        "findings": findings,
        "tasks_run": MAX_TASKS - budget[0],
        "duration_s": round(time.monotonic() - started, 2),
        "summary": {
            "steps": len(wf.steps), "tasks": MAX_TASKS - budget[0],
            "findings": len(findings), "proposals": len(proposals), "by_severity": by_sev,
        },
        "warnings": [w for r in results for w in r.warnings],
    }


def plan(wf: Workflow, extra_vars: dict[str, Any] | None = None) -> dict[str, Any]:
    """The STATIC fan-out shape of a workflow, computed without running anything — the builder's
    preview and the shape the tests assert. For a batch step over a list supplied in context (an
    extra var), the item count is exact; over a prior step's output it is unknown until run time
    and reported as ``dynamic``. Executes nothing."""
    context = _base_context("repo", "", wf.playbook, extra_vars)
    rows: list[dict[str, Any]] = []
    static_total = 0
    for st in wf.steps:
        branches = _clamp(st.siblings, 1, MAX_SIBLINGS)
        item_count: int | str
        if st.kind == "batch" and st.batch_over:
            head = st.batch_over.split(".")[0]
            if head in {"steps"} or head in {s.id for s in wf.steps}:
                item_count = "dynamic"  # depends on a prior step's output
            else:
                val = resolve_ref(context, st.batch_over)
                item_count = len(val) if isinstance(val, list) else 1
        else:
            item_count = 1
        if isinstance(item_count, int):
            tasks: int | str = item_count * branches * (st.depth + 1 if st.kind == "batch" else 1)
            static_total += tasks
        else:
            tasks = "dynamic"
        rows.append({
            "step_id": st.id, "title": st.title, "kind": st.kind,
            "batch_over": st.batch_over, "items": item_count,
            "siblings": branches, "depth": st.depth, "tasks": tasks,
        })
    return {"workflow": wf.id, "steps": rows, "static_tasks": static_total, "task_ceiling": MAX_TASKS}


# --------------------------------------------------------------------------- #
# the seeded built-ins (open·kritt's defaultWorkflows.js) — visible on first load
# --------------------------------------------------------------------------- #
def _external_flow_builtin() -> Workflow:
    """The generic web-app decomposition as an editable workflow: enumerate -> trace (batch) ->
    verify (batch). Mirrors ``ai_audit``'s external-flow playbook, so a heuristic run of it
    delegates to that proven decomposition for the offline demo."""
    return Workflow(
        id="external-flow",
        name="External-flow analysis (web app)",
        description="Map externally-reachable entrypoints, trace each entrypoint's flows, then "
                    "verify one flow per agent — concrete vuln or honest stub. The proven web-app "
                    "decomposition, editable.",
        playbook="external-flow-analysis",
        builtin=True,
        steps=[
            Step(
                id="enumerate", title="Enumerate entrypoints", kind="analyze",
                prompt="Repo: {{repo}}. Map the externally-reachable entrypoints (HTTP routes, "
                       "handlers, RPC, consumers) that process attacker-controlled input. Return "
                       "one JSON object with an `entrypoints` array of "
                       "{id, name, file, kind}.",
                output_format=[OutputField("entrypoints", "list", True, "Entrypoints")],
                note="One pass over the tree — context-cheap, mapped once.",
            ),
            Step(
                id="trace", title="Trace flows per entrypoint", kind="batch",
                batch_over="steps.enumerate.output.0.entrypoints", item_var="entrypoint",
                prompt="Entrypoint: {{entrypoint}}. In repo {{repo}}, enumerate the materially "
                       "different production flows from this entrypoint (validation outcomes, authz "
                       "boundaries, state changes, external calls, sensitive sinks). Return one "
                       "JSON object with a `flows` array of {id, title, file}.",
                output_format=[OutputField("flows", "list", True, "Flows")],
            ),
            Step(
                id="verify", title="Verify each flow", kind="batch",
                batch_over="steps.trace.output.0.flows", item_var="flow", depth=1,
                prompt="Flow: {{flow}} in repo {{repo}}. Spend your whole attention on THIS flow. "
                       "Return either a concrete finding {finding:true, title, severity, "
                       "attacker_path, source_refs:[\"file:line\"], impact, vuln_class} or an "
                       "honest stub {finding:false, reason}.",
                note="One agent per flow — the map-once/verify-each primitive.",
            ),
        ],
    )


def _evm_flow_builtin() -> Workflow:
    """The EVM external-flow (Solidity) decomposition as an editable workflow — the second built-in
    the spec asks for. Mirrors ``ai_audit``'s ``evm-external-flow`` playbook."""
    return Workflow(
        id="evm-external-flow",
        name="EVM external-flow (Solidity)",
        description="Solidity: map external/public functions, trace value/state/external-call/"
                    "oracle flows, then verify each for loss-of-funds / reentrancy / access-control "
                    "/ oracle-manipulation. The proven web3 decomposition, editable.",
        playbook="evm-external-flow",
        builtin=True,
        steps=[
            Step(
                id="enumerate", title="Enumerate external functions", kind="analyze",
                prompt="Repo: {{repo}} (Solidity). Map the external/public functions and the "
                       "state they touch. Return one JSON object with an `entrypoints` array of "
                       "{id, name, file, contract}.",
                output_format=[OutputField("entrypoints", "list", True, "Functions")],
            ),
            Step(
                id="trace", title="Trace value/state/oracle flows", kind="batch",
                batch_over="steps.enumerate.output.0.entrypoints", item_var="fn",
                prompt="Function: {{fn}} in {{repo}}. Enumerate the flows that move value, mutate "
                       "state, make external calls, or read an oracle. Return one JSON object with "
                       "a `flows` array of {id, title, file, function}.",
                output_format=[OutputField("flows", "list", True, "Flows")],
            ),
            Step(
                id="verify", title="Verify each flow for loss-of-funds", kind="batch",
                batch_over="steps.trace.output.0.flows", item_var="flow",
                prompt="Flow: {{flow}} in {{repo}}. Hunt reentrancy / access-control / "
                       "oracle-manipulation / loss-of-funds on THIS flow only. Return a concrete "
                       "finding {finding:true, title, severity, attacker_path, "
                       "source_refs:[\"file:line\"], impact, vuln_class, chain:\"evm\", contract, "
                       "function} or an honest stub {finding:false, reason}.",
            ),
        ],
    )


def default_workflows() -> list[Workflow]:
    """The seeded built-ins visible on first load — one web, one web3 (spec acceptance)."""
    return [_external_flow_builtin(), _evm_flow_builtin()]


# --------------------------------------------------------------------------- #
# the store — JSON-backed CRUD with an optimistic version lock (workflowLocks.js)
# --------------------------------------------------------------------------- #
class WorkflowStore:
    """A tiny persistent store: the seeded built-ins plus the operator's authored/imported
    workflows, kept in one JSON file. Authoring is the ONLY thing that writes here, and it writes
    data — it launches nothing. The version lock is open·kritt's ``workflowLocks``: a save that
    carries a stale ``version`` is refused, so two editors cannot silently clobber each other."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._items: dict[str, Workflow] = {}
        self._seed_builtins()
        self._load()

    # --- persistence ------------------------------------------------------- #
    def _seed_builtins(self) -> None:
        for wf in default_workflows():
            self._items[wf.id] = wf

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return
        for d in raw.get("workflows", []):
            try:
                wf = Workflow.from_dict(d)
            except WorkflowError:
                continue
            if wf.builtin:                 # built-ins always come from code, never the file
                continue
            self._items[wf.id] = wf

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema": SCHEMA_VERSION,
                   "workflows": [w.to_dict() for w in self._items.values() if not w.builtin]}
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    # --- read -------------------------------------------------------------- #
    def list(self) -> list[Workflow]:
        return sorted(self._items.values(),
                      key=lambda w: (not w.builtin, w.name.lower()))

    def get(self, wid: str) -> Workflow:
        wf = self._items.get(wid)
        if wf is None:
            raise WorkflowError(f"no workflow {wid!r}")
        return wf

    # --- write (authoring — executes nothing) ------------------------------ #
    def create(self, data: dict[str, Any]) -> Workflow:
        wf = Workflow.from_dict({**data, "builtin": False})
        if wf.id in self._items:
            raise WorkflowError(f"a workflow {wf.id!r} already exists")
        wf.version = 1
        wf.updated_at = _now()
        self._items[wf.id] = wf
        self._save()
        return wf

    def update(self, wid: str, data: dict[str, Any], *, expected_version: int | None = None
               ) -> Workflow:
        cur = self.get(wid)
        if cur.builtin:
            raise WorkflowError("a built-in workflow is read-only — clone it to edit")
        if expected_version is not None and expected_version != cur.version:
            raise WorkflowError(
                f"stale edit: the workflow is at v{cur.version}, your edit was against "
                f"v{expected_version} — reload and re-apply")
        merged = {**cur.to_dict(), **data, "id": wid, "builtin": False}
        wf = Workflow.from_dict(merged)
        wf.version = cur.version + 1
        wf.updated_at = _now()
        wf.imported = cur.imported and not data.get("steps")  # a real edit clears the import flag
        self._items[wid] = wf
        self._save()
        return wf

    def delete(self, wid: str) -> None:
        cur = self.get(wid)
        if cur.builtin:
            raise WorkflowError("a built-in workflow cannot be deleted")
        del self._items[wid]
        self._save()

    def import_workflow(self, data: dict[str, Any]) -> Workflow:
        """Parse + STORE an external export, flagged imported (inspect-before-run). Does NOT run
        it. If the id collides, it is suffixed so an import never overwrites an existing one."""
        wf = from_portable(data)
        wf.id = self._unique_id(wf.id)
        wf.version = 1
        wf.updated_at = _now()
        wf.imported = True
        self._items[wf.id] = wf
        self._save()
        return wf

    def _unique_id(self, base: str) -> str:
        if base not in self._items:
            return base
        n = 2
        while f"{base}-{n}" in self._items:
            n += 1
        return f"{base}-{n}"


def _now() -> float:
    return time.time()
