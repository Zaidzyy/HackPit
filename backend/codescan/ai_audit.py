"""AI-agent code audit — the context-saving fan-out (open·kritt's engine, HackPit-gated).

WHAT THIS IS
The rule-mode scan (runner.py) matches patterns file-by-file. This is the other half: an
AI-agent audit that decomposes the repo the way open·kritt does — **map the externally-reachable
entrypoints and their flows ONCE, then hand each downstream agent exactly ONE flow to verify
against source**, so every agent spends its whole context on a single path and returns either a
concrete vuln-with-attacker-path or a no-finding stub. The findings are then de-duplicated and
severity-ranked. Mapping once is the whole point: it is what keeps the context cost linear in the
number of flows instead of quadratic, and what produces attacker-path-backed findings rather than
repo-wide hand-waving.

THE ONE INVARIANT (do not weaken — §0 of the spec)
This module **reads source and PROPOSES**. It executes nothing: it walks files, reads their text,
and calls the LLM layer (an INJECTED agent runner). It launches no scanner against the code, opens
no socket, and imports no executor / engagement / sandbox module. HackPit does NOT adopt
open·kritt's autonomous-root model — any PoC a finding suggests is a *string* the operator runs
approve-each through the existing gated executor, never from here. ``test_ai_audit_safety.py``
locks this from the outside.

SHAPE (reusing backend/reasoning/ as the fan-out substrate)
  enumerate_entrypoints  stage 1, one pass  -> the entrypoint map (context-cheap)
  trace_flows            stage 2, per ep     -> the flow frontier
  verify_flow            stage 3, per flow   -> concrete-or-stub, gated by :func:`gate_finding`
  dedup / rank           post-processing     -> IMPACT_LEVELS-ranked engagement findings
Domain framing comes from ``reasoning.specialists``; KB grounding from an injected search;
model-tier selection from ``reasoning.tiering`` (in :func:`default_agents`).

The ``agent`` is a ``Callable[[str, str], str]`` — (system, user) -> raw text — so the pipeline is
provider-agnostic and hermetically testable (a fake agent needs no network). A deterministic
:func:`run_heuristic_audit` runs the SAME three stages with no LLM at all (regex sinks loaded from
``ai_audit_rules.json``) — the graceful-degradation path and the source of the offline demo.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import runner  # read-only: path validation, file walking, SKIP_DIRS

# --------------------------------------------------------------------------- #
# severity — open·kritt's IMPACT_LEVELS, ported verbatim, mapped to state's vocab
# --------------------------------------------------------------------------- #
IMPACT_LEVELS = ("critical", "high", "medium", "low", "informational")
_IMPACT_RANK = {s: i for i, s in enumerate(IMPACT_LEVELS)}
# engagement-state Finding uses "info", not "informational".
_STATE_SEVERITY = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "informational": "info",
}

# bounds on the fan-out (context + credits). A repo with more entrypoints than this maps the
# top slice and WARNS — it never silently drops the rest.
MAX_ENTRYPOINTS = 40
MAX_FLOWS_PER_EP = 8
MAX_FLOWS_TOTAL = 120
MAX_SOURCE_FILES = 4000
_SNIPPET_BYTES = 12_000            # per-file source handed to an agent
_LISTING_CAP = 600                 # files named in the stage-1 listing

# languages worth mapping for entrypoints (attacker-reachable code, not assets)
_CODE_EXT = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php", ".java", ".cs",
    ".rs", ".sol", ".kt", ".scala", ".clj", ".ex", ".exs",
})

_RULES_PATH = Path(__file__).parent / "ai_audit_rules.json"
_WEB3_RULES_PATH = Path(__file__).parent / "ai_audit_web3_rules.json"

AgentRunner = Callable[[str, str], str]


class AuditError(RuntimeError):
    """The audit could not be run (bad path, no agent, oversized tree). Operator-facing."""


# --------------------------------------------------------------------------- #
# records
# --------------------------------------------------------------------------- #
@dataclass
class Entrypoint:
    id: str
    name: str                 # the route/handler as named in source
    file: str                 # repo-relative
    kind: str = "handler"     # http-route | handler | cli | rpc | consumer
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "file": self.file, "kind": self.kind,
                "note": self.note}


@dataclass
class Flow:
    id: str
    entrypoint_id: str
    title: str                # the materially-different path being verified
    file: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "entrypoint_id": self.entrypoint_id, "title": self.title,
                "file": self.file, "note": self.note}


@dataclass
class Verdict:
    """One flow's result — a concrete finding, or an honest no-finding stub."""

    flow_id: str
    finding: bool
    title: str = ""
    vuln_class: str = ""
    severity: str = "informational"
    attacker_path: str = ""
    source_refs: list[str] = field(default_factory=list)   # ["file.py:42", ...]
    impact: str = ""
    confidence: str = "medium"
    cwe: str | None = None
    poc: str = ""                                           # propose-only PoC command
    kb_refs: list[dict[str, str]] = field(default_factory=list)
    reason: str = ""                                        # why a stub, or gate downgrade note
    # web3 provenance — the chain/contract/function a smart-contract finding sits on. Empty for
    # the generic web-app playbook; the frontend renders them when present.
    chain: str = ""                                         # evm | cosmos | solana | ""
    contract: str = ""                                      # contract / module / program name
    function: str = ""                                      # the entrypoint function/method

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id, "finding": self.finding, "title": self.title,
            "vuln_class": self.vuln_class, "severity": self.severity,
            "attacker_path": self.attacker_path, "source_refs": list(self.source_refs),
            "impact": self.impact, "confidence": self.confidence, "cwe": self.cwe,
            "poc": self.poc, "kb_refs": list(self.kb_refs), "reason": self.reason,
            "chain": self.chain, "contract": self.contract, "function": self.function,
        }


# --------------------------------------------------------------------------- #
# the finding output schema (open·kritt schema.py) — dynamic, jsonschema-free
# --------------------------------------------------------------------------- #
# A tiny, zero-dependency validator: enough to force the agent to return a structured
# finding-or-stub. ``finding: false`` is a valid no-finding answer; ``finding: true`` must carry
# the concreteness fields. Ported from open·kritt's ``output_schema`` / ``validate_payload``.
FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["finding"],
    "properties": {
        "finding": {"type": "boolean"},
        "title": {"type": "string"},
        "vuln_class": {"type": "string"},
        "severity": {"type": "string", "enum": list(IMPACT_LEVELS)},
        "attacker_path": {"type": "string"},
        "source_refs": {"type": "array", "items": {"type": "string"}},
        "impact": {"type": "string"},
        "confidence": {"type": "string"},
        "poc": {"type": "string"},
        "chain": {"type": "string"},
        "contract": {"type": "string"},
        "function": {"type": "string"},
    },
    # only meaningful when finding is true — checked by gate_finding, not the shape validator
    "if_finding_required": ["title", "severity", "attacker_path", "source_refs", "impact"],
}


def validate_payload(payload: Any, schema: dict[str, Any] = FINDING_SCHEMA) -> tuple[bool, list[str]]:
    """Shape-check a parsed agent payload against the finding schema. (ok, problems).

    Type-only: it does not judge whether a finding is *concrete* — that is :func:`gate_finding`.
    Kept deliberately small (open·kritt uses jsonschema; HackPit stays dependency-free).
    """
    problems: list[str] = []
    if not isinstance(payload, dict):
        return False, ["payload is not a JSON object"]
    if schema.get("type") == "object":
        for key in schema.get("required", []):
            if key not in payload:
                problems.append(f"missing required field '{key}'")
        props = schema.get("properties", {})
        for key, spec in props.items():
            if key not in payload:
                continue
            val = payload[key]
            t = spec.get("type")
            if t == "boolean" and not isinstance(val, bool):
                problems.append(f"'{key}' must be a boolean")
            elif t == "string" and not isinstance(val, str):
                problems.append(f"'{key}' must be a string")
            elif t == "array" and not isinstance(val, list):
                problems.append(f"'{key}' must be an array")
            enum = spec.get("enum")
            if enum and isinstance(val, str) and val not in enum:
                problems.append(f"'{key}' must be one of {enum}")
    return (not problems, problems)


_LOC_RE = re.compile(r"[^:\s]+:\d+")


def gate_finding(payload: dict[str, Any]) -> tuple[bool, str]:
    """The concrete-or-stub gate — the critic HackPit's source audit actually needs.

    A claimed finding (``finding: true``) is only kept if it is CONCRETE: a title, an attacker
    path, an impact, and at least one source ref that names a real ``file:line`` location. A
    claim that fails any of these is not a bug we can act on — it is downranked to a stub, exactly
    as ``reasoning.critic`` downranks a proposal that rests on nothing rather than silently
    deleting it. (``reasoning.critic`` itself checks CVE-vs-observed-version, which does not apply
    to a source read — noted in the PR per spec §5.) Returns (is_concrete_finding, reason).
    """
    if not payload.get("finding"):
        return False, "no-finding stub"
    if not str(payload.get("title") or "").strip():
        return False, "claimed a finding but gave no title"
    if not str(payload.get("attacker_path") or "").strip():
        return False, "claimed a finding but described no attacker path"
    if not str(payload.get("impact") or "").strip():
        return False, "claimed a finding but stated no impact"
    refs = [str(r) for r in (payload.get("source_refs") or []) if _LOC_RE.search(str(r))]
    if not refs:
        return False, "claimed a finding but cited no concrete file:line source location"
    return True, ""


# --------------------------------------------------------------------------- #
# repo reading (read-only)
# --------------------------------------------------------------------------- #
def _iter_code_files(root: Path, changed: set[str] | None,
                     exts: frozenset[str] | None = None) -> list[str]:
    """Repo-relative code files, dependency/build trees skipped, optionally limited to a diff.

    ``exts`` (a playbook's extension set) narrows the walk to one language — a Solidity playbook
    maps only ``.sol`` files, so the entrypoint pass is not diluted by unrelated tooling code."""
    allowed = exts or _CODE_EXT
    out: list[str] = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in runner.SKIP_DIRS and not d.startswith(".")]
        for name in files:
            if Path(name).suffix.lower() not in allowed:
                continue
            rel = os.path.relpath(os.path.join(base, name), root).replace("\\", "/")
            if changed is not None and rel not in changed:
                continue
            out.append(rel)
            if len(out) >= MAX_SOURCE_FILES:
                return sorted(out)
    return sorted(out)


def _read_snippet(root: Path, rel: str, cap: int = _SNIPPET_BYTES) -> str:
    try:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return ""
    return text[:cap]


def _numbered(text: str, start: int = 1) -> str:
    return "\n".join(f"{i}\t{line}" for i, line in enumerate(text.splitlines(), start))


# --------------------------------------------------------------------------- #
# KB grounding (injected search; reasoning.retrieval in spirit)
# --------------------------------------------------------------------------- #
def _ground(query: str, kb_search: Callable[[str, int, str], list[dict]] | None,
            limit: int = 4) -> list[dict[str, str]]:
    """Top KB entries for a flow's vuln hypothesis — the grounding HackPit has and open·kritt
    does not. Best-effort: any failure yields no grounding, never breaks the audit."""
    if not kb_search or not query.strip():
        return []
    try:
        rows = kb_search(query, limit, "hybrid")
    except Exception:  # noqa: BLE001 — grounding must never sink the audit
        return []
    out: list[dict[str, str]] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        eid = str(r.get("id") or "").strip()
        title = str(r.get("title") or r.get("name") or "").strip()
        if eid:
            out.append({"id": eid, "title": title[:120]})
    return out[:limit]


# --------------------------------------------------------------------------- #
# stage prompts
# --------------------------------------------------------------------------- #
_ENUM_SYS = (
    "You are a senior application-security auditor mapping the ATTACK SURFACE of a codebase. "
    "You are given a file listing and a few entry files. Identify the EXTERNALLY-REACHABLE "
    "entrypoints — HTTP routes, RPC/GraphQL handlers, message consumers, CLI commands — i.e. the "
    "code that first receives attacker-controlled input. Map, do not audit. Return STRICT JSON: "
    '{"entrypoints": [{"name": "<route or handler>", "file": "<repo-relative path>", '
    '"kind": "http-route|handler|rpc|cli|consumer", "note": "<what input it takes>"}]}. '
    "No prose outside the JSON."
)
_FLOW_SYS = (
    "You are auditing ONE entrypoint. Enumerate the materially-DIFFERENT production paths through "
    "it — distinct validation outcomes, authorization boundaries, state changes, external calls, "
    "and sensitive sinks. Each flow is one path a single downstream agent will verify. Return "
    'STRICT JSON: {"flows": [{"title": "<the specific path>", "note": "<the sink/branch it '
    'exercises>"}]}. No prose outside the JSON.'
)
_VERIFY_SYS = (
    "You are verifying ONE flow against its source. Spend your whole attention on THIS flow. "
    "Decide: is there a CONCRETE, exploitable vulnerability with a real attacker path (RCE, authz "
    "bypass, injection, SSRF, loss-of-funds, consensus halt), or not? Do NOT invent bugs and do "
    "NOT hand-wave. Return STRICT JSON matching this schema:\n"
    '{"finding": true|false, "title": "<short>", "vuln_class": "<e.g. ssrf>", '
    '"severity": "critical|high|medium|low|informational", '
    '"attacker_path": "<concrete steps an attacker takes>", '
    '"source_refs": ["<file>:<line>", ...], "impact": "<what it gains>", '
    '"confidence": "high|medium|low", "poc": "<a single command a human could run to CONFIRM '
    'it, approve-each — you never run it>"}\n'
    "If there is no real vulnerability on this flow, return {\"finding\": false, \"reason\": "
    "\"<why it is safe>\"}. When you DO claim a finding you MUST cite at least one real "
    "file:line in source_refs. No prose outside the JSON."
)


def _parse(agent_out: str) -> Any:
    from llm import extract_json  # local import: the audit is LLM-shaped, llm is not a target
    return extract_json(agent_out)


# --------------------------------------------------------------------------- #
# playbooks — the built-in audit decompositions (open·kritt's seeded workflows, ported)
# --------------------------------------------------------------------------- #
# Each playbook steers the SAME three-stage fan-out at a domain: it appends a framing fragment to
# each stage prompt (LLM path), restricts the mapped file extensions, and selects the heuristic
# sink group (no-LLM path). The generic web-app playbook keeps the original behaviour verbatim
# (empty fragments, all code extensions, ai_audit_rules.json). The three web3 playbooks port
# open·kritt's `external-flow-analysis` and `Cosmos ABCI Panic Halt Review` (+ an Anchor one).
@dataclass(frozen=True)
class Playbook:
    key: str
    label: str
    description: str
    exts: frozenset          # code extensions this playbook maps; empty -> all _CODE_EXT
    chain: str               # evm | cosmos | solana | "" (generic)
    rules_group: str         # "" -> ai_audit_rules.json ; else key into ai_audit_web3_rules.json
    enum_frag: str = ""
    flow_frag: str = ""
    verify_frag: str = ""


_EVM_ENUM = (
    " FOCUS — this is a Solidity/EVM codebase. The externally-reachable entrypoints are the "
    "external/public contract functions plus fallback()/receive(); each first receives attacker "
    "calldata and value. Name each contract and its external/public functions."
)
_EVM_FLOW = (
    " The materially-different paths through a contract function are its value transfers, "
    "balance/accounting state changes, external calls (.call/.transfer/delegatecall), oracle "
    "reads, and access-control branches. One flow per sink/branch."
)
_EVM_VERIFY = (
    " You are auditing a SMART CONTRACT for LOSS-OF-FUNDS. Hunt, in order of payout: reentrancy "
    "(external call before the state update), missing/incorrect access control on a privileged "
    "function, oracle manipulation (missing staleness check, or a flash-loan-manipulatable spot "
    "price from reserves/slot0), unchecked arithmetic, and delegatecall/selfdestruct hijack. A "
    "finding needs a concrete on-chain attacker path. Set chain='evm' and fill contract + "
    "function."
)
_COSMOS_ENUM = (
    " FOCUS — this is a Cosmos-SDK / Go chain. The entrypoints are the WIRED ABCI methods "
    "(BeginBlock/EndBlock/DeliverTx/CheckTx/InitChain/Commit/PrepareProposal/ProcessProposal) and "
    "the module BeginBlocker/EndBlocker/handlers they call — the code consensus runs every block."
)
_COSMOS_FLOW = (
    " For each ABCI method, enumerate the FOUR panic classes as separate flows: (1) explicit "
    "panic(), (2) arithmetic panic (sdk.Int.Sub underflow / Quo divide-by-zero), (3) a Must*/"
    "mustGet helper that panics instead of erroring, (4) a bounds/type panic (slice index or "
    "type assertion without the comma-ok form). One flow per class per method."
)
_COSMOS_VERIFY = (
    " You are reviewing a Cosmos chain for a CONSENSUS HALT. A panic inside an ABCI method aborts "
    "block processing on every validator — a chain halt, not a caught error. Report ONLY panics "
    "that are (a) production-reachable inside a consensus phase AND (b) triggerable by "
    "attacker-controlled input (a crafted message/proposal field). A panic behind an "
    "operator-only or genesis-only path is NOT a finding. Set chain='cosmos' and fill contract "
    "(module) + function (the ABCI method)."
)
_ANCHOR_ENUM = (
    " FOCUS — this is a Rust/Anchor Solana program. The entrypoints are the instruction handlers "
    "(`pub fn name(ctx: Context<..>)` inside the #[program] module). Name each instruction and "
    "its Accounts struct."
)
_ANCHOR_FLOW = (
    " For each instruction, the materially-different paths are its account validation (owner / "
    "has_one / typed Account<T> vs UncheckedAccount/AccountInfo), signer checks, CPI "
    "(invoke/invoke_signed), and arithmetic on balances/amounts. One flow per check."
)
_ANCHOR_VERIFY = (
    " You are auditing an Anchor/Solana program. Hunt: a missing owner check (UncheckedAccount/"
    "AccountInfo used where a program-owned account is expected), a signer spoof (an authority "
    "not typed Signer<'info> and never asserted is_signer), unchecked integer arithmetic on "
    "lamports/amounts, and CPI confusion (invoke to a program whose id is not asserted). A "
    "finding needs a concrete attacker path in the Solana account model. Set chain='solana' and "
    "fill contract (program) + function (instruction)."
)

_SOL_EXTS = frozenset({".sol"})
_GO_EXTS = frozenset({".go"})
_RS_EXTS = frozenset({".rs"})

PLAYBOOKS: dict[str, Playbook] = {
    "external-flow-analysis": Playbook(
        key="external-flow-analysis",
        label="External-flow analysis (web app)",
        description="Map externally-reachable entrypoints and their flows; one agent per flow.",
        exts=frozenset(), chain="", rules_group="",
    ),
    "evm-external-flow": Playbook(
        key="evm-external-flow",
        label="EVM external-flow (Solidity)",
        description="Solidity: entrypoints -> flows (value/state/external-call/oracle) -> "
                    "loss-of-funds / reentrancy / access-control / oracle-manipulation.",
        exts=_SOL_EXTS, chain="evm", rules_group="evm-external-flow",
        enum_frag=_EVM_ENUM, flow_frag=_EVM_FLOW, verify_frag=_EVM_VERIFY,
    ),
    "cosmos-abci-halt": Playbook(
        key="cosmos-abci-halt",
        label="Cosmos ABCI panic-halt (Go)",
        description="Cosmos-Go: wired ABCI methods -> four panic classes -> "
                    "maliciously-triggerable, production-reachable consensus halts.",
        exts=_GO_EXTS, chain="cosmos", rules_group="cosmos-abci-halt",
        enum_frag=_COSMOS_ENUM, flow_frag=_COSMOS_FLOW, verify_frag=_COSMOS_VERIFY,
    ),
    "anchor-solana": Playbook(
        key="anchor-solana",
        label="Anchor account-model (Rust/Solana)",
        description="Anchor: instructions -> account/signer/CPI/arithmetic checks -> "
                    "missing-owner / signer-spoof / integer-overflow / CPI-confusion.",
        exts=_RS_EXTS, chain="solana", rules_group="anchor-solana",
        enum_frag=_ANCHOR_ENUM, flow_frag=_ANCHOR_FLOW, verify_frag=_ANCHOR_VERIFY,
    ),
}

DEFAULT_PLAYBOOK = "external-flow-analysis"


def resolve_playbook(key: str | None) -> Playbook:
    """The Playbook for a key, defaulting to the generic web-app one for an unknown/empty key."""
    return PLAYBOOKS.get((key or "").strip() or DEFAULT_PLAYBOOK, PLAYBOOKS[DEFAULT_PLAYBOOK])


def list_playbooks() -> list[dict[str, str]]:
    """The built-in playbooks, for the picker the /code-scan AI view offers."""
    return [{"key": p.key, "label": p.label, "description": p.description, "chain": p.chain}
            for p in PLAYBOOKS.values()]


# --------------------------------------------------------------------------- #
# stages (LLM path)
# --------------------------------------------------------------------------- #
def enumerate_entrypoints(root: Path, files: list[str], agent: AgentRunner,
                          warnings: list[str], pb: Playbook | None = None) -> list[Entrypoint]:
    """Stage 1 — map the externally-reachable entrypoints in ONE pass (context-cheap)."""
    pb = pb or PLAYBOOKS[DEFAULT_PLAYBOOK]
    listing = "\n".join(files[:_LISTING_CAP])
    if len(files) > _LISTING_CAP:
        warnings.append(f"repo has {len(files)} code files; mapped the first {_LISTING_CAP} in "
                        "the entrypoint pass")
    # a few likely entry files, read in full-ish, to anchor the map. A domain playbook (one
    # language) just takes the first files; the generic one heuristically picks app/main/routes.
    if pb.exts:
        anchors = files[:6]
    else:
        anchors = [f for f in files if re.search(r"(app|main|server|routes?|urls|handler|index)\.",
                                                 f, re.I)][:6]
    anchor_src = "\n\n".join(f"### {a}\n{_numbered(_read_snippet(root, a))}" for a in anchors)
    user = (f"FILE LISTING ({len(files)} code files):\n{listing}\n\n"
            f"ENTRY FILES:\n{anchor_src}\n\nMap the externally-reachable entrypoints.")
    try:
        parsed = _parse(agent(_ENUM_SYS + pb.enum_frag, user))
    except Exception as exc:  # noqa: BLE001
        raise AuditError(f"entrypoint enumeration failed: {exc}") from exc
    raw = parsed.get("entrypoints") if isinstance(parsed, dict) else None
    eps: list[Entrypoint] = []
    for i, item in enumerate(raw or []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        f = str(item.get("file") or "").strip().replace("\\", "/")
        if not name:
            continue
        eps.append(Entrypoint(id=f"ep{i+1}", name=name[:200], file=f,
                              kind=str(item.get("kind") or "handler").strip() or "handler",
                              note=str(item.get("note") or "")[:300]))
        if len(eps) >= MAX_ENTRYPOINTS:
            warnings.append(f"entrypoint map capped at {MAX_ENTRYPOINTS}")
            break
    return eps


def trace_flows(root: Path, ep: Entrypoint, agent: AgentRunner,
                pb: Playbook | None = None) -> list[Flow]:
    """Stage 2 — the flow frontier for one entrypoint (materially-different paths)."""
    pb = pb or PLAYBOOKS[DEFAULT_PLAYBOOK]
    src = _numbered(_read_snippet(root, ep.file)) if ep.file else ""
    user = (f"ENTRYPOINT: {ep.name}  (kind={ep.kind}, file={ep.file})\n"
            f"NOTE: {ep.note}\n\nSOURCE of {ep.file}:\n{src}\n\nEnumerate its flows.")
    try:
        parsed = _parse(agent(_FLOW_SYS + pb.flow_frag, user))
    except Exception:  # noqa: BLE001 — one entrypoint failing must not sink the run
        return []
    raw = parsed.get("flows") if isinstance(parsed, dict) else None
    flows: list[Flow] = []
    for i, item in enumerate(raw or []):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        flows.append(Flow(id=f"{ep.id}-f{i+1}", entrypoint_id=ep.id, title=title[:220],
                          file=ep.file, note=str(item.get("note") or "")[:300]))
        if len(flows) >= MAX_FLOWS_PER_EP:
            break
    return flows


def verify_flow(root: Path, flow: Flow, ep: Entrypoint, agent: AgentRunner,
                kb_search: Callable[[str, int, str], list[dict]] | None,
                pb: Playbook | None = None) -> Verdict:
    """Stage 3 — the fan-out. ONE agent, ONE flow: a concrete finding or an honest stub.

    Reuses ``reasoning.specialists`` for domain framing and the injected KB search for grounding.
    The concrete-or-stub decision is enforced by :func:`gate_finding` — a non-concrete claim is
    downranked to a stub, never surfaced as a finding.
    """
    from reasoning import specialists

    pb = pb or PLAYBOOKS[DEFAULT_PLAYBOOK]
    spec = specialists.route(_ShimState(), last_command=f"{ep.name} {flow.title} {flow.note}")
    framing = specialists.prompt_fragment(spec)
    grounding = _ground(f"{flow.title} {flow.note}", kb_search)
    ground_txt = ""
    if grounding:
        ground_txt = "\n\nKB GROUNDING (cite an id if you rely on it):\n" + "\n".join(
            f"  [{g['id']}] {g['title']}" for g in grounding)
    src = _numbered(_read_snippet(root, flow.file)) if flow.file else ""
    user = (f"FLOW TO VERIFY: {flow.title}\nfrom entrypoint {ep.name} ({ep.kind})\n"
            f"SINK/BRANCH: {flow.note}\n\nSOURCE of {flow.file}:\n{src}{ground_txt}")
    try:
        parsed = _parse(agent(_VERIFY_SYS + pb.verify_frag + framing, user))
    except Exception as exc:  # noqa: BLE001
        return Verdict(flow_id=flow.id, finding=False, reason=f"verify failed: {exc}")
    if not isinstance(parsed, dict):
        return Verdict(flow_id=flow.id, finding=False, reason="agent returned no JSON object")
    ok, _problems = validate_payload(parsed)
    concrete, reason = gate_finding(parsed)
    if not concrete:
        return Verdict(flow_id=flow.id, finding=False,
                       reason=str(parsed.get("reason") or reason))
    sev = str(parsed.get("severity") or "medium").lower()
    if sev not in _IMPACT_RANK:
        sev = "medium"
    refs = [str(r).replace("\\", "/") for r in (parsed.get("source_refs") or []) if str(r).strip()]
    # web3 provenance: prefer what the agent returned, fall back to the playbook chain + the file
    # stem / entrypoint name so a finding always carries chain/contract/function on a web3 playbook.
    contract = str(parsed.get("contract") or "").strip()[:120]
    if not contract and pb.chain:
        contract = Path(flow.file).stem if flow.file else ""
    function = str(parsed.get("function") or "").strip()[:120] or ep.name[:120]
    return Verdict(
        flow_id=flow.id, finding=True, title=str(parsed.get("title"))[:220],
        vuln_class=str(parsed.get("vuln_class") or "").strip()[:60],
        severity=sev, attacker_path=str(parsed.get("attacker_path"))[:1500],
        source_refs=refs, impact=str(parsed.get("impact"))[:600],
        confidence=str(parsed.get("confidence") or "medium").lower(),
        poc=str(parsed.get("poc") or "")[:400], kb_refs=grounding,
        chain=str(parsed.get("chain") or pb.chain).strip()[:20],
        contract=contract, function=function if pb.chain else "",
    )


class _ShimState:
    """A minimal engagement-state shim so ``reasoning.specialists.route`` can score a flow's
    domain from its text alone — the audit has no live services/findings to route on."""

    services: list = []
    findings: list = []
    hosts: list = []
    credentials = None


# --------------------------------------------------------------------------- #
# dedup + rank (open·kritt post_processing.py)
# --------------------------------------------------------------------------- #
def _finding_key(v: Verdict) -> tuple:
    """Same bug, found via more than one flow, collapses to one. Keyed on vuln class + the
    primary source location, NOT the title (two flows word the same bug differently)."""
    primary = sorted(v.source_refs)[0] if v.source_refs else v.title.lower()
    return (v.vuln_class.lower() or v.title.lower(), primary)


def dedup_and_rank(verdicts: list[Verdict]) -> list[Verdict]:
    """Concrete findings only, de-duplicated, severity-ranked by IMPACT_LEVELS (open·kritt's
    ``BATCH_SIZE``-style pass). A no-finding stub is never a finding."""
    best: dict[tuple, Verdict] = {}
    for v in verdicts:
        if not v.finding:
            continue
        k = _finding_key(v)
        cur = best.get(k)
        if cur is None:
            best[k] = v
            continue
        # keep the worse severity; merge source refs and flow provenance
        if _IMPACT_RANK.get(v.severity, 9) < _IMPACT_RANK.get(cur.severity, 9):
            for r in cur.source_refs:
                if r not in v.source_refs:
                    v.source_refs.append(r)
            best[k] = v
        else:
            for r in v.source_refs:
                if r not in cur.source_refs:
                    cur.source_refs.append(r)
    return sorted(best.values(),
                  key=lambda v: (_IMPACT_RANK.get(v.severity, 9), v.title.lower()))


def to_state_findings(session_id: str, ranked: list[Verdict], repo: str,
                      run_id: str | None = None) -> list[dict[str, Any]]:
    """Ranked verdicts -> the payload the (injected) engagement-state sink upserts. Kept as
    dicts so this module never imports ``state`` (orthogonality — the sink builds the record)."""
    out: list[dict[str, Any]] = []
    for v in ranked:
        loc = v.source_refs[0] if v.source_refs else repo
        out.append({
            "session_id": session_id,
            "title": v.title,
            "severity": _STATE_SEVERITY.get(v.severity, "info"),
            "target": loc,
            "evidence": (v.attacker_path + ("\n\nImpact: " + v.impact if v.impact else "")
                         + ("\n\nSource: " + ", ".join(v.source_refs) if v.source_refs else "")),
            "tool": "ai-audit",
            "reference": v.cwe or v.vuln_class,
            "source_run_id": run_id,
        })
    return out


def _summary(entrypoints: list[Entrypoint], flows: list[Flow],
             verdicts: list[Verdict], ranked: list[Verdict]) -> dict[str, Any]:
    by_sev = {s: 0 for s in IMPACT_LEVELS}
    for v in ranked:
        by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
    return {
        "entrypoints": len(entrypoints),
        "flows": len(flows),
        "verified": len(verdicts),
        "stubs": sum(1 for v in verdicts if not v.finding),
        "findings": len(ranked),
        "by_severity": by_sev,
    }


# --------------------------------------------------------------------------- #
# the pipeline
# --------------------------------------------------------------------------- #
def run_audit(
    repo: str | Path,
    agent: AgentRunner,
    verify_agent: AgentRunner | None = None,
    kb_search: Callable[[str, int, str], list[dict]] | None = None,
    changed_paths: set[str] | None = None,
    patched_since: str | None = None,
    playbook: str = "external-flow-analysis",
) -> dict[str, Any]:
    """The three-stage fan-out: enumerate -> trace -> verify (per flow) -> dedup+rank.

    ``agent`` runs the routine stages (enumerate/trace); ``verify_agent`` (defaults to ``agent``)
    runs the hard verify fan-out — the split is where ``reasoning.tiering`` points the hard step
    at a stronger model (see :func:`default_agents`). ``changed_paths`` (a set of repo-relative
    paths) restricts the whole audit to a diff — the ``patched-since`` mode. Executes nothing.
    """
    started = time.monotonic()
    root = runner.resolve_target(str(repo))
    n_files, too_big = runner.count_files(root)
    if too_big:
        raise AuditError(f"tree has more than {runner.MAX_FILES:,} files — point the audit at a "
                         "subdirectory")
    verify_agent = verify_agent or agent
    pb = resolve_playbook(playbook)
    warnings: list[str] = []

    files = _iter_code_files(root, changed_paths, pb.exts or None)
    if pb.exts and not files:
        warnings.append(f"playbook '{pb.key}' maps only {sorted(pb.exts)} files — none were "
                        "found in this tree")
    if changed_paths is not None and not files:
        warnings.append(f"no code files changed since {patched_since or 'the ref'} — nothing to "
                        "audit in patched-since mode")

    entrypoints = enumerate_entrypoints(root, files, agent, warnings, pb) if files else []

    flows: list[Flow] = []
    for ep in entrypoints:
        flows.extend(trace_flows(root, ep, agent, pb))
        if len(flows) >= MAX_FLOWS_TOTAL:
            warnings.append(f"flow frontier capped at {MAX_FLOWS_TOTAL}")
            break
    flows = flows[:MAX_FLOWS_TOTAL]

    ep_by_id = {e.id: e for e in entrypoints}
    verdicts = [verify_flow(root, fl, ep_by_id.get(fl.entrypoint_id, Entrypoint(fl.entrypoint_id,
                "", fl.file)), verify_agent, kb_search, pb) for fl in flows]

    ranked = dedup_and_rank(verdicts)
    return {
        "repo": str(root),
        "playbook": pb.key,
        "chain": pb.chain,
        "mode": "ai",
        "patched_since": patched_since,
        "changed_only": changed_paths is not None,
        "duration_s": round(time.monotonic() - started, 2),
        "files_scanned": n_files,
        "grounded": bool(kb_search),
        "entrypoints": [e.to_dict() for e in entrypoints],
        "flows": [f.to_dict() for f in flows],
        "verdicts": [v.to_dict() for v in verdicts],
        "findings": [_finding_dict(v) for v in ranked],
        "summary": _summary(entrypoints, flows, verdicts, ranked),
        "warnings": warnings,
        "static_only": True,
    }


def _finding_dict(v: Verdict) -> dict[str, Any]:
    d = v.to_dict()
    d.pop("flow_id", None)
    d.pop("finding", None)
    d.pop("reason", None)
    return d


# --------------------------------------------------------------------------- #
# production agent runners (backend/llm.py + reasoning.tiering)
# --------------------------------------------------------------------------- #
def default_agents(cfg: dict[str, Any] | None = None) -> tuple[AgentRunner, AgentRunner]:
    """(routine_agent, hard_agent) bound to HackPit's LLM layer. The hard agent routes the verify
    fan-out through ``reasoning.tiering`` so an operator can point it at a stronger model. Raises
    ``AuditError`` at CALL time (not import time) if the LLM layer is unreachable."""
    import llm
    from reasoning import tiering

    base = cfg or llm.load_config()

    def _run(step_kind: str) -> AgentRunner:
        step_cfg = tiering.select(base, step_kind)

        def agent(system: str, user: str) -> str:
            try:
                return llm.chat(system, user, step_cfg, max_tokens=1600)
            except llm.LLMError as exc:
                raise AuditError(f"LLM audit step failed: {exc}") from exc

        return agent

    return _run("routine"), _run("hard")


# --------------------------------------------------------------------------- #
# heuristic analyst — SAME three stages, no LLM (degradation + offline demo)
# --------------------------------------------------------------------------- #
def _load_rules(pb: Playbook | None = None) -> dict[str, Any]:
    """The heuristic sink/entrypoint rules for a playbook. The generic web-app playbook loads
    ``ai_audit_rules.json``; a web3 playbook loads its group from ``ai_audit_web3_rules.json``."""
    pb = pb or PLAYBOOKS[DEFAULT_PLAYBOOK]
    if pb.rules_group:
        try:
            groups = json.loads(_WEB3_RULES_PATH.read_text(encoding="utf-8")).get("playbooks", {})
            grp = groups.get(pb.rules_group)
            if isinstance(grp, dict):
                return grp
        except (OSError, ValueError):
            pass
        return {"entrypoint_patterns": [], "sinks": [], "taint_sources": []}
    try:
        return json.loads(_RULES_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"entrypoint_patterns": [], "sinks": [], "taint_sources": []}


def run_heuristic_audit(
    repo: str | Path,
    kb_search: Callable[[str, int, str], list[dict]] | None = None,
    changed_paths: set[str] | None = None,
    patched_since: str | None = None,
    playbook: str = "external-flow-analysis",
) -> dict[str, Any]:
    """A deterministic, no-LLM run of the SAME enumerate->trace->verify->rank pipeline.

    This is the graceful-degradation path (no LLM configured/reachable) and the source of the
    offline demo the screenshot uses. It reads source and matches the ``ai_audit_rules.json``
    sinks — real static analysis, framed as the same fan-out — and executes nothing.
    """
    started = time.monotonic()
    root = runner.resolve_target(str(repo))
    pb = resolve_playbook(playbook)
    rules = _load_rules(pb)
    ep_pats = [(p.get("kind", "handler"), re.compile(p["pattern"]))
               for p in rules.get("entrypoint_patterns", []) if p.get("pattern")]
    taint = re.compile("|".join(rules.get("taint_sources") or ["request"]))
    sinks = []
    for s in rules.get("sinks", []):
        try:
            sinks.append((s, re.compile(s["pattern"])))
        except (re.error, KeyError):
            continue

    warnings: list[str] = []
    files = _iter_code_files(root, changed_paths, pb.exts or None)
    if pb.exts and not files:
        warnings.append(f"playbook '{pb.key}' maps only {sorted(pb.exts)} files — none found")
    if changed_paths is not None and not files:
        warnings.append(f"no code files changed since {patched_since or 'the ref'}")

    entrypoints: list[Entrypoint] = []
    flows: list[Flow] = []
    verdicts: list[Verdict] = []

    for rel in files:
        text = _read_snippet(root, rel, cap=200_000)
        if not text:
            continue
        lines = text.splitlines()
        # stage 1 — entrypoints in this file, kept WITH their declaration line so a sink can map
        # to the route that ENCLOSES it (nearest preceding declaration), not just the first one.
        file_eps: list[tuple[int, Entrypoint]] = []
        for lineno, line in enumerate(lines, 1):
            for kind, rx in ep_pats:
                m = rx.search(line)
                if m:
                    name = (m.group(1) if m.groups() else line.strip())[:120]
                    ep = Entrypoint(id=f"ep{len(entrypoints)+1}", name=name, file=rel,
                                    kind=kind, note=f"declared at {rel}:{lineno}")
                    entrypoints.append(ep)
                    file_eps.append((lineno, ep))
                    break
            if len(entrypoints) >= MAX_ENTRYPOINTS:
                break

        def _enclosing(sink_line: int) -> Entrypoint | None:
            best = None
            for decl_line, ep in file_eps:
                if decl_line <= sink_line:
                    best = ep
                else:
                    break
            return best

        module_anchor: Entrypoint | None = None
        # stage 2+3 — sinks become flows, each verified into a concrete finding
        for lineno, line in enumerate(lines, 1):
            window = "\n".join(lines[max(0, lineno - 4):lineno + 1])
            for s, rx in sinks:
                if not rx.search(line):
                    continue
                if s.get("needs_taint") and not taint.search(window):
                    continue
                anchor = _enclosing(lineno)
                if anchor is None:
                    # a file with a sink but no enclosing route is still an entrypoint-bearing module
                    if module_anchor is None:
                        module_anchor = Entrypoint(id=f"ep{len(entrypoints)+1}", name=rel,
                                                   file=rel, kind="handler",
                                                   note="module with a reachable sink")
                        entrypoints.append(module_anchor)
                    anchor = module_anchor
                loc = f"{rel}:{lineno}"
                flow = Flow(id=f"{anchor.id}-f{len(flows)+1}", entrypoint_id=anchor.id,
                            title=f"{s['title']} in {anchor.name}", file=rel,
                            note=f"sink at {loc}")
                flows.append(flow)
                grounding = _ground(s["vuln_class"], kb_search)
                base_url = ""
                # {ep} = the function/method for a contract playbook (a Solidity fn, an ABCI
                # method, an Anchor instruction), else the web route or a placeholder.
                if pb.chain:
                    ep_ref = anchor.name
                else:
                    ep_ref = anchor.name if anchor.name.startswith("/") else "/<endpoint>"
                verdicts.append(Verdict(
                    flow_id=flow.id, finding=True, title=flow.title,
                    vuln_class=s["vuln_class"], severity=s.get("severity", "medium"),
                    attacker_path=s["attacker_path"].format(ep=ep_ref, loc=loc, base=base_url),
                    source_refs=[loc], impact=s.get("impact", ""), confidence="medium",
                    cwe=s.get("cwe"),
                    poc=s.get("poc", "").format(ep=ep_ref, base=base_url or "http://TARGET"),
                    kb_refs=grounding,
                    chain=rules.get("chain", pb.chain), contract=Path(rel).stem if pb.chain else "",
                    function=anchor.name if pb.chain else "",
                ))
                if len(flows) >= MAX_FLOWS_TOTAL:
                    break
            if len(flows) >= MAX_FLOWS_TOTAL:
                warnings.append(f"flow frontier capped at {MAX_FLOWS_TOTAL}")
                break
        if len(flows) >= MAX_FLOWS_TOTAL or len(entrypoints) >= MAX_ENTRYPOINTS:
            break

    ranked = dedup_and_rank(verdicts)
    n_files, _ = runner.count_files(root)
    return {
        "repo": str(root),
        "playbook": pb.key,
        "chain": pb.chain,
        "mode": "heuristic",
        "patched_since": patched_since,
        "changed_only": changed_paths is not None,
        "duration_s": round(time.monotonic() - started, 2),
        "files_scanned": n_files,
        "grounded": bool(kb_search),
        "entrypoints": [e.to_dict() for e in entrypoints],
        "flows": [f.to_dict() for f in flows],
        "verdicts": [v.to_dict() for v in verdicts],
        "findings": [_finding_dict(v) for v in ranked],
        "summary": _summary(entrypoints, flows, verdicts, ranked),
        "warnings": warnings,
        "static_only": True,
    }
