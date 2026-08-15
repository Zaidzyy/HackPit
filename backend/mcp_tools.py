"""THE MCP TOOL REGISTRY — eyes for an agent, and deliberately no hands.

`hexstrike-ai` already gives an agent hands: a hundred tools that run scanners. What no agent can
see is **this** engagement — its scope, its capture, its findings, its knowledge base. That is the
gap this closes, and it closes it by exposing READS.

*** THE LINE, AND IT IS NOT NEGOTIABLE. ***
HackPit's action routes take ``approved=true`` and ``dangerous_ack=true`` **in the request body**.
If an MCP tool could set those fields, the agent would approve itself and every gate in this
codebase would become theatre. This is exactly why ``proxy._gate_request`` hands the gate
``GATE_KEY_PLACEHOLDER`` — *the gate is never given the real thing.*

So:

* **NO TOOL MAY DECLARE AN APPROVAL FIELD.** :data:`APPROVAL_FIELD_NAMES` lists the spellings,
  :func:`audit_no_approval_fields` walks every registered tool's schema, and
  `test_mcp_safety.py` fails the build if one appears. The check is on the SCHEMA rather than on
  the handler body, because a field an agent cannot name is a field an agent cannot set.
* **NO TOOL MAY REACH AN EXECUTION PATH.** :data:`FORBIDDEN_CALLS` names the entry points that
  spawn things, and the test AST-walks every handler — and everything those handlers call inside
  this module — to assert none of them is reached. AST, not substring: this module's own
  docstrings NAME `run_kali` and `start_scan` while explaining that they must never be called,
  and a substring scan would trip on the sentence that exists to prevent the problem. That trap
  has bitten this repo twice, most recently in build #18's fronting module.
* **ONE WRITE-SHAPED TOOL, AND IT WRITES TO A PIECE OF PAPER.** ``propose_command`` appends to
  the approval queue (`cockpit/proposals.py`). A human reads it in the cockpit and then, if they
  want it, sends it to the execution route themselves with the gate fields THEY set. Approving a
  queue row does not run it; that is stated in the queue module and tested.

*** THIS MODULE DOES NOT IMPORT `mcp`, AND THAT IS STRUCTURAL. ***
The registry is plain data and plain functions. The transport (`backend/mcp_server.py`) is what
speaks the protocol. Splitting them means the safety lock can enumerate every exposed tool with
no MCP SDK installed — so the hermetic suite covers the line that matters even in CI, where the
optional dependency is absent.

TRANSPORT NOTE, from build #19's own week. Burp's MCP server rejects browser-looking
`User-Agent`s and non-allowlisted `Origin` headers as DNS-rebinding defence, and it was measured
answering 403 to every combination tried. HackPit's is **stdio**, which needs no port and
therefore has no rebinding surface to defend. If it is ever moved to HTTP it needs that same
protection, and route auth is still not built.
"""

from __future__ import annotations

import ast
import inspect
import os
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- #
# THE TWO PROHIBITIONS, AS DATA
# --------------------------------------------------------------------------- #
#: Every spelling of "I approve this" that appears on a HackPit request model, plus the obvious
#: near-misses. A tool schema may not contain any of them, at any nesting depth.
APPROVAL_FIELD_NAMES = frozenset({
    "approved", "approve", "dangerous_ack", "dangerous_acknowledged", "danger_ack",
    "ack", "acknowledged", "confirm", "confirmed", "red_confirm", "force", "yes",
    "authorized", "authorised", "consent", "override",
})

#: Function names that START something. A handler that calls one of these has hands.
#: Named as bare identifiers AND as attribute tails, because a bare call and an attribute call
#: are the same call.
#:
#: *** THE ENTRY POINTS THAT ALREADY HAVE A WHOLE-TREE LOCK ARE DELIBERATELY ABSENT. ***
#: The first draft named the `:kali` shell and the tunnel starter here, and `test_kali.py` and
#: `test_tunnels.py` immediately failed the build ON THIS FILE — correctly, both times. Those
#: scanners strip docstrings and comments but NOT other string literals, because blanking every
#: string would go blind to `import_module("cockpit.kali")`, which is precisely the indirection
#: they exist to catch. A name in a frozenset is a real hit by their rules.
#:
#: The fix is neither to weaken those scanners nor to spell the names evasively. It is to notice
#: that this list was carrying a SECOND, WEAKER COPY of locks that already cover every file in
#: the tree — this one included — and that catch imports and `import_module` indirection a
#: name-match here never could. The stronger lock is the one that fired, twice.
#:
#: THE RULE THIS LEAVES: a HackPit entry point belongs here only if it has NO whole-tree lock of
#: its own. Currently that means the ZAP surfaces and this build's own verbs. If you add a name
#: and the suite fails somewhere unrelated, that is this list duplicating a better lock — delete
#: the name, do not narrow the lock.
FORBIDDEN_CALLS = frozenset({
    # process spawners
    "run", "Popen", "call", "check_call", "check_output", "system", "spawn", "spawnv",
    "popen", "fork", "execv", "execve",
    # HackPit execution entry points with no whole-tree lock of their own
    "execute", "run_command", "start_proxy", "start_scan", "start_spider",
    "start_intruder", "send", "start", "apply_auth_context",
    "install_bypass_headers", "set_breaking", "release", "replace_held", "panic",
    "kill", "stop_proxy", "stop_scan",
})

#: `subprocess.run` is forbidden; `str.join`, `list.sort` and friends are not. Attribute calls
#: whose receiver is one of these are exempt from the bare-name check, because the name collision
#: is with a method rather than with an entry point.
SAFE_RECEIVERS = frozenset({
    "json", "re", "os.path", "str", "list", "dict", "sorted", "time", "textwrap",
})


class ToolSpec(BaseModel):
    """One exposed tool. ``schema`` is JSON Schema, exactly as the MCP client will see it."""

    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=dict)
    #: True for `propose_command` and nothing else. Declared so the audit can assert the count
    #: rather than trusting a reader to notice a second one appearing.
    writes: bool = False

    model_config = {"arbitrary_types_allowed": True}


_REGISTRY: dict[str, ToolSpec] = {}
_HANDLERS: dict[str, Callable[..., Any]] = {}


def tool(name: str, description: str, schema: dict[str, Any] | None = None,
         writes: bool = False) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register a read tool. The decorator is the ONLY way in, so the audit sees everything."""

    def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
        _REGISTRY[name] = ToolSpec(name=name, description=description,
                                   input_schema=schema or _EMPTY_SCHEMA, writes=writes)
        _HANDLERS[name] = fn
        return fn

    return wrap


_EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}, "additionalProperties": False}


def _asdict(obj: Any) -> dict[str, Any]:
    """Pydantic model, dataclass or dict -> dict. The state store mixes all three."""
    import dataclasses

    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    return {"value": str(obj)}


def _kb_search_module() -> Any:
    """`pipeline/search.py`, importable the way main.py makes it importable.

    It does a bare ``import embed``, so the pipeline directory has to be ON THE PATH rather than
    imported as a package — which is why `from pipeline import search` fails and this exists.
    Found by checking, not assumed: the first draft of this module was written against
    `pipeline.search`, `state.store.list_findings`, `arsenal.catalog` and three other names that
    do not exist. Build #14's lesson, arriving on schedule.
    """
    import sys
    from pathlib import Path

    pipeline_dir = Path(__file__).resolve().parents[1] / "pipeline"
    if str(pipeline_dir) not in sys.path:
        sys.path.insert(0, str(pipeline_dir))
    import search as kb_search                                     # noqa: PLC0415

    return kb_search


_KB_CACHE: list[dict[str, Any]] | None = None


def _kb_entries() -> list[dict[str, Any]]:
    """The KB, loaded once per process and filtered exactly as main.py filters it.

    ``filter_excluded`` is applied HERE and not left to the caller, because main.py applies it
    "once, at the door — they can't leak anywhere", and an MCP server that skipped it would be a
    second door onto the same data with the excluded entries still behind it.
    """
    global _KB_CACHE
    if _KB_CACHE is not None:
        return _KB_CACHE
    from pathlib import Path

    kb_search = _kb_search_module()
    # THE FILE, not the directory — `load_entries(kb_path: Path)` wants `entries.jsonl` itself,
    # and main.py's DATA_KB is spelled that way. Passing the directory returned zero entries and
    # this function reported "the knowledge base is not built", which was a confident wrong
    # answer about a KB sitting right there with 2,744 rows in it.
    data_kb = Path(__file__).resolve().parents[1] / "data" / "kb" / "entries.jsonl"
    try:
        _KB_CACHE = kb_search.filter_excluded(kb_search.load_entries(data_kb))
    except Exception:                                              # noqa: BLE001
        _KB_CACHE = []
    return _KB_CACHE


def _schema(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    """Build a schema with ``additionalProperties: False``.

    *** THE `additionalProperties: False` IS PART OF THE LINE, NOT TIDINESS. ***
    A schema that allows extra properties lets a client send `{"approved": true}` alongside the
    declared arguments. Whether the handler reads it is beside the point — the audit's claim is
    "an agent cannot NAME an approval field", and an open schema makes that claim false.
    """
    return {
        "type": "object", "properties": props,
        "required": required or [],
        "additionalProperties": False,
    }


def tools() -> list[ToolSpec]:
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


def handler(name: str) -> Callable[..., Any] | None:
    return _HANDLERS.get(name)


def call(name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Dispatch. An unknown tool is an ERROR VALUE, not an exception — an MCP client shows it."""
    fn = _HANDLERS.get(name)
    if fn is None:
        return {"error": f"no such tool {name!r}", "available": sorted(_REGISTRY)}
    try:
        return fn(**(arguments or {}))
    except TypeError as exc:
        return {"error": f"bad arguments for {name!r}: {exc}"}
    except Exception as exc:                                        # noqa: BLE001
        # A read that fails is reported; it never takes the server down, and it never falls back
        # to a plausible empty answer — this repo's recurring silent zero.
        return {"error": f"{name} failed: {type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- #
# THE AUDIT — importable, so the lock test and the server agree on the rules
# --------------------------------------------------------------------------- #
def _schema_field_names(node: Any, out: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                out.update(str(k).lower() for k in value)
            _schema_field_names(value, out)
    elif isinstance(node, list):
        for item in node:
            _schema_field_names(item, out)


def audit_no_approval_fields() -> list[str]:
    """Offending "<tool>.<field>" strings. EMPTY IS THE ONLY ACCEPTABLE ANSWER."""
    bad: list[str] = []
    for spec in tools():
        names: set[str] = set()
        _schema_field_names(spec.input_schema, names)
        for field in sorted(names & APPROVAL_FIELD_NAMES):
            bad.append(f"{spec.name}.{field}")
        if spec.input_schema.get("additionalProperties") is not False:
            bad.append(f"{spec.name}.<additionalProperties is not False>")
    return bad


def _called_names(tree: ast.AST) -> set[str]:
    """Every callee name in an AST, as bare names and as attribute tails. AST, NOT SUBSTRING."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name):
            found.add(fn.id)
        elif isinstance(fn, ast.Attribute):
            receiver = fn.value
            recv_name = receiver.id if isinstance(receiver, ast.Name) else ""
            if recv_name in SAFE_RECEIVERS:
                continue
            found.add(fn.attr)
    return found


def audit_no_execution_paths() -> list[str]:
    """Offending "<tool> -> <call>" strings. EMPTY IS THE ONLY ACCEPTABLE ANSWER.

    Walks each handler AND every function this module defines that a handler could reach, because
    a handler that calls a local helper that calls `subprocess.run` has hands at one remove.
    """
    import textwrap

    module_fns = {
        name: obj for name, obj in globals().items()
        if inspect.isfunction(obj) and getattr(obj, "__module__", "") == __name__
    }
    bad: list[str] = []
    for tool_name in sorted(_REGISTRY):
        fn = _HANDLERS[tool_name]
        seen: set[str] = set()
        queue = [fn]
        while queue:
            current = queue.pop()
            key = getattr(current, "__name__", "")
            if key in seen:
                continue
            seen.add(key)
            try:
                # *** DEDENT, NOT lstrip. ***
                # `lstrip()` strips only the FIRST line's indentation, so a handler defined at
                # any indentation raised IndentationError and — before this was fixed — was
                # silently skipped. The control test in test_mcp_safety.py planted a handler that
                # calls `subprocess.run` and the audit reported CLEAN.
                tree = ast.parse(textwrap.dedent(inspect.getsource(current)))
            except (OSError, SyntaxError, IndentationError) as exc:
                # *** AN UNREADABLE HANDLER IS AN OFFENCE, NOT A PASS. ***
                # "We could not check this" must never read as "this is fine" — the whole point
                # of the audit is that its empty result means something. Same rule as
                # `read_ok` everywhere else in this codebase.
                bad.append(f"{tool_name} -> <UNAUDITABLE: {type(exc).__name__}>")
                continue
            for called in sorted(_called_names(tree)):
                if called in FORBIDDEN_CALLS:
                    bad.append(f"{tool_name} -> {called}")
                nxt = module_fns.get(called)
                if nxt is not None:
                    queue.append(nxt)
    return bad


# --------------------------------------------------------------------------- #
# THE TOOLS — reads
# --------------------------------------------------------------------------- #
_CONTAINER = _schema({
    "container": {"type": "string", "description": "Sandbox container the ZAP proxy runs in."},
    "port": {"type": "integer", "description": "Proxy port. Defaults to the standard one."},
}, ["container"])


@tool("hackpit_engagement", "The active engagement: its program scope, what is in and out of "
      "scope, and its rules of engagement. Read this FIRST — every other answer is bounded by "
      "it, and a host outside it must not be suggested.",
      _schema({"engagement_id": {"type": "string"}}))
def hackpit_engagement(engagement_id: str = "") -> dict[str, Any]:
    from cockpit import engagement as eng_mod

    if engagement_id:
        rec = eng_mod.get_active(engagement_id)
        records = [rec] if rec is not None else []
    else:
        records = list(eng_mod.list_active())
    out = []
    for rec in records:
        matcher = eng_mod.resolved_scope(rec)
        out.append({
            "engagement_id": rec.engagement_id,
            "target": rec.target,
            # `authorization` is the operator's free-text rules-of-engagement note. It is
            # INCLUDED because it is the single most useful thing an agent can be told about
            # what it may suggest — and it is not, and has never been, an enforced field.
            "authorization": rec.authorization,
            "active": rec.active,
            "scope": matcher.describe(),
            "includes": matcher.includes(),
            "excludes": matcher.excludes(),
            "unbounded": matcher.unbounded(),
            # NAMES ONLY. `bypass_header_names` is names-only by construction (build #18) and
            # this reads that field rather than any value-carrying one.
            "bypass_header_names": list(getattr(rec, "bypass_header_names", []) or []),
        })
    return {"engagements": out, "count": len(out)}


@tool("hackpit_proxy_history", "Search the recording proxy's captured traffic. Filter by host, "
      "method, status (404 or 4 for the whole class), URL substring, whether the request carries "
      "parameters, response content-type, and engagement scope. Returns the honest counts: how "
      "many were scanned, matched, unparseable, and whether the scan was truncated.",
      _schema({
          "container": {"type": "string"},
          "port": {"type": "integer"},
          "host": {"type": "string"},
          "method": {"type": "array", "items": {"type": "string"}},
          "status": {"type": "array", "items": {"type": "integer"}},
          "url_contains": {"type": "string"},
          "has_param": {"type": "boolean"},
          "content_type": {"type": "string"},
          "in_scope_of": {"type": "string"},
          "limit": {"type": "integer"},
      }, ["container"]))
def hackpit_proxy_history(container: str, port: int = 0, limit: int = 50,
                          **filters: Any) -> dict[str, Any]:
    from cockpit import proxy

    filt = proxy.HistoryFilter(**{k: v for k, v in filters.items() if v is not None})
    page = proxy.filter_history(container, port or proxy.DEFAULT_PROXY_PORT, filt,
                                limit=max(1, min(int(limit or 50), 200)))
    return {
        "total": page.total, "scanned": page.scanned, "matched": page.matched,
        "returned": page.returned, "dropped": page.dropped,
        "read_ok": page.read_ok, "truncated": page.truncated, "scope_note": page.scope_note,
        "exchanges": [
            {"id": e.id, "method": e.request.method, "url": e.request.url,
             "status": e.response.status, "size": e.response.size_bytes}
            for e in page.exchanges
        ],
    }


@tool("hackpit_scan_status", "Every active scan ZAP knows about, with its real progress, request "
      "count and alert count — observed from ZAP, never cached.", _CONTAINER)
def hackpit_scan_status(container: str, port: int = 0) -> dict[str, Any]:
    from cockpit import proxy

    scans, read_ok = proxy.scans_snapshot(container, port or proxy.DEFAULT_PROXY_PORT)
    return {"read_ok": read_ok,
            "scans": [s.model_dump() for s in scans]}


@tool("hackpit_alerts", "Vulnerability alerts the scanner has raised, with risk, confidence, the "
      "URL and the attacked parameter.", _CONTAINER)
def hackpit_alerts(container: str, port: int = 0) -> dict[str, Any]:
    from cockpit import proxy

    alerts, read_ok = proxy.alerts_snapshot(container, port or proxy.DEFAULT_PROXY_PORT)
    return {"read_ok": read_ok, "count": len(alerts),
            "alerts": [a.model_dump() for a in alerts]}


@tool("hackpit_session_health", "Does the captured traffic still look AUTHENTICATED? An expired "
      "session makes a scan report zero findings, which reads exactly like 'the application is "
      "secure'. Verdict is ok | suspect | unknown, and unknown is a real answer.", _CONTAINER)
def hackpit_session_health(container: str, port: int = 0) -> dict[str, Any]:
    from cockpit import proxy

    exchanges = proxy.history(container, port or proxy.DEFAULT_PROXY_PORT, count=200)
    return proxy.session_health(exchanges)


@tool("hackpit_intercept_state", "Is request interception on, and is a request being held right "
      "now? Read-only — this cannot turn breaking on, replace a held request, forward it or drop "
      "it. Those are a human's presses.", _CONTAINER)
def hackpit_intercept_state(container: str, port: int = 0) -> dict[str, Any]:
    from cockpit import intercept, proxy

    state = intercept.observed(container, port or proxy.DEFAULT_PROXY_PORT)
    # The HELD MESSAGE IS NOT RETURNED. A held request routinely carries a session cookie and an
    # Authorization header, and this is the one read whose payload is a live credential rather
    # than recorded traffic. The agent is told THAT something is held, which is the actionable
    # fact; reading it is the operator's screen.
    return {
        "breaking": state.breaking, "held": state.held, "read_ok": state.read_ok,
        "held_message_bytes": len(state.message), "detail": state.detail,
    }


@tool("hackpit_fronting", "Is this host behind a CDN or WAF, and what is in front of it? "
      "PASSIVE — CNAME/ASN/SPF lookups plus the single HEAD request a browser makes opening the "
      "page. `unknown` means the lookups did not answer, which is a DIFFERENT answer from "
      "`not-fronted` and must not be read as it.",
      _schema({"host": {"type": "string"}}, ["host"]))
def hackpit_fronting(host: str) -> dict[str, Any]:
    from cockpit import fronting

    # `with_ct` left at its default. Certificate transparency is a third-party query about a
    # host, and an agent poll should not be what triggers it — the operator turns that on from
    # the cockpit where the choice is visible.
    return fronting.analyse(host).model_dump()


@tool("hackpit_engagement_state", "Everything the engagement has learned: hosts, services, "
      "endpoints, findings, and WHICH credentials are known (names only — this store never "
      "hands back a secret value).",
      _schema({"session_id": {"type": "string"}}, ["session_id"]))
def hackpit_engagement_state(session_id: str) -> dict[str, Any]:
    from state import store

    summary = store.load(session_id)
    return {
        "session_id": session_id,
        "hosts": [_asdict(h) for h in summary.hosts],
        "services": [_asdict(s) for s in summary.services],
        "endpoints": [_asdict(e) for e in summary.endpoints],
        "findings": [_asdict(f) for f in summary.findings],
        # *** NAMES AND KINDS ONLY. *** The Credential record carries a value, and this is a
        # channel to a third-party model. What an agent needs to reason is "there is a domain
        # admin credential for HOST", never the password itself.
        "credentials": [
            {k: v for k, v in _asdict(c).items()
             if k in ("host", "username", "kind", "domain", "source_run_id")}
            for c in summary.credentials
        ],
    }


@tool("hackpit_findings", "Just the findings for a session — what has actually been proven, with "
      "severity. A narrower read than the full engagement state.",
      _schema({"session_id": {"type": "string"}}, ["session_id"]))
def hackpit_findings(session_id: str) -> dict[str, Any]:
    from state import store

    rows = [_asdict(f) for f in store.load(session_id).findings]
    return {"session_id": session_id, "count": len(rows), "findings": rows}


@tool("hackpit_kb_search", "Search the offensive knowledge base — 2,744 curated entries of "
      "technique, methodology and writeup material. Use it to ground a suggestion in something "
      "written down rather than in recall.",
      _schema({"query": {"type": "string"}, "limit": {"type": "integer"},
               "mode": {"type": "string"}}, ["query"]))
def hackpit_kb_search(query: str, limit: int = 8, mode: str = "lexical") -> dict[str, Any]:
    """*** IT DEFAULTS TO `lexical`, NOT `hybrid`, AND THAT IS DELIBERATE. ***

    The vector half needs Ollama up and an embedding index built; `pipeline/search.py` raises
    SystemExit when it cannot embed a query, which in a long-lived stdio server would take the
    whole process down rather than fail one call. main.py's route degrades to lexical for the
    same reason. Lexical BM25 needs nothing and always answers, so that is the floor; an agent
    that wants the vector half can ask for it and gets an error string if it is unavailable.
    """
    entries = _kb_entries()
    if not entries:
        return {"query": query, "count": 0, "results": [],
                "error": "the knowledge base is not built in this checkout — "
                         "data/kb/entries.jsonl is missing or empty. This is not 'no results'."}
    hits = _kb_search_module().search(entries, query, max(1, min(int(limit or 8), 25)),
                                      mode=mode if mode in ("hybrid", "lexical", "vector")
                                      else "lexical")
    return {"query": query, "mode": mode, "count": len(hits),
            "results": [
                {"id": h.get("id"), "title": h.get("title"), "category": h.get("category"),
                 "source": h.get("source"), "snippet": h.get("snippet")}
                for h in hits
            ]}


@tool("hackpit_arsenal", "The tool catalog: what is installed in the sandboxes, what each is "
      "for, the phases it belongs to and the command TEMPLATE it takes. Filter by phase, or by "
      "a technique needle.",
      _schema({"phase": {"type": "string"}, "needle": {"type": "string"},
               "limit": {"type": "integer"}}))
def hackpit_arsenal(phase: str = "", needle: str = "", limit: int = 20) -> dict[str, Any]:
    from arsenal import loader

    ars = loader.load()
    rows = loader.suggest(ars, phase or None, needle or None,
                          limit=max(1, min(int(limit or 20), 80)))
    return {
        "catalog_size": len(ars.tools),
        "count": len(rows),
        "tools": [
            {"name": t.name, "category": t.category, "purpose": t.purpose,
             "phases": list(t.phases or []), "platform": t.platform,
             # `template`, not `command` — the field name was checked against the dataclass
             # rather than guessed, after six guesses in this module turned out wrong.
             "templates": [{"label": tpl.label, "template": tpl.template} for tpl in t.templates],
             "kb_entry_id": t.kb_entry_id}
            for t in rows
        ],
    }


@tool("hackpit_exploit_lookup", "The CVE / exploit index, including the curated overlay. Ask by "
      "CVE id, or by product and version — the VERSION VERDICT outranks token similarity, and "
      "`no fixed release` is a real answer for a vulnerability that has never been patched.",
      _schema({"cve": {"type": "string"}, "product": {"type": "string"},
               "version": {"type": "string"}, "limit": {"type": "integer"}}))
def hackpit_exploit_lookup(cve: str = "", product: str = "", version: str = "",
                           limit: int = 20) -> dict[str, Any]:
    from exploits import index as exploit_index

    idx = exploit_index.get_index()
    if not idx.ready:
        return {"ready": False, "results": [],
                "error": "the exploit index is not built — data/kb/exploitdb.json is absent. "
                         "That is 'nothing to look in', NOT 'no such vulnerability'."}
    if cve:
        return {"ready": True, "query": cve, "results": idx.for_cve(cve)[:limit]}
    hits = idx.search_service(product, version or None, limit=max(1, min(int(limit or 20), 60)))
    return {
        "ready": True,
        "query": f"{product} {version}".strip(),
        "results": [_asdict(h) for h in hits],
        "cves": idx.cves_for(product, version or None)[:limit],
    }


@tool("hackpit_command_scope", "Would this command be IN SCOPE for the engagement? Judges the "
      "hosts a command names against the program scope and answers runnable / not / unknown. "
      "Ask BEFORE proposing — a proposal aimed at an out-of-scope host wastes a human's review.",
      _schema({"command": {"type": "string"}, "engagement_id": {"type": "string"}},
              ["command"]))
def hackpit_command_scope(command: str, engagement_id: str = "") -> dict[str, Any]:
    import attack_path

    from cockpit import engagement as eng_mod

    resolved = None
    if engagement_id:
        rec = eng_mod.get_active(engagement_id)
        if rec is not None:
            resolved = eng_mod.resolved_scope(rec)
    runnable, reason = attack_path.check_command_scope(command, resolved)
    return {
        "command": command,
        # (None, None) is "no scope declared, nothing to judge against" — reported as unknown
        # rather than as a pass, which is the same distinction the fronting verdict makes.
        "verdict": "unknown" if runnable is None else ("in-scope" if runnable else "out-of-scope"),
        "reason": reason or "",
        "hosts_named": attack_path.command_hosts(command),
    }


@tool("hackpit_proposals", "The approval queue: commands waiting for a human, with the gate "
      "verdict each would meet. Read this to see what has already been proposed before proposing "
      "it again.",
      _schema({"session_id": {"type": "string"}, "status": {"type": "string"}}))
def hackpit_proposals(session_id: str = "", status: str = "") -> dict[str, Any]:
    from cockpit import proposals

    rows = proposals.listing(session_id or None, status)
    return {"count": len(rows),
            "proposals": [
                {**r.model_dump(), "command_line": r.command_line(),
                 "gate_preview": proposals.gate_preview(r)}
                for r in rows
            ]}


# --------------------------------------------------------------------------- #
# THE OFFENSIVE-BUILD READS (Q2/Q3) — graphs, governance, discovery
#
# These arrived AFTER the first registry (which was written around the proxy/ZAP world) and give
# an agent eyes onto what the recent builds actually know: the attack-path graphs, the OPPLAN, and
# the discovery surfaces. Every one is a READ — it reads a store or rebuilds a graph from stored
# state, and none reaches an execution path (the AST audit proves it). The two secret-bearing
# surfaces (JS-recon secrets, engagement credentials) hand back NAMES/locations only, never a value.
# --------------------------------------------------------------------------- #
@tool("hackpit_killchain_graph", "The cross-domain kill-chain: the merged web/cloud/on-prem graph "
      "for a session plus the computed route from an owned foothold to the objective, with each "
      "hop's technique. Read-only — it stitches the STORED cloud + AD graphs and the engagement "
      "findings; nothing runs. With no session (or demo=true) it returns the synthetic sample.",
      _schema({"session_id": {"type": "string"},
               "demo": {"type": "boolean", "description": "Return the synthetic sample graph."}}))
def hackpit_killchain_graph(session_id: str = "", demo: bool = False) -> dict[str, Any]:
    from adgraph import store as ad_store
    from cloudgraph import store as cloud_store
    from killchain import service as kc_service
    from state import store as state_store

    if demo or not session_id:
        graph = kc_service.build_demo()
    else:
        cloud_row = cloud_store.latest_for_session(session_id)
        ad_row = ad_store.latest_for_session(session_id)
        cloud_dict = cloud_row.get("graph") if isinstance(cloud_row, dict) else None
        ad_dict = ad_row.get("graph") if isinstance(ad_row, dict) else None
        findings = state_store.load(session_id).findings
        graph = kc_service.build_from_session(cloud_dict, ad_dict, findings)
        if not graph.nodes:
            graph = kc_service.build_demo()
    # grounder left None — the per-hop technique still resolves; only the KB citation is omitted,
    # which an agent that wants it can get from hackpit_kb_search.
    return kc_service.graph_payload(graph, None, None)


@tool("hackpit_cloud_graph", "The parsed cloud IAM privilege-escalation graph for a session — "
      "principals, roles, resources and the abusable edges between them, plus which nodes are "
      "OWNED. Read-only; the latest parsed graph for the session, or null if none has been parsed.",
      _schema({"session_id": {"type": "string"}}, ["session_id"]))
def hackpit_cloud_graph(session_id: str) -> dict[str, Any]:
    from cloudgraph import store as cloud_store

    row = cloud_store.latest_for_session(session_id)
    if not row:
        return {"session_id": session_id, "graph": None,
                "note": "no cloud IAM graph has been parsed for this session yet — this is "
                        "'nothing parsed', NOT 'no privilege-escalation path exists'."}
    return {"session_id": session_id, **row}


@tool("hackpit_ad_graph", "The parsed Active Directory attack-path graph for a session — the "
      "BloodHound-style nodes and the abusable edges (ACLs, sessions, delegation) between them. "
      "Read-only; the latest parsed graph, or null if none has been parsed.",
      _schema({"session_id": {"type": "string"}}, ["session_id"]))
def hackpit_ad_graph(session_id: str) -> dict[str, Any]:
    from adgraph import store as ad_store

    row = ad_store.latest_for_session(session_id)
    if not row:
        return {"session_id": session_id, "graph": None,
                "note": "no AD graph has been parsed for this session yet — this is 'nothing "
                        "parsed', NOT 'no attack path exists'."}
    return {"session_id": session_id, **row}


@tool("hackpit_governance", "The engagement's governance package: the RoE, ConOps and "
      "deconfliction documents, and the full OPPLAN — its objectives tree, status counts, and "
      "MITRE ATT&CK coverage. Read this to know what the operator is trying to ACHIEVE, not just "
      "what is in scope. Read-only.",
      _schema({"session_id": {"type": "string"}}, ["session_id"]))
def hackpit_governance(session_id: str) -> dict[str, Any]:
    from state import governance as gov

    return gov.package(session_id)


@tool("hackpit_recon_surface", "The ranked recon surface for a session — the hosts worth testing "
      "first, each with the WHY that earned its place (open services, CVE stacks, param/auth "
      "endpoints, findings) and the endpoints worth pointing a scanner at. Read-only; ranks the "
      "engagement's stored state, runs no scan.",
      _schema({"session_id": {"type": "string"}}, ["session_id"]))
def hackpit_recon_surface(session_id: str) -> dict[str, Any]:
    from cockpit import recon

    return recon.rank_surface(session_id).model_dump()


@tool("hackpit_discover_results", "Parameter/content discovery results for a session — the "
      "discovered parameter names (with the injection/SSRF/redirect-magnet ones flagged) and the "
      "discovered paths, per job. Counts are what HAPPENED. Read-only.",
      _schema({"session_id": {"type": "string"}}))
def hackpit_discover_results(session_id: str = "") -> dict[str, Any]:
    from cockpit import discover

    jobs = discover.list_jobs(session_id or None)
    return {"count": len(jobs), "jobs": [j.model_dump() for j in jobs]}


@tool("hackpit_jsrecon_results", "JavaScript-recon results for a session — endpoints and "
      "parameters mined from JS, recovered source-map paths, and secrets found. SECRETS ARE "
      "NAMES ONLY: type, location, a value-free masked preview and the loot-file path — never the "
      "value itself (mirror of the credential read). Read-only.",
      _schema({"session_id": {"type": "string"}}))
def hackpit_jsrecon_results(session_id: str = "") -> dict[str, Any]:
    from cockpit import jsrecon

    # `MinedSecret` carries only type/source_url/verified/masked/loot_file by construction — the
    # value lives solely in the loot file — so model_dump() here cannot leak a secret. A jsrecon
    # test pins that property; this read inherits it rather than re-filtering.
    jobs = jsrecon.list_jobs(session_id or None)
    return {"count": len(jobs), "jobs": [j.model_dump() for j in jobs]}


# --------------------------------------------------------------------------- #
# THE ONE WRITE-SHAPED TOOL — it writes to a piece of paper
# --------------------------------------------------------------------------- #
@tool("propose_command",
      "Put ONE command in the approval queue for a human to review. IT DOES NOT RUN. A human "
      "reads it in the cockpit and, if they want it, sends it to the execution route themselves "
      "with the approval flags THEY set. Say WHY in `rationale` and what you expect to learn in "
      "`expected` — a proposal without a reason is a command the operator has to reverse-engineer.",
      _schema({
          "command": {"type": "string", "description": "The binary. One command, not a pipeline."},
          "args": {"type": "array", "items": {"type": "string"}},
          "rationale": {"type": "string"},
          "expected": {"type": "string"},
          "session_id": {"type": "string"},
          "engagement_id": {"type": "string"},
      }, ["command"]),
      writes=True)
def propose_command(command: str, args: list[str] | None = None, rationale: str = "",
                    expected: str = "", session_id: str = "",
                    engagement_id: str = "") -> dict[str, Any]:
    """*** THERE IS NO APPROVAL ARGUMENT HERE AND THERE NEVER WILL BE. ***

    The schema above is closed (`additionalProperties: False`) and names six fields, none of
    which is a gate field. That is the whole of item 6's line, expressed where a client can see
    it. The gate verdict comes back on the response so the proposer LEARNS what would stand in
    the way — which is useful — without being able to do anything about it.
    """
    from cockpit import proposals

    p = proposals.propose(command, args or [], rationale=rationale, expected=expected,
                          source="mcp", session_id=session_id or None,
                          engagement_id=engagement_id or None)
    return {
        "proposal_id": p.id,
        "status": p.status,
        "command_line": p.command_line(),
        "gate_preview": proposals.gate_preview(p),
        "note": "QUEUED, NOT RUN. A human approves this in the cockpit and then sends it to the "
                "execution route with their own approval flags. Nothing was executed.",
    }


# --------------------------------------------------------------------------- #
# THE OPT-IN EXECUTION SURFACE — OFF BY DEFAULT, AND THE DEFAULT IS THE POINT
#
# The whole registry above is eyes-and-no-hands: the audit refuses to expose any tool that can
# self-approve or reach an execution path, and `test_mcp_safety.py` fails the build if one does.
# That is the right default for a PUBLIC tool anyone can install — installing the MCP server must
# never silently hand an AI the ability to run offensive commands.
#
# But the operator can DELIBERATELY remove the human-in-the-loop for their own engagement by
# setting HACKPIT_MCP_EXECUTE=1. When they do, one execution-capable tool is registered:
# `hackpit_execute`, wired to the SAME executor the cockpit route uses, self-approving the gate
# fields (approved / dangerous_ack) so no human press is required. This is a real capability with
# a real cost, so:
#
#   * It is OFF unless the env var is exactly "1". No flag → this tool does not exist, the audits
#     see nothing new, and CI (which never sets the flag) stays green.
#   * The execution audit stays HONEST: `audit_no_execution_paths()` still reports this tool as an
#     execution path. Only `mcp_server.preflight()` TOLERATES it, only when the flag is set, and it
#     prints a loud banner saying the human gate is off. The approval-FIELD audit is never relaxed
#     — the agent still cannot NAME an approval field; the tool hardcodes it in its body.
#   * It is a second write-shaped tool, by design, and only in this mode.
# --------------------------------------------------------------------------- #
#: The env-gated execution tools. Named so `mcp_server.preflight()` can tolerate exactly these
#: (and nothing else) when execution mode is on.
EXECUTION_TOOL_NAMES: tuple[str, ...] = ("hackpit_execute", "hackpit_surface")


#: Surfaces the loop/UI drive that ALSO make sense as an agent action. `repeater` is EXCLUDED — its
#: send is human-only (test_repeater_is_human_only); the graphs and `:kali`/`:terminal` stay out too.
_MCP_SURFACES: tuple[str, ...] = (
    "recon", "discover", "jsrecon", "nuclei", "intruder", "smuggle", "cache", "race",
    "credentials", "tokens", "codescan", "oob", "tunnels", "c2", "capture",
)


def _surface_req(ReqCls: Any, params: dict[str, Any], sid: str, eid: str) -> Any:
    """Build a surface request from MCP params, SELF-APPROVING the gate (this is the hands). The
    agent's params can never carry a gate field — they are STRIPPED, then forced — and the ids are
    filled only where the model actually has them."""
    fields = ReqCls.model_fields
    data = {k: v for k, v in dict(params or {}).items() if k not in ("approved", "dangerous_ack")}
    if "approved" in fields:
        data["approved"] = True
    if "dangerous_ack" in fields:
        data["dangerous_ack"] = True
    if "session_id" in fields and not data.get("session_id"):
        data["session_id"] = sid or eid or None
    if "engagement_id" in fields and not data.get("engagement_id"):
        data["engagement_id"] = eid or None
    return ReqCls(**data)


def _run_surface(surface: str, params: dict[str, Any], sid: str, eid: str) -> dict[str, Any]:
    """Route a surface name + params to that surface's real start engine. The engine's own
    scope / target-lock / mode checks still apply; this only self-approves the human gate. The
    `.start`/`send` calls below are why `audit_no_execution_paths` honestly flags `hackpit_surface`."""
    s = (surface or "").strip().lower()
    p = dict(params or {})
    if s == "repeater":
        raise ValueError("repeater is human-only — its send has no agent path (by design)")
    if s == "recon":
        from cockpit import recon
        fn = recon.start_passive if str(p.get("mode", "")).lower() == "passive" else recon.start_active
        return _asdict(fn(_surface_req(recon.ReconRequest, p, sid, eid)))
    if s == "discover":
        from cockpit import discover
        return _asdict(discover.start(_surface_req(discover.DiscoverRequest, p, sid, eid)))
    if s == "jsrecon":
        from cockpit import jsrecon
        return _asdict(jsrecon.start(_surface_req(jsrecon.JsReconRequest, p, sid, eid)))
    if s == "nuclei":
        from cockpit import nuclei
        return _asdict(nuclei.start(_surface_req(nuclei.NucleiRequest, p, sid, eid)))
    if s == "intruder":
        from cockpit import intruder
        return _asdict(intruder.start(_surface_req(intruder.IntruderRequest, p, sid, eid)))
    if s == "smuggle":
        from cockpit import smuggle
        return _asdict(smuggle.start(_surface_req(smuggle.SmuggleRequest, p, sid, eid)))
    if s == "cache":
        from cockpit import cache
        return _asdict(cache.start(_surface_req(cache.CacheRequest, p, sid, eid)))
    if s == "race":
        from cockpit import race
        return _asdict(race.start(_surface_req(race.RaceRequest, p, sid, eid)))
    if s == "credentials":
        from cockpit import credattack, router
        if str(p.get("mode", "")).lower() == "crack":
            return _asdict(router.start_crack(_surface_req(credattack.CrackRequest, p, sid, eid)))
        return _asdict(router.start_spray(_surface_req(credattack.SprayRequest, p, sid, eid)))
    if s == "tokens":
        from cockpit import router, tokenjobs
        return _asdict(router.start_token_crack(_surface_req(tokenjobs.TokenCrackRequest, p, sid, eid)))
    if s == "codescan":
        from codescan import router as cs_router
        return _asdict(cs_router.codescan_scan(_surface_req(cs_router.ScanIn, p, sid, eid)))
    if s == "oob":
        from oob import tokens as oob_tokens
        return _asdict(oob_tokens.mint(eid or sid or "", note=str(p.get("note", ""))))
    if s == "tunnels":
        from cockpit import tunnels
        return _asdict(tunnels.start_tunnel(_surface_req(tunnels.TunnelStartRequest, p, sid, eid)))
    if s == "c2":
        from cockpit import sliver
        return _asdict(sliver.start_server(_surface_req(sliver.SliverServerRequest, p, sid, eid)))
    if s == "capture":
        from cockpit import hostbench
        return _asdict(hostbench.start(_surface_req(hostbench.BenchStartRequest, p, sid, eid)))
    raise ValueError(f"unknown or non-invokable surface: {surface!r}")

#: True only when the operator has explicitly opted in. Read once, at import.
EXECUTE_ENABLED: bool = os.environ.get("HACKPIT_MCP_EXECUTE") == "1"


def _register_execution_tools() -> None:
    """Register the opt-in execution surface. Called at import when EXECUTE_ENABLED, and callable
    directly from the safety test so the opt-in behaviour is a tested invariant, not an accident."""

    @tool("hackpit_execute",
          "RUN a command in the sandbox with NO human approval. This exists only when the operator "
          "set HACKPIT_MCP_EXECUTE=1 — it self-approves the gate and executes. Prefer "
          "propose_command unless you have been told this engagement runs agent-driven. One "
          "command, not a pipeline; it still passes the executor's target-lock and mode rules.",
          _schema({
              "command": {"type": "string", "description": "The binary. One command, not a pipeline."},
              "args": {"type": "array", "items": {"type": "string"}},
              "session_id": {"type": "string"},
              "engagement_id": {"type": "string"},
              "timeout_seconds": {"type": "integer"},
          }, ["command"]),
          writes=True)
    def hackpit_execute(command: str, args: list[str] | None = None, session_id: str = "",
                        engagement_id: str = "", timeout_seconds: int = 0) -> dict[str, Any]:
        """*** THIS IS THE HANDS. *** It sets `approved` and `dangerous_ack` itself and calls the
        real executor. There is no human between the agent and the target here; that is what the
        operator opted into. The executor's own target-lock and mode resolution still apply."""
        from cockpit import executor
        from cockpit.models import ExecRequest

        req = ExecRequest(
            command=command, args=args or [], approved=True, dangerous_ack=True,
            session_id=session_id or None, engagement_id=engagement_id or None,
            timeout_seconds=timeout_seconds or None,
        )
        record = executor.run_command(req)
        return _asdict(record)

    @tool("hackpit_surface",
          "RUN a HackPit SURFACE with NO human approval — exists only when HACKPIT_MCP_EXECUTE=1. It "
          "self-approves the gate and calls the surface's real start engine (scope-filtered, "
          "state-ingesting; the engine's target-lock and mode rules still apply). `surface` is one of: "
          "recon, discover, jsrecon, nuclei, intruder, smuggle, cache, race, credentials, tokens, "
          "codescan, oob, tunnels, c2, capture. `params` matches that surface (see the cockpit surface "
          "contract, e.g. nuclei {targets, severities, attach_session}). NOT here: repeater — its send "
          "is human-only. Prefer propose_command / a read tool unless this engagement runs agent-driven.",
          _schema({
              "surface": {"type": "string", "description": "One of the invokable surface names."},
              "params": {"type": "object", "description": "Surface params (see the surface contract)."},
              "session_id": {"type": "string"},
              "engagement_id": {"type": "string"},
          }, ["surface"]),
          writes=True)
    def hackpit_surface(surface: str, params: dict[str, Any] | None = None,
                        session_id: str = "", engagement_id: str = "") -> dict[str, Any]:
        """*** HANDS for the surfaces. *** Self-approves and calls the surface's real start engine —
        the same opt-in the operator made for hackpit_execute. The agent cannot name a gate field
        (the schema does not declare one and `_surface_req` strips any it tries to pass)."""
        return _run_surface(surface, params or {}, session_id, engagement_id)


if EXECUTE_ENABLED:
    _register_execution_tools()
