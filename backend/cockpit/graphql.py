"""GraphQL — DETECTION, PARSING, and the operator's round trip.

*** THIS MODULE IS PURE. It does no I/O, spawns nothing and reaches no daemon. ***
That is what lets the hermetic suite cover every claim below against fixtures, the same way
``exchange_matches`` is covered, and it is why a GraphQL filter needs no daemon to be trusted.

Why it exists, from a measurement rather than a hunch. The source evaluation on 2026-08-05
produced exactly one HackPit capability finding, and it was evidence-backed:

    Report #61's injection point is a GraphQL argument, reachable only by composing a query with
    variables. Attacking it through the repeater means hand-writing quadruple-escaped
    JSON-in-JSON.

Measured against the tree the same day: ``graphql`` appeared in the backend once, incidentally,
in ``attack_path.py``; in the frontend zero times; and the arsenal carried no GraphQL tooling.

*** IT IS RECOGNISED BY BODY SHAPE, NOT BY PATH. ***
``/graphql`` is a convention, not a rule. Shopify serves GraphQL from
``/admin/api/2024-01/graphql.json``, plenty of APIs mount it at ``/api``, and a site can perfectly
well serve JSON that is not GraphQL from a path called ``/graphql``. A path test would therefore
both miss real endpoints and invent fake ones. The test is: a JSON object (or a batched ARRAY of
them) carrying a string ``query``, or ``?query=`` on a GET whose value opens like a GraphQL
document, or ``Content-Type: application/graphql`` where the body IS the document.

:attr:`GraphQLDetection.path_hint` records that the path LOOKS like GraphQL, separately, because
it is worth reporting to an operator — but nothing in this module branches on it.

*** NAMES, NEVER VALUES. ***
:class:`GraphQLArgument` has no value field, deliberately, and for the reason build #19 gave
``CookieAttachment`` none: a GraphQL argument is routinely a session token (report #61's is
literally called ``token``), these models travel into run records, endpoint records, API
responses and onto the screen, and never handing a secret over cannot regress while redacting it
afterwards depends on a redactor being correct forever. The operator's own repeater body is the
one place values live, and that is a body they typed.

*** WHY THE ARGUMENT NAMES ARE `field.argument`. ***
Not a spelling this module invented. ``docs/proof/build20_graphql_api.py`` measured ZAP raising a
High SQL Injection with ``param='search.limit'`` while the JSON variable key was ``search_limit``
— a DOT where the JSON has an UNDERSCORE. So ZAP's own GraphQL variant names an argument by
field and argument, and matching it means the names HackPit shows the operator BEFORE a scan are
the names ZAP will report in the alerts AFTER it.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field

#: Paths that CONVENTIONALLY carry GraphQL. Reported as a hint; never used as the test. See the
#: module docstring — a path heuristic both misses real endpoints and invents fake ones.
PATH_HINTS: tuple[str, ...] = ("/graphql", "/api/graphql", "/v1/graphql", "/gql", "/graphiql")

#: Content types whose BODY IS the document, with no JSON envelope at all.
_RAW_DOC_TYPES = ("application/graphql", "application/graphql-response+json")

_OPERATION_WORDS = ("query", "mutation", "subscription")

#: A GraphQL name: /[_A-Za-z][_0-9A-Za-z]*/ per the spec.
_NAME = r"[_A-Za-z][_0-9A-Za-z]*"


class GraphQLArgument(BaseModel):
    """One argument on one field. NO VALUE FIELD — see the module docstring.

    ``name`` is the ``field.argument`` spelling ZAP uses in its alerts, so what an operator is
    shown before a scan is what they will read in the findings after it.
    """

    name: str = Field(..., description="`field.argument`, e.g. `search.limit`.")
    field_name: str = Field(..., description="The field the argument belongs to.")
    argument: str = Field(..., description="The argument's own name.")
    from_variable: bool = Field(
        False,
        description="True when the argument's value comes from a $variable rather than being "
        "written inline. Both are reachable by the scanner; this is the operator's cue for which "
        "key in `variables` to edit.",
    )


class GraphQLOperation(BaseModel):
    """One operation out of a document. Structure only."""

    operation_type: str = Field("query", description="query | mutation | subscription.")
    operation_name: str = Field("", description="Empty for an anonymous or shorthand operation.")
    root_fields: list[str] = Field(default_factory=list)
    arguments: list[GraphQLArgument] = Field(default_factory=list)
    variable_names: list[str] = Field(
        default_factory=list, description="Names declared in the operation's ($x: T) list."
    )


class GraphQLDetection(BaseModel):
    """Is this GraphQL, how do we know, and what is in it.

    ``is_graphql`` is decided by SHAPE. ``path_hint`` is decided by path and decides nothing.
    """

    is_graphql: bool = False
    where: str = Field(
        "", description="json_body | json_batch | query_param | raw_document — where the document "
        "was found. Empty when this is not GraphQL."
    )
    path_hint: bool = Field(
        False, description="The URL path is one of the conventional GraphQL paths. REPORTED, "
        "never tested on: see the module docstring."
    )
    batched: bool = Field(
        False, description="A JSON ARRAY of operations in one request. Worth knowing on its own — "
        "batching is how rate limits and per-operation authorisation get walked around."
    )
    operations: list[GraphQLOperation] = Field(default_factory=list)
    introspection: bool = Field(
        False, description="The document asks for __schema or __type."
    )
    note: str = Field(
        "", description="Why a document that LOOKED like GraphQL could not be parsed. A request "
        "this module cannot parse is still reported as GraphQL when its envelope says so — the "
        "parse failing is not evidence the request is something else."
    )

    @property
    def argument_names(self) -> list[str]:
        seen: list[str] = []
        for op in self.operations:
            for arg in op.arguments:
                if arg.name not in seen:
                    seen.append(arg.name)
        return seen


# --------------------------------------------------------------------------- #
# the tokenizer — small on purpose
# --------------------------------------------------------------------------- #
def _mask(document: str) -> str:
    """Blank out comments and string contents, preserving LENGTH and structure.

    Structure-aware parsing without a real parser only works if ``#``, ``{`` and ``(`` inside a
    string literal cannot be mistaken for syntax. Replacing rather than deleting keeps every
    offset valid, so a match found in the mask indexes straight back into the original.
    """
    out = list(document)
    i, n = 0, len(document)
    while i < n:
        ch = document[i]
        if ch == "#":
            while i < n and document[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == '"':
            triple = document.startswith('"""', i)
            quote = '"""' if triple else '"'
            i += len(quote)
            while i < n:
                if document[i] == "\\" and not triple:
                    out[i] = " "
                    if i + 1 < n:
                        out[i + 1] = " "
                    i += 2
                    continue
                if document.startswith(quote, i):
                    i += len(quote)
                    break
                out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def _matching(masked: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index just past the bracket that closes the one at ``start``. -1 if unbalanced."""
    depth = 0
    for i in range(start, len(masked)):
        if masked[i] == open_ch:
            depth += 1
        elif masked[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def _arguments_in(masked: str, document: str, field_name: str, inside: str,
                  offset: int) -> list[GraphQLArgument]:
    """Argument names for one field, from the text between its parentheses."""
    out: list[GraphQLArgument] = []
    depth = 0
    i = 0
    while i < len(inside):
        ch = inside[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0:
            m = re.match(rf"({_NAME})\s*:", inside[i:])
            if m:
                name = m.group(1)
                rest = inside[i + m.end():]
                out.append(GraphQLArgument(
                    name=f"{field_name}.{name}", field_name=field_name, argument=name,
                    from_variable=bool(re.match(r"\s*\$", rest)),
                ))
                i += m.end()
                continue
        i += 1
    return out


def parse_document(document: str) -> tuple[list[GraphQLOperation], str]:
    """A GraphQL document -> its operations. Returns ``(operations, note)``; NEVER raises.

    Deliberately NOT a full GraphQL parser, and deliberately not a regex over raw text either.
    It masks strings and comments first (:func:`_mask`) and then walks brackets, which is enough
    to name operations, their variables, their root fields and those fields' arguments — the four
    things the rest of this build needs. Fragments, directives and nested selections are stepped
    over rather than modelled.

    A document it cannot make sense of comes back as ``([], note)`` and the CALLER decides what
    that means. It is never evidence the request was not GraphQL: an operation this parser trips
    on is still an operation.
    """
    text = str(document or "")
    if not text.strip():
        return [], "the document is empty"
    masked = _mask(text)
    ops: list[GraphQLOperation] = []

    # Anonymous shorthand: a document that is just a selection set.
    head = masked.lstrip()
    if head.startswith("{"):
        start = masked.index("{")
        end = _matching(masked, start, "{", "}")
        if end < 0:
            return [], "unbalanced braces in the selection set"
        op = GraphQLOperation(operation_type="query", operation_name="")
        _fill_selection(op, masked, text, start, end)
        return [op], ""

    for m in re.finditer(rf"\b({'|'.join(_OPERATION_WORDS)})\b", masked):
        # Only at the top level: a `query` appearing inside a selection set is a field name.
        if masked[:m.start()].count("{") != masked[:m.start()].count("}"):
            continue
        op = GraphQLOperation(operation_type=m.group(1))
        cursor = m.end()
        name = re.match(rf"\s*({_NAME})", masked[cursor:])
        if name:
            op.operation_name = name.group(1)
            cursor += name.end()
        var_open = masked.find("(", cursor)
        brace = masked.find("{", cursor)
        if var_open != -1 and (brace == -1 or var_open < brace):
            var_end = _matching(masked, var_open, "(", ")")
            if var_end > 0:
                op.variable_names = re.findall(rf"\$({_NAME})\s*:",
                                               text[var_open:var_end])
                cursor = var_end
                brace = masked.find("{", cursor)
        if brace == -1:
            ops.append(op)
            continue
        end = _matching(masked, brace, "{", "}")
        if end < 0:
            return ops, "unbalanced braces in a selection set"
        _fill_selection(op, masked, text, brace, end)
        ops.append(op)

    if not ops:
        return [], "no query, mutation or subscription found"
    return ops, ""


def _fill_selection(op: GraphQLOperation, masked: str, text: str, brace: int, end: int) -> None:
    """Root fields and their arguments, from one selection set."""
    inner_masked = masked[brace + 1:end - 1]
    base = brace + 1
    i = 0
    while i < len(inner_masked):
        ch = inner_masked[i]
        if ch == "{":
            skip = _matching(inner_masked, i, "{", "}")
            i = skip if skip > 0 else len(inner_masked)
            continue
        m = re.match(rf"({_NAME})", inner_masked[i:])
        if not m:
            i += 1
            continue
        name = m.group(1)
        after = i + m.end()
        # `alias: field` — the FIELD is what the server sees and what ZAP names.
        alias = re.match(rf"\s*:\s*({_NAME})", inner_masked[after:])
        if alias:
            name = alias.group(1)
            after += alias.end()
        if name not in op.root_fields:
            op.root_fields.append(name)
        paren = re.match(r"\s*\(", inner_masked[after:])
        if paren:
            open_at = after + paren.end() - 1
            close = _matching(inner_masked, open_at, "(", ")")
            if close > 0:
                op.arguments.extend(_arguments_in(
                    masked, text, name,
                    text[base + open_at + 1:base + close - 1], base + open_at))
                after = close
        i = after


# --------------------------------------------------------------------------- #
# detection
# --------------------------------------------------------------------------- #
def looks_like_document(text: str) -> bool:
    """Does this text OPEN like a GraphQL document?

    Used only for the ``?query=`` case, where there is no envelope to go on. A JSON body is
    decided by its envelope instead — a ``query`` key that holds a string is the shape, whatever
    the string turns out to say — because refusing to call a malformed operation GraphQL would
    hide exactly the requests worth looking at.
    """
    head = _mask(str(text or "")).lstrip()
    if head.startswith("{"):
        return True
    return bool(re.match(rf"\b({'|'.join(_OPERATION_WORDS)}|fragment)\b", head))


def _header(headers: Any, name: str) -> str:
    want = name.lower()
    for h in headers or ():
        hn = getattr(h, "name", None)
        hv = getattr(h, "value", None)
        if hn is None and isinstance(h, (tuple, list)) and len(h) == 2:
            hn, hv = h
        if str(hn or "").lower() == want:
            return str(hv or "")
    return ""


def _detect_json(payload: Any) -> tuple[bool, bool]:
    """``(is_graphql, batched)`` for a decoded JSON body."""
    if isinstance(payload, dict):
        return isinstance(payload.get("query"), str), False
    if isinstance(payload, list) and payload:
        every = all(isinstance(x, dict) and isinstance(x.get("query"), str) for x in payload)
        return every, every
    return False, False


def detect(method: str, url: str, headers: Any = (), body: str = "") -> GraphQLDetection:
    """Is this request GraphQL? BY SHAPE. See the module docstring.

    Never raises: a body that is not JSON, not text, or half-truncated by a capture comes back
    ``is_graphql=False`` rather than propagating, because this runs over every row of a capture
    and one malformed message must not empty a filter.
    """
    out = GraphQLDetection()
    url = str(url or "")
    path = url.split("?", 1)[0].lower()
    out.path_hint = any(path.endswith(h) or h + "/" in path + "/" for h in PATH_HINTS)

    body = str(body or "")
    ctype = _header(headers, "content-type").lower()
    documents: list[str] = []

    if any(t in ctype for t in _RAW_DOC_TYPES) and body.strip():
        out.is_graphql, out.where, documents = True, "raw_document", [body]
    else:
        payload: Any = None
        if body.strip():
            try:
                payload = json.loads(body)
            except (ValueError, TypeError):
                payload = None
        if payload is not None:
            ok, batched = _detect_json(payload)
            if ok:
                out.is_graphql = True
                out.batched = batched
                out.where = "json_batch" if batched else "json_body"
                documents = ([str(x.get("query")) for x in payload] if batched
                             else [str(payload.get("query"))])

    if not out.is_graphql and "?" in url:
        from urllib.parse import parse_qs, urlsplit

        raw = parse_qs(urlsplit(url).query).get("query") or []
        if raw and looks_like_document(raw[0]):
            out.is_graphql, out.where, documents = True, "query_param", [raw[0]]

    if not out.is_graphql:
        return out

    notes: list[str] = []
    for doc in documents:
        ops, note = parse_document(doc)
        out.operations.extend(ops)
        if note:
            notes.append(note)
        if "__schema" in doc or "__type" in doc:
            out.introspection = True
    out.note = "; ".join(dict.fromkeys(notes))
    return out


def detect_exchange(exchange: Any) -> GraphQLDetection:
    """:func:`detect` for a ``CapturedExchange``/``RepeaterExchange``-shaped object."""
    try:
        req = exchange.request
        return detect(req.method, req.url, req.headers, req.body)
    except Exception:  # noqa: BLE001 - a detector must never break a capture read
        return GraphQLDetection()


# --------------------------------------------------------------------------- #
# the repeater's round trip — item 3
# --------------------------------------------------------------------------- #
class GraphQLEditorState(BaseModel):
    """A captured GraphQL body, split so it can be EDITED without hand-escaping JSON in JSON.

    *** A BODY THAT WILL NOT SPLIT IS RETURNED AS RAW, AND SAYS SO. ***
    ``parsed=False`` with ``raw_body`` intact. It is never silently discarded and never silently
    rewritten — what the operator captured is what they get back. That is the same rule build #19
    applied to the cookie jar for the same reason: state that quietly rewrites a request is a trap.
    """

    parsed: bool = False
    query: str = ""
    variables: str = Field(
        "{}", description="The `variables` object, PRETTY-PRINTED, for a human to edit."
    )
    operation_name: str = ""
    raw_body: str = Field("", description="Exactly what was captured. Always populated.")
    note: str = Field("", description="Why it would not split, when it would not.")


def split_body(body: str) -> GraphQLEditorState:
    """Captured body -> query + variables + operationName. NEVER raises, never discards.

    A batched request (a JSON array) does NOT split: there are several operations and a single
    query box would silently drop all but one of them. It comes back raw, with the reason said
    out loud, which is the honest answer — see :func:`build_body` for the other half.
    """
    raw = str(body or "")
    state = GraphQLEditorState(raw_body=raw)
    if not raw.strip():
        state.note = "the captured body is empty"
        return state
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError) as exc:
        state.note = f"the body is not JSON ({exc.__class__.__name__}); edit it as raw text"
        return state
    if isinstance(payload, list):
        plural = "operation" if len(payload) == 1 else "operations"
        state.note = (
            f"this is a BATCHED request carrying {len(payload)} {plural}. One query box would "
            "drop all but one of them, so it stays raw."
        )
        return state
    if not isinstance(payload, dict) or not isinstance(payload.get("query"), str):
        state.note = "the body is JSON but carries no string `query`; edit it as raw text"
        return state

    variables = payload.get("variables")
    if variables is None:
        variables = {}
    state.parsed = True
    state.query = payload["query"]
    state.operation_name = str(payload.get("operationName") or "")
    try:
        state.variables = json.dumps(variables, indent=2, sort_keys=True)
    except (TypeError, ValueError):
        state.variables = "{}"
        state.note = "the captured `variables` could not be re-rendered; it is shown as empty"
    return state


def build_body(query: str, variables: str = "{}", operation_name: str = "") -> tuple[str, str]:
    """query + variables + name -> one correct JSON body. Returns ``(body, error)``.

    ``error`` non-empty means the VARIABLES would not parse and NOTHING was built — the caller
    must then send what the operator typed rather than a body this function guessed at. This is
    the whole point of the feature: nobody hand-writes quadruple-escaped JSON-in-JSON, and nobody
    gets a silently-corrected one either.

    ``operationName`` is omitted entirely when blank rather than sent as ``null``. Both are legal;
    servers differ on whether a null name with several operations in the document is an error, and
    omitting the key is the shape a browser actually sends.
    """
    text = (variables or "").strip() or "{}"
    try:
        decoded = json.loads(text)
    except (ValueError, TypeError) as exc:
        return "", f"variables is not valid JSON: {exc}"
    if not isinstance(decoded, dict):
        return "", (f"variables must be a JSON object, not {type(decoded).__name__} — GraphQL "
                    "names its variables, so an array or a bare value has nowhere to bind")

    payload: dict[str, Any] = {"query": str(query or "")}
    if operation_name.strip():
        payload["operationName"] = operation_name.strip()
    payload["variables"] = decoded
    return json.dumps(payload), ""
