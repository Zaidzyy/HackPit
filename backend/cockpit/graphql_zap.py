"""GraphQL against a real endpoint and against ZAP — items 4 and 5.

Everything here does I/O. The PURE half (detection, parsing, the repeater's round trip) is
``cockpit/graphql.py`` and stays importable with no daemon anywhere.

*** EVERY CLAIM IN THIS MODULE WAS MEASURED FIRST. ***
``docs/proof/build20_graphql_api.py`` — 55 passed, 0 failed against ZAP 2.17.0 running
graphql-alpha-0.33.0 — and it changed the plan. Three of its findings are load-bearing here:

1. *** ZAP CANNOT TELL YOU WHY AN IMPORT FAILED. ***
   ``graphql/action/importUrl`` answers ``illegal_parameter``, with the same message, for an
   endpoint that REFUSES introspection the way production does and for a host that is not
   listening at all. The build brief required "disabled / error / empty are three facts and the
   operator needs to know which". ZAP cannot supply that, so :func:`probe_schema` asks the
   endpoint itself and classifies. That is a measurement, not a preference.

2. *** THE GENERATED OPERATIONS NEVER ENTER THE SITES TREE. ***
   The plan assumed: import -> generate -> land in the tree -> ``ascan`` attacks them there. The
   middle link is missing. ZAP sends the generated operations at the endpoint for real — the
   proof's origin log counts them every time — and the tree never hears about them. Measured on a
   fresh daemon, on a node primed through the proxy and on one that was not, and out to 60
   seconds in case the insert was merely late. So :func:`import_schema` reports what it did
   WITHOUT claiming the scanner can now reach any of it, and item 5 scans CAPTURED operations
   instead. Which is the better answer anyway: an operator holding report #61's request has the
   request, not the schema.

3. *** ZAP VALIDATES ITS OWN BOUNDS NOT AT ALL. ***
   ``setOptionMaxQueryDepth?Integer=-1`` answers OK and reads back ``-1``. So :func:`apply_bounds`
   WARNS on a bound that will generate nothing and SENDS IT ANYWAY — the bound is the operator's
   to set. What it will not do is report a depth it did not apply: every field is read back and
   ``observed`` is what the panel shows.

*** ZAP PERSISTS THESE OPTIONS ACROSS RESTARTS AND ACROSS SESSIONS. ***
They are configuration, not session state, and they survive ``core/action/newSession``. This
project has been bitten twice by exactly that (``api.disablekey`` persisting into ``$HOME/.ZAP``,
and the scan policy), so :func:`observed_bounds` exists to read the daemon's CURRENT values and
every apply reports requested-vs-observed rather than assuming.

*** NO NEW GATE, IN EITHER DIRECTION. ***
A schema probe is one request to a URL a human typed, in the position the repeater already takes:
the press is the approval. Where it could refuse — a host outside the named engagement's scope —
it WARNS AND CONTINUES and says so in ``scope_note``, because human approval is the only bound.
A GraphQL scan is an ``ascan`` like any other and runs behind the EXISTING four gates via
``proxy.start_scan``; :func:`scan_plan_for` computes a target and stops.

KNOWN GAP, RECORDED RATHER THAN HALF-BUILT: field-suggestion / clairvoyance enumeration when
introspection is disabled. When ``probe_schema`` returns ``disabled`` there is no fallback here —
the arsenal's ``clairvoyance`` entry is the tool for that job and it is a separate, gated command.
"""

from __future__ import annotations

import json
import subprocess
import time
from typing import Any

from pydantic import BaseModel, Field

from . import graphql_enum

#: The introspection document. Deliberately the ONE ZAP itself sends (measured on the wire in
#: docs/proof/build20_graphql_api.py: `query IntrospectionQuery { __schema { ... } }`), trimmed to
#: what this module renders. A server that refuses introspection refuses this identically.
INTROSPECTION_QUERY = """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args { name description type { ...TypeRef } defaultValue }
        type { ...TypeRef }
        isDeprecated
      }
      inputFields { name type { ...TypeRef } defaultValue }
      enumValues(includeDeprecated: true) { name }
    }
  }
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name } } }
}"""

#: Words a server uses when it is refusing introspection ON PURPOSE. Matched case-insensitively
#: against the `errors[].message` text. NOT a blocklist and nothing is refused on the strength of
#: it — it only decides whether the answer reads `disabled` or the more general `error`, and the
#: raw message is reported either way so a phrasing this list does not know is still legible.
_DISABLED_PHRASES = (
    "introspection is not allowed",
    "introspection is disabled",
    "get introspection query",
    "introspectionquery",
    "__schema` is not available",
    "cannot query field \"__schema\"",
    "cannot query field '__schema'",
    "introspection has been disabled",
)


class SchemaArgument(BaseModel):
    """One argument on one schema field. NO VALUE — see cockpit/graphql.py on why."""

    name: str
    type: str = ""
    required: bool = False


class SchemaField(BaseModel):
    name: str
    type: str = ""
    description: str = ""
    args: list[SchemaArgument] = Field(default_factory=list)

    @property
    def argument_names(self) -> list[str]:
        return [f"{self.name}.{a.name}" for a in self.args]


class SchemaProbe(BaseModel):
    """What the endpoint said when asked for its schema.

    *** `status` HAS SIX VALUES AND AN EMPTY `queries` LIST IS FIVE OF THEM. ***
    That is the whole reason this model exists rather than a bare list. Returning ``[]`` for
    "introspection is switched off", "the host is not listening", "it answered 403", "it answered
    something that is not JSON" and "it really does expose nothing" is precisely the silent-empty
    class this repo keeps finding, in the one place where the difference decides what an operator
    does next: `disabled` means reach for `clairvoyance`, `unreachable` means fix the network,
    and `empty` means stop looking.
    """

    status: str = Field(
        "unreachable",
        description="ok | disabled | empty | http_error | unparseable | unreachable.",
    )
    url: str = ""
    http_status: int | None = Field(
        None, description="The response code, when there was a response at all."
    )
    query_type: str = ""
    mutation_type: str = ""
    subscription_type: str = ""
    type_count: int = 0
    queries: list[SchemaField] = Field(default_factory=list)
    mutations: list[SchemaField] = Field(default_factory=list)
    subscriptions: list[SchemaField] = Field(default_factory=list)
    server_errors: list[str] = Field(
        default_factory=list,
        description="`errors[].message` verbatim from the endpoint. Kept even when `status` is "
        "`disabled`, because the wording is how an operator recognises the server.",
    )
    note: str = Field("", description="What happened, in one sentence, always populated.")
    scope_note: str = Field(
        "",
        description="Set when the host is outside the named engagement's scope. IT IS A WARNING, "
        "NOT A REFUSAL — the probe was sent. Human approval is the only bound.",
    )

    @property
    def argument_names(self) -> list[str]:
        out: list[str] = []
        for f in [*self.queries, *self.mutations, *self.subscriptions]:
            for name in f.argument_names:
                if name not in out:
                    out.append(name)
        return out


def _type_name(ref: Any) -> str:
    """A ZAP/GraphQL type reference -> its readable spelling: ``[User!]!``."""
    if not isinstance(ref, dict):
        return ""
    kind = ref.get("kind")
    inner = _type_name(ref.get("ofType"))
    if kind == "NON_NULL":
        return f"{inner}!" if inner else ""
    if kind == "LIST":
        return f"[{inner}]" if inner else ""
    return str(ref.get("name") or "")


def _fields_of(types: list[Any], name: str) -> list[SchemaField]:
    if not name:
        return []
    for t in types:
        if isinstance(t, dict) and t.get("name") == name:
            out = []
            for f in t.get("fields") or []:
                if not isinstance(f, dict):
                    continue
                out.append(SchemaField(
                    name=str(f.get("name") or ""),
                    type=_type_name(f.get("type")),
                    description=str(f.get("description") or ""),
                    args=[SchemaArgument(
                        name=str(a.get("name") or ""),
                        type=_type_name(a.get("type")),
                        required=_type_name(a.get("type")).endswith("!"),
                    ) for a in (f.get("args") or []) if isinstance(a, dict)],
                ))
            return out
    return []


def parse_introspection(payload: Any) -> SchemaProbe:
    """A decoded introspection RESPONSE -> a :class:`SchemaProbe`. PURE, so it is unit-testable.

    Split out of :func:`probe_schema` for exactly that reason: the five non-``ok`` answers are the
    part worth testing and none of them needs a socket.
    """
    out = SchemaProbe()
    if not isinstance(payload, dict):
        out.status = "unparseable"
        out.note = "the endpoint answered something that is not a JSON object"
        return out

    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        out.server_errors = [str(e.get("message") if isinstance(e, dict) else e)
                             for e in errors][:10]
        blob = " ".join(out.server_errors).lower()
        if any(p in blob for p in _DISABLED_PHRASES):
            out.status = "disabled"
            out.note = ("introspection is DISABLED on this endpoint — that is not an empty "
                        "schema. The API is there; it will not describe itself.")
        else:
            out.status = "http_error"
            out.note = f"the endpoint returned {len(out.server_errors)} GraphQL error(s)"
        return out

    schema = (payload.get("data") or {}).get("__schema") if isinstance(
        payload.get("data"), dict) else None
    if not isinstance(schema, dict):
        out.status = "unparseable"
        out.note = "the response carried neither `data.__schema` nor `errors`"
        return out

    types = [t for t in (schema.get("types") or []) if isinstance(t, dict)]
    out.type_count = len(types)
    out.query_type = str((schema.get("queryType") or {}).get("name") or "")
    out.mutation_type = str((schema.get("mutationType") or {}).get("name") or "")
    out.subscription_type = str((schema.get("subscriptionType") or {}).get("name") or "")
    out.queries = _fields_of(types, out.query_type)
    out.mutations = _fields_of(types, out.mutation_type)
    out.subscriptions = _fields_of(types, out.subscription_type)

    if not out.queries and not out.mutations and not out.subscriptions:
        out.status = "empty"
        out.note = ("introspection ANSWERED and the schema exposes no queries, mutations or "
                    "subscriptions. This is a real empty, not a refusal.")
        return out
    out.status = "ok"
    out.note = (f"{len(out.queries)} queries, {len(out.mutations)} mutations, "
                f"{len(out.subscriptions)} subscriptions across {out.type_count} types")
    return out


def _curl_json(container: str, url: str, body: str, headers: list[tuple[str, str]],
               timeout: int = 25, impersonate: bool = False) -> tuple[int | None, str, str]:
    """POST a JSON body from inside the sandbox. ``(http_status, text, transport_error)``.

    The body goes over STDIN, never an argv. A GraphQL request routinely carries an
    Authorization header and a token-shaped argument, and a `docker exec … curl … --data '…'`
    argv is readable by `ps` on this host — build #18's bypass-header reasoning and build #19's
    intercept reasoning, applied to a third body.

    ``impersonate`` swaps curl for ``curl_chrome116`` (curl-impersonate, baked in the sandbox):
    a real browser's TLS/JA3, so a Cloudflare/Akamai-fronted GraphQL endpoint serves the request
    instead of 403-ing a plain client — the exact wall behind a WAF'd ``/graph`` returning 403.
    """
    argv = ["docker", "exec", "-i", container,
            "curl_chrome116" if impersonate else "curl", "-s", "--max-time", str(timeout),
            "-o", "-", "-w", "\\n__HACKPIT_GQL_STATUS__%{http_code}",
            "-X", "POST", "--data-binary", "@-",
            "-H", "Content-Type: application/json"]
    for name, value in headers:
        argv += ["-H", f"{name}: {value}"]
    argv.append(url)
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout + 10,
                           input=body.encode("utf-8"))
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", f"{exc.__class__.__name__}: {exc}"
    text = (p.stdout or b"").decode("utf-8", "replace")
    marker = "__HACKPIT_GQL_STATUS__"
    status: int | None = None
    if marker in text:
        text, _, tail = text.rpartition(marker)
        try:
            status = int(tail.strip())
        except ValueError:
            status = None
        text = text.rstrip("\n")
    if status in (0, None):
        # curl prints 000 when it never got a response. THAT IS NOT AN HTTP STATUS, and reporting
        # it as one would make "the host is down" read as "the host answered 0".
        return None, text, ((p.stderr or b"").decode("utf-8", "replace").strip()
                            or "no response from the endpoint")
    return status, text, ""


def probe_schema(container: str, url: str, headers: Any = (),
                 engagement_id: str | None = None, timeout: int = 25,
                 impersonate: bool = False) -> SchemaProbe:
    """Ask an endpoint for its schema and CLASSIFY the answer. See :class:`SchemaProbe`.

    UNGATED, in the repeater's position: one request to a URL a human typed and pressed. Where a
    scope check could refuse, it WARNS and sends — ``scope_note`` carries the warning. Human
    approval is the only bound, and refusing to look at an endpoint the operator named would be a
    prohibition invented by the tooling.
    """
    from . import graphql as graphql_mod  # noqa: F401 - kept for the module's shared vocabulary

    out = SchemaProbe(url=url)
    pairs: list[tuple[str, str]] = []
    for h in headers or ():
        name = getattr(h, "name", None)
        value = getattr(h, "value", None)
        if name is None and isinstance(h, (tuple, list)) and len(h) == 2:
            name, value = h
        if str(name or "").strip():
            pairs.append((str(name).strip(), str(value or "")))

    out.scope_note = _scope_warning(url, engagement_id)

    status, text, transport = _curl_json(container, url, json.dumps(
        {"query": INTROSPECTION_QUERY, "operationName": "IntrospectionQuery"}), pairs, timeout,
        impersonate=impersonate)
    out.http_status = status
    if transport:
        out.status = "unreachable"
        out.note = f"nothing answered at {url} ({transport})"
        return out

    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        out.status = "unparseable"
        out.note = (f"the endpoint answered HTTP {status} with a body that is not JSON "
                    f"({len(text)} bytes) — it may not be a GraphQL endpoint at all")
        return out

    parsed = parse_introspection(payload)
    parsed.url = url
    parsed.http_status = status
    parsed.scope_note = out.scope_note
    # A 4xx/5xx that still carried a parseable GraphQL error is the SERVER's answer and keeps its
    # classification; a 4xx with a schema in it is odd but not our business to overrule.
    if parsed.status == "ok" and status is not None and status >= 400:
        parsed.note += f" (returned over HTTP {status})"
    return parsed


def _scope_warning(url: str, engagement_id: str | None) -> str:
    """A WARNING, never a refusal. See the module docstring."""
    if not engagement_id:
        return ""
    try:
        from . import engagement as engagement_mod
        from . import scope as scope_mod

        eng = engagement_mod.get_active(engagement_id)
        if eng is None:
            return (f"engagement {engagement_id!r} is not active, so no scope was applied. "
                    "The probe was sent.")
        host = scope_mod.bare_host(url)
        matcher = engagement_mod.resolved_scope(eng)
        if not host:
            return f"could not read a host from {url!r}; no scope check was possible."
        if not matcher.in_scope(host):
            return (f"WARNING: {host} is OUTSIDE the scope of engagement {engagement_id} "
                    f"({matcher.describe()}). The probe was sent anyway — you approved it.")
        return f"in scope for {engagement_id}: {matcher.describe()}"
    except Exception as exc:  # noqa: BLE001 - a warning must never break the probe
        return f"scope could not be checked ({exc.__class__.__name__}); the probe was sent."


# --------------------------------------------------------------------------- #
# ZAP's query generator — the bounds are the APPROVED SURFACE
# --------------------------------------------------------------------------- #
#: view name -> (action name, ZAP's parameter name). Every one MEASURED from `/UI/graphql/`,
#: which is the enumeration endpoint build #19 needed and never found: it lists every view and
#: action of a component with its parameters, where `/JSON/<component>/view/` answers with ZAP's
#: WELCOME PAGE and `core/view/apiSummary` is `bad_view`.
_OPTION_API: dict[str, tuple[str, str]] = {
    "max_query_depth": ("MaxQueryDepth", "Integer"),
    "max_args_depth": ("MaxArgsDepth", "Integer"),
    "max_additional_query_depth": ("MaxAdditionalQueryDepth", "Integer"),
    "max_cycle_detection_alerts": ("MaxCycleDetectionAlerts", "Integer"),
    "lenient_max_query_depth": ("LenientMaxQueryDepthEnabled", "Boolean"),
    "optional_args": ("OptionalArgsEnabled", "Boolean"),
    "query_gen_enabled": ("QueryGenEnabled", "Boolean"),
    "args_type": ("ArgsType", "String"),
    "query_split_type": ("QuerySplitType", "String"),
    "request_method": ("RequestMethod", "String"),
}

#: The values 0.33.0 actually accepts, each set-then-read-back in the proof. `cycleDetectionMode`
#: is absent on purpose: QUICK is the only one of six probed spellings that applies, so it is a
#: choice with one option and HackPit does not offer it.
ARGS_TYPES = ("INLINE", "VARIABLES", "BOTH")
QUERY_SPLIT_TYPES = ("LEAF", "ROOT_FIELD", "OPERATION")
REQUEST_METHODS = ("POST_JSON", "POST_GRAPHQL", "GET")


class GraphQLBounds(BaseModel):
    """How much ZAP may generate. THE OPERATOR'S, and every field optional.

    Depth and generation bounds are part of the approved surface for the same reason crawl depth
    and duration are: a generator that decides its own bounds has stopped describing what runs.
    An unset field is left exactly as the daemon has it — which, because ZAP persists these, is
    whatever the last engagement left behind, and :func:`observed_bounds` is how you find out.
    """

    max_query_depth: int | None = None
    max_args_depth: int | None = None
    max_additional_query_depth: int | None = None
    max_cycle_detection_alerts: int | None = None
    lenient_max_query_depth: bool | None = None
    optional_args: bool | None = None
    query_gen_enabled: bool | None = None
    args_type: str | None = Field(
        None, description="INLINE | VARIABLES | BOTH. VARIABLES gives every argument its own key "
        "in `variables`; INLINE writes them into the query text. Both are reachable by the "
        "scanner — measured.")
    query_split_type: str | None = Field(None, description="LEAF | ROOT_FIELD | OPERATION.")
    request_method: str | None = Field(None, description="POST_JSON | POST_GRAPHQL | GET.")


class AppliedBound(BaseModel):
    field_name: str
    requested: str
    observed: str
    applied: bool
    warning: str = ""


class AppliedBounds(BaseModel):
    """Requested vs READ BACK, per field. An OK is not a result."""

    bounds: list[AppliedBound] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    read_ok: bool = True

    @property
    def all_applied(self) -> bool:
        return all(b.applied for b in self.bounds)


def _get_option(container: str, port: int, api_name: str) -> str:
    """One option, read back. An ERROR IS NOT A VALUE.

    *** THIS RETURNED THE STRING `bad_view` AS THOUGH IT WERE THE SETTING. ***
    ZAP's error shape is ``{"code": ..., "message": ...}`` and a view's success shape is
    ``{"MaxQueryDepth": "5"}`` — both are one-key dicts, so "take the first value" rendered the
    error CODE into the panel as the daemon's configuration. Found by looking at the screen: the
    engage sandbox answered `100` for `optionMaxCycleDetectionAlerts` and the kali sandbox
    answered `bad_view`, because THE TWO CONTAINERS DO NOT SHIP THE SAME ADD-ON SURFACE. An
    option list read off one daemon is not a claim about another.

    The unreadable case is spelled out rather than blanked, because "we could not read this" and
    "this is empty" are the distinction this whole build keeps insisting on.
    """
    from . import proxy

    raw = proxy._api_get(container, port, f"/JSON/graphql/view/option{api_name}/")
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return ""
    if not isinstance(obj, dict):
        return ""
    if "code" in obj:
        return f"unreadable ({obj.get('code')})"
    for value in obj.values():
        return str(value)
    return ""


def observed_bounds(container: str, port: int) -> dict[str, str]:
    """What the daemon is holding RIGHT NOW, read back field by field.

    *** THIS EXISTS BECAUSE ZAP PERSISTS THESE OPTIONS. *** They are configuration rather than
    session state and survive both a restart and ``core/action/newSession``, so one engagement's
    settings condition the next one silently unless somebody looks. Twice bitten already.
    """
    return {name: _get_option(container, port, api) for name, (api, _) in _OPTION_API.items()}


def _bound_warning(name: str, value: Any) -> str:
    """WARN, never refuse. See the module docstring's point 3."""
    if isinstance(value, bool) or value is None:
        return ""
    if name.startswith("max_") and isinstance(value, int) and value < 0:
        return (f"{name}={value} is negative. ZAP accepts it and reads it back unchanged "
                "(measured), and it will generate nothing. Sent as asked.")
    if name == "max_query_depth" and isinstance(value, int) and value > 20:
        return (f"{name}={value} is deep. Generation is exponential in depth on a cyclic schema; "
                "expect a long import and a lot of traffic. Sent as asked.")
    if name in ("args_type", "query_split_type", "request_method"):
        legal = {"args_type": ARGS_TYPES, "query_split_type": QUERY_SPLIT_TYPES,
                 "request_method": REQUEST_METHODS}[name]
        if str(value).upper() not in legal:
            return (f"{name}={value!r} is not one of {', '.join(legal)}. ZAP answers "
                    "internal_error for an unknown value and LEAVES THE PREVIOUS ONE IN PLACE "
                    "(measured) — it is sent, and the read-back below is what actually holds.")
    return ""


def apply_bounds(container: str, port: int, bounds: GraphQLBounds) -> AppliedBounds:
    """Set what the operator asked for, then READ EVERY FIELD BACK.

    Nothing is refused here. A nonsense bound gets a warning and goes out anyway, because the
    bound is the operator's to choose; what would be dishonest is reporting a depth that was
    never applied. ``applied`` is derived from the read-back, never from ZAP's ``{"Result":"OK"}``
    — which it will happily return for a value it then discards.
    """
    from . import proxy

    out = AppliedBounds()
    for name, (api, param) in _OPTION_API.items():
        value = getattr(bounds, name, None)
        if value is None:
            continue
        warning = _bound_warning(name, value)
        if warning:
            out.warnings.append(warning)
        if param == "Boolean":
            wire = "true" if value else "false"
        else:
            wire = str(value).upper() if param == "String" else str(value)
        proxy._api_post(container, port, f"/JSON/graphql/action/setOption{api}/", {param: wire})
        observed = _get_option(container, port, api)
        if not observed:
            out.read_ok = False
        out.bounds.append(AppliedBound(
            field_name=name, requested=wire, observed=observed,
            applied=observed.upper() == wire.upper(),
            warning=warning,
        ))
    return out


class SchemaImport(BaseModel):
    """What ZAP did with a schema — and, just as importantly, what it did NOT do."""

    ok: bool = False
    endpoint_url: str = ""
    source: str = Field("", description="introspection | schema_url | sdl_text.")
    zap_code: str = Field("", description="ZAP's own code, verbatim: OK | illegal_parameter | …")
    bounds: AppliedBounds | None = None
    note: str = ""
    scannable: bool = Field(
        False,
        description="ALWAYS FALSE, and it is a field rather than a silence on purpose. *** THE "
        "OPERATIONS ZAP GENERATES FROM AN IMPORT ARE SENT AT THE ENDPOINT AND ARE NEVER ADDED TO "
        "THE SITES TREE *** — measured four ways in docs/proof/build20_graphql_api.py. So an "
        "import is COVERAGE TRAFFIC, not a way to give the active scanner new targets. Use the "
        "proxy capture for that: see scan_plan_for().",
    )
    scope_note: str = ""


def import_schema(container: str, port: int, endpoint_url: str,
                  schema_url: str = "", sdl_text: str = "",
                  bounds: GraphQLBounds | None = None,
                  engagement_id: str | None = None) -> SchemaImport:
    """Hand a schema to ZAP and let it exercise the endpoint. NO NEW GATE.

    Three sources, all three MEASURED working:

    * neither ``schema_url`` nor ``sdl_text``  -> ``importUrl(endurl)``, which INTROSPECTS
    * ``schema_url``                           -> ``importUrl(endurl, url)``, a GET for a document
    * ``sdl_text``                             -> ``importFile(endurl, file)``, SDL written into
      the sandbox first

    *** WHAT THIS DOES NOT DO IS GIVE THE SCANNER TARGETS. *** See :attr:`SchemaImport.scannable`.
    It sends real operations at a real endpoint with the operator's bounds, which is worth doing
    on its own — it is coverage, and ZAP's passive rules see every response — and it is not the
    same thing as an attack surface.
    """
    from . import proxy

    out = SchemaImport(endpoint_url=endpoint_url)
    out.scope_note = _scope_warning(endpoint_url, engagement_id)
    if bounds is not None:
        out.bounds = apply_bounds(container, port, bounds)

    if sdl_text.strip():
        out.source = "sdl_text"
        path = "/tmp/hackpit_graphql_schema.graphql"
        try:
            subprocess.run(["docker", "exec", "-i", container, "sh", "-c", f"cat > {path}"],
                           input=sdl_text.encode("utf-8"), capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            out.note = f"the schema could not be written into {container}: {exc}"
            return out
        raw = proxy._api_post(container, port, "/JSON/graphql/action/importFile/",
                              {"endurl": endpoint_url, "file": path})
    elif schema_url.strip():
        out.source = "schema_url"
        raw = proxy._api_post(container, port, "/JSON/graphql/action/importUrl/",
                              {"endurl": endpoint_url, "url": schema_url.strip()})
    else:
        out.source = "introspection"
        raw = proxy._api_post(container, port, "/JSON/graphql/action/importUrl/",
                              {"endurl": endpoint_url})

    try:
        answer = json.loads(raw)
    except (ValueError, TypeError):
        answer = {}
    if not isinstance(answer, dict):
        answer = {}
    out.zap_code = str(answer.get("Result") or answer.get("code") or "")
    out.ok = out.zap_code == "OK"

    if out.ok:
        out.note = (
            "ZAP parsed the schema and sent the operations it generated at the endpoint. "
            "*** THOSE OPERATIONS ARE NOT IN THE SITES TREE AND THE ACTIVE SCANNER CANNOT AIM "
            "AT THEM *** — measured. To scan GraphQL, capture an operation through the proxy "
            "and scan that."
        )
        if out.source == "introspection":
            out.note += (
                " An OK here also does NOT mean the endpoint answered: importFile returns OK "
                "against a host that is not listening (measured)."
            )
    elif out.zap_code == "illegal_parameter":
        out.note = (
            "ZAP refused the import with `illegal_parameter`. *** IT ANSWERS EXACTLY THIS FOR "
            "BOTH 'introspection is disabled' AND 'nothing is listening', with the same message "
            "*** — it cannot tell you which. Run a schema probe against the endpoint; that is "
            "what distinguishes them."
        )
    elif out.zap_code == "does_not_exist":
        out.note = "ZAP could not find the schema file inside the sandbox."
    else:
        out.note = f"ZAP answered {out.zap_code or 'nothing readable'}."
    return out


# --------------------------------------------------------------------------- #
# item 5 — the scan, behind THE EXISTING FOUR GATES
# --------------------------------------------------------------------------- #
class GraphQLScanPlan(BaseModel):
    """What a GraphQL scan would attack, computed BEFORE anything is approved.

    The point of showing this first: the operator approves a scan knowing which arguments it can
    reach, and the names here are the names ZAP puts in its alerts afterwards (`field.argument` —
    measured, `search.limit`, where the JSON variable key was `search_limit`).
    """

    ok: bool = False
    target_url: str = Field(
        "", description="The endpoint node. Query string stripped: ZAP's tree is keyed on the "
        "path, and the operations hang off it."
    )
    recurse_required: bool = Field(
        True,
        description="ALWAYS TRUE, and not a preference. ZAP files captured GraphQL under a "
        "SYNTHETIC `<endpoint>/query` child node — measured — so a scan of the endpoint alone "
        "reaches the path-based rules and no GraphQL at all. The first measurement of this sent "
        "114 requests and touched zero arguments.",
    )
    argument_names: list[str] = Field(
        default_factory=list,
        description="`field.argument` for every argument in the captured operation. NAMES ONLY.",
    )
    operation_names: list[str] = Field(default_factory=list)
    note: str = ""


def scan_plan_for(exchange: Any) -> GraphQLScanPlan:
    """A captured exchange -> the scan that would attack it. PURE; it starts nothing.

    Hand the result to ``proxy.start_scan`` with a ``ScanStartRequest``: the SAME four gates run,
    unchanged, and this build adds none. An intruder-style "one approval buys many requests" is
    the established position — ffuf, nuclei and the active scanner are each one approval buying
    thousands, and the proof measured 1,630 requests from this one.
    """
    from . import graphql as graphql_mod

    out = GraphQLScanPlan()
    found = graphql_mod.detect_exchange(exchange)
    if not found.is_graphql:
        out.note = ("this exchange is not a GraphQL operation by body shape, so there are no "
                    "arguments to aim at. Scan it as ordinary traffic instead.")
        return out
    try:
        url = str(exchange.request.url)
    except Exception:  # noqa: BLE001
        out.note = "the exchange carries no readable URL"
        return out

    out.ok = True
    out.target_url = url.split("?", 1)[0]
    out.argument_names = found.argument_names
    out.operation_names = [op.operation_name for op in found.operations if op.operation_name]
    if found.batched:
        out.note = ("this is a BATCHED request. ZAP scans the JSON body it captured, so the "
                    "batch is attacked as one message rather than per operation. ")
    if not out.argument_names:
        out.note += ("the operation carries no arguments, so there is nothing argument-shaped to "
                     "inject into — the scan will still run every non-argument rule.")
    else:
        out.note += (f"{len(out.argument_names)} argument(s) reachable individually; ZAP will "
                     "name them exactly as listed.")
    return out


# =============================================================================================
# BUILD #21 -- FIELD-SUGGESTION ENUMERATION. The runner; the parsing is graphql_enum.py (pure).
# =============================================================================================
#
# WHY THE RUNNER IS HERE AND NOT IN ITS OWN MODULE: it reuses :func:`_curl_json` unchanged. The
# brief said reuse build #19's plumbing rather than growing a second HTTP path, and a second path
# is not just duplicated code -- it is a second place for the "body over stdin, never an argv"
# rule to be forgotten, and a GraphQL request routinely carries an Authorization header.
#
# *** UNGATED, LIKE THE PROBE, AND FOR THE SAME REASON. *** These are requests to a URL a human
# typed and pressed. Where a scope check could refuse it WARNS and sends. The BOUNDS below are
# not a gate: they are the run describing its own size, the way crawl depth and scan policy do.
# When a bound is reached the run STOPS and says which bound stopped it, and everything found so
# far is returned -- discarding a partial schema would punish an operator for setting a bound.


def fingerprint_engine(container: str, url: str, headers: Any = (),
                       engagement_id: str | None = None,
                       timeout: int = 25,
                       impersonate: bool = False) -> graphql_enum.EngineFingerprint:
    """Which core formats this endpoint's errors. Four requests, then a PURE classification.

    Native rather than driving ``graphw00f``, and the choice is deliberate:

    * the enumerator and the fingerprint must travel the SAME HTTP path, or the thing that
      chooses the parser and the thing that uses it can disagree about proxying, headers and
      TLS. ``graphw00f`` is a subprocess with its own client.
    * ``graphw00f`` answers with a BRAND (`apollo`, `mercurius`, `graphql_yoga`); the parser
      lookup needs a CORE. Driving the tool would not remove the brand->core table, it would add
      a subprocess to it.
    * fingerprinting is recon in the repeater's position -- one request to a named URL, no gate.
      ``graphw00f`` is a gated arsenal command, and routing an ungated feature through a gated
      tool would either add friction or route around the gate.

    ``graphw00f`` stays in the arsenal as the operator's INDEPENDENT cross-check, which is worth
    more than a shared implementation: two implementations that agree is evidence, and
    ``docs/proof/build21_graphql_enum.py`` runs it against the same endpoints for exactly that.
    """
    pairs = _header_pairs(headers)
    responses: dict[str, str] = {}
    for name, document in graphql_enum.FINGERPRINT_PROBES:
        _status, text, transport = _curl_json(
            container, url, json.dumps({"query": document}), pairs, timeout,
            impersonate=impersonate)
        responses[name] = "" if transport else text
    out = graphql_enum.classify_fingerprint(responses)
    scope = _scope_warning(url, engagement_id)
    if scope:
        # WARN AND CONTINUE. The probes were already sent; saying so afterwards is honest, and
        # refusing to look at an endpoint the operator named would be a prohibition the tooling
        # invented. Same position as `probe_schema`.
        out.note = f"{out.note} [{scope}]"
    return out


def _header_pairs(headers: Any) -> list[tuple[str, str]]:
    """The `(name, value)` list `_curl_json` wants, from whatever shape the caller had."""
    pairs: list[tuple[str, str]] = []
    for h in headers or ():
        name = getattr(h, "name", None)
        value = getattr(h, "value", None)
        if name is None and isinstance(h, (tuple, list)) and len(h) == 2:
            name, value = h
        if str(name or "").strip():
            pairs.append((str(name).strip(), str(value or "")))
    return pairs


def enumerate_schema(container: str, url: str, wordlist: list[str],
                     bounds: graphql_enum.EnumerationBounds | None = None,
                     headers: Any = (), engagement_id: str | None = None,
                     fingerprint: graphql_enum.EngineFingerprint | None = None,
                     timeout: int = 25,
                     impersonate: bool = False) -> graphql_enum.EnumerationResult:
    """Mine a schema out of the server's own error messages.

    *** IT REFUSES TO GUESS THE PARSER, AND THAT IS NOT A GATE. *** When the core is unknown the
    run does not send a wordlist, because running graphql-js's parser against graphql-core
    returns zero suggestions and is INDISTINGUISHABLE from a hardened server. The operator gets
    `engine_unknown` and the reason, which is a true answer; three thousand requests producing a
    confident empty schema is a false one. Nothing is forbidden -- the operator may name the
    engine and run again.
    """
    bounds = bounds or graphql_enum.EnumerationBounds()
    out = graphql_enum.EnumerationResult(url=url, bounds=bounds)
    out.scope_note = _scope_warning(url, engagement_id)

    out.fingerprint = fingerprint or fingerprint_engine(
        container, url, headers, engagement_id, timeout)
    dialect = out.fingerprint.dialect
    if not out.fingerprint.suggests or not dialect:
        out.status, out.note = graphql_enum.status_for(out.fingerprint, 0, 0, 0)
        return out

    pairs = _header_pairs(headers)
    names = [n for n in wordlist if n]
    bounds.wordlist_size = bounds.wordlist_size or len(names)
    batch = max(1, int(bounds.batch_size or 1))
    started = time.monotonic()

    for start in range(0, len(names), batch):
        if bounds.max_requests and out.requests_sent >= bounds.max_requests:
            out.stopped_early = True
            out.stop_reason = f"max_requests={bounds.max_requests} reached"
            break
        if bounds.max_seconds and (time.monotonic() - started) >= bounds.max_seconds:
            out.stopped_early = True
            out.stop_reason = f"max_seconds={bounds.max_seconds} reached"
            break

        document = graphql_enum.build_probe_document(names[start:start + batch])
        if not document:
            continue
        _status, text, transport = _curl_json(
            container, url, json.dumps({"query": document}), pairs, timeout,
            impersonate=impersonate)
        out.requests_sent += 1
        if transport:
            continue

        for message in graphql_enum.error_messages(text):
            kind = graphql_enum.classify_message(message, dialect)
            if kind == "not_this_error":
                # Could still be an ARGUMENT error, which is a different sentence and the one
                # report #61 actually needed -- the injection point there was an argument.
                graphql_enum.merge_suggestions(
                    out.arguments, graphql_enum.parse_argument_suggestions(message, dialect))
                continue
            out.unknown_field_errors += 1
            found = graphql_enum.parse_suggestions(message, dialect)
            if len(found) == graphql_enum.SUGGESTION_CAP:
                # The server's own cap, not the end of the list. Counted rather than assumed
                # complete: an enumerator that read five as "all of them" would stop early and
                # report a schema it had not finished reading.
                out.truncated_suggestion_lists += 1
            graphql_enum.merge_suggestions(out.fields, found)

    out.seconds_elapsed = round(time.monotonic() - started, 2)
    out.status, out.note = graphql_enum.status_for(
        out.fingerprint, out.unknown_field_errors, len(out.fields), out.requests_sent)
    if out.stopped_early:
        out.note = f"{out.note}; STOPPED EARLY: {out.stop_reason}"
    return out


# The response-body parser lives in `graphql_enum.error_messages` -- PURE, shared by the
# fingerprint and the enumeration loop. One implementation on purpose: an earlier draft had the
# fingerprint matching RAW body text while the loop matched parsed messages, and because JSON
# escapes double quotes and leaves single quotes alone, that read every graphql-js server as
# `unknown` while every graphql-core server worked. Two parsers is how that divergence lived.
