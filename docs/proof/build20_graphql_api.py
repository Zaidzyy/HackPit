#!/usr/bin/env python3
"""Build #20 item 1 -- the go/no-go for GraphQL, MEASURED against a live ZAP 2.17.0.

*** IT PRINTS WHICH ADD-ON VERSION IT MEASURED, BECAUSE THAT IS NOT A CONSTANT. ***
The recorded 56/0 run was against graphql-alpha-0.33.0. The IMAGE ships 0.29.0; the 0.33.0 was a
runtime upgrade sitting in one container's writable layer, and 0.29.0 does not even have
`optionMaxCycleDetectionAlerts` -- it answers `bad_view`. Build #14's trap in a new place: the
container is not the image. Read the version line this script prints before comparing your run
to this one.

*** THIS IS THE SCRIPT THAT DECIDED HOW ITEMS 4 AND 5 ARE BUILT, AND IT CHANGED THE PLAN. ***
Build #14 was written against `zap-baseline.py`, which does not exist in Kali. Build #19 found
four of its five assumed break-API facts were wrong. The add-on measured here is ALPHA, so
nothing in items 4 or 5 was written before this answered -- and the answer was not the expected
one.

The plan assumed the chain would be: import a schema -> ZAP generates operations -> the
operations land in the Sites tree -> `ascan` attacks them there. The middle link is missing.
ZAP sends the generated operations at the endpoint for real, and never files them. What DOES
put a GraphQL operation somewhere `ascan` can reach it is the PROXY -- which is the one thing
HackPit has had since build #14 part 2. So item 5 scans CAPTURED operations, and that is both
ZAP's own path and exactly what report #61 describes: the operator has the request, not the
schema.

It stands up its own GraphQL origin INSIDE the container and reads that origin's request log as
the arbiter, because every one of these endpoints will answer `{"Result":"OK"}` for things it did
not do -- including for an endpoint that is not listening at all -- and because "did the scanner
reach ONE argument" can only be answered by looking at what actually arrived.

WHAT IT PROVES, each checked rather than taken from the add-on's documentation:

   1. /UI/<component>/ IS the enumeration surface -- 11 views and 13 actions, by name, with
      their parameters. Build #19 had to probe the break API name by name for want of this.
   2. there is NO view that reads an imported schema back -- every view is option*
   3. the option enums, set-then-READ-BACK      -- an OK is not a result
   4. cycleDetectionMode has ONE usable value   -- QUICK; five other spellings are refused
   5. a REFUSED enum leaves the previous value  -- no corruption
   6. maxQueryDepth=-1 IS ACCEPTED              -- ZAP validates its own bound not at all
   7. importFile takes SDL; importUrl(endurl) introspects; importUrl(endurl,url) GETs a document
   8. *** importFile answers OK WITH NOTHING LISTENING *** -- the OK means "parsed", not "ran"
   9. *** importUrl CANNOT TELL YOU WHY IT FAILED *** -- introspection-disabled and a dead host
      answer with the SAME code and the SAME message, which is why HackPit classifies itself
  10. *** THE GENERATED OPERATIONS NEVER ENTER THE SITES TREE *** -- measured on a fresh daemon,
      on a node primed through the proxy, out to 60 seconds. This is the link the plan assumed.
  11. CONTROL: ONE GraphQL request through the PROXY does create <endpoint> and the synthetic
      <endpoint>/query node -- so captured traffic is what feeds the scanner
  12. argsType=VARIABLES gives every argument its own key in `variables`; INLINE puts them in
      the query text
  13. *** THE ACTIVE SCANNER REACHES ONE GRAPHQL ARGUMENT AT A TIME *** -- on a CAPTURED
      operation, with no schema imported at all

Every phase uses its own endpoint PATH so that nothing measures the leftovers of the phase
before it. That is deliberate: `core/action/newSession` would have done the same job by throwing
the daemon's capture away, and a proof that destroys the operator's traffic to measure something
is not a proof anyone can run twice.

Run it with the stack up:

    docker exec -d hackpit-engage-sandbox sh -c 'zaproxy -daemon -host 127.0.0.1 -port 8090 \
        -config api.disablekey=false -config api.key=KEY'
    python docs/proof/build20_graphql_api.py hackpit-engage-sandbox 8090 [KEY]

With no KEY it recovers one from the daemon's own argv, the way `proxy.api_key_for` does.
Prints VERDICT= and exits non-zero on failure. ASCII only: this console is cp1252.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.parse

CONTAINER = sys.argv[1] if len(sys.argv) > 1 else "hackpit-engage-sandbox"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8090
KEY = sys.argv[3] if len(sys.argv) > 3 else ""

#: A GraphQL origin inside the SAME container. Self-contained on purpose: the arbiter for every
#: claim below is this server's request log. A third-party endpoint would have given us a status
#: code instead of a record of which argument actually carried the payload.
ORIGIN_PORT = 18110
ORIGIN = f"http://127.0.0.1:{ORIGIN_PORT}"
LOG = "/tmp/build20_gql_origin.log"
MODE = "/tmp/build20_gql_mode"
SERVER = "/tmp/build20_gql_origin_server.py"
SCHEMA_FILE = "/tmp/build20_schema.graphql"
JUNK_FILE = "/tmp/build20_junk.graphql"

#: THREE arguments on one field is the whole point. Item 5 needs the scanner to reach `token`
#: without also having to rewrite `id` -- that is what "a single argument" means.
SDL = """schema { query: Query mutation: Mutation }
type Query {
  userById(id: ID!, token: String, locale: String): User
  search(term: String!, limit: Int): [User]
}
type Mutation { setEmail(id: ID!, email: String!): User }
type User { id: ID! name: String email: String }
"""

#: What an operator's browser actually sends -- query text, operationName, variables. Item 5's
#: whole subject. Note this is NOT ZAP's generated shape: it is a hand-written operation with
#: three arguments, which is the shape report #61 was fighting with in the repeater.
CAPTURED_VARS = {"id": "1", "token": "abc123", "locale": "en"}
CAPTURED = json.dumps({
    "query": ("query ($id: ID!, $token: String, $locale: String) "
              "{ userById(id: $id, token: $token, locale: $locale) { id name email } }"),
    "operationName": None,
    "variables": CAPTURED_VARS,
})

ORIGIN_SRC = '''#!/usr/bin/env python3
"""build #20 proof origin -- a minimal GraphQL endpoint whose LOG is the arbiter. stdlib only.
Answers on ANY path, so each phase of the proof can have an endpoint to itself."""
import http.server, json, urllib.parse

LOG = "%(log)s"
MODE = "%(mode)s"
PORT = %(port)d
SDL = """%(sdl)s"""

def T(kind, name=None, of=None): return {"kind": kind, "name": name, "ofType": of}
def NN(t): return T("NON_NULL", None, t)
def LIST(t): return T("LIST", None, t)
def SC(n): return T("SCALAR", n)
def OB(n): return T("OBJECT", n)

def field(name, ftype, args=()):
    return {"name": name, "description": None, "type": ftype,
            "args": [{"name": a, "description": None, "type": t, "defaultValue": None}
                     for a, t in args],
            "isDeprecated": False, "deprecationReason": None}

def objtype(name, fields):
    return {"kind": "OBJECT", "name": name, "description": None, "fields": fields,
            "inputFields": None, "interfaces": [], "enumValues": None, "possibleTypes": None}

def sc(name):
    return {"kind": "SCALAR", "name": name, "description": None, "fields": None,
            "inputFields": None, "interfaces": None, "enumValues": None, "possibleTypes": None}

USER = objtype("User", [field("id", NN(SC("ID"))), field("name", SC("String")),
                        field("email", SC("String"))])
QUERY = objtype("Query", [
    field("userById", OB("User"), [("id", NN(SC("ID"))), ("token", SC("String")),
                                   ("locale", SC("String"))]),
    field("search", LIST(OB("User")), [("term", NN(SC("String"))), ("limit", SC("Int"))]),
])
MUTATION = objtype("Mutation", [
    field("setEmail", OB("User"), [("id", NN(SC("ID"))), ("email", NN(SC("String")))])])

SCHEMA = {"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "subscriptionType": None,
    "types": [QUERY, MUTATION, USER, sc("ID"), sc("String"), sc("Int"), sc("Boolean")],
    "directives": []}}}

DISABLED = {"errors": [{"message": "GraphQL introspection is not allowed, but the query "
                                   "contained __schema or __type"}]}

def mode():
    try:
        with open(MODE) as f: return f.read().strip()
    except OSError: return "on"

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _record(self, method, path, body):
        with open(LOG, "a") as f:
            f.write(json.dumps({"m": method, "p": path, "b": body}) + "\\n")
    def _send(self, obj, ctype="application/json"):
        b = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def _answer(self, probe):
        if "__schema" in probe or "__typename" not in probe and "__type" in probe:
            self._send(DISABLED if mode() == "disabled" else SCHEMA)
        elif "__typename" in probe:
            # A real server names its ROOT TYPE here. `graphql-cop` crashes with a bare KeyError
            # on a server that does not, so an origin that skipped this would have made a working
            # arsenal tool look broken -- which is how a toy target produces a false finding.
            self._send({"data": {"__typename": "Query"}})
        else:
            self._send({"data": {"echo": len(probe)}})
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        self._record("POST", self.path, body)
        self._answer(body)
    def do_GET(self):
        self._record("GET", self.path, "")
        if "schema.graphql" in self.path:
            self._send(SDL.encode(), "text/plain"); return
        self._answer(urllib.parse.unquote(urllib.parse.urlparse(self.path).query))
    def log_message(self, *a): pass

if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
''' % {"log": LOG, "mode": MODE, "port": ORIGIN_PORT, "sdl": SDL}

#: The values this run finds in place BEFORE it touches anything. ZAP PERSISTS its add-on
#: options, so a proof that left them where it happened to finish would silently condition the
#: next run -- exactly what `api.disablekey` and the scan policy each did to this project once.
BASELINE: dict[str, str] = {}

VIEWS = ("optionArgsType", "optionCycleDetectionMode", "optionLenientMaxQueryDepthEnabled",
         "optionMaxAdditionalQueryDepth", "optionMaxArgsDepth", "optionMaxCycleDetectionAlerts",
         "optionMaxQueryDepth", "optionOptionalArgsEnabled", "optionQueryGenEnabled",
         "optionQuerySplitType", "optionRequestMethod")

SETTER = {
    "optionArgsType": ("setOptionArgsType", "String"),
    "optionCycleDetectionMode": ("setOptionCycleDetectionMode", "String"),
    "optionLenientMaxQueryDepthEnabled": ("setOptionLenientMaxQueryDepthEnabled", "Boolean"),
    "optionMaxAdditionalQueryDepth": ("setOptionMaxAdditionalQueryDepth", "Integer"),
    "optionMaxArgsDepth": ("setOptionMaxArgsDepth", "Integer"),
    "optionMaxCycleDetectionAlerts": ("setOptionMaxCycleDetectionAlerts", "Integer"),
    "optionMaxQueryDepth": ("setOptionMaxQueryDepth", "Integer"),
    "optionOptionalArgsEnabled": ("setOptionOptionalArgsEnabled", "Boolean"),
    "optionQueryGenEnabled": ("setOptionQueryGenEnabled", "Boolean"),
    "optionQuerySplitType": ("setOptionQuerySplitType", "String"),
    "optionRequestMethod": ("setOptionRequestMethod", "String"),
}

PASS = 0
FAIL = 0
_PHASE = [0]


#: A per-RUN token in every endpoint path. ZAP's sites tree persists for the life of the daemon,
#: so a fixed path accumulates across runs and the SECOND run of this script measures the first
#: one's leftovers -- which is exactly what happened: a node primed with 3 messages read back 4.
RUN_TAG = f"r{int(time.time()) % 100000}"


def endpoint(tag: str) -> str:
    """A fresh endpoint path per phase AND per run, so nothing measures anything but itself.

    ZAP will not re-send an operation it already has, and its tree is per-URL. Giving every phase
    its own path is how this proof stays repeatable WITHOUT calling `core/action/newSession`,
    which would throw away whatever capture the daemon was holding."""
    _PHASE[0] += 1
    return f"{ORIGIN}/gql{RUN_TAG}{_PHASE[0]:02d}{tag}"


def check(ok: bool, label: str, detail: str = "") -> bool:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")
        if detail:
            print(f"        {detail}")
    return ok


def dex(*argv: str, stdin: bytes | None = None, timeout: int = 300) -> tuple[int, str]:
    p = subprocess.run(["docker", "exec", "-i", CONTAINER, *argv],
                       capture_output=True, timeout=timeout, input=stdin)
    return p.returncode, (p.stdout or b"").decode("utf-8", "replace")


def raw(path: str) -> str:
    _, out = dex("curl", "-s", "--max-time", "60", "-H", f"X-ZAP-API-Key: {KEY}",
                 f"http://127.0.0.1:{PORT}{path}")
    return out


def api(path: str, fields: dict[str, str] | None = None) -> dict:
    """One ZAP API call. Anything with a body goes over POST -- a captured operation routinely
    carries an Authorization header, and `_api_get` would put that in ZAP's own history AND on a
    `docker exec ... curl ...` argv that `ps` on the host can read. Build #18's bypass-header
    reasoning, applied again."""
    url = f"http://127.0.0.1:{PORT}/JSON/{path}"
    argv = ["curl", "-s", "--max-time", "120", "-H", f"X-ZAP-API-Key: {KEY}"]
    body = None
    if fields is not None:
        body = "&".join(f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(v)}"
                        for k, v in fields.items()).encode()
        argv += ["-X", "POST", "--data-binary", "@-",
                 "-H", "Content-Type: application/x-www-form-urlencoded"]
    argv.append(url)
    _, out = dex(*argv, stdin=body)
    try:
        return json.loads(out)
    except ValueError:
        return {"_raw": out[:300]}


def opt(view: str) -> str:
    for v in api(f"graphql/view/{view}/").values():
        return str(v)
    return ""


def set_opt(view: str, value: str) -> dict:
    action, param = SETTER[view]
    return api(f"graphql/action/{action}/?{param}={urllib.parse.quote(value)}")


def recover_key() -> str:
    probe = (
        'for f in /proc/[0-9]*/cmdline; do '
        'L=$(tr "\\0" "\\n" < "$f" 2>/dev/null) || continue; '
        'K=$(printf "%s\\n" "$L" | grep -m1 -e "^api[.]key=") || continue; '
        'printf "%s\\n" "${K#*=}"; break; done'
    )
    _, out = dex("sh", "-c", probe)
    return out.strip()


def origin_rows() -> list[dict]:
    _, out = dex("sh", "-c", f"cat {LOG} 2>/dev/null")
    rows = []
    for line in out.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows


def clear_log() -> None:
    dex("sh", "-c", f": > {LOG}")


def real_ops(rows: list[dict]) -> list[str]:
    """Operations that name a field from OUR schema.

    Deliberately NOT "everything that is not a fingerprint probe": the add-on opens with a dozen
    engine-fingerprinting requests (`{__typename @include(if: falsee)}`, `{zaproxy}`, an empty
    query) and an earlier draft of this script counted those as generated operations, which made
    a working import look like a broken one."""
    out = []
    for r in rows:
        b = r.get("b") or ""
        if any(f in b for f in ("userById", "setEmail", '"search"', "search(", "search (")):
            out.append(b)
    return out


def import_file(endurl: str, path: str = SCHEMA_FILE) -> dict:
    return api("graphql/action/importFile/", {"endurl": endurl, "file": path})


def set_mode(mode: str) -> None:
    dex("sh", "-c", f"printf '{mode}' > {MODE}")


def proxied(endurl: str, body: str) -> None:
    """Send one request THROUGH ZAP's proxy -- the way HackPit's recording proxy sees traffic."""
    dex("curl", "-s", "--max-time", "20", "-x", f"http://127.0.0.1:{PORT}", "-X", "POST",
        "-H", "Content-Type: application/json", "--data-binary", body, endurl)


def messages_on(endurl: str) -> int:
    r = api("core/view/numberOfMessages/?baseurl=" + urllib.parse.quote(endurl))
    try:
        return int(r.get("numberOfMessages", "0"))
    except (TypeError, ValueError):
        return -1


#: A BRACKETED pattern, and that is load-bearing. `pkill -f build20_gql_origin_server` matches
#: the `sh -c "pkill -f build20_gql_origin_server"` process running it, so the shell kills itself
#: and every command after the `;` in that same `sh -c` is silently never run. This repo has been
#: bitten by it once already (build #14 part 2, the wrapper `pkill -f` matching itself) and again
#: while writing this script, where a redeploy quietly kept serving the OLD origin. The bracket
#: cannot match the literal pattern text on the argv.
_KILL_ORIGIN = "pkill -f 'build20_gql[_]origin_server' 2>/dev/null; true"


def start_origin() -> bool:
    dex("sh", "-c", _KILL_ORIGIN)
    time.sleep(1)
    dex("sh", "-c", f"cat > {SERVER}", stdin=ORIGIN_SRC.encode())
    dex("sh", "-c", f"cat > {SCHEMA_FILE}", stdin=SDL.encode())
    dex("sh", "-c", f"printf 'this is not graphql at all\\n' > {JUNK_FILE}")
    set_mode("on")
    clear_log()
    subprocess.Popen(["docker", "exec", "-d", CONTAINER, "sh", "-c",
                      f"exec python3 {SERVER} >> /tmp/build20_gql_origin.err 2>&1"])
    time.sleep(3)
    rc, out = dex("curl", "-s", "--max-time", "8", "-X", "POST",
                  "-H", "Content-Type: application/json",
                  "--data-binary", '{"query":"{__schema{queryType{name}}}"}', ORIGIN + "/probe")
    return rc == 0 and "__schema" in out


def stop_origin() -> None:
    dex("sh", "-c", _KILL_ORIGIN)


def restore_baseline() -> None:
    for view, value in BASELINE.items():
        set_opt(view, value)


def finish(code: int, note: str) -> int:
    stop_origin()
    restore_baseline()
    print()
    print(f"{PASS} passed, {FAIL} failed")
    print(note)
    return code


def main() -> int:  # noqa: C901 - a proof reads top to bottom or it proves nothing
    global KEY
    print("== build #20 item 1 -- what does graphql-alpha-0.33.0 ACTUALLY expose? ==")
    if not KEY:
        KEY = recover_key()
    if not KEY:
        print(f"VERDICT=NOT-RUN (no ZAP daemon found in {CONTAINER}; "
              f"start one on port {PORT} first)")
        return 1

    ver = api("core/view/version/").get("version", "")
    if not check(bool(ver), f"a ZAP daemon answers on {CONTAINER}:{PORT}", str(ver)):
        print("VERDICT=NOT-RUN (no daemon)")
        return 1
    print(f"        ZAP {ver}")

    # *** WHICH ADD-ON VERSION THIS RUN IS ABOUT, AND IT IS NOT THE IMAGE'S. ***
    # The image ships graphql-alpha-0.29.0 at /usr/share/zaproxy/plugin/. The container this was
    # first measured in ALSO had 0.33.0 in /root/.ZAP/plugin/ -- a runtime upgrade that lives in
    # one container's writable layer and would vanish on a rebuild. The two are not the same
    # surface: 0.29.0 has no `optionMaxCycleDetectionAlerts` at all and answers `bad_view`.
    #
    # Build #14's trap, exactly: THE CONTAINER IS NOT THE IMAGE. So this prints the version every
    # claim below is about, rather than letting a reader assume it is whatever they have.
    _, plugins = dex("sh", "-c",
                     "ls /usr/share/zaproxy/plugin/ $HOME/.ZAP/plugin/ 2>/dev/null "
                     "| grep -i '^graphql' | sort -u")
    installed = [p.strip() for p in plugins.splitlines() if p.strip()]
    check(bool(installed), "the graphql add-on is present on disk", str(plugins[:200]))
    print(f"        graphql add-on(s) visible in {CONTAINER}: {', '.join(installed) or 'NONE'}")
    if len(installed) > 1:
        print("        *** MORE THAN ONE. ZAP loads the NEWEST, which is a runtime upgrade "
              "living in this container's writable layer -- a rebuild would drop it. ***")

    # ---- A. THE ENUMERATION SURFACE ------------------------------------------------------
    # Build #19 established that `core/view/apiSummary` is bad_view in 2.17.0 and that
    # `/JSON/<component>/view/` answers with ZAP's WELCOME PAGE as a 200 of HTML, so it had to
    # establish the break surface by probing names one at a time and reading the error CODE.
    # `/UI/<component>/` is the listing it never found: every view and action, with parameters,
    # and which of them are required. That is worth more than this build -- it is how any future
    # go/no-go against a ZAP component should start.
    ui = raw("/UI/graphql/")
    views = sorted(set(re.findall(r"/UI/graphql/view/([A-Za-z]+)/", ui)))
    actions = sorted(set(re.findall(r"/UI/graphql/action/([A-Za-z]+)/", ui)))
    check(len(views) == 11 and len(actions) == 13,
          f"/UI/graphql/ ENUMERATES the component: {len(views)} views, {len(actions)} actions",
          f"views={views} actions={actions}")
    check(sorted(views) == sorted(VIEWS), "...and the 11 views are the ones named here",
          str(views))
    check("importFile" in actions and "importUrl" in actions,
          "importFile and importUrl both EXIST")
    check("Welcome to the Zed Attack Proxy" in raw("/JSON/graphql/view/"),
          "CONTROL: /JSON/graphql/view/ is ZAP's WELCOME PAGE, not a listing "
          "(this is why /UI/ is the surface and /JSON/ is not)")
    check(api("graphql/action/thisDoesNotExist/").get("code") == "bad_action",
          "CONTROL: a genuinely absent action answers bad_action")

    # An ABSENCE, named. "Read back what was imported -- an OK is not a result" was a sub-item of
    # this build, and it CANNOT be satisfied through graphql/: there is no view of the imported
    # schema. All 11 are option getters. So the read-back has to come from somewhere else, and
    # section D below is the measurement of where that somewhere else actually is.
    check(all(v.startswith("option") for v in views),
          "*** THERE IS NO VIEW THAT READS AN IMPORTED SCHEMA BACK -- all 11 are option* ***")

    for v in VIEWS:
        BASELINE[v] = opt(v)
    print(f"        persisted baseline: {json.dumps(BASELINE, sort_keys=True)}")

    # ---- B. THE OPTIONS, SET THEN READ BACK ----------------------------------------------
    enums = {
        "optionArgsType": (["INLINE", "VARIABLES", "BOTH"], []),
        "optionQuerySplitType": (["LEAF", "ROOT_FIELD", "OPERATION"], []),
        "optionRequestMethod": (["POST_JSON", "POST_GRAPHQL", "GET"], []),
        # Documented as a mode. In 0.33.0 it is a mode with ONE setting.
        "optionCycleDetectionMode": (["QUICK"],
                                     ["OFF", "THOROUGH", "PRECISE", "NONE", "COMPLETE"]),
    }
    for view, (legal, illegal) in enums.items():
        short = view[6:]
        for value in legal:
            r = set_opt(view, value)
            check(r.get("Result") == "OK" and opt(view).upper() == value,
                  f"{short}={value} is accepted AND reads back", f"{r} readback={opt(view)}")
        for value in illegal:
            before = opt(view)
            r = set_opt(view, value)
            check(r.get("code") == "internal_error" and opt(view) == before,
                  f"{short}={value} is REFUSED and leaves {before} in place",
                  f"{r} readback={opt(view)}")
    check(opt("optionCycleDetectionMode") == "QUICK",
          "*** cycleDetectionMode has exactly ONE usable value of the six probed: QUICK ***")
    check(set_opt("optionArgsType", "inline").get("Result") == "OK"
          and opt("optionArgsType") == "INLINE",
          "the enums are CASE-INSENSITIVE (lowercase `inline` reads back INLINE)")
    before = opt("optionArgsType")
    check(set_opt("optionArgsType", "NOPE").get("code") == "internal_error"
          and opt("optionArgsType") == before,
          "a refused enum leaves the previous value intact -- it does NOT corrupt the option")

    # ZAP will take a nonsense bound without a word. This is why HackPit WARNS on one and sends
    # it anyway rather than refusing: the bound is the operator's to set, and the thing that must
    # not happen is HackPit reporting a depth it did not apply. It reads back what it set.
    r = set_opt("optionMaxQueryDepth", "-1")
    check(r.get("Result") == "OK" and opt("optionMaxQueryDepth") == "-1",
          "*** maxQueryDepth=-1 is ACCEPTED and READS BACK -1 -- ZAP validates no bound ***",
          f"{r} readback={opt('optionMaxQueryDepth')}")
    r = set_opt("optionMaxQueryDepth", "notanumber")
    check(r.get("code") == "illegal_parameter",
          "...but a NON-NUMERIC depth is illegal_parameter (the TYPE is checked, the RANGE is not)",
          str(r))
    set_opt("optionMaxQueryDepth", "5")
    set_opt("optionRequestMethod", "POST_JSON")
    set_opt("optionArgsType", "BOTH")

    # ---- the origin ----------------------------------------------------------------------
    if not check(start_origin(), f"a GraphQL origin answers on {ORIGIN}"):
        print("VERDICT=NOT-RUN (no origin to measure against)")
        restore_baseline()
        return 1

    # ---- C. IMPORT -----------------------------------------------------------------------
    end = endpoint("file")
    clear_log()
    r = import_file(end)
    check(r.get("Result") == "OK", "importFile ACCEPTS an SDL document", str(r))
    time.sleep(6)
    rows = origin_rows()
    ops = real_ops(rows)
    check(len(ops) > 0,
          f"...and the ORIGIN received {len(ops)} generated operations "
          f"(of {len(rows)} requests -- an OK is not a result)")
    check(any("__typename" in (x.get("b") or "") for x in rows),
          "the add-on FINGERPRINTS THE ENGINE first (it already does graphw00f's job)")
    check(import_file(end, "/tmp/build20_no_such_file.graphql").get("code") == "does_not_exist",
          "importFile with a missing file answers does_not_exist")
    check(import_file(end, JUNK_FILE).get("code") == "internal_error",
          "importFile with a non-schema answers internal_error")

    # *** An OK that means "I parsed your schema", NOT "I did anything with it". ***
    # Nothing is listening on 19998. The API is happy. Anything that reported success from this
    # return value would tell an operator a scan had run against an endpoint that does not exist.
    clear_log()
    dead_import = import_file("http://127.0.0.1:19998/graphql")
    time.sleep(3)
    check(dead_import.get("Result") == "OK" and not real_ops(origin_rows()),
          "*** importFile answers OK against an endpoint that is NOT LISTENING ***",
          str(dead_import))

    end = endpoint("url")
    clear_log()
    r = api("graphql/action/importUrl/", {"endurl": end})
    check(r.get("Result") == "OK", "importUrl with endurl ALONE introspects the endpoint", str(r))
    time.sleep(6)
    rows = origin_rows()
    check(any("IntrospectionQuery" in (x.get("b") or "") for x in rows),
          "...and the origin saw ZAP's IntrospectionQuery go out")
    check(len(real_ops(rows)) > 0, "...and operations were generated from what came back")

    end = endpoint("doc")
    clear_log()
    r = api("graphql/action/importUrl/", {"endurl": end, "url": ORIGIN + "/schema.graphql"})
    check(r.get("Result") == "OK",
          "importUrl with BOTH endurl and url fetches the SDL from `url` (a third shape)", str(r))
    time.sleep(5)
    check(any(x.get("m") == "GET" and "schema.graphql" in (x.get("p") or "")
              for x in origin_rows()),
          "...and the origin log shows `url` was fetched with a GET, not introspected")

    # *** THE FINDING THAT DECIDED HOW ITEM 4 IS BUILT. ***
    # The build brief said: "INTROSPECTION DISABLED IS NOT AN EMPTY SCHEMA... disabled / error /
    # empty are three facts and the operator needs to know which." ZAP cannot tell them apart.
    # An endpoint that REFUSES introspection the way production does and a host that is not
    # listening answer with the SAME code and the SAME message. So HackPit probes the endpoint
    # itself and classifies -- and that is a measurement, not a preference.
    set_mode("disabled")
    disabled = api("graphql/action/importUrl/", {"endurl": endpoint("off")})
    dead = api("graphql/action/importUrl/", {"endurl": "http://127.0.0.1:19999/graphql"})
    set_mode("on")
    check(disabled.get("code") == "illegal_parameter",
          "introspection DISABLED -> importUrl answers illegal_parameter", str(disabled))
    check(dead.get("code") == "illegal_parameter",
          "a DEAD HOST -> importUrl answers illegal_parameter", str(dead))
    check(disabled.get("code") == dead.get("code")
          and disabled.get("message") == dead.get("message"),
          "*** SAME CODE, SAME MESSAGE -- ZAP CANNOT SAY WHY. HackPit must classify itself ***",
          f"disabled={disabled} dead={dead}")

    # ---- D. *** THE LINK THE PLAN ASSUMED, AND IT IS NOT THERE *** -----------------------
    # The plan's chain was: import -> generate -> land in the Sites tree -> ascan attacks them.
    # It does not land. This was measured four ways before it was believed: on a daemon that had
    # never had a session reset, on a node primed through the proxy and on one that was not, and
    # out to 60 seconds in case the insert was merely late. The operations reach the ORIGIN every
    # time -- they are real traffic -- and the tree never hears about them.
    end = endpoint("tree")
    proxied(end, '{"query":"{__typename}"}')
    time.sleep(2)
    primed = messages_on(end)
    check(primed > 0,
          f"CONTROL: ONE GraphQL request THROUGH THE PROXY puts {primed} messages on the node")
    kids = api("core/view/childNodes/?url=" + urllib.parse.quote(end)).get("childNodes", [])
    check(any(k.get("name", "").endswith("/query") for k in kids),
          "...and ZAP builds the synthetic <endpoint>/query node from that captured traffic",
          str([k.get("name") for k in kids]))

    clear_log()
    import_file(end)
    time.sleep(8)
    sent = len(real_ops(origin_rows()))
    after = messages_on(end)

    def generated_in_tree() -> int:
        """Messages ON THE NODE that are actually generated operations.

        A COUNT COMPARISON WAS NOT ENOUGH, and the first version of this check used one: the node
        went from 4 messages to 5 after an import that sent 4 operations, so `after == primed`
        failed while the claim it was defending held perfectly. One request does get filed -- the
        add-on's own probing goes through a path that records -- and none of the OPERATIONS do.
        So the check asks the question it means: is a generated operation in the tree?
        """
        rows = api("core/view/messages/?baseurl=" + urllib.parse.quote(end)
                   + "&start=0&count=500").get("messages", [])
        return sum(1 for m in rows
                   if any(f in str(m.get("requestBody") or "")
                          for f in ("userById", "setEmail", "search(", "search (")))

    check(sent > 0 and generated_in_tree() == 0,
          f"*** {sent} generated operations REACHED THE ORIGIN and NOT ONE is in the tree ***",
          f"primed={primed} after={after} sent={sent} in_tree={generated_in_tree()}")
    time.sleep(20)
    check(generated_in_tree() == 0,
          "...still absent 28 seconds later -- it is not a late insert, it is no insert")

    # ---- E. THE SHAPE OF AN ARGUMENT -----------------------------------------------------
    shapes: dict[str, list[str]] = {}
    for args_type in ("VARIABLES", "INLINE"):
        set_opt("optionArgsType", args_type)
        clear_log()
        import_file(endpoint(args_type[:4].lower()))
        time.sleep(6)
        shapes[args_type] = real_ops(origin_rows())

    def named_vars(bodies: list[str]) -> set[str]:
        keys: set[str] = set()
        for b in bodies:
            try:
                d = json.loads(b)
            except ValueError:
                continue
            if isinstance(d, dict) and isinstance(d.get("variables"), dict):
                keys |= set(d["variables"])
        return keys

    vkeys = named_vars(shapes["VARIABLES"])
    ikeys = named_vars(shapes["INLINE"])
    check({"userById_id", "userById_token", "userById_locale"} <= vkeys,
          "argsType=VARIABLES gives EVERY argument its own key in `variables`",
          f"{sorted(vkeys)} from {len(shapes['VARIABLES'])} operations")
    check(not ikeys and any("userById" in b for b in shapes["INLINE"]),
          "CONTROL: argsType=INLINE puts the arguments in the query TEXT, `variables` empty",
          f"{sorted(ikeys)} from {len(shapes['INLINE'])} operations")

    # RPC_JSON is bit 4. Its presence is what makes a JSON body an input vector at all, and it
    # is on by default rather than something this build had to switch on.
    rpc = int(api("ascan/view/optionTargetParamsEnabledRPC/").get("TargetParamsEnabledRPC", "0"))
    check(rpc & 4 == 4,
          f"ascan's enabled-RPC mask ({rpc}) includes RPC_JSON -- a JSON body IS an input vector")

    # ---- F. *** THE ONE REPORT #61 NEEDS: ONE ARGUMENT AT A TIME *** ---------------------
    # On a CAPTURED operation. No schema imported against this endpoint at all -- which is the
    # point, because an operator with a request in their proxy history does not have the schema,
    # and section D just proved that having the schema would not have helped anyway.
    end = endpoint("scan")
    proxied(end, CAPTURED)
    time.sleep(2)
    check(messages_on(end) > 0, "a CAPTURED GraphQL operation is on the node", str(end))

    clear_log()
    scan = api("ascan/action/scan/", {"url": end, "recurse": "true", "inScopeOnly": "false"})
    sid = scan.get("scan")
    if not check(sid is not None, "ascan accepts the captured GraphQL node", str(scan)):
        return finish(1, "VERDICT=FAIL -- the scanner cannot be aimed at captured operations.")
    t0 = time.time()
    while time.time() - t0 < 1500:
        if api(f"ascan/view/status/?scanId={sid}").get("status") == "100":
            break
        time.sleep(5)
    print(f"        scan finished in {int(time.time() - t0)}s")
    time.sleep(3)

    rows = origin_rows()
    single = multi = withvars = 0
    per_arg: dict[str, int] = {}
    for x in rows:
        try:
            d = json.loads(x.get("b") or "")
        except ValueError:
            continue
        if not isinstance(d, dict) or not isinstance(d.get("variables"), dict):
            continue
        v = d["variables"]
        if not v:
            continue
        withvars += 1
        diff = [k for k in set(v) | set(CAPTURED_VARS) if v.get(k) != CAPTURED_VARS.get(k)]
        for k in diff:
            per_arg[k] = per_arg.get(k, 0) + 1
        if len(diff) == 1:
            single += 1
        elif len(diff) > 1:
            multi += 1
    print(f"        the origin received {len(rows)} requests, {withvars} carrying variables")
    print(f"        per-argument counts: {json.dumps(per_arg, sort_keys=True)}")
    check(single > 0,
          f"*** {single} requests mutated EXACTLY ONE argument, leaving the others alone ***",
          "no request changed exactly one argument")
    check(multi == 0,
          f"...and {multi} mutated more than one -- the scanner isolates the argument under test")
    check(set(per_arg) == set(CAPTURED_VARS),
          f"...and all {len(per_arg)} arguments were reached individually",
          f"reached={sorted(per_arg)} expected={sorted(CAPTURED_VARS)}")

    # ---- restore -------------------------------------------------------------------------
    stop_origin()
    restore_baseline()
    after_opts = {v: opt(v) for v in VIEWS}
    check(after_opts == BASELINE,
          "the persisted add-on options are back to what this run found (ZAP PERSISTS them)",
          f"before={BASELINE} after={after_opts}")

    print()
    print(f"{PASS} passed, {FAIL} failed")
    if FAIL:
        print("VERDICT=FAIL -- items 4 and 5 must be reconsidered against what is above.")
        return 1
    print("VERDICT=PASS -- schema import works and its generated operations are NOT scannable; "
          "captured operations ARE, one argument at a time. Item 4 is recon, item 5 scans the "
          "capture.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        stop_origin()
        print("VERDICT=NOT-RUN (interrupted)")
        raise SystemExit(1) from None
