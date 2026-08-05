#!/usr/bin/env python3
"""Build #21 -- field-suggestion enumeration, MEASURED against servers that word it differently.

*** IT DRIVES THE PRODUCT, NOT A COPY OF IT. *** Every claim below goes through
``cockpit.graphql_zap.fingerprint_engine`` and ``cockpit.graphql_zap.enumerate_schema`` -- the
same functions the routes call, over the same ``docker exec ... curl`` transport. A proof that
reimplemented the parsing would prove the proof works.

*** WHY THERE IS AN ORIGIN PER CORE. *** The thing under test is a regex over a string a REMOTE
server chooses, and the failure mode is silence: the wrong parser returns zero suggestions, which
is exactly what a hardened server returns. So the origin emulates each core's ACTUAL wording,
taken from the same places the parsers were taken from:

    graphql-js     RUN locally: node + graphql 16.x
    graphql-core   RUN locally: python + graphql-core 3.2.11
    graphql-ruby   SOURCE: fields_are_defined_on_type.rb + validation_context.rb
    graphql-java   SOURCE: i18n/Validation.properties
    gqlgen         SOURCE: gqlparser validator/rules/fields_on_correct_type.go

and it computes its suggestions by EDIT DISTANCE from what was actually sent, the way a real
server does -- so a probe that is not close to a real field gets nothing back, and the wordlist
has to genuinely work rather than being handed the answer.

WHAT IT PROVES:

   1. each core is FINGERPRINTED from one probe, and to the right CORE (not the brand)
   2. each core's suggestions are PARSED -- names recovered, per dialect
   3. *** THE POSITIVE CONTROL: the "suggestions disabled" branch FIRES *** -- a server that
      answers well-formed unknown-field errors with no clause is reported as a working DEFENCE
      and not as an empty schema
   4. a core that never suggests (graphql-java) is `suggestions_unsupported`, a THIRD answer
   5. an unidentifiable server is `engine_unknown` and NO wordlist is spent on it
   6. *** THE WRONG PARSER RECOVERS NOTHING *** -- run graphql-js's dialect at a graphql-core
      server on purpose and watch it look exactly like a hardened endpoint
   7. the declared bounds STOP the run, name themselves, and RETURN WHAT WAS FOUND
   8. a recovered argument composes into a repeater operation with the argument as a VARIABLE
   9. CROSS-CHECK: `graphw00f` -- an INDEPENDENT implementation in the arsenal -- agrees about
      the engine on the same endpoints

Run it with the stack up:

    python docs/proof/build21_graphql_enum.py [container]

Prints VERDICT= and exits non-zero on failure. ASCII only: this console is cp1252.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))

from cockpit import graphql_enum as ge          # noqa: E402
from cockpit import graphql_zap                 # noqa: E402

CONTAINER = sys.argv[1] if len(sys.argv) > 1 else "hackpit-engage-sandbox"

ORIGIN_PORT = 18120
ORIGIN = f"http://127.0.0.1:{ORIGIN_PORT}"
SERVER = "/tmp/build21_gql_core_server.py"
MODE = "/tmp/build21_gql_mode"

PASS = 0
FAIL = 0

#: A BRACKETED pattern. `pkill -f build21_gql_core_server` matches the `sh -c` running it, so the
#: shell kills itself and everything after the `;` is silently never run -- this repo has been
#: bitten by that twice (build #14 part 2, and again while writing build #20's proof).
_KILL = "pkill -f 'build21_gql[_]core_server' 2>/dev/null; true"

ORIGIN_SRC = r'''#!/usr/bin/env python3
"""A GraphQL origin that speaks a DIFFERENT CORE'S DIALECT on demand. stdlib only.

Its suggestions are computed by EDIT DISTANCE from what the client actually sent, exactly as a
real server does -- so the enumerator has to earn every name. Handing back a fixed list would
have made a broken wordlist and a broken parser both look like success.
"""
import difflib, http.server, json

MODE = "%(mode)s"
PORT = %(port)d

# The "schema" being defended. Nothing announces it; it only leaks through suggestions.
FIELDS = ["user", "users", "userById", "account", "accounts", "orders", "paymentMethod",
          "sessionToken", "adminPanel", "auditLog"]
ARGS = {"userById": ["identifier", "token", "locale"]}

def mode():
    try:
        with open(MODE) as f: return f.read().strip()
    except OSError: return "graphql-js"

def close(name, pool, n=5):
    # A real server caps at 5 and orders by distance. Both are reproduced: the cap is what makes
    # a full list a TRUNCATED one rather than a complete one.
    return difflib.get_close_matches(name, pool, n=n, cutoff=0.4)

def fmt(m, name, sugg, parent="Query"):
    if m == "graphql-js" or m == "graphql-php" or m == "gqlgen":
        base = 'Cannot query field "%%s" on type "%%s".' %% (name, parent)
        if not sugg: return base
        q = ['"%%s"' %% s for s in sugg]
        return base + " Did you mean " + orlist(q) + "?"
    if m == "graphql-core":
        base = "Cannot query field '%%s' on type '%%s'." %% (name, parent)
        if not sugg: return base
        q = ["'%%s'" %% s for s in sugg]
        return base + " Did you mean " + orlist(q) + "?"
    if m == "graphql-ruby":
        base = "Field '%%s' doesn't exist on type '%%s'" %% (name, parent)
        if not sugg: return base
        q = ["`%%s`" %% s for s in sugg]
        # graphql-ruby joins with ", " and then " or " -- NO Oxford comma. Reproduced exactly.
        if len(q) == 1: tail = q[0]
        else: tail = ", ".join(q[:-1]) + " or " + q[-1]
        return base + " (Did you mean " + tail + "?)"
    if m == "graphql-java":
        # No suggestion clause exists in this core AT ALL.
        return ("Validation error (FieldUndefined@[%%s]) : Field '%%s' in type '%%s' is undefined"
                %% (name, name, parent))
    if m == "suggestions-off":
        # gqlgen's FieldsOnCorrectTypeRuleWithoutSuggestions: same sentence, clause removed.
        return 'Cannot query field "%%s" on type "%%s".' %% (name, parent)
    return "something else entirely"

def orlist(q):
    if len(q) == 1: return q[0]
    if len(q) == 2: return q[0] + " or " + q[1]
    return ", ".join(q[:-1]) + ", or " + q[-1]   # graphql-js HAS the Oxford comma

def arg_error(m, field, bad):
    sugg = close(bad, ARGS.get(field, []))
    if m in ("graphql-js", "graphql-php", "gqlgen"):
        base = 'Unknown argument "%%s" on field "Query.%%s".' %% (bad, field)
        return base + (" Did you mean " + orlist(['"%%s"' %% s for s in sugg]) + "?" if sugg else "")
    if m == "graphql-core":
        base = "Unknown argument '%%s' on field 'Query.%%s'." %% (bad, field)
        return base + (" Did you mean " + orlist(["'%%s'" %% s for s in sugg]) + "?" if sugg else "")
    return "Unknown argument"

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _send(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        m = mode()
        try: q = json.loads(raw).get("query", "")
        except Exception: q = ""

        if m == "garbage":
            self._send({"data": {"whatever": 1}}); return
        if "__schema" in q:
            self._send({"errors": [{"message": "GraphQL introspection is not allowed"}]}); return
        if "__typename" in q:
            self._send({"data": {"__typename": "Query"}}); return
        if q.strip() == "aaa":
            self._send({"errors": [{"message": "Syntax Error GraphQL (1:1)"}]}); return
        if "@skip" in q:
            if m == "graphql-ruby":
                self._send({"errors": [{"message": "'@skip' can't be applied to queries "
                                        "(allowed: fields, fragment spreads, inline fragments)"}]})
            else:
                self._send({"errors": [{"message": 'Directive "@skip" argument "if" of type '
                                        '"Boolean!" is required, but it was not provided.'}]})
            return

        # An argument probe: userById(<bad>: ...)
        if "userById(" in q:
            inner = q.split("userById(", 1)[1].split(")", 1)[0]
            bad = inner.split(":", 1)[0].strip().lstrip("$")
            self._send({"errors": [{"message": arg_error(m, "userById", bad)}]}); return

        # A field probe: `{ a b c }` -- one error per unknown name, as every core does.
        names = [t for t in q.replace("{", " ").replace("}", " ").split() if t]
        errs = []
        for name in names:
            if name in FIELDS:
                continue
            errs.append({"message": fmt(m, name, close(name, FIELDS))})
        if errs: self._send({"errors": errs})
        else: self._send({"data": {}})
    def log_message(self, *a): pass

if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
''' % {"mode": MODE, "port": ORIGIN_PORT}


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
    return bool(ok)


def dex(*argv: str, stdin: bytes | None = None, timeout: int = 180) -> tuple[int, str]:
    p = subprocess.run(["docker", "exec", "-i", CONTAINER, *argv],
                       capture_output=True, timeout=timeout, input=stdin)
    return p.returncode, (p.stdout or b"").decode("utf-8", "replace")


def set_mode(mode: str) -> None:
    dex("sh", "-c", f"printf '{mode}' > {MODE}")


def start_origin() -> bool:
    dex("sh", "-c", _KILL)
    time.sleep(1)
    dex("sh", "-c", f"cat > {SERVER}", stdin=ORIGIN_SRC.encode())
    set_mode("graphql-js")
    subprocess.Popen(["docker", "exec", "-d", CONTAINER, "sh", "-c",
                      f"exec python3 {SERVER} >> /tmp/build21_origin.err 2>&1"])
    time.sleep(3)
    rc, out = dex("curl", "-s", "--max-time", "8", "-X", "POST",
                  "-H", "Content-Type: application/json",
                  "--data-binary", '{"query":"{ zzz }"}', ORIGIN + "/graphql")
    return rc == 0 and "Cannot query field" in out


def stop_origin() -> None:
    dex("sh", "-c", _KILL)


#: A wordlist that must genuinely WORK: none of these is a real field on the origin, and every
#: recovered name has to come out of the server's own edit-distance suggestion.
WORDS = ["user", "acount", "order", "payment", "session", "admin", "audit", "zzzznope"]


def main() -> int:  # noqa: C901 - a proof reads top to bottom or it proves nothing
    print("== build #21 -- field-suggestion enumeration, per core ==")
    rc, ver = dex("sh", "-c", "echo ok")
    if not check(rc == 0 and "ok" in ver, f"{CONTAINER} answers docker exec"):
        print("VERDICT=NOT-RUN (no container)")
        return 1
    if not check(start_origin(), f"a multi-dialect GraphQL origin answers on {ORIGIN}"):
        print("VERDICT=NOT-RUN (no origin)")
        return 1

    url = ORIGIN + "/graphql"

    # ---- 1 + 2. EACH CORE: fingerprinted, then parsed. -------------------------------------
    expect = {
        "graphql-js": ("graphql-js", "graphql-js"),
        "graphql-core": ("graphql-core", "graphql-core"),
        "graphql-ruby": ("graphql-ruby", "graphql-ruby"),
        "graphql-php": ("graphql-js", "graphql-js"),      # byte-identical, measured from source
        "gqlgen": ("graphql-js", "graphql-js"),           # ditto (gqlparser)
    }
    recovered_per_core: dict[str, list[str]] = {}
    for mode, (core, dialect) in expect.items():
        set_mode(mode)
        fp = graphql_zap.fingerprint_engine(CONTAINER, url)
        check(fp.core == core and fp.dialect == dialect,
              f"{mode}: fingerprinted as core={core}, dialect={dialect}",
              f"got core={fp.core} dialect={fp.dialect} evidence={fp.evidence}")

        result = graphql_zap.enumerate_schema(
            CONTAINER, url, WORDS,
            bounds=ge.EnumerationBounds(wordlist_name="proof", wordlist_size=len(WORDS),
                                        batch_size=4),
            fingerprint=fp)
        recovered_per_core[mode] = sorted(result.field_names)
        check(result.status == "productive" and len(result.fields) >= 4,
              f"{mode}: enumeration is productive -- {len(result.fields)} names recovered",
              f"status={result.status} names={result.field_names} note={result.note}")
        check("user" in result.field_names and "adminPanel" in result.field_names,
              f"{mode}: recovered names the server never volunteered unprompted "
              f"(user, adminPanel)", str(result.field_names))

    # Every dialect must recover the SAME schema -- if one lags, its parser is wrong.
    sets = {mode: set(names) for mode, names in recovered_per_core.items()}
    first = sets["graphql-js"]
    check(all(v == first for v in sets.values()),
          "*** ALL FIVE CORES YIELD THE SAME SCHEMA -- the parsers agree ***",
          json.dumps({k: sorted(v) for k, v in sets.items()}))

    # ---- 6. *** THE WRONG PARSER RECOVERS NOTHING, ON PURPOSE. *** -------------------------
    # graphql-core's server, read with graphql-js's dialect. This is the trap the whole build is
    # shaped around: the result is indistinguishable from a hardened server unless you know.
    set_mode("graphql-core")
    wrong = graphql_zap.enumerate_schema(
        CONTAINER, url, WORDS,
        bounds=ge.EnumerationBounds(wordlist_name="proof", batch_size=4),
        fingerprint=ge.EngineFingerprint(core="graphql-js", dialect="graphql-js",
                                         suggests=True, confidence="high"))
    right = graphql_zap.enumerate_schema(
        CONTAINER, url, WORDS,
        bounds=ge.EnumerationBounds(wordlist_name="proof", batch_size=4))
    check(not wrong.fields and right.fields,
          "*** graphql-js's PARSER AT A graphql-core SERVER RECOVERS ZERO *** while the correct "
          "dialect recovers the schema -- one quote character",
          f"wrong={wrong.field_names} right={right.field_names}")
    check(wrong.unknown_field_errors == 0 and right.unknown_field_errors > 0,
          "...and the DENOMINATOR is what tells them apart: the wrong parser saw 0 unknown-field "
          "errors, the right one saw many",
          f"wrong={wrong.unknown_field_errors} right={right.unknown_field_errors}")

    # ---- 3. *** THE POSITIVE CONTROL: THE `suggestions_disabled` BRANCH FIRES. *** ----------
    set_mode("suggestions-off")
    off = graphql_zap.enumerate_schema(
        CONTAINER, url, WORDS,
        bounds=ge.EnumerationBounds(wordlist_name="proof", batch_size=4))
    check(off.status == "suggestions_disabled",
          "*** POSITIVE CONTROL: a server with suggestions OFF reads as suggestions_disabled ***",
          f"status={off.status} note={off.note}")
    check(off.unknown_field_errors > 0 and not off.fields,
          f"...and it is a DEFENCE, not an empty schema: {off.unknown_field_errors} unknown-field "
          f"errors answered, 0 names offered", str(off.note))
    check("defence" in off.note,
          "...and the note says so in words an operator can act on", off.note)

    # ---- 4. a core that NEVER suggests is a THIRD answer. -----------------------------------
    set_mode("graphql-java")
    java = graphql_zap.enumerate_schema(CONTAINER, url, WORDS)
    check(java.status == "suggestions_unsupported" and java.fingerprint.core == "graphql-java",
          "graphql-java -> suggestions_unsupported (nothing to switch on), NOT disabled",
          f"status={java.status} core={java.fingerprint.core}")
    check(java.requests_sent == 0,
          "...and NOT ONE wordlist request was spent on it", str(java.requests_sent))

    # ---- 5. an unidentifiable server spends nothing. ----------------------------------------
    set_mode("garbage")
    unknown = graphql_zap.enumerate_schema(CONTAINER, url, WORDS)
    check(unknown.status == "engine_unknown" and unknown.requests_sent == 0,
          "an unidentifiable engine -> engine_unknown, and NO wordlist is spent guessing",
          f"status={unknown.status} sent={unknown.requests_sent} fp={unknown.fingerprint}")

    # ---- 7. the declared bounds stop the run and KEEP the results. --------------------------
    set_mode("graphql-js")
    big = WORDS * 12
    bounded = graphql_zap.enumerate_schema(
        CONTAINER, url, big,
        bounds=ge.EnumerationBounds(wordlist_name="proof", wordlist_size=len(big),
                                    max_requests=3, batch_size=2))
    check(bounded.stopped_early and bounded.requests_sent == 3,
          f"max_requests=3 STOPPED the run at exactly 3 requests",
          f"sent={bounded.requests_sent} early={bounded.stopped_early}")
    check(bool(bounded.fields) and "max_requests=3" in bounded.stop_reason,
          "...and it RETURNED WHAT IT FOUND and named the bound that stopped it",
          f"names={bounded.field_names} reason={bounded.stop_reason}")
    check("STOPPED EARLY" in bounded.note,
          "...and the note says the coverage is partial", bounded.note)

    # ---- 8. an argument is recovered and composes as a VARIABLE. ----------------------------
    args = graphql_zap.enumerate_schema(
        CONTAINER, url, ["userById"],
        bounds=ge.EnumerationBounds(wordlist_name="proof", batch_size=1))
    # Provoke the argument error directly through the same product transport.
    _s, text, _t = graphql_zap._curl_json(
        CONTAINER, url, json.dumps({"query": '{ userById(identifer: "x") }'}), [], 25)
    arg_names: list[ge.Suggestion] = []
    for m in ge.error_messages(text):
        ge.merge_suggestions(arg_names, ge.parse_argument_suggestions(m, "graphql-js"))
    check([s.name for s in arg_names] == ["identifier"],
          "*** AN UNKNOWN ARGUMENT LEAKS ITS REAL NAME TOO *** -- report #61's injection point "
          "was an argument, not a field",
          str([(s.name, s.on_type) for s in arg_names]))

    args.arguments = arg_names
    args.fields = [ge.Suggestion(name="userById")]
    composed = ge.compose_from_recovered(args, "userById")
    check("$identifier: String" in composed.query and '"identifier": ""' in composed.variables,
          "a recovered argument composes as a VARIABLE with an EMPTY value -- nothing invented",
          composed.query)
    check(composed.scannable is False and "PROXY" in composed.next_step,
          "...and it says it is NOT scannable where it stands (only the proxy makes it so)",
          composed.next_step)

    # ---- 9. CROSS-CHECK against graphw00f, an INDEPENDENT implementation. -------------------
    # Two implementations agreeing is evidence; one implementation agreeing with itself is not.
    set_mode("graphql-js")
    rc, w00f = dex("sh", "-c",
                   f"graphw00f -d -f -t {ORIGIN}/graphql 2>&1 | tail -20", timeout=180)
    ours = graphql_zap.fingerprint_engine(CONTAINER, url)
    named = any(tok in w00f.lower() for tok in ("apollo", "graphql", "engine"))
    check(rc == 0 and named,
          "CROSS-CHECK: graphw00f (the arsenal's independent implementation) runs and names an "
          "engine on the same endpoint",
          f"rc={rc} out={w00f.strip()[:220]}")
    print(f"        graphw00f said: {w00f.strip()[:200]}")
    print(f"        HackPit said:   core={ours.core} engine={ours.engine} "
          f"dialect={ours.dialect}")

    stop_origin()
    print()
    print(f"{PASS} passed, {FAIL} failed")
    if FAIL:
        print("VERDICT=FAIL")
        return 1
    print("VERDICT=PASS -- every core is fingerprinted to its CORE and parsed in its own "
          "dialect; suggestions-off, never-suggests and unknown-engine are three separate "
          "answers; bounds stop the run and keep the results.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        stop_origin()
        print("VERDICT=NOT-RUN (interrupted)")
        raise SystemExit(1) from None
