"""Field-suggestion enumeration: read a schema off a server that refuses to hand one over.

THE PURE HALF. No I/O, no subprocess, no socket -- asserted by AST in test_graphql_safety.py, the
same way ``cockpit/graphql.py`` is, so every claim below is covered by the hermetic suite with no
daemon and no network anywhere. The runner that actually sends requests lives in
``graphql_zap.py`` and reuses ``_curl_json``: build #19's plumbing, not a second HTTP path.

WHAT THIS IS FOR. Build #20 measured that when introspection is off, ZAP tells you nothing -- an
endpoint refusing introspection the way production does and a host that is not listening answer
with the SAME code and the SAME message. ``probe_schema`` classifies that into six. When it says
``disabled``, this module is what happens next: many servers still answer a wrong field name with
``Did you mean "user"?``, and that suggestion leaks the schema one field at a time.

*** THE UNIT IS THE ERROR-PRODUCING CORE, NOT THE SERVER BRAND. ***
"Apollo, graphql-js, Hasura, Graphene" is four brands that are not four implementations: Apollo IS
graphql-js, and Graphene sits on graphql-core, the Python port of graphql-js. Grouping by brand
produces parsers that duplicate each other in some places and miss entirely in others. So the
lookup is keyed on the core that FORMATS THE ERROR, and brands map onto cores.

*** THE WORDING WAS MEASURED, NOT REMEMBERED. *** Every string below was taken either by running
the library or by reading the line of its source that formats the message. Provenance is recorded
per dialect, because "I am fairly sure Ruby uses backticks" is exactly how a parser that finds
nothing gets shipped green.

    graphql-js     3 fixtures RUN locally (graphql 16.x, node)
    graphql-core   3 fixtures RUN locally (graphql-core 3.2.11)
    graphql-php    src/Validator/Rules/FieldsOnCorrectType.php + Utils::orList
    gqlparser      validator/rules/fields_on_correct_type.go (gqlgen's parser)
    graphql-ruby   static_validation/rules/fields_are_defined_on_type.rb + validation_context.rb
    graphql-java   src/main/resources/i18n/Validation.properties
    absinthe       phase/document/validation/fields_on_correct_type.ex
                     + .../utils/message_suggestions.ex
    async-graphql  src/validation/rules/fields_on_correct_type.rs + src/validation/suggestion.rs
    hotchocolate   Core/src/Validation/Properties/Resources.resx + Rules/FieldSelectionsRule.cs
    graphql-dotnet Validation/Errors/FieldsOnCorrectTypeError.cs + Utilities/StringUtils.cs
                     + Validation/Errors/KnownArgumentNamesError.cs

*** THE THREE READ LAST WENT THREE DIFFERENT WAYS, WHICH IS THE ARGUMENT FOR READING THEM. ***
They were added together, from one plan, on one assumption -- that each would need its own parser.
One did, one needed none, and one turned out to already be covered::

    absinthe       Cannot query field "usr" on type "Query". Did you mean "user" or "users"?
    async-graphql  Unknown field "usr" on type "Query". Did you mean "user", "users"?
    hotchocolate   The field `usr` does not exist on the type `Query`.

Absinthe is BYTE-IDENTICAL to graphql-js -- sentence, joiner, Oxford comma and the cap of five,
all four read and all four matching, from an implementation in a different language that shares no
code with it. async-graphql shares neither half: a different verb, and a separator that is a bare
comma where every other core in this file writes `or`. HotChocolate never suggests a name at all,
so the honest answer there is `suggestions_unsupported` -- do not spend three thousand requests.

Guessing would have got all three wrong in a different direction each time.

*** AND .NET TURNED OUT TO BE TWO IMPLEMENTATIONS THAT AGREE ON NOTHING. ***
`graphql-dotnet` is not a variant of HotChocolate; they share no wording at all. It reproduces
graphql-core's grammar to the character -- single quotes, bare ``or`` at two, an Oxford comma from
three, the same cap of five -- from a C# codebase, so a .NET server can fingerprint as either
`hotchocolate` (suggests nothing) or `graphql-core` (suggests everything). Reading only one of them
and calling .NET done would have left half the platform unenumerable and looked complete.

It also contradicts itself, and the contradiction was worth a fix: its FIELD clause ends in ``?``
and its ARGUMENT clause does not (`KnownArgumentNamesError.cs` omits it where
`FieldsOnCorrectTypeError.cs` appends it). A clause pattern demanding a literal question mark
recovered its fields and silently dropped every argument name it volunteered.

*** AND THE MEASUREMENT OVERTURNED THE OBVIOUS GUESS. ***
graphql-core is NOT byte-identical to graphql-js. The grammar is identical and the quote character
is not: graphql-js writes ``Did you mean "user"?`` and graphql-core writes ``Did you mean 'user'?``.
So a parser written against graphql-js -- the one everybody writes first, because it is the one
every article quotes -- returns ZERO suggestions against every Python GraphQL server there is:
Graphene, Strawberry, Ariadne. Silently. It looks exactly like a server with suggestions switched
off. That is the "one regex over all of them" trap this project has been burned by repeatedly,
and it is why the dialect is chosen from a MEASURED probe rather than assumed.

The same measurement in the other direction stopped three parsers being written for no reason:
graphql-php and gqlparser (gqlgen) ARE byte-identical to graphql-js, from their own source. They
share the parser and the fixture set records that they were checked rather than lumped in.

*** graphql-ruby IS THE ONE THAT MATTERS MOST AND THE ONE LEAST LIKE THE REST. ***
GitHub, Shopify and GitLab all run graphql-ruby. Its wording shares not one delimiter with
graphql-js::

    graphql-js    Cannot query field "usr" on type "Query". Did you mean "user" or "users"?
    graphql-ruby  Field 'usr' doesn't exist on type 'Query' (Did you mean `user` or `users`?)

Backticks, inside parentheses, after a different sentence, with the field in single quotes -- and
NO Oxford comma before ``or`` where graphql-js has one. Four independent differences.

*** SOME CORES NEVER SUGGEST AT ALL, AND THAT IS NOT THE SAME AS "SWITCHED OFF". ***
graphql-java's `FieldsOnCorrectType.unknownField` has no suggestion clause in the source at all.
Neither does Hasura's. Telling an operator "suggestions are disabled" there implies a setting
somebody could have left on; the truth is there is nothing to enable, and the actionable answer
is "do not spend three thousand requests here". So that is its own outcome.
"""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, Field

# --------------------------------------------------------------------------------------------
# Dialects: how a core WORDS a suggestion.
# --------------------------------------------------------------------------------------------

#: The three suggestion dialects that exist, and the cores that speak each one.
#:
#: A dialect is (a) the sentence that says the field is unknown and (b) the clause that carries
#: the suggestions. They are separate patterns on purpose: an unknown-field sentence WITHOUT a
#: suggestion clause is the whole basis of the "suggestions are switched off" answer, and a
#: parser that only had one combined regex could not tell that apart from a failed request.
DIALECTS: dict[str, dict[str, str]] = {
    "graphql-js": {
        # MEASURED by running graphql 16.x:
        #   Cannot query field "usr" on type "Query". Did you mean "user" or "users"?
        "unknown_field": r'Cannot query field "(?P<name>[^"]+)" on type "(?P<type>[^"]+)"',
        "suggestion_clause": r'Did you mean (?P<body>"[^?]*?)\?',
        "quote": '"',
        "provenance": "RUN: graphql 16.x via node; and read in graphql-php + gqlparser sources",
    },
    "graphql-core": {
        # MEASURED by running graphql-core 3.2.11:
        #   Cannot query field 'usr' on type 'Query'. Did you mean 'user' or 'users'?
        # IDENTICAL GRAMMAR, DIFFERENT QUOTE. See the module docstring.
        # *** THE TRAILING `?` IS OPTIONAL HERE AND THAT IS MEASURED, NOT DEFENSIVE. ***
        # graphql-dotnet shares this dialect byte for byte on the FIELD sentence and then
        # contradicts itself on the argument one: FieldsOnCorrectTypeError.cs appends
        # `...QuotedOrList(names)}?"` and KnownArgumentNamesError.cs:45 appends the same clause
        # WITHOUT the question mark. A clause pattern that demanded `\?` recovered graphql-dotnet's
        # field names and silently dropped every argument name it offered -- and an argument is
        # what report #61 actually needed. The body must still open and close on a quote, so an
        # optional terminator cannot match an empty one.
        "unknown_field": r"Cannot query field '(?P<name>[^']+)' on type '(?P<type>[^']+)'",
        "suggestion_clause": r"Did you mean (?P<body>'[^?]*')\??",
        "quote": "'",
        "provenance": ("RUN: graphql-core 3.2.11 via python; and read in graphql-dotnet "
                       "Validation/Errors/FieldsOnCorrectTypeError.cs + Utilities/StringUtils.cs"),
    },
    "graphql-ruby": {
        # SOURCE: fields_are_defined_on_type.rb
        #     "Field '#{node.name}' doesn't exist on type '#{parent_type.graphql_name}'#{suggestion}"
        #   validation_context.rb
        #     " (Did you mean `#{suggestions.first}`?)"
        #     " (Did you mean #{...join(", ")} or `#{last}`?)"
        "unknown_field": (r"Field '(?P<name>[^']+)' doesn't exist on type "
                          r"'(?P<type>[^']+)'"),
        "suggestion_clause": r"\(Did you mean (?P<body>`[^?]*?)\?\)",
        "quote": "`",
        "provenance": "SOURCE: graphql-ruby fields_are_defined_on_type.rb + validation_context.rb",
    },
    "async-graphql": {
        # SOURCE: src/validation/rules/fields_on_correct_type.rs
        #     format!("Unknown field \"{}\" on type \"{}\".{}", ...)
        #   src/validation/suggestion.rs -- make_suggestion(" Did you mean", ...)
        #     pushes the prefix, then a space, then each name as "name" JOINED WITH ", ",
        #     then '?'. There is no branch for the last element.
        #
        # *** NEITHER HALF MATCHES graphql-js, AND THE JOINER HAS NO `or` AT ALL. ***
        #     graphql-js     Cannot query field "usr" on type "Query". Did you mean "user" or "users"?
        #     async-graphql  Unknown field "usr" on type "Query". Did you mean "user", "users"?
        # Two independent differences -- the verb, and a separator that is a bare comma where
        # every other core reaches for `or`. The quoted-run extraction in `parse_suggestions`
        # absorbs the missing `or` without a change, which is the whole reason it pulls quoted
        # runs instead of splitting on a separator.
        #
        # Suggestions are behind `registry.enable_suggestions`, so this core CAN be switched off
        # and `no_suggestion` is a real observation against it -- unlike graphql-java or
        # HotChocolate, where there is nothing to switch.
        "unknown_field": r'Unknown field "(?P<name>[^"]+)" on type "(?P<type>[^"]+)"',
        "suggestion_clause": r'Did you mean (?P<body>"[^?]*?)\?',
        "quote": '"',
        "provenance": ("SOURCE: async-graphql src/validation/rules/fields_on_correct_type.rs "
                       "+ src/validation/suggestion.rs"),
    },
}

#: Cores that FORMAT AN UNKNOWN FIELD BUT NEVER SUGGEST. Not a dialect -- an absence, and the
#: reason `suggestions_unsupported` is a separate outcome from `suggestions_disabled`.
NON_SUGGESTING_CORES: dict[str, str] = {
    "graphql-java": (
        # SOURCE: i18n/Validation.properties
        #   FieldsOnCorrectType.unknownField=Validation error ({0}) : Field ''{1}'' in type
        #   ''{2}'' is undefined
        # The doubled quotes are Java MessageFormat escaping; on the wire it is one quote.
        r"Validation error \([^)]*\) ?: Field '(?P<name>[^']+)' in type '(?P<type>[^']+)' "
        r"is undefined"
    ),
    "hasura": r"field \"?(?P<name>[^\"']+)\"? not found in type: '?(?P<type>[^\"']+)'?",
    "hotchocolate": (
        # SOURCE: src/HotChocolate/Core/src/Validation/Properties/Resources.resx
        #   ErrorHelper_FieldDoesNotExist=The field `{0}` does not exist on the type `{1}`.
        # raised from Rules/FieldSelectionsRule.cs -> ErrorHelper.FieldDoesNotExist, which
        # attaches extensions.type and extensions.field and NO suggestion of any kind.
        #
        # *** BACKTICKS -- AND THE ONE `Did you mean` IN THAT FILE BELONGS TO ANOTHER RULE. ***
        # The validation resources contain exactly one `Did you mean`, on the leaf-selection rule:
        #   Field "{0}" of type "{1}" must have a selection of subfields. Did you mean "{0} {{...}}"?
        # It suggests a SHAPE, never a name. A suggestion_clause regex pointed at this core would
        # harvest `usr { ... }` and report it as a schema field the server had volunteered. So
        # this core deliberately has no clause pattern, and a test asserts that message parses to
        # nothing rather than to a fake field.
        r"The field `(?P<name>[^`]+)` does not exist on the type `(?P<type>[^`]+)`"
    ),
}

#: Which dialect each core speaks. A core with no entry here cannot be enumerated by suggestion.
#:
#: graphql-php and gqlparser point at `graphql-js` because their message construction was READ
#: and found identical, not because they looked similar. Each still carries its own fixture and
#: its own test, so a future divergence fails a test rather than quietly returning nothing.
#: `absinthe` points at `graphql-js` on the same terms, and it is the strongest case of the three
#: read in this round: Absinthe's sentence, its joiner AND its five-suggestion cap were all read
#: and all match. It is an independent Elixir implementation that arrived at a byte-identical
#: field error, so it gets its own core id, its own fixture and its own test -- and the day it
#: diverges, that test fails instead of the enumerator quietly returning nothing.
CORE_DIALECT: dict[str, str] = {
    "graphql-js": "graphql-js",
    "graphql-php": "graphql-js",
    "gqlparser": "graphql-js",
    "absinthe": "graphql-js",
    "graphql-core": "graphql-core",
    # graphql-dotnet's StringUtils.QuotedOrList is graphql-core's grammar to the character: single
    # quotes, bare ` or ` at two, an Oxford comma from three, and the same cap of five. A C#
    # implementation and a Python one that agree byte for byte.
    #
    # *** IT IS THEREFORE INDISTINGUISHABLE FROM graphql-core BY THE FIELD SENTENCE. ***
    # A .NET server running graphql-dotnet fingerprints as core `graphql-core`, exactly the way a
    # graphql-php server fingerprints as `graphql-js`. The DIALECT is right, which is what the
    # parser needs; the brand is not recoverable from this probe and is not guessed.
    "graphql-dotnet": "graphql-core",
    "graphql-ruby": "graphql-ruby",
    "async-graphql": "async-graphql",
}

#: Brand -> core. The brands are graphw00f's own engine ids where they overlap, so the two tools
#: can be compared without a translation table in the operator's head. THE PARSER LOOKUP IS ON
#: THE CORE: keying it on the brand is how "Apollo" and "graphql-js" end up as two entries that
#: must be kept in step forever.
ENGINE_CORE: dict[str, str] = {
    "apollo": "graphql-js",
    "graphql_yoga": "graphql-js",
    "mercurius": "graphql-js",
    "express-graphql": "graphql-js",
    "graphql-js": "graphql-js",
    "graphene": "graphql-core",
    "strawberry": "graphql-core",
    "ariadne": "graphql-core",
    "tartiflette": "graphql-core",
    "ruby": "graphql-ruby",
    "graphqlphp": "graphql-php",
    "lighthouse": "graphql-php",
    "graphqljava": "graphql-java",
    "hasura": "hasura",
    "gqlgen": "gqlparser",
    "graphqlgo": "gqlparser",
    # graphw00f spells it `absinthe-graphql`; the bare name is carried too because that is what
    # an operator types.
    "absinthe-graphql": "absinthe",
    "absinthe": "absinthe",
    "hotchocolate": "hotchocolate",
    # .NET IS TWO IMPLEMENTATIONS, and they share nothing: HotChocolate never suggests and writes
    # backticks, graphql-dotnet suggests in graphql-core's exact grammar. graphw00f carries them as
    # two engines and so does this table -- collapsing them to "dotnet" is the brand-vs-core
    # mistake this module was written to avoid.
    "graphql-dotnet": "graphql-dotnet",
    # *** graphw00f HAS NO ID FOR async-graphql. *** Its only Rust engine is `juniper`, so this
    # one brand cannot be compared across the two tools and there is nothing to align to. Named
    # for the crate. Note also that graphw00f carries `graphql-dotnet` as an engine SEPARATE from
    # `hotchocolate`: .NET is two implementations and only one of them is read here.
    "async-graphql": "async-graphql",
}

#: Suggestion cap. BOTH measured implementations stop at five however many are close, so a
#: response carrying exactly five is a TRUNCATED list, not a complete one -- and an enumerator
#: that treated five as "all of them" would stop early and report a schema it had not finished
#: reading. Reported, never silently assumed.
SUGGESTION_CAP = 5

#: A GraphQL name, from the spec's own Name production: ``[_A-Za-z][_0-9A-Za-z]*``.
#:
#: *** THIS IS A FIX, NOT A TIDY-UP, AND IT WAS SHIPPING. ***
#: `parse_suggestions` harvests the quoted runs out of a `Did you mean` clause, and it did not
#: require the unknown-field SENTENCE to have matched first -- it could not, because
#: `parse_argument_suggestions` reuses it on a message that has a different sentence entirely.
#: So any message carrying a quoted `Did you mean` contributed "suggestions". graphql-js has one::
#:
#:     Field "user" of type "User" must have a selection of subfields. Did you mean "user { ... }"?
#:
#: That is graphql-js's own ScalarLeafs rule, and it fires whenever a probe stem NAMES A REAL
#: COMPOSITE FIELD -- `user`, `account`, `order`, which is most of the wordlist against most
#: schemas. The enumerator recovered `user { ... }` and reported it to the operator as a field the
#: server had volunteered. A fabricated schema entry, from a real server, on a common path.
#:
#: A name the server volunteered is a name the server could accept. `user { ... }` is not a name
#: in any GraphQL grammar, so the filter is the spec's own production rather than a blocklist of
#: the wordings we happen to have seen -- HotChocolate copied that message from graphql-js, and
#: the next core to copy it is not a change here.
GRAPHQL_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")


#: The default candidate list. NAMED AND SIZED, and it is part of what the operator approves --
#: the same rule as crawl depth and scan policy.
#:
#: *** THESE ARE PROBES, NOT GUESSES AT THE SCHEMA. *** Nothing here needs to BE a real field.
#: A suggestion is computed by edit distance from what we sent, so `user` provokes `users`,
#: `userById`, `userId` and `usersConnection` in one response. Short, common stems therefore
#: out-perform a long list of plausible full names, and that is why this list is stems.
DEFAULT_WORDLIST: tuple[str, ...] = (
    "user", "users", "account", "accounts", "profile", "profiles", "me", "viewer",
    "admin", "role", "roles", "permission", "permissions", "group", "groups",
    "team", "teams", "org", "organization", "member", "members", "session", "sessions",
    "token", "tokens", "key", "keys", "secret", "secrets", "credential", "credentials",
    "password", "email", "phone", "address", "payment", "payments", "card", "cards",
    "invoice", "invoices", "order", "orders", "product", "products", "price", "cart",
    "customer", "customers", "employee", "staff", "node", "nodes", "edge", "search",
    "query", "mutation", "subscription", "id", "name", "title", "description", "status",
    "file", "files", "upload", "download", "document", "documents", "image", "images",
    "message", "messages", "comment", "comments", "post", "posts", "article", "notification",
    "setting", "settings", "config", "configuration", "feature", "flag", "audit", "log",
    "logs", "event", "events", "webhook", "webhooks", "integration", "api", "client",
    "project", "projects", "repository", "repositories", "issue", "pull", "branch", "commit",
    "device", "devices", "location", "report", "reports", "export", "import", "job", "task",
)


class Suggestion(BaseModel):
    """One name a server volunteered. NO VALUE, ever -- the build #20 rule, unchanged."""

    name: str
    kind: str = Field("field", description="field | argument | type")
    on_type: str = ""
    from_probe: str = Field("", description="The wrong name that provoked it.")


def parse_suggestions(message: str, dialect: str) -> list[Suggestion]:
    """Every name a single error message suggests, in the given dialect.

    Returns ``[]`` for a message that is not an unknown-field error in this dialect AND for one
    that is but carries no suggestions. Those two are NOT the same thing and the caller must not
    conflate them -- :func:`classify_message` is what tells them apart, and it exists precisely
    so that this function's empty list never has to carry two meanings.
    """
    spec = DIALECTS.get(dialect)
    if not spec or not message:
        return []
    field_match = re.search(spec["unknown_field"], message)
    on_type = field_match.group("type") if field_match else ""
    probe = field_match.group("name") if field_match else ""

    clause = re.search(spec["suggestion_clause"], message)
    if not clause:
        return []
    quote = spec["quote"]
    # The clause body is `"a", "b", or "c"` / `` `a`, `b` or `c` ``. Pulling the QUOTED RUNS out
    # is deliberate rather than splitting on ", ": graphql-js puts an Oxford comma before `or`
    # and graphql-ruby does not, and a split-based parser silently yields a name called `or "b"`
    # on one of them. A quoted run cannot straddle the separator whichever separator it is.
    names = re.findall(re.escape(quote) + r"([^" + re.escape(quote) + r"]+)" + re.escape(quote),
                       clause.group("body"))
    out: list[Suggestion] = []
    for name in names:
        cleaned = name.strip()
        if not GRAPHQL_NAME.fullmatch(cleaned):
            continue
        if cleaned not in {s.name for s in out}:
            out.append(Suggestion(name=cleaned, on_type=on_type, from_probe=probe))
    return out


#: An unknown ARGUMENT leaks the same way a field does, and it is the one report #61 actually
#: needed: the injection point was an argument, not a field. Measured alongside the field form::
#:     graphql-js    Unknown argument "identifer" on field "Query.user". Did you mean "identifier"?
#:     graphql-core  Unknown argument 'identifer' on field 'Query.user'. Did you mean 'identifier'?
#:     async-graphql Unknown argument "identifer" on field "user" of type "Query". Did you mean ...
#:
#: *** THE ARGUMENT SENTENCE IS WHERE ABSINTHE STOPS BEING graphql-js. ***
#: Absinthe matches graphql-js byte for byte on the FIELD error and does not on this one:
#:     graphql-js    Unknown argument "identifer" on field "Query.user". Did you mean "identifier"?
#:     absinthe      Unknown argument "identifer" on field "user" of type "Query".
#: A dotted `Query.user` in one token versus a field and a type in two -- and, decisively, ABSINTHE
#: ATTACHES NO SUGGESTION HERE AT ALL (known_argument_names.ex builds the sentence and stops).
#: Absinthe therefore rides the graphql-js entry, matches its prefix, finds no clause and yields
#: nothing, which is the correct answer. Recorded because it looks like an oversight and is not:
#: "fixing" it by loosening the pattern would invent argument names Absinthe never offered.
_ARG_PATTERNS: dict[str, str] = {
    "graphql-js": r'Unknown argument "(?P<name>[^"]+)" on field "(?P<field>[^"]+)"',
    "graphql-core": r"Unknown argument '(?P<name>[^']+)' on field '(?P<field>[^']+)'",
    "graphql-ruby": r"Field '(?P<field>[^']+)' doesn't accept argument '(?P<name>[^']+)'",
    # SOURCE: async-graphql src/validation/rules/known_argument_names.rs -- same
    # make_suggestion(" Did you mean", ...) helper as the field rule, so the clause parses the same.
    "async-graphql": (r'Unknown argument "(?P<name>[^"]+)" on field "(?P<field>[^"]+)" '
                      r'of type "(?P<type>[^"]+)"'),
}


def parse_argument_suggestions(message: str, dialect: str) -> list[Suggestion]:
    """Argument names a server volunteered. Same dialects, a different sentence."""
    pattern = _ARG_PATTERNS.get(dialect)
    if not pattern or not message:
        return []
    head = re.search(pattern, message)
    if not head:
        return []
    on_field = head.groupdict().get("field", "")
    return [Suggestion(name=s.name, kind="argument", on_type=on_field,
                       from_probe=head.groupdict().get("name", ""))
            for s in parse_suggestions(message, dialect)]


def classify_message(message: str, dialect: str) -> str:
    """What a single error message MEANS. Never a bare boolean.

    ``suggested``      an unknown-field error carrying at least one suggestion
    ``no_suggestion``  an unknown-field error in this dialect with the clause ABSENT --
                       the server validated the name and declined to help. This is the
                       observation the `suggestions_disabled` verdict is built from.
    ``not_this_error`` something else entirely (a real result, an auth error, a syntax error)

    The distinction is the entire point. gqlgen ships a
    `FieldsOnCorrectTypeRuleWithoutSuggestions` rule and Apollo has `didYouMean` off in plenty of
    production deployments; both answer with a perfectly well-formed unknown-field error and no
    clause. Returning ``[]`` for that and for "the request failed" is the silent-empty class this
    codebase has now fixed four times.
    """
    spec = DIALECTS.get(dialect)
    if not spec or not message:
        return "not_this_error"
    if not re.search(spec["unknown_field"], message):
        return "not_this_error"
    return "suggested" if re.search(spec["suggestion_clause"], message) else "no_suggestion"


# --------------------------------------------------------------------------------------------
# Fingerprinting -- which core is formatting these errors?
# --------------------------------------------------------------------------------------------

#: The probes, and why each one is here. The FIRST is the important one and the rest only refine
#: the brand: a deliberately wrong field name provokes the unknown-field sentence, and that
#: sentence IS the dialect. One request decides which parser to use.
#:
#: `hackpit` is in the probe name so an operator reading their own server's logs can see who sent
#: it. A random-looking token in an error log during an engagement is a support ticket.
FINGERPRINT_PROBES: tuple[tuple[str, str], ...] = (
    ("bad_field", "{ zzz_hackpit_probe_zzz }"),
    ("skip_directive", "query @skip { __typename }"),
    ("typename", "{ __typename }"),
    ("syntax_error", "aaa"),
)


class EngineFingerprint(BaseModel):
    """Which core is answering, how sure we are, and what said so.

    *** ``unknown`` IS A REAL ANSWER AND IS NEVER QUIETLY UPGRADED TO APOLLO. ***
    An engine that cannot be identified must not be enumerated against a guessed parser:
    graphql-js's parser run against graphql-core returns zero suggestions and looks exactly like
    a hardened server. A confident wrong answer is worse here than an honest empty one, because
    the operator's next move is "stop looking" either way and only one of them is true.
    """

    core: str = Field("unknown", description="graphql-js | graphql-core | graphql-ruby | "
                                             "graphql-php | graphql-java | hasura | "
                                             "gqlparser | unknown")
    engine: str = Field("unknown", description="The brand, when a probe named one.")
    dialect: str = Field("", description="Suggestion dialect, '' when the core never suggests.")
    suggests: bool = Field(
        False, description="Whether this core implements suggestions AT ALL. False here means "
                           "there is nothing to switch on -- not that somebody switched it off.")
    confidence: str = Field("none", description="high | medium | none")
    evidence: list[str] = Field(default_factory=list,
                                description="The probe and the wording that decided it.")
    note: str = Field("", description="One sentence, always populated.")


def error_messages(text: str) -> list[str]:
    """`errors[].message` out of a response body, tolerantly. PURE.

    *** THE UNESCAPING HERE IS LOAD-BEARING AND ITS ABSENCE WAS A REAL BUG. ***
    On the wire a message arrives inside JSON, so graphql-js's message reads
    ``Cannot query field \\"usr\\" on type \\"Query\\"`` -- the quotes are ESCAPED. A dialect
    regex looking for a plain ``"`` never matches it. graphql-core's single quotes are NOT
    escaped by JSON and match raw text perfectly, so matching against the raw body would have
    identified every Python server correctly and read every Apollo, Yoga and Mercurius server as
    `unknown`. Asymmetric, silent, and pointing the wrong way -- it would have looked like
    graphql-js servers were hardened. Caught by a fixture, fixed by parsing the envelope first.

    A body that will NOT parse as JSON comes back as one message rather than being dropped:
    plenty of servers answer a validation error as an HTML page with the wording in it, and
    discarding that is how an endpoint that IS talking to us reads as one that is not.
    """
    if not text:
        return []
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return [text]
    if not isinstance(payload, dict):
        return [text]
    errors = payload.get("errors")
    if not isinstance(errors, list):
        return [text]
    out: list[str] = []
    for e in errors:
        if isinstance(e, dict) and isinstance(e.get("message"), str):
            out.append(e["message"])
        elif isinstance(e, str):
            out.append(e)
    return out or [text]


def classify_fingerprint(responses: dict[str, str]) -> EngineFingerprint:
    """``{probe_name: raw response text}`` -> which core is answering. PURE.

    Fed RAW text rather than parsed JSON on purpose -- a server that answers an HTML error page
    still identifies itself, and demanding valid JSON first would throw away the case where all
    we get is a stack trace. :func:`error_messages` does the unwrapping and falls back to the raw
    body, so both shapes reach the matchers.
    """
    out = EngineFingerprint()
    bad = "\n".join(error_messages(responses.get("bad_field", "") or ""))

    # 1. THE DIALECT, from the unknown-field sentence. This is the answer the parser needs.
    #
    # *** DRIVEN OFF `DIALECTS`, AND THAT IS LOAD-BEARING. *** This loop used to carry a literal
    # tuple of the three dialects that existed when it was written. Adding a fourth entry to
    # `DIALECTS` did NOTHING: the new dialect was never tried, every server speaking it
    # fingerprinted as `unknown`, and the whole suite stayed green -- because the per-dialect
    # parser tests call `parse_suggestions` directly and never come through here. Silent, green
    # and useless, which is this codebase's most expensive recurring shape. Two tests now hold it
    # shut: every DIALECTS key must be reachable from this function, and each core's fixture must
    # classify to its OWN core rather than a neighbour's, because this is first-match-wins and a
    # loosely-written new pattern could shadow one that already worked.
    for dialect, spec in DIALECTS.items():
        if re.search(spec["unknown_field"], bad):
            out.core, out.dialect, out.suggests = dialect, dialect, True
            out.confidence = "high"
            out.evidence.append(f"bad_field: matched the {dialect} unknown-field wording")
            break
    else:
        for core, pattern in NON_SUGGESTING_CORES.items():
            if re.search(pattern, bad):
                out.core, out.suggests, out.confidence = core, False, "high"
                out.evidence.append(f"bad_field: matched {core}'s unknown-field wording")
                break

    # 2. THE BRAND, where a probe names one. Refinement only -- it must never change the dialect,
    #    because the dialect was measured directly and a brand check is an inference about it.
    skip = "\n".join(error_messages(responses.get("skip_directive", "") or ""))
    syntax = "\n".join(error_messages(responses.get("syntax_error", "") or ""))
    # `__typename` succeeds, so its answer is DATA and not an error -- read raw.
    typename = responses.get("typename", "") or ""
    if '"@skip" argument "if" of type "Boolean!" is required' in skip:
        out.engine = "apollo"
        out.evidence.append("skip_directive: Apollo's required-argument wording")
    elif "can't be applied to queries" in skip or "missing required arguments: if" in skip:
        out.engine = "ruby"
        out.evidence.append("skip_directive: graphql-ruby's directive-location wording")
    if '"RootQueryType"' in typename or "'RootQueryType'" in typename:
        # SOURCE: absinthe lib/absinthe/schema.ex -- `@default_query_name "RootQueryType"`, the
        # default for the `query do ... end` macro. BRAND ONLY, and it must stay that way: the
        # dialect was matched directly from Absinthe's own sentence, whereas this is an inference
        # from a name a schema is free to override with `query name: "..."`. It refines who is
        # answering; it never decides how to parse them.
        out.engine = "absinthe"
        out.evidence.append("typename: root type is RootQueryType, Absinthe's default")
    if '"query_root"' in typename or "'query_root'" in typename:
        # Hasura names its root type `query_root`. Strong enough to SET the core, because Hasura
        # is not a library somebody wrapped -- if the root type is query_root it is Hasura.
        out.core, out.engine, out.suggests, out.confidence = "hasura", "hasura", False, "high"
        out.dialect = ""
        out.evidence.append("typename: root type is query_root")
    if "Syntax Error GraphQL (1:1)" in syntax and out.core in ("unknown", "graphql-core"):
        out.engine = out.engine if out.engine != "unknown" else "graphene"
        out.evidence.append("syntax_error: graphene's 1:1 syntax-error wording")

    if out.core == "unknown":
        out.note = ("no probe matched a known core -- enumeration is NOT attempted, because "
                    "the wrong parser returns zero suggestions and reads exactly like a "
                    "hardened server")
    elif out.suggests:
        out.note = (f"{out.core} formats suggestions in the {out.dialect} dialect"
                    + (f" (brand: {out.engine})" if out.engine != "unknown" else ""))
    else:
        out.note = (f"{out.core} never emits field suggestions -- there is nothing to enable "
                    f"here, so enumeration by suggestion cannot work against it")
    return out


# --------------------------------------------------------------------------------------------
# Bounds -- DECLARED PARAMETERS, NOT A GATE.
# --------------------------------------------------------------------------------------------


class EnumerationBounds(BaseModel):
    """What the operator said this run may cost. A DESCRIPTION, not a permission.

    *** THIS IS NOT THE SCANNER-WIDE REQUEST CAP THAT WAS DECLINED. *** That would have been a
    limit the tool imposes on the operator across every feature. This is one feature stating its
    own size before it runs, the same way crawl depth and scan policy do -- because enumeration
    is inherently thousands of requests and "it is still going" is not an answer anybody can act
    on. A generator that decides its own bounds has stopped describing what runs.
    """

    wordlist_name: str = Field("", description="Which list. Part of the approved surface.")
    wordlist_size: int = Field(0, description="How many candidate names, stated before the run.")
    max_requests: int = Field(
        0, description="0 means the wordlist decides. NOT a refusal at any point -- when it is "
                       "reached the run STOPS and says so, and the operator may start another.")
    max_seconds: int = Field(0, description="0 means no wall-clock limit.")
    batch_size: int = Field(
        1, description="Candidate names per request. >1 uses one document with many bad fields; "
                       "every core reports every unknown field in one response, so this is a "
                       "measured saving rather than a guess.")

    def describe(self) -> str:
        """The bounds in one line, for the panel and for the run record."""
        parts = [f"wordlist={self.wordlist_name or 'unnamed'} ({self.wordlist_size} names)",
                 f"batch={self.batch_size}"]
        parts.append(f"max_requests={self.max_requests}" if self.max_requests
                     else "max_requests=unbounded")
        parts.append(f"max_seconds={self.max_seconds}" if self.max_seconds
                     else "max_seconds=unbounded")
        return ", ".join(parts)


class EnumerationResult(BaseModel):
    """*** THREE OUTCOMES, THREE ANSWERS, NEVER ONE EMPTY LIST. ***

    ``productive``               suggestions are on and the server is leaking names
    ``suggestions_disabled``     the server validated our wrong names and REFUSED to help.
                                 A real, deliberate defence -- `didYouMean` off, or gqlgen's
                                 `FieldsOnCorrectTypeRuleWithoutSuggestions`. Stop looking.
    ``suggestions_unsupported``  the core has no suggestion feature at all (graphql-java,
                                 Hasura). Not a setting anybody could turn on.
    ``engine_unknown``           nothing identified the core, so no parser was chosen
    ``failed``                   the requests did not complete

    Build #20 found ZAP's `importUrl` answering the same code for introspection-disabled and a
    dead host, and classified around it rather than inheriting the ambiguity. Handing back an
    empty schema for all five of these would be the same defect in a new place -- and it is the
    one an operator most needs to tell apart, because `suggestions_disabled` means the defence
    worked and `failed` means try again.
    """

    status: str = "failed"
    url: str = ""
    fingerprint: EngineFingerprint = Field(default_factory=EngineFingerprint)
    bounds: EnumerationBounds = Field(default_factory=EnumerationBounds)
    requests_sent: int = 0
    seconds_elapsed: float = 0.0
    stopped_early: bool = Field(
        False, description="True when a declared bound ended the run before the wordlist did. "
                           "The names found so far are still returned -- a partial schema is a "
                           "result, and discarding it would punish the operator for setting a "
                           "bound.")
    stop_reason: str = ""
    fields: list[Suggestion] = Field(default_factory=list)
    arguments: list[Suggestion] = Field(default_factory=list)
    types: list[Suggestion] = Field(default_factory=list)
    unknown_field_errors: int = Field(
        0, description="Unknown-field errors seen. THE DENOMINATOR: `fields: 0` beside "
                       "`unknown_field_errors: 900` is a server that answered every probe and "
                       "suggested nothing, which is a completely different fact from "
                       "`unknown_field_errors: 0`, where nothing we sent was even understood.")
    truncated_suggestion_lists: int = Field(
        0, description=f"Responses that carried exactly {SUGGESTION_CAP} suggestions and were "
                       f"therefore CUT OFF by the server's own cap, not complete.")
    note: str = ""
    scope_note: str = Field("", description="A WARNING when the host is outside the named "
                                            "engagement. The requests were still sent.")

    @property
    def field_names(self) -> list[str]:
        return [s.name for s in self.fields]


def merge_suggestions(into: list[Suggestion], found: list[Suggestion]) -> int:
    """Add the ones we do not have. Returns how many were new."""
    seen = {(s.name, s.kind, s.on_type) for s in into}
    added = 0
    for s in found:
        key = (s.name, s.kind, s.on_type)
        if key not in seen:
            seen.add(key)
            into.append(s)
            added += 1
    return added


def build_probe_document(names: list[str]) -> str:
    """One GraphQL document asking for several names that almost certainly do not exist.

    Batching is safe because every core validates the WHOLE document and reports one error per
    unknown field, so a document of 20 bad names comes back with 20 suggestion clauses. The names
    are sent verbatim -- no prefix, no mangling -- because the server's suggestion is computed by
    edit distance FROM WHAT WE SENT, and mangling the candidate moves it away from the real name
    we are trying to make it volunteer.
    """
    safe = [n for n in names if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", n or "")]
    if not safe:
        return ""
    return "{ " + " ".join(safe) + " }"


def status_for(fingerprint: EngineFingerprint, unknown_field_errors: int,
               found: int, requests_sent: int) -> tuple[str, str]:
    """``(status, note)`` for a finished run. The three-outcome decision, in one place.

    It is a pure function of what was OBSERVED, so the same reasoning is testable without a
    server and cannot drift between the runner and the panel.
    """
    if fingerprint.core == "unknown":
        return ("engine_unknown",
                "the engine could not be identified, so no suggestion parser was chosen -- "
                "running one anyway would return zero and be indistinguishable from a server "
                "that simply does not suggest")
    if not fingerprint.suggests:
        return ("suggestions_unsupported",
                f"{fingerprint.core} implements no field-suggestion feature at all, so there is "
                f"nothing here to enumerate and nothing anybody could switch on")
    if requests_sent == 0:
        return "failed", "no request completed"
    if found:
        return ("productive",
                f"{found} names recovered from {unknown_field_errors} unknown-field errors")
    if unknown_field_errors:
        return ("suggestions_disabled",
                f"the server answered {unknown_field_errors} unknown-field errors and offered "
                f"NO suggestions -- this is a working defence, not an empty schema")
    return ("failed",
            f"{requests_sent} requests completed but not one produced an unknown-field error in "
            f"the {fingerprint.dialect} dialect -- the endpoint may need auth, or may not be the "
            f"GraphQL endpoint")


# --------------------------------------------------------------------------------------------
# WHAT THE RECOVERED SCHEMA IS FOR. A schema nobody consumes is not worth the requests.
# --------------------------------------------------------------------------------------------


class ComposedOperation(BaseModel):
    """A recovered field turned into something the repeater can actually send."""

    query: str = ""
    variables: str = "{}"
    operation_name: str = ""
    note: str = ""
    #: *** ALWAYS FALSE, AND SAYING SO IS THE POINT. *** Build #20 measured that ZAP files none
    #: of its generated operations in the Sites tree, and that the PROXY is what puts a GraphQL
    #: operation somewhere `ascan` can reach. A composed operation is therefore not scannable
    #: where it stands: it becomes scannable by being SENT THROUGH THE PROXY and captured. Same
    #: shape as `SchemaImport.scannable`, and for the same measured reason.
    scannable: bool = False
    next_step: str = ""


def compose_from_recovered(result: EnumerationResult, field_name: str) -> ComposedOperation:
    """Turn one recovered field into a repeater-ready operation. PURE.

    *** WITH ITS RECOVERED ARGUMENTS AS VARIABLES, NOT INLINE. *** Build #20 measured that
    `argsType=VARIABLES` gives every argument its own key, and that ZAP's active scanner reaches
    exactly one argument at a time on a captured operation. Composing with variables is what
    makes each recovered argument a separate injection point instead of one blob of query text --
    which is the whole chain report #61 needed: no introspection -> enumerate -> aim at ONE
    argument.

    *** NO VALUES ARE INVENTED FOR ARGUMENTS WE ONLY KNOW THE NAME OF. *** The placeholder is
    empty and the operator fills it. A composer that guessed `"1"` for an ID would put a request
    on the wire that nobody wrote, which is the rule the repeater already holds.
    """
    out = ComposedOperation()
    known = {s.name for s in result.fields}
    if field_name not in known:
        out.note = (f"{field_name!r} is not among the {len(known)} recovered names -- compose it "
                    f"by hand rather than having this guess at a schema it did not recover")
        return out

    args = [s for s in result.arguments if s.on_type in (field_name, f"Query.{field_name}")]
    if args:
        decl = ", ".join(f"${a.name}: String" for a in args)
        use = ", ".join(f"{a.name}: ${a.name}" for a in args)
        out.query = f"query ({decl}) {{ {field_name}({use}) }}"
        out.variables = "{\n" + ",\n".join(f'  "{a.name}": ""' for a in args) + "\n}"
        out.note = (f"{len(args)} recovered argument(s), each its own variable so the scanner "
                    f"can reach them one at a time. The VALUES are blank on purpose -- nothing "
                    f"here knows what they should be, and inventing one would send a request "
                    f"nobody wrote.")
    else:
        # A SELECTION SET IS A GUESS AND IS LEFT OUT. We recovered a field NAME; we do not know
        # whether it returns a scalar or an object, and a wrong `{ id }` produces a different
        # error that reads like the field does not exist. Empty is honest.
        out.query = f"{{ {field_name} }}"
        out.note = ("no arguments were recovered for this field. If it returns an object the "
                    "server will say so and name its fields -- which is another round of "
                    "enumeration, not a failure.")
    out.next_step = ("SEND IT THROUGH THE PROXY. A composed operation is not scannable where it "
                     "stands: ZAP files nothing it generates into the Sites tree (measured, "
                     "build #20), and the proxy capture is what gives `ascan` something to aim "
                     "at. Send, then use /proxy/graphql/scan-plan on the captured exchange.")
    return out


def recovered_state_records(result: EnumerationResult, session_id: str) -> dict[str, object]:
    """The engagement records for a recovered schema -- ENDPOINT and FINDING. PURE.

    *** PROVENANCE IS THE WHOLE REASON THIS IS NOT JUST AN ENDPOINT UPDATE. *** A schema handed
    over by introspection and a schema MINED one field at a time out of error messages are not
    the same artefact, and a report that presents them identically is dishonest: the second is
    incomplete by construction (only names close enough to a wordlist entry ever surface), and
    the difference changes what a reader should conclude from a field's absence.
    So the evidence string says how it was obtained, with what, and at what cost.

    *** NAMES, NEVER VALUES. *** `params` carries `field.argument` spellings and nothing else --
    build #20's rule, and the reason no header, token or argument value can reach a run record
    or a report through this path.
    """
    argument_names: list[str] = []
    for a in result.arguments:
        spelling = f"{a.on_type.split('.')[-1]}.{a.name}" if a.on_type else a.name
        if spelling not in argument_names:
            argument_names.append(spelling)

    how = (f"Recovered by FIELD-SUGGESTION MINING, not by introspection. "
           f"Engine core: {result.fingerprint.core} "
           f"(dialect {result.fingerprint.dialect or 'n/a'}, "
           f"confidence {result.fingerprint.confidence}). "
           f"Bounds: {result.bounds.describe()}. "
           f"{result.requests_sent} requests in {result.seconds_elapsed}s produced "
           f"{result.unknown_field_errors} unknown-field errors and "
           f"{len(result.fields)} field names, {len(result.arguments)} argument names.")
    if result.truncated_suggestion_lists:
        how += (f" {result.truncated_suggestion_lists} response(s) hit the server's "
                f"{SUGGESTION_CAP}-suggestion cap, so those lists were CUT OFF -- this schema is "
                f"a lower bound, not a complete one.")
    if result.stopped_early:
        how += f" The run STOPPED EARLY: {result.stop_reason}, so coverage is partial."
    else:
        how += (" Coverage is bounded by the wordlist: a name no wordlist entry is close to "
                "cannot be suggested, so absence here is NOT evidence of absence.")

    return {
        "endpoint": {
            "session_id": session_id,
            "url": result.url,
            "method": "POST",
            "tech": "graphql",
            "params": argument_names,
        },
        "finding": {
            "session_id": session_id,
            "title": "GraphQL schema recoverable by field suggestion",
            "severity": "medium" if result.status == "productive" else "info",
            "target": result.url,
            "tool": "hackpit-graphql-enum",
            "evidence": how,
        },
        "status": result.status,
    }
