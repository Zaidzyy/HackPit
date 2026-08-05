# Three more error-producing cores: HotChocolate, Absinthe, async-graphql

**Date:** 2026-08-05
**Follows:** build #21 (`2026-08-05-build21-plan.md`), which shipped field-suggestion enumeration
against six cores and deliberately left these three unwritten.

---

## 1. Why this exists

Build #21 shipped `backend/cockpit/graphql_enum.py`: when introspection is off, a wrong field name
still provokes `Did you mean "user"?` from many servers, and that clause leaks the schema one name
at a time. It works by keying on the **error-producing core** rather than the server brand, because
Apollo *is* graphql-js and Graphene *is* graphql-core, and grouping by brand builds parsers that
duplicate each other in some places and miss entirely in others.

Six cores are covered today: graphql-js, graphql-core, graphql-ruby, graphql-php, gqlparser,
graphql-java, plus Hasura as a non-suggesting core.

Three were named in the build #21 plan and deliberately not written, because their wording had not
been measured: **HotChocolate** (.NET), **Absinthe** (Elixir), and — substituted here for the
plan's Juniper — **async-graphql** (Rust). They fingerprint as `unknown`, which refuses to
enumerate, spends nothing, and says why. That was and remains a correct answer. This spec turns
three correct non-answers into three measured answers.

### What is actually lost today

Only in one situation: a target running .NET, Elixir or Rust GraphQL **and** serving with
introspection disabled. Both conditions. With introspection on, none of this matters. With any of
the six covered cores, the operator is already served.

In that situation the product stops and the operator falls back to hand-testing in Repeater or to
clairvoyance/graphw00f outside the gated, recorded path.

### Why the work cannot come back empty

Each engine resolves to one of two useful outcomes:

* **It suggests** — a working schema-reader for that whole ecosystem.
* **It does not suggest** — `suggests: False`, and the operator gets the
  `suggestions_unsupported` verdict: *there is nothing to enable here, do not spend three thousand
  requests.* Exactly the value graphql-java and Hasura already deliver.

The only bad outcome is getting the wording **wrong**, which is why §2 governs evidence.

### Why async-graphql instead of Juniper

Juniper is the Rust GraphQL library that gets named; async-graphql is the one that gets deployed.
Spending the Rust slot on Juniper buys the plan's list closed exactly as written and buys little
else. This is a deliberate deviation from the build #21 plan and is recorded as one.

---

## 2. Evidence standard

**Source-read tier.** The same standard graphql-php, gqlparser, graphql-ruby and graphql-java
already meet — see the provenance block in the `graphql_enum.py` module docstring. Nothing in this
spec may be written from recollection. The module exists because a remembered dialect ships a
parser that returns zero and looks exactly like a hardened server.

Per engine, two things are read:

1. The validation rule that formats the **unknown-field sentence**.
2. Whatever builds the **suggestion list**, if one exists.

Both matter and they are usually different files. graphql-ruby needed
`fields_are_defined_on_type.rb` for the sentence and `validation_context.rb` for the clause, and
the second is where the missing Oxford comma — a real parser-breaking difference — turned out to
live.

Both file paths, at the commit read, go into that engine's `provenance` string.

**Ambiguity is an allowed outcome.** If a message is assembled across enough layers that the wire
wording cannot be pinned down from source, that engine stays `unknown` and this spec records why.
It does not get a guessed regex, and it does not get "close enough to graphql-js".

---

## 3. The design is outcome-neutral

This spec does not assert that any of the three suggests. That is the measurement, and predicting
it here would be the same failure the module was built around. Each engine lands in one of three
places, decided by what its source actually says:

| Finding | Lands in | Shape |
|---|---|---|
| Formats an unknown-field sentence **with** a suggestion clause | `DIALECTS` + `CORE_DIALECT` | full entry: `unknown_field`, `suggestion_clause`, `quote`, `provenance` |
| Formats an unknown-field sentence with **no** suggestion clause anywhere in source | `NON_SUGGESTING_CORES` | one regex, `suggests: False` |
| Wording byte-identical to an existing dialect | `CORE_DIALECT` → that dialect | **still its own fixture and its own test** |

The third row is the graphql-php / gqlparser pattern (`graphql_enum.py:127-136`). Pointing at a
shared dialect is an assertion that the two were compared, not an omission — so a future divergence
fails a test rather than quietly returning nothing.

---

## 4. The trap this must not walk into

`classify_fingerprint` hardcodes the dialect list:

```python
for core, dialect in (("graphql-js", "graphql-js"), ("graphql-core", "graphql-core"),
                      ("graphql-ruby", "graphql-ruby")):
```

`graphql_enum.py:373-374`.

Adding a fourth entry to `DIALECTS` does **nothing**. The new dialect is never tried, the engine
fingerprints as `unknown`, and every existing test still passes — because the per-dialect parser
tests call `parse_suggestions` directly and never go through `classify_fingerprint`. Silent, green,
and useless: the exact shape this project has been burned by repeatedly.

Fixes, both required:

* Drive the loop off `DIALECTS` rather than a literal tuple.
* **Test that every `DIALECTS` key is reachable from `classify_fingerprint`.** Without this, the
  next core added hits the identical bug and the suite stays green again.

And because the loop is first-match-wins, a second test: **each fixture must classify to its own
core and not a neighbour's.** A new regex written broadly enough to shadow an existing one is a
silent regression against servers that already worked.

---

## 5. Everything that changes

* `backend/cockpit/graphql_enum.py`
  * `DIALECTS` and/or `NON_SUGGESTING_CORES` entries per §3
  * `CORE_DIALECT` entries for cores that suggest
  * `ENGINE_CORE` brand→core entries, using **graphw00f's own engine ids** where they overlap, so
    the two tools compare without a translation table in the operator's head. Ids are read off the
    graphw00f installed in the sandbox image at implementation time — not from memory.
  * `classify_fingerprint` loop driven off `DIALECTS` (§4)
  * Module docstring provenance block extended with the three new reads
* `backend/test_graphql_enum.py` — fixtures as explicit constants and explicit assertions, matching
  the existing style; plus the two structural tests from §4
* `docs/ASSESSMENT-2026-07-26.md` and the regenerated html/pdf, in the same commit

**Not changed:** no new fingerprint probes, no I/O, nothing in `graphql_zap.py`. The module stays
pure and the AST purity assertion in `test_graphql_safety.py` keeps holding.

---

## 6. What this deliberately does not do

It does not touch `unknown` semantics. An engine that cannot be identified still refuses to
enumerate, because a confident wrong answer is worse than an honest empty one — the operator's next
move is "stop looking" either way, and only one of those is true.

This adds three doors. It does not loosen the lock on the rest.
