"use client";

import { useCallback, useState } from "react";
import {
  ApiError,
  enumerateGraphQLSchema,
  fingerprintGraphQLEngine,
  getGraphQLBounds,
  importGraphQLSchema,
  probeGraphQLSchema,
  type EnumerationResult,
  type EngineFingerprint,
  type GraphQLBounds,
  type SchemaImport,
  type SchemaProbe,
} from "@/lib/api";

/**
 * GRAPHQL SCHEMA RECON AND ZAP'S QUERY GENERATOR — build #20 items 4 and 5.
 *
 * *** WHY THE PROBE EXISTS AT ALL: ZAP CANNOT TELL YOU WHY AN IMPORT FAILED. ***
 * `graphql/action/importUrl` answers `illegal_parameter`, with an identical message, for an
 * endpoint that REFUSES introspection the way production does AND for a host that is not
 * listening. Measured in `docs/proof/build20_graphql_api.py`. So HackPit asks the endpoint
 * itself and classifies the answer into six, because `disabled` means reach for `clairvoyance`,
 * `unreachable` means fix the network and `empty` means stop looking — and four of the six would
 * be an empty list from a naive implementation.
 *
 * *** AND WHY THE IMPORT SAYS WHAT IT DID NOT DO. ***
 * The operations ZAP generates from a schema are SENT AT THE ENDPOINT and are NEVER added to the
 * Sites tree — measured four ways: fresh daemon, primed node, unprimed node, and out to 60
 * seconds in case the insert was merely late. So an import is coverage traffic, not an attack
 * surface, and the panel says so rather than letting an operator infer otherwise. To SCAN
 * GraphQL, capture an operation through the proxy and aim the ordinary active scanner at it.
 *
 * NO NEW GATE anywhere here. The probe is one request to a URL a human typed and pressed, in the
 * repeater's position. Where a scope check could refuse, it WARNS and sends.
 */

const STATUS_CLASS: Record<string, string> = {
  ok: "is-ok",
  disabled: "is-disabled",
  empty: "is-disabled",
  http_error: "is-bad",
  unparseable: "is-bad",
  unreachable: "is-bad",
};

/** What the operator should DO about each answer. The status word alone is not an instruction. */
const STATUS_ADVICE: Record<string, string> = {
  ok: "The schema is readable. Every argument below is individually reachable by the scanner.",
  disabled:
    "Introspection is switched off — that is NOT an empty schema. The API is there and will " +
    "not describe itself. Enumerate it below: many servers still answer a wrong field name " +
    "with “Did you mean …?”, and that leaks the schema one field at a time. " +
    "`clairvoyance` in the arsenal is the independent cross-check.",
  empty:
    "Introspection ANSWERED and the schema exposes nothing. A real zero — stop looking here.",
  http_error: "The endpoint returned GraphQL errors that are not an introspection refusal.",
  unparseable:
    "The endpoint answered with something that is not a GraphQL response. It may not be a " +
    "GraphQL endpoint at all — check the path.",
  unreachable: "Nothing answered. This is a network fact, not a schema fact.",
};

/**
 * *** FIVE OUTCOMES, AND FOUR OF THEM ARE AN EMPTY LIST FROM A NAIVE IMPLEMENTATION. ***
 * `suggestions_disabled` in particular is a WORKING DEFENCE, not a missing schema, and an
 * operator who reads it as "nothing here" draws the opposite conclusion to the true one.
 */
const ENUM_STATUS_CLASS: Record<string, string> = {
  productive: "is-ok",
  suggestions_disabled: "is-disabled",
  suggestions_unsupported: "is-disabled",
  engine_unknown: "is-bad",
  failed: "is-bad",
};

const ENUM_ADVICE: Record<string, string> = {
  productive:
    "The server is leaking its schema. Every recovered ARGUMENT is an injection point — " +
    "compose one in the repeater, send it through the proxy, then aim the scanner at the " +
    "captured operation.",
  suggestions_disabled:
    "The server answered every probe and offered no suggestions. That is a DEFENCE WORKING, " +
    "not an empty schema — the API is there and will not spell itself out. Stop mining and " +
    "look for names in the client bundle, mobile app or documentation instead.",
  suggestions_unsupported:
    "This core has no field-suggestion feature at all, so there is nothing here anybody could " +
    "have switched on. Do not spend requests — this is not a hardening decision, it is an " +
    "absent feature.",
  engine_unknown:
    "No probe identified the core, so no parser was chosen and NO wordlist was spent. Running " +
    "one anyway would return zero and be indistinguishable from a hardened server. Name the " +
    "engine yourself if you know it.",
  failed:
    "The requests completed but nothing came back that looks like an unknown-field error. The " +
    "endpoint may need authentication, or may not be the GraphQL endpoint.",
};

/** The bounds that ACTUALLY APPLIED, read back rather than echoed from what was asked. */
function describeBounds(r: EnumerationResult): string {
  const b = r.bounds;
  const parts = [
    `wordlist ${b.wordlist_name || "unnamed"} (${b.wordlist_size} names)`,
    `batch ${b.batch_size}`,
    b.max_requests ? `max_requests ${b.max_requests}` : "max_requests unbounded",
    b.max_seconds ? `max_seconds ${b.max_seconds}` : "max_seconds unbounded",
  ];
  if (r.stopped_early) parts.push(`STOPPED EARLY — ${r.stop_reason}`);
  return parts.join(" · ");
}

export function GraphQLPanel({
  container,
  port,
  engagementId,
}: {
  /** null when no proxy is running. The section still RENDERS — see below. */
  container: string | null;
  port: number;
  engagementId?: string | null;
}) {
  const [endpoint, setEndpoint] = useState("");
  const [impersonate, setImpersonate] = useState(false);
  const [probe, setProbe] = useState<SchemaProbe | null>(null);
  const [probing, setProbing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [observed, setObserved] = useState<Record<string, string> | null>(null);
  const [depth, setDepth] = useState("");
  const [argsDepth, setArgsDepth] = useState("");
  const [argsType, setArgsType] = useState("");
  const [requestMethod, setRequestMethod] = useState("");
  const [sdl, setSdl] = useState("");
  const [imported, setImported] = useState<SchemaImport | null>(null);
  const [importing, setImporting] = useState(false);

  // build #21 — field-suggestion enumeration
  const [enumWords, setEnumWords] = useState("");
  const [maxRequests, setMaxRequests] = useState("");
  const [batchSize, setBatchSize] = useState("20");
  const [fingerprint, setFingerprint] = useState<EngineFingerprint | null>(null);
  const [enumResult, setEnumResult] = useState<EnumerationResult | null>(null);
  const [enumerating, setEnumerating] = useState(false);

  const runProbe = useCallback(async () => {
    if (!endpoint.trim() || probing) return;
    setProbing(true);
    setError(null);
    try {
      setProbe(
        await probeGraphQLSchema(container ?? "", endpoint.trim(), [], engagementId ?? null, impersonate)
      );
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setProbe(null);
    } finally {
      setProbing(false);
    }
  }, [container, endpoint, engagementId, impersonate, probing]);

  /** The wordlist as the operator typed it. Blank means the built-in list, whose NAME and SIZE
   *  come back in the result — a run that could not say which list produced a schema has not
   *  described what it did. */
  const words = useCallback(
    () => enumWords.split(/[\s,]+/).filter(Boolean),
    [enumWords]
  );

  const runFingerprint = useCallback(async () => {
    if (!endpoint.trim() || enumerating) return;
    setEnumerating(true);
    setError(null);
    setEnumResult(null);
    try {
      setFingerprint(
        await fingerprintGraphQLEngine({
          container: container ?? "",
          url: endpoint.trim(),
          engagement_id: engagementId ?? null,
          impersonate,
        })
      );
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setFingerprint(null);
    } finally {
      setEnumerating(false);
    }
  }, [container, endpoint, engagementId, impersonate, enumerating]);

  const runEnumerate = useCallback(async () => {
    if (!endpoint.trim() || enumerating) return;
    setEnumerating(true);
    setError(null);
    try {
      const custom = words();
      const result = await enumerateGraphQLSchema({
        container: container ?? "",
        url: endpoint.trim(),
        engagement_id: engagementId ?? null,
        impersonate,
        wordlist: custom,
        wordlist_name: custom.length ? "operator" : "",
        max_requests: Number(maxRequests) || 0,
        batch_size: Number(batchSize) || 20,
      });
      setEnumResult(result);
      setFingerprint(result.fingerprint);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setEnumResult(null);
    } finally {
      setEnumerating(false);
    }
  }, [batchSize, container, endpoint, engagementId, impersonate, enumerating, maxRequests, words]);

  const readBounds = useCallback(async () => {
    setError(null);
    try {
      const b = await getGraphQLBounds(container ?? "", port);
      setObserved(b.observed);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [container, port]);

  const runImport = useCallback(async () => {
    if (!endpoint.trim() || importing) return;
    setImporting(true);
    setError(null);
    const bounds: GraphQLBounds = {};
    if (depth.trim()) bounds.max_query_depth = Number.parseInt(depth, 10);
    if (argsDepth.trim()) bounds.max_args_depth = Number.parseInt(argsDepth, 10);
    if (argsType) bounds.args_type = argsType;
    if (requestMethod) bounds.request_method = requestMethod;
    try {
      setImported(
        await importGraphQLSchema({
          container: container ?? "",
          port,
          endpoint_url: endpoint.trim(),
          sdl_text: sdl.trim(),
          bounds: Object.keys(bounds).length ? bounds : null,
          engagement_id: engagementId ?? null,
        })
      );
      const b = await getGraphQLBounds(container ?? "", port);
      setObserved(b.observed);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setImported(null);
    } finally {
      setImporting(false);
    }
  }, [container, port, endpoint, sdl, depth, argsDepth, argsType, requestMethod, engagementId,
      importing]);

  return (
    <section className="hp-tn-card">
      <div className="hp-tn-cardhead">GraphQL — schema, and what ZAP will generate</div>
      <div className="hp-tn-cardsub">
        Ask the endpoint for its schema, then let ZAP exercise it within bounds you set.{" "}
        <strong>
          Introspection disabled is not an empty schema, and ZAP cannot tell the two apart
        </strong>{" "}
        — it answers the same error code for a refusal and for a host that is not listening, so
        the probe below asks the endpoint directly.
      </div>

      {/* *** THE SECTION RENDERS EVEN WITH NO PROXY, AND SAYS WHY IT CANNOT ACT. ***
          Hiding it would be this repo's recurring silent empty in a new place: a panel that is
          simply absent reads as "HackPit does not do GraphQL", which is the belief this whole
          build exists to correct. The intercept section three cards up takes exactly this
          position with exactly this wording. */}
      {!container ? (
        <p className="hp-tn-note">
          Start a proxy first — the bounds and the import go to <em>that</em> daemon, and there
          is none running.
        </p>
      ) : null}

      <div className="hp-tn-form">
        <input
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
          placeholder="https://host/graphql — the path is part of the target, never assumed"
          disabled={!container}
        />
        <button type="button" onClick={runProbe} disabled={!endpoint.trim() || probing}>
          {probing ? "asking…" : "probe schema"}
        </button>
        <button type="button" onClick={readBounds} disabled={!container}>
          read ZAP&rsquo;s bounds
        </button>
        <label
          className="hp-tn-opt"
          title="Fetch via curl-impersonate (curl_chrome116, browser JA3) to reach a Cloudflare/Akamai-fronted GraphQL endpoint that 403s a plain client. Applies to probe, fingerprint and enumerate."
        >
          <input
            type="checkbox"
            checked={impersonate}
            onChange={(e) => setImpersonate(e.target.checked)}
          />{" "}
          impersonate browser (WAF bypass)
        </label>
      </div>

      {error ? <p className="hp-tn-error">{error}</p> : null}

      {probe ? (
        <>
          <div className="hp-tn-form">
            <span className={`hp-gql-status ${STATUS_CLASS[probe.status] ?? ""}`}>
              {probe.status}
            </span>
            <span className="hp-tn-olhint">
              {probe.http_status == null ? "no HTTP response" : `HTTP ${probe.http_status}`}
              {probe.type_count ? ` · ${probe.type_count} types` : ""}
            </span>
          </div>
          <p className="hp-tn-note">{probe.note}</p>
          <p className="hp-tn-note">{STATUS_ADVICE[probe.status]}</p>
          {probe.scope_note ? <p className="hp-tn-note">{probe.scope_note}</p> : null}
          {probe.server_errors.length ? (
            <p className="hp-tn-note">
              The server said: {probe.server_errors.map((m) => `“${m}”`).join(" · ")}
            </p>
          ) : null}

          {/* NAMES AND TYPES. No value ever appears here — a GraphQL argument is routinely a
              token, and the model this renders has no field that could carry one. */}
          {[
            ["queries", probe.queries],
            ["mutations", probe.mutations],
            ["subscriptions", probe.subscriptions],
          ].map(([label, fields]) =>
            (fields as SchemaProbe["queries"]).length ? (
              <div key={label as string}>
                <div className="hp-tn-cardsub">{label as string}</div>
                <div className="hp-gql-fields">
                  {(fields as SchemaProbe["queries"]).map((f) => (
                    <div key={f.name} className="hp-gql-field">
                      <span className="hp-gql-fieldname">{f.name}</span>
                      <span className="hp-gql-fieldtype">: {f.type || "?"}</span>
                      {f.args.map((a) => (
                        <span key={`${f.name}.${a.name}`} className="hp-gql-arg">
                          {f.name}.{a.name}
                          {a.required ? "!" : ""}
                        </span>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            ) : null
          )}
        </>
      ) : null}

      {/* ---- FIELD-SUGGESTION ENUMERATION (build #21) --------------------------------- */}
      <div className="hp-tn-cardsub">
        When introspection is off, the schema is often still readable: a wrong field name comes
        back as <em>Did you mean “user”?</em> That is the only route to the argument report #61
        needed.{" "}
        <strong>The engine is fingerprinted first</strong> — suggestion wording is a property of
        the error-producing <em>core</em>, not the brand, and graphql-js says{" "}
        <code>&quot;user&quot;</code> where graphql-core says <code>&apos;user&apos;</code>.
        Measured. A parser written for one recovers <em>nothing</em> from the other and looks
        exactly like a hardened server.
      </div>
      <div className="hp-tn-form">
        <input
          value={enumWords}
          onChange={(e) => setEnumWords(e.target.value)}
          placeholder="wordlist (comma or space separated) — blank uses the built-in list"
        />
        <input
          className="hp-tn-port"
          value={maxRequests}
          onChange={(e) => setMaxRequests(e.target.value)}
          placeholder="max req"
          title="0 or blank = the wordlist decides. This is a DECLARED BOUND, not a gate: when it is reached the run stops, says which bound stopped it, and returns everything it found."
        />
        <input
          className="hp-tn-port"
          value={batchSize}
          onChange={(e) => setBatchSize(e.target.value)}
          placeholder="batch"
          title="Candidate names per request. Every core reports one error per unknown field, so a batch of 20 comes back with 20 suggestion clauses."
        />
        <button
          type="button"
          onClick={runFingerprint}
          disabled={!endpoint.trim() || enumerating}
        >
          fingerprint engine
        </button>
        <button
          type="button"
          onClick={runEnumerate}
          disabled={!endpoint.trim() || enumerating}
        >
          {enumerating ? "enumerating…" : "enumerate schema"}
        </button>
      </div>
      <p className="hp-tn-note">
        Enumeration is inherently hundreds to thousands of requests, so it states its size before
        it runs and reports it back — the same rule as crawl depth and scan policy.{" "}
        <strong>The bounds do not refuse anything</strong>: reaching one ends the run, names
        itself and hands back the partial schema.
      </p>

      {fingerprint && !enumResult ? (
        <div className="hp-gql-fields">
          <div className="hp-tn-form">
            <span
              className={`hp-gql-status ${
                fingerprint.core === "unknown" ? "is-bad" : fingerprint.suggests ? "is-ok" : "is-disabled"
              }`}
            >
              {fingerprint.core}
            </span>
            <span className="hp-tn-olhint">
              {fingerprint.engine !== "unknown" ? `brand ${fingerprint.engine} · ` : ""}
              {fingerprint.dialect ? `dialect ${fingerprint.dialect}` : "no suggestion dialect"} ·{" "}
              {fingerprint.confidence} confidence
            </span>
          </div>
          <p className="hp-tn-note">{fingerprint.note}</p>
          {fingerprint.evidence.map((e) => (
            <p key={e} className="hp-tn-note">
              {e}
            </p>
          ))}
        </div>
      ) : null}

      {enumResult ? (
        <div className="hp-gql-fields">
          <div className="hp-tn-form">
            <span className={`hp-gql-status ${ENUM_STATUS_CLASS[enumResult.status] ?? ""}`}>
              {enumResult.status}
            </span>
            <span className="hp-tn-olhint">
              core {enumResult.fingerprint.core} · {enumResult.requests_sent} requests in{" "}
              {enumResult.seconds_elapsed}s · {enumResult.unknown_field_errors} unknown-field
              errors
            </span>
          </div>
          <p className="hp-tn-note">{enumResult.note}</p>
          <p className="hp-tn-note">{ENUM_ADVICE[enumResult.status]}</p>
          <p className="hp-tn-note">bounds applied: {describeBounds(enumResult)}</p>
          {enumResult.scope_note ? (
            <p className="hp-tn-note">{enumResult.scope_note}</p>
          ) : null}
          {enumResult.truncated_suggestion_lists ? (
            <p className="hp-tn-note">
              {enumResult.truncated_suggestion_lists}
              {" "}
              response(s) hit the server&apos;s own five-suggestion cap, so those lists were{" "}
              <strong>cut off</strong>. What you see is a lower bound on the schema, not the whole
              of it.
            </p>
          ) : null}

          {enumResult.fields.length ? (
            <>
              <div className="hp-tn-cardsub">
                recovered fields ({enumResult.fields.length})
              </div>
              <div className="hp-gql-args">
                {enumResult.fields.map((f) => (
                  <span key={f.name} className="hp-gql-arg">
                    {f.name}
                  </span>
                ))}
              </div>
            </>
          ) : null}
          {enumResult.arguments.length ? (
            <>
              <div className="hp-tn-cardsub">
                recovered arguments ({enumResult.arguments.length}) — these are the injection
                points
              </div>
              <div className="hp-gql-args">
                {enumResult.arguments.map((a) => (
                  <span key={`${a.on_type}.${a.name}`} className="hp-gql-arg">
                    {a.on_type ? `${a.on_type.split(".").pop()}.` : ""}
                    {a.name}
                  </span>
                ))}
              </div>
            </>
          ) : null}
          <p className="hp-tn-note">
            A schema recovered this way is <strong>mined, not introspected</strong>, and the
            engagement record says so: only names close enough to a wordlist entry can ever
            surface, so a field&apos;s absence here is not evidence it does not exist.
          </p>
        </div>
      ) : null}

      {/* ---- ZAP's generator, and its bounds ------------------------------------------- */}
      <div className="hp-tn-cardsub">
        Hand the schema to ZAP. <strong>The bounds are yours to set</strong>, for the same reason
        crawl depth and duration are: a generator that decides its own bounds has stopped
        describing what runs. ZAP validates them <em>not at all</em>{" "}
        {/* *** THE EXPLICIT {" "} IS LOAD-BEARING AND WAS ADDED AFTER LOOKING AT THE SCREEN. ***
            The source had a plain space after </em> and the DOM did not: reading textContent in
            the real browser returned "not at all— it accepts". Build #19 hit the same thing in
            the same place — JSX dropping a space that IS in the source — and neither `tsc`,
            `next build` nor `eslint` can see it, because all three are happy with prose that
            renders wrong. */}
        — it accepts a depth of &minus;1 and reads it back unchanged — so a nonsense bound is
        warned about and sent anyway, and what you see below is read back from the daemon rather
        than assumed.
      </div>
      <div className="hp-tn-form">
        <input
          className="hp-tn-port"
          value={depth}
          onChange={(e) => setDepth(e.target.value)}
          placeholder="max query depth"
        />
        <input
          className="hp-tn-port"
          value={argsDepth}
          onChange={(e) => setArgsDepth(e.target.value)}
          placeholder="max args depth"
        />
        <select value={argsType} onChange={(e) => setArgsType(e.target.value)}>
          <option value="">args: leave as ZAP has it</option>
          <option value="VARIABLES">VARIABLES — one key per argument</option>
          <option value="INLINE">INLINE — arguments in the query text</option>
          <option value="BOTH">BOTH</option>
        </select>
        <select value={requestMethod} onChange={(e) => setRequestMethod(e.target.value)}>
          <option value="">method: leave as ZAP has it</option>
          <option value="POST_JSON">POST_JSON</option>
          <option value="POST_GRAPHQL">POST_GRAPHQL</option>
          <option value="GET">GET</option>
        </select>
      </div>
      <div className="hp-tn-form">
        <textarea
          className="hp-rp-body"
          value={sdl}
          onChange={(e) => setSdl(e.target.value)}
          placeholder="SDL — paste a schema document, or leave empty to have ZAP introspect the endpoint"
          rows={4}
        />
      </div>
      <div className="hp-tn-form">
        <button type="button" onClick={runImport} disabled={!container || !endpoint.trim() || importing}>
          {importing ? "importing…" : "import into ZAP"}
        </button>
      </div>

      {observed ? (
        <div className="hp-gql-fields">
          {Object.entries(observed).map(([k, v]) => (
            <div key={k} className="hp-gql-field">
              <span className="hp-gql-fieldname">{k}</span>
              <span className="hp-gql-fieldtype">{v || "—"}</span>
            </div>
          ))}
        </div>
      ) : null}
      {observed ? (
        <p className="hp-tn-note">
          Read back from the daemon just now. <strong>ZAP persists these across restarts and
          across sessions</strong>, so unless you set them, they are whatever the last engagement
          left behind.
        </p>
      ) : null}

      {imported ? (
        <>
          <p className={imported.ok ? "hp-tn-note" : "hp-tn-error"}>
            ZAP answered <strong>{imported.zap_code || "nothing readable"}</strong> ·{" "}
            {imported.source}. {imported.note}
          </p>
          {/* THE SENTENCE THIS PANEL EXISTS TO SAY OUT LOUD. */}
          {imported.ok ? (
            <p className="hp-tn-error">
              Those generated operations are <strong>not in the Sites tree</strong>, so the active
              scanner cannot be aimed at them. To scan GraphQL, capture an operation through this
              proxy and scan <em>that</em> — with recurse on, because the capture is filed under a
              synthetic <code>/query</code> child node.
            </p>
          ) : null}
          {imported.scope_note ? <p className="hp-tn-note">{imported.scope_note}</p> : null}
          {imported.bounds?.warnings.map((w) => (
            <p key={w} className="hp-tn-note">
              {w}
            </p>
          ))}
          {imported.bounds?.bounds.length ? (
            <div className="hp-gql-fields">
              {imported.bounds.bounds.map((b) => (
                <div key={b.field_name} className="hp-gql-field">
                  <span className="hp-gql-fieldname">{b.field_name}</span>
                  <span className="hp-gql-fieldtype">
                    asked {b.requested} · ZAP holds {b.observed || "—"}
                  </span>
                  <span className={`hp-gql-status ${b.applied ? "is-ok" : "is-bad"}`}>
                    {b.applied ? "applied" : "NOT applied"}
                  </span>
                </div>
              ))}
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
