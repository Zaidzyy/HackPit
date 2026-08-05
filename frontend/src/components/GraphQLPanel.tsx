"use client";

import { useCallback, useState } from "react";
import {
  ApiError,
  getGraphQLBounds,
  importGraphQLSchema,
  probeGraphQLSchema,
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
    "not describe itself. This is what `clairvoyance` in the arsenal is for; HackPit does not " +
    "do field-suggestion enumeration itself, and that gap is deliberate rather than hidden.",
  empty:
    "Introspection ANSWERED and the schema exposes nothing. A real zero — stop looking here.",
  http_error: "The endpoint returned GraphQL errors that are not an introspection refusal.",
  unparseable:
    "The endpoint answered with something that is not a GraphQL response. It may not be a " +
    "GraphQL endpoint at all — check the path.",
  unreachable: "Nothing answered. This is a network fact, not a schema fact.",
};

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

  const runProbe = useCallback(async () => {
    if (!endpoint.trim() || probing) return;
    setProbing(true);
    setError(null);
    try {
      setProbe(
        await probeGraphQLSchema(container ?? "", endpoint.trim(), [], engagementId ?? null)
      );
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setProbe(null);
    } finally {
      setProbing(false);
    }
  }, [container, endpoint, engagementId, probing]);

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
        <button type="button" onClick={runProbe} disabled={!container || !endpoint.trim() || probing}>
          {probing ? "asking…" : "probe schema"}
        </button>
        <button type="button" onClick={readBounds} disabled={!container}>
          read ZAP&rsquo;s bounds
        </button>
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
