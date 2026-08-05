"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  clearRepeaterCookies,
  composeGraphQLBody,
  detectGraphQL,
  getRepeaterStatus,
  repeaterCookies,
  getRepeaterShapes,
  repeaterPreview,
  repeaterSend,
  splitGraphQLBody,
  type GraphQLDetection,
  type RepeaterExchange,
  type ShapeVocabulary,
  type RepeaterHeader,
  type RepeaterRequest,
  type RepeaterStatus,
} from "@/lib/api";

/**
 * The HTTP repeater — compose a request, send it, tweak a header, send it again.
 *
 * Same containment as :kali (the send runs argv-only curl inside the hardcoded OPEN sandbox,
 * never from this browser or the backend host; human-only; audited). A human clicking Send IS
 * the approval — there is no per-send gate. A scope refusal (out of scope for a named
 * engagement) comes back as a 403 and is shown as an error; nothing was sent.
 */

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const;

type HeaderRow = RepeaterHeader & { id: number };

let _hid = 0;
const newHeader = (name = "", value = ""): HeaderRow => ({ id: _hid++, name, value });

function statusClass(status: number | null): string {
  if (status == null) return "is-none";
  if (status < 300) return "is-2xx";
  if (status < 400) return "is-3xx";
  if (status < 500) return "is-4xx";
  return "is-5xx";
}

export function RepeaterScreen() {
  const [status, setStatus] = useState<RepeaterStatus | null>(null);
  const [method, setMethod] = useState<string>("GET");
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState<HeaderRow[]>([newHeader()]);
  const [body, setBody] = useState("");
  const [follow, setFollow] = useState(false);
  const [insecure, setInsecure] = useState(false);
  const [engagementId, setEngagementId] = useState("");
  // The cookie jar (build #19 item 2). `jarCount` is null until it has been read once — "we
  // have not looked" is a different thing from "the jar is empty", and the button says so.
  const [useJar, setUseJar] = useState(true);
  const [jarCount, setJarCount] = useState<number | null>(null);

  // ---- GraphQL mode (build #20 item 3) ------------------------------------------------
  // THE MEASURED PAIN: report #61's injection point is a GraphQL argument, and reaching it
  // through this screen meant hand-writing quadruple-escaped JSON-in-JSON.
  //
  // *** THE OPERATOR'S RAW BODY WINS. *** `composedRef` remembers the last body the composer
  // produced. The moment the raw textarea holds something else — because a human typed in it —
  // the structured editor CLOSES rather than overwriting what they wrote. Same rule build #19
  // gave the cookie jar, for the same reason: state that silently rewrites a request is a trap.
  const [gql, setGql] = useState<GraphQLDetection | null>(null);
  const [gqlOpen, setGqlOpen] = useState(false);
  const [gqlQuery, setGqlQuery] = useState("");
  const [gqlVars, setGqlVars] = useState("{}");
  const [gqlOp, setGqlOp] = useState("");
  const [gqlNote, setGqlNote] = useState("");
  const [gqlError, setGqlError] = useState("");
  const composedRef = useRef<string>("");

  const [history, setHistory] = useState<RepeaterExchange[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A second exchange pinned for diffing against `selected`.
  const [diffAgainst, setDiffAgainst] = useState<string | null>(null);

  // PAYLOAD SHAPING (build #18 item 4). An OPTION, not a gate: no confirm, no acknowledgement,
  // no refusal if unset. A human clicking Send is already the approval, and this changes the
  // bytes of that same request. It lives on the repeater and NOT on the scanner because ZAP's
  // API exposes no arbitrary payload transform -- a switch there would have had nothing behind it.
  const [vocab, setVocab] = useState<ShapeVocabulary | null>(null);
  const [shapes, setShapes] = useState<string[]>([]);
  const [preview, setPreview] = useState<{
    url: string;
    body: string;
    shapes_applied: string[];
    warnings: string[];
  } | null>(null);

  const ctrlRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    getRepeaterStatus(ctrl.signal)
      .then(setStatus)
      .catch(() => setStatus(null));
    // The list comes FROM THE BACKEND so this screen carries no second copy of it -- the drift
    // trap the credential vault's docstring names.
    getRepeaterShapes(ctrl.signal)
      .then(setVocab)
      .catch(() => setVocab(null));
    // send-to-repeater seed from the OOB canary panel: a URL payload lands in the URL field, any
    // other payload (an XXE body, a header value) lands in the body for the operator to place.
    // Applied via a microtask so the setState is in an async callback, not the effect body
    // (frontend/AGENTS.md keeps the eslint set-state-in-effect count at baseline).
    Promise.resolve().then(() => {
      try {
        const seed = sessionStorage.getItem("hp-repeater-seed");
        if (seed) {
          sessionStorage.removeItem("hp-repeater-seed");
          if (/^https?:\/\//i.test(seed)) setUrl(seed);
          else setBody(seed);
        }
      } catch {
        /* storage disabled — nothing to seed */
      }
    });
    return () => ctrl.abort();
  }, []);

  const current = history.find((e) => e.id === selected) ?? null;
  const other = history.find((e) => e.id === diffAgainst) ?? null;

  const send = useCallback(async () => {
    if (!url.trim() || sending) return;
    setSending(true);
    setError(null);
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    const req: RepeaterRequest = {
      method,
      url: url.trim(),
      headers: headers
        .filter((h) => h.name.trim())
        .map((h) => ({ name: h.name, value: h.value })),
      body,
      follow_redirects: follow,
      insecure,
      http2: false,
      engagement_id: engagementId.trim() || null,
      session_id: engagementId.trim() || null,
      shapes,
      use_cookie_jar: useJar,
    };
    try {
      const ex = await repeaterSend(req, ctrl.signal);
      setHistory((h) => [ex, ...h].slice(0, 200));
      setSelected(ex.id);
    } catch (e) {
      if (e instanceof ApiError) setError(e.message);
      else if ((e as Error)?.name !== "AbortError") setError(String(e));
    } finally {
      setSending(false);
    }
  }, [method, url, headers, body, follow, insecure, engagementId, sending, shapes, useJar]);

  /** Empty this session's jar. Ungated — clearing state removes capability, never adds it. */
  const clearJar = useCallback(async () => {
    try {
      const out = await clearRepeaterCookies(engagementId.trim() || null);
      setJarCount(0);
      setError(
        out.cleared > 0
          ? `cookie jar emptied — ${out.cleared} cookie(s) dropped`
          : "cookie jar was already empty"
      );
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [engagementId]);

  // Re-read the jar after every send, because a send is the only thing that changes it.
  useEffect(() => {
    let live = true;
    repeaterCookies(engagementId.trim() || null)
      .then((cs) => live && setJarCount(cs.length))
      .catch(() => live && setJarCount(null));
    return () => {
      live = false;
    };
  }, [engagementId, history.length]);

  /**
   * Show the request AS IT WOULD GO ON THE WIRE, without sending it. It calls the same backend
   * function the send path uses, so what is previewed IS what is transmitted -- one derivation
   * rather than a second implementation that can drift.
   */
  const showPreview = useCallback(async () => {
    if (!url.trim()) return;
    try {
      setPreview(
        await repeaterPreview({
          method,
          url: url.trim(),
          headers: headers
            .filter((h) => h.name.trim())
            .map((h) => ({ name: h.name, value: h.value })),
          body,
          follow_redirects: follow,
          insecure,
          http2: false,
          engagement_id: null,
          session_id: null,
          shapes,
        })
      );
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [method, url, headers, body, follow, insecure, shapes]);

  const toggleShape = (name: string) =>
    setShapes((cur) =>
      cur.includes(name) ? cur.filter((s) => s !== name) : [...cur, name]
    );

  // ---- GraphQL: detect, split, compose -------------------------------------------------
  // Detection runs on the BACKEND so there is ONE derivation of "is this GraphQL", shared with
  // the history filter and the scan plan — not a second implementation in TypeScript that could
  // disagree with the one the scanner uses. Debounced, because it runs on every keystroke.
  //
  // The "there is nothing to detect" reset lives INSIDE the timeout rather than as an early
  // return in the effect body. Both would clear the badge; only one of them keeps the lint
  // baseline at 11 errors, because `react-hooks/set-state-in-effect` is exactly what those 11
  // are and a synchronous `setGql(null)` here would have made it 12.
  useEffect(() => {
    const ac = new AbortController();
    const t = setTimeout(() => {
      if (!body.trim() && !url.includes("query=")) {
        setGql(null);
        return;
      }
      detectGraphQL(
        {
          method,
          url,
          headers: headers.filter((h) => h.name.trim()).map((h) => ({ name: h.name, value: h.value })),
          body,
        },
        ac.signal
      )
        .then(setGql)
        .catch(() => {
          /* a detector that broke the screen would be worse than no badge */
        });
    }, 250);
    return () => {
      clearTimeout(t);
      ac.abort();
    };
  }, [method, url, headers, body]);

  /**
   * *** RAW BODY WINS. ***
   * The one handler the raw textarea uses. If the structured editor is open and the operator
   * types in the raw box, the editor STEPS ASIDE rather than overwriting them on the next
   * keystroke. Same rule build #19 gave the cookie jar — a typed value beats stored state —
   * and for the same reason: state that silently rewrites a request is a trap.
   *
   * This lives in the change handler and NOT in an effect, deliberately: the frontend AGENTS.md
   * baseline is 11 lint errors + 1 warning, `react-hooks/set-state-in-effect` is what those
   * errors are, and new setState is required to go through callbacks. It also reads better —
   * "the human typed here" is an event, not a derived condition.
   */
  const onRawBodyChange = useCallback(
    (next: string) => {
      setBody(next);
      if (gqlOpen && next !== composedRef.current) {
        setGqlOpen(false);
        setGqlNote(
          "You edited the raw body, so the structured editor stepped aside — what you typed is " +
            "what will be sent. Press “edit as GraphQL” to split it again."
        );
      }
    },
    [gqlOpen]
  );

  /** Split the captured body into query + variables. A body that will not split stays RAW. */
  const openGraphQL = useCallback(async () => {
    setGqlError("");
    try {
      const state = await splitGraphQLBody(body);
      setGqlNote(state.note);
      if (!state.parsed) {
        setGqlOpen(false);
        return;
      }
      setGqlQuery(state.query);
      setGqlVars(state.variables);
      setGqlOp(state.operation_name);
      composedRef.current = body;
      setGqlOpen(true);
    } catch (e) {
      setGqlError(e instanceof ApiError ? e.message : String(e));
    }
  }, [body]);

  /** Re-serialise. If the variables will not parse, the body is LEFT ALONE and the error shown:
   *  a composer that quietly repaired a body would put a request on the wire nobody wrote. */
  const recompose = useCallback(
    async (query: string, variables: string, opName: string) => {
      try {
        const out = await composeGraphQLBody(query, variables, opName);
        if (!out.ok) {
          setGqlError(out.error);
          return;
        }
        setGqlError("");
        composedRef.current = out.body;
        setBody(out.body);
      } catch (e) {
        setGqlError(e instanceof ApiError ? e.message : String(e));
      }
    },
    []
  );

  /** Load a past exchange's request back into the editor to tweak-and-resend. */
  const loadForEdit = useCallback((ex: RepeaterExchange) => {
    setMethod(ex.request.method);
    setUrl(ex.request.url);
    setHeaders(
      ex.request.headers.length
        ? ex.request.headers.map((h) => newHeader(h.name, h.value))
        : [newHeader()]
    );
    setBody(ex.request.body);
    setFollow(ex.request.follow_redirects);
    setInsecure(ex.request.insecure);
    setEngagementId(ex.request.engagement_id ?? "");
    setSelected(ex.id);
  }, []);

  const setHeader = (id: number, patch: Partial<RepeaterHeader>) =>
    setHeaders((hs) => hs.map((h) => (h.id === id ? { ...h, ...patch } : h)));
  const addHeader = () => setHeaders((hs) => [...hs, newHeader()]);
  const removeHeader = (id: number) =>
    setHeaders((hs) => (hs.length > 1 ? hs.filter((h) => h.id !== id) : hs));

  const up = status?.up ?? false;

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "repeater" }]}>
      <div className="hp-rp">
        <header className="hp-rp-head">
          <div className="hp-ap-kicker">compose · send · replay · diff</div>
          <h1 className="hp-rp-title">:repeater</h1>
          <p className="hp-rp-sub">
            Compose an HTTP request, send it, tweak a header, send it again. The send runs
            inside the sandbox — never from this browser — and is scope-checked and recorded.
            You clicking Send is the approval; there is no per-send prompt.
          </p>
          <div className={`hp-rp-status ${up ? "is-up" : "is-down"}`}>
            <span className="hp-rp-dot" />
            {up
              ? `sandbox ready · ${status?.container}`
              : `sandbox down — bring the stack up (${status?.detail || "container not running"})`}
          </div>
        </header>

        <div className="hp-rp-grid">
          {/* ---- request editor ---- */}
          <section className="hp-rp-req" aria-label="Request">
            <div className="hp-rp-line">
              <select
                className="hp-rp-method"
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                aria-label="Method"
              >
                {METHODS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
              <input
                className="hp-rp-url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://target.example/path?q=1"
                onKeyDown={(e) => {
                  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) send();
                }}
                aria-label="URL"
              />
              <button
                type="button"
                className="hp-rp-send"
                onClick={send}
                disabled={sending || !url.trim()}
                title="Send (Ctrl/Cmd+Enter)"
              >
                {sending ? "sending…" : "Send ▸"}
              </button>
            </div>

            <div className="hp-rp-headers">
              <div className="hp-rp-subhead">headers</div>
              {headers.map((h) => (
                <div key={h.id} className="hp-rp-hrow">
                  <input
                    className="hp-rp-hname"
                    value={h.name}
                    onChange={(e) => setHeader(h.id, { name: e.target.value })}
                    placeholder="Header"
                  />
                  <input
                    className="hp-rp-hval"
                    value={h.value}
                    onChange={(e) => setHeader(h.id, { value: e.target.value })}
                    placeholder="value"
                  />
                  <button
                    type="button"
                    className="hp-rp-hx"
                    onClick={() => removeHeader(h.id)}
                    aria-label="Remove header"
                  >
                    ✕
                  </button>
                </div>
              ))}
              <button type="button" className="hp-rp-addh" onClick={addHeader}>
                + header
              </button>
            </div>

            <div className="hp-rp-bodywrap">
              <div className="hp-rp-subhead">body</div>
              <textarea
                className="hp-rp-body"
                value={body}
                onChange={(e) => onRawBodyChange(e.target.value)}
                placeholder="request body (sent on stdin — any content is safe)"
                rows={5}
              />
            </div>

            {/* ---- GRAPHQL MODE (build #20 item 3) -------------------------------------
                Detected by BODY SHAPE, not by path: this fires on a GraphQL operation posted
                to /api just as readily as one posted to /graphql, and does NOT fire on plain
                JSON that happens to be posted to /graphql. */}
            {gql?.is_graphql ? (
              <div className="hp-gql">
                <div className="hp-gql-head">
                  <span className="hp-gql-badge">GraphQL</span>
                  <span className="hp-rp-sub">
                    {gql.where.replace("_", " ")}
                    {gql.batched ? " · batched" : ""}
                    {gql.introspection ? " · introspection" : ""}
                    {gql.path_hint ? " · conventional path" : " · non-conventional path"}
                  </span>
                  {!gqlOpen ? (
                    <button type="button" onClick={openGraphQL}>
                      edit as GraphQL
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() => {
                        setGqlOpen(false);
                        setGqlNote("Closed — the raw body is unchanged.");
                      }}
                    >
                      back to raw
                    </button>
                  )}
                </div>

                {gql.operations.length > 0 ? (
                  <div className="hp-rp-sub">
                    {gql.operations
                      .map(
                        (op) =>
                          `${op.operation_type} ${op.operation_name || "(anonymous)"} → ${
                            op.root_fields.join(", ") || "—"
                          }`
                      )
                      .join(" · ")}
                  </div>
                ) : null}

                {/* NAMES, NEVER VALUES. A GraphQL argument is routinely a token — report #61's
                    is literally called `token` — so this line lists what ZAP will call them in
                    its alerts and nothing about what is in them. */}
                {gql.operations.some((op) => op.arguments.length) ? (
                  <div className="hp-gql-args">
                    {gql.operations.flatMap((op) =>
                      op.arguments.map((a) => (
                        <span key={`${op.operation_name}-${a.name}`} className="hp-gql-arg">
                          {a.name}
                          {a.from_variable ? " $" : ""}
                        </span>
                      ))
                    )}
                  </div>
                ) : null}

                {gql.note ? (
                  <p className="hp-rp-sub">
                    This is still GraphQL — the envelope says so. It just would not parse:{" "}
                    {gql.note}.
                  </p>
                ) : null}

                {gqlOpen ? (
                  <>
                    <div className="hp-rp-subhead">query</div>
                    <textarea
                      className="hp-rp-body"
                      value={gqlQuery}
                      onChange={(e) => {
                        setGqlQuery(e.target.value);
                        void recompose(e.target.value, gqlVars, gqlOp);
                      }}
                      rows={6}
                    />
                    <div className="hp-rp-subhead">variables (JSON)</div>
                    <textarea
                      className="hp-rp-body"
                      value={gqlVars}
                      onChange={(e) => {
                        setGqlVars(e.target.value);
                        void recompose(gqlQuery, e.target.value, gqlOp);
                      }}
                      rows={5}
                    />
                    <div className="hp-tn-form">
                      <input
                        value={gqlOp}
                        onChange={(e) => {
                          setGqlOp(e.target.value);
                          void recompose(gqlQuery, gqlVars, e.target.value);
                        }}
                        placeholder="operationName — omitted from the body when blank"
                      />
                    </div>
                    {gqlError ? (
                      <p className="hp-rp-error">
                        {gqlError} — <strong>the body above was left exactly as it was.</strong>{" "}
                        Nothing was guessed at or repaired.
                      </p>
                    ) : null}
                  </>
                ) : null}

                {gqlNote ? <p className="hp-rp-sub">{gqlNote}</p> : null}
              </div>
            ) : null}

            <div className="hp-rp-opts">
              <label className="hp-rp-opt">
                <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
                follow redirects
              </label>
              <label className="hp-rp-opt">
                <input
                  type="checkbox"
                  checked={insecure}
                  onChange={(e) => setInsecure(e.target.checked)}
                />
                accept invalid TLS
              </label>
              {/* THE COOKIE JAR (build #19 item 2). ON by default, because the thing it fixes —
                  every authenticated flow breaking on the SECOND request — is the common case.
                  Unchecking it sends with NO session WITHOUT emptying the jar, because "what
                  does an unauthenticated caller see" is a real test that must not cost you the
                  session you spent five minutes establishing. */}
              <label className="hp-rp-opt" title="Attach stored cookies and store Set-Cookie.">
                <input
                  type="checkbox"
                  checked={useJar}
                  onChange={(e) => setUseJar(e.target.checked)}
                />
                use cookie jar
              </label>
              <button type="button" className="hp-rp-addh" onClick={clearJar}>
                empty jar{jarCount === null ? "" : ` (${jarCount})`}
              </button>
              <input
                className="hp-rp-eng"
                value={engagementId}
                onChange={(e) => setEngagementId(e.target.value)}
                placeholder="engagement id (optional — enables the scope check)"
                aria-label="Engagement id"
              />
            </div>

            {/* ---- PAYLOAD SHAPING (build #18 item 4) --------------------------------
                No confirm and no acknowledgement: the repeater is human-only and clicking Send
                IS the approval. Mark the payload with the span markers below; everything
                outside them is untouched, and with no shapes selected the markers are simply
                stripped -- which is what makes shaped-vs-unshaped a ONE-VARIABLE comparison
                rather than two different requests. */}
            {vocab && (
              /* `hp-rp-headers` is the LABELLED-BLOCK wrapper, the same one the headers and
                 body sections use. The subhead has to sit OUTSIDE `hp-rp-opts`, which is a
                 flex ROW — inside it the heading rendered on the same line as the first
                 checkbox. Found by looking at the screen, which is the only way it could be. */
              <div className="hp-rp-headers">
                <div className="hp-rp-subhead">
                  shape the payload &mdash; mark it {vocab.open}like this{vocab.close}
                </div>
                <div className="hp-rp-opts">
                  {Object.entries(vocab.shapes).map(([name, desc]) => (
                    <label key={name} className="hp-rp-opt" title={desc}>
                      <input
                        type="checkbox"
                        checked={shapes.includes(name)}
                        onChange={() => toggleShape(name)}
                      />
                      {name}
                    </label>
                  ))}
                </div>
                <button type="button" className="hp-rp-addh" onClick={showPreview}>
                  preview the bytes
                </button>
              </div>
            )}

            {preview && (
              <div className="hp-rp-bodywrap">
                <div className="hp-rp-subhead">
                  what goes on the wire
                  {preview.shapes_applied.length
                    ? ` — ${preview.shapes_applied.join(", ")}`
                    : " — nothing applied; the markers are stripped either way"}
                </div>
                <pre className="hp-rp-body">{preview.url}</pre>
                {preview.body ? <pre className="hp-rp-body">{preview.body}</pre> : null}
                {preview.warnings.map((w) => (
                  <div key={w} className="hp-rp-error">
                    {w}
                  </div>
                ))}
              </div>
            )}

            {current && current.shapes_applied.length > 0 && (
              <div className="hp-rp-bodywrap">
                <div className="hp-rp-subhead">
                  last send was SHAPED &mdash; {current.shapes_applied.join(", ")}
                </div>
                <pre className="hp-rp-body">{current.sent_url}</pre>
              </div>
            )}

            {/* ---- THE JAR'S DISCLOSURE (build #19 item 2) ----------------------
                A `Cookie:` header the operator did not type has to explain itself, or the jar
                is state that silently changes a request. NAMES ONLY — there is no value field
                on the wire and none on the screen; to see a value, read the response that set
                it in the history below. */}
            {current &&
            (current.cookies_attached.length > 0 ||
              current.cookies_stored.length > 0 ||
              current.cookie_warnings.length > 0) ? (
              <div className="hp-rp-bodywrap">
                <div className="hp-rp-subhead">
                  cookie jar
                  {current.cookie_jar_used ? "" : " — NOT USED for this send"}
                </div>
                {current.cookies_attached.length > 0 && (
                  <pre className="hp-rp-body">
                    {"attached to this request:\n"}
                    {current.cookies_attached
                      .map((c) => `  ${c.name}  (${c.domain}${c.path}) set by ${c.set_by_url}`)
                      .join("\n")}
                  </pre>
                )}
                {current.cookies_stored.length > 0 && (
                  <pre className="hp-rp-body">
                    {"stored from this response:\n"}
                    {current.cookies_stored
                      .map((c) => `  ${c.name}  (${c.domain}${c.path})`)
                      .join("\n")}
                  </pre>
                )}
                {current.cookie_warnings.map((w) => (
                  <div key={w} className="hp-rp-error">
                    {w}
                  </div>
                ))}
              </div>
            ) : null}

            {error && <div className="hp-rp-error">{error}</div>}
          </section>

          {/* ---- response ---- */}
          <section className="hp-rp-resp" aria-label="Response">
            {!current && <p className="hp-rp-empty">No response yet — compose a request and Send.</p>}
            {current && (
              <ResponseView exchange={current} diff={other} />
            )}
          </section>
        </div>

        {/* ---- history ---- */}
        {history.length > 0 && (
          <section className="hp-rp-hist" aria-label="History">
            <div className="hp-rp-subhead">
              history · {history.length}
              {diffAgainst && (
                <button type="button" className="hp-rp-clrdiff" onClick={() => setDiffAgainst(null)}>
                  clear diff
                </button>
              )}
            </div>
            <ul className="hp-rp-histlist">
              {history.map((ex) => (
                <li
                  key={ex.id}
                  className={`hp-rp-histrow${ex.id === selected ? " is-sel" : ""}${
                    ex.id === diffAgainst ? " is-diff" : ""
                  }`}
                >
                  <button
                    type="button"
                    className="hp-rp-histmain"
                    onClick={() => setSelected(ex.id)}
                  >
                    <span className={`hp-rp-histcode ${statusClass(ex.response.status)}`}>
                      {ex.response.status ?? "—"}
                    </span>
                    <span className="hp-rp-histmethod">{ex.request.method}</span>
                    <span className="hp-rp-histurl">{ex.request.url}</span>
                    <span className="hp-rp-histtime">{ex.response.time_ms}ms</span>
                  </button>
                  <button
                    type="button"
                    className="hp-rp-histact"
                    onClick={() => loadForEdit(ex)}
                    title="Load into the editor to tweak and resend"
                  >
                    edit
                  </button>
                  <button
                    type="button"
                    className="hp-rp-histact"
                    onClick={() => setDiffAgainst(ex.id === diffAgainst ? null : ex.id)}
                    title="Diff the selected response against this one"
                  >
                    {ex.id === diffAgainst ? "diffing" : "diff"}
                  </button>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </PageShell>
  );
}

/** Split a body into lines for a simple line-level diff. */
function lineSet(text: string): Set<string> {
  return new Set(text.split("\n"));
}

function ResponseView({
  exchange,
  diff,
}: {
  exchange: RepeaterExchange;
  diff: RepeaterExchange | null;
}) {
  const r = exchange.response;
  const diffing = diff && diff.id !== exchange.id;
  const otherLines = diffing ? lineSet(diff!.response.body) : null;
  const bodyLines = r.body.split("\n");

  return (
    <div className="hp-rp-respbody">
      {r.error ? (
        <div className="hp-rp-error">{r.error}</div>
      ) : (
        <>
          <div className="hp-rp-respline">
            <span className={`hp-rp-respcode ${statusClass(r.status)}`}>
              {r.status ?? "—"}
              {r.reason ? ` ${r.reason}` : ""}
            </span>
            <span className="hp-rp-respmeta">
              {r.http_version} · {r.time_ms}ms · {r.size_bytes} bytes
            </span>
            {diffing && <span className="hp-rp-diffbadge">diff vs {diff!.response.status ?? "—"}</span>}
          </div>

          <div className="hp-rp-respheaders">
            {r.headers.map((h, i) => (
              <div key={i} className="hp-rp-rhrow">
                <span className="hp-rp-rhname">{h.name}:</span>{" "}
                <span className="hp-rp-rhval">{h.value}</span>
              </div>
            ))}
          </div>

          <div className="hp-code hp-rp-respcode-wrap">
            <div className="hp-code-bar">
              <span className="hp-code-lang">body{r.body_truncated ? " · truncated" : ""}</span>
              <CopyButton text={r.body} />
            </div>
            <pre className="hp-code-pre hp-rp-resppre">
              <code>
                {diffing
                  ? bodyLines.map((ln, i) => (
                      <span
                        key={i}
                        className={otherLines!.has(ln) ? "" : "hp-rp-diffline"}
                      >
                        {ln}
                        {"\n"}
                      </span>
                    ))
                  : r.body}
              </code>
            </pre>
          </div>
        </>
      )}
    </div>
  );
}
