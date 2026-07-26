"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  getRepeaterStatus,
  repeaterSend,
  type RepeaterExchange,
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

  const [history, setHistory] = useState<RepeaterExchange[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A second exchange pinned for diffing against `selected`.
  const [diffAgainst, setDiffAgainst] = useState<string | null>(null);

  const ctrlRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    getRepeaterStatus(ctrl.signal)
      .then(setStatus)
      .catch(() => setStatus(null));
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
  }, [method, url, headers, body, follow, insecure, engagementId, sending]);

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
                onChange={(e) => setBody(e.target.value)}
                placeholder="request body (sent on stdin — any content is safe)"
                rows={5}
              />
            </div>

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
              <input
                className="hp-rp-eng"
                value={engagementId}
                onChange={(e) => setEngagementId(e.target.value)}
                placeholder="engagement id (optional — enables the scope check)"
                aria-label="Engagement id"
              />
            </div>

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
