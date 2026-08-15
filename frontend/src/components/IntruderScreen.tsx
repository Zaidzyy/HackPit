"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  getIntruderStatus,
  getRepeaterShapes,
  intruderPreview,
  listIntruderJobs,
  startIntruder,
  stopIntruderJob,
  type IntruderJob,
  type IntruderPreview,
  type IntruderRequest,
  type ShapeVocabulary,
} from "@/lib/api";

/**
 * The intruder — one request, marked positions, a payload set, ONE approval.
 *
 * *** WHY ONE APPROVAL BUYS MANY REQUESTS, SAID ON THE SCREEN AND NOT ONLY IN THE CODE. ***
 * HackPit refuses BATCHING ACROSS APPROVALS. It has never refused one approval that produces
 * many requests, and could not: ffuf, nuclei and the ZAP active scanner are each a single press
 * buying thousands. This is that same shape, gated by the same four gates.
 *
 * The red-confirm is demanded by the GATE and not by this form. A payload set of ordinary SQLi
 * strings does not trip it; a payload carrying `| sh` does, as "reverse-shell / code-exec
 * pattern". The preview asks the gate BEFORE anything is sent and shows the answer, so the
 * confirm appears when it is earned rather than always — a confirm that fires on everything is
 * a confirm the operator learns to click through.
 */
const MODES = ["sniper", "battering-ram"] as const;

function blankRequest(): IntruderRequest {
  return {
    url: "",
    method: "GET",
    headers: [],
    body: "",
    payloads: [],
    mode: "sniper",
    shapes: [],
    follow_redirects: false,
    insecure: false,
    impersonate: false,
    delay_ms: 0,
    engagement_id: null,
    session_id: null,
    use_cookie_jar: true,
    approved: false,
    dangerous_ack: false,
  };
}

export function IntruderScreen() {
  const [status, setStatus] = useState<{
    container: string;
    up: boolean;
    running: number;
    detail: string;
  } | null>(null);
  const [jobs, setJobs] = useState<IntruderJob[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [url, setUrl] = useState("");
  const [method, setMethod] = useState("GET");
  const [body, setBody] = useState("");
  const [payloadText, setPayloadText] = useState("");
  const [mode, setMode] = useState<string>("sniper");
  const [shapes, setShapes] = useState<string[]>([]);
  const [vocab, setVocab] = useState<ShapeVocabulary | null>(null);
  const [delayMs, setDelayMs] = useState("0");
  const [engagementId, setEngagementId] = useState("");
  const [useJar, setUseJar] = useState(true);
  const [impersonate, setImpersonate] = useState(false);
  const [attachSession, setAttachSession] = useState(false);
  const [approved, setApproved] = useState(false);
  const [ack, setAck] = useState(false);
  const [preview, setPreview] = useState<IntruderPreview | null>(null);
  const [starting, setStarting] = useState(false);

  const payloads = payloadText
    .split("\n")
    .map((p) => p.trim())
    .filter(Boolean);

  const request = useCallback(
    (): IntruderRequest => ({
      ...blankRequest(),
      url: url.trim(),
      method,
      body,
      payloads,
      mode,
      shapes,
      delay_ms: Number.parseInt(delayMs, 10) || 0,
      engagement_id: engagementId.trim() || null,
      session_id: engagementId.trim() || null,
      use_cookie_jar: useJar,
      impersonate,
      attach_session: attachSession,
      approved,
      dangerous_ack: ack,
    }),
    [url, method, body, payloads, mode, shapes, delayMs, engagementId, useJar, impersonate, attachSession, approved, ack]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    getIntruderStatus(ctrl.signal)
      .then(setStatus)
      .catch(() => setStatus(null));
    // The shape vocabulary comes FROM THE BACKEND, so this screen carries no second copy of the
    // list — the same drift trap the repeater's docstring names.
    getRepeaterShapes(ctrl.signal)
      .then(setVocab)
      .catch(() => setVocab(null));
    return () => ctrl.abort();
  }, []);

  const refreshJobs = useCallback(() => {
    listIntruderJobs()
      .then(setJobs)
      .catch(() => setJobs([]));
  }, []);

  // A running job's results grow, so this polls. `sent` and `planned` come back on every read,
  // which is what lets the progress line below say what HAPPENED rather than what was intended.
  useEffect(() => {
    refreshJobs();
    const t = setInterval(refreshJobs, 2000);
    return () => clearInterval(t);
  }, [refreshJobs]);

  const doPreview = useCallback(async () => {
    if (!url.trim()) return;
    setError(null);
    try {
      setPreview(await intruderPreview(request()));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [url, request]);

  const run = useCallback(async () => {
    if (!url.trim() || starting) return;
    setStarting(true);
    setError(null);
    try {
      const job = await startIntruder(request());
      setSelected(job.id);
      refreshJobs();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setStarting(false);
    }
  }, [url, starting, request, refreshJobs]);

  const stop = useCallback(
    async (id: string) => {
      try {
        await stopIntruderJob(id);
        refreshJobs();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
      }
    },
    [refreshJobs]
  );

  const toggleShape = (name: string) =>
    setShapes((cur) => (cur.includes(name) ? cur.filter((s) => s !== name) : [...cur, name]));

  const job = jobs.find((j) => j.id === selected) ?? jobs[0] ?? null;
  const open = vocab?.open ?? "[[";
  const close = vocab?.close ?? "]]";

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "intruder" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">mark a position · run a payload set · one approval</div>
          <h1 className="hp-tn-title">:intruder</h1>
          <p className="hp-tn-sub">
            Take one request, mark the interesting spans with{" "}
            <code>
              {open}…{close}
            </code>
            , and run a payload set through them. It is <strong>one gated job</strong> — the same
            four gates the active scanner clears, and no new ones. Every request goes out
            argv-only from inside the sandbox, scope-checked on the <em>substituted</em> URL.
          </p>
          {status && (
            <div className={`hp-tn-status ${status.up ? "is-up" : "is-down"}`}>
              <span className="hp-tn-dot" />
              {status.container}: {status.up ? "up" : "down"} · running {status.running}
            </div>
          )}
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">the request</div>
          <div className="hp-tn-cardsub">
            Mark positions with{" "}
            <code>
              {open}…{close}
            </code>
            . What is <em>inside</em> the markers is the BASELINE value — in sniper mode the other
            positions keep it, so each run changes one thing and the results stay readable.
          </div>
          <div className="hp-tn-form">
            <select value={method} onChange={(e) => setMethod(e.target.value)}>
              {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={`https://host/search?q=${open}test${close}&page=1`}
            />
          </div>
          <div className="hp-tn-form">
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={3}
              placeholder="request body (optional) — positions can be marked here too"
              style={{ width: "100%" }}
            />
          </div>
          <div className="hp-tn-form">
            <select value={mode} onChange={(e) => setMode(e.target.value)}>
              {MODES.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <input
              className="hp-tn-port"
              value={delayMs}
              onChange={(e) => setDelayMs(e.target.value)}
              placeholder="delay ms"
              aria-label="Delay between requests, milliseconds"
            />
            <label>
              <input
                type="checkbox"
                checked={useJar}
                onChange={(e) => setUseJar(e.target.checked)}
              />{" "}
              use the repeater&rsquo;s cookie jar
            </label>
            <label title="Send each payload as a real browser (curl-impersonate) to get past a WAF that fingerprints the TLS handshake. Note: ffuf bulk fuzzing can't impersonate — the per-payload curl sends do.">
              <input
                type="checkbox"
                checked={impersonate}
                onChange={(e) => setImpersonate(e.target.checked)}
              />{" "}
              impersonate browser (WAF bypass)
            </label>
            <label title="Merge the engagement's stored operator session (saved in :repeater) into every send, so fuzzing runs authenticated. Your OWN session; added at send time, never stored.">
              <input
                type="checkbox"
                checked={attachSession}
                onChange={(e) => setAttachSession(e.target.checked)}
              />{" "}
              attach session (authenticated)
            </label>
            <input
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
              placeholder="engagement id (optional — enables the per-request scope check)"
            />
          </div>
          <p className="hp-tn-note">
            <strong>sniper</strong> runs the set through one position at a time, leaving the
            others at their baseline. <strong>battering-ram</strong> puts the same payload in
            every position at once. Pitchfork and cluster bomb are deliberately absent — they need
            two independent sets, and a cluster bomb of two 1,000-entry lists is a million
            requests from one press, which deserves its own argument rather than inheriting this
            one.
          </p>
        </section>

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">the payload set</div>
          <div className="hp-tn-cardsub">
            One payload per line. <strong>Every one of them goes into the approved surface</strong>{" "}
            — not a count and not a sample, because a payload carrying a shell pattern at line
            5,000 must be visible to the danger gate and not hidden behind an &ldquo;and 4,993
            more&rdquo;.
          </div>
          <textarea
            value={payloadText}
            onChange={(e) => setPayloadText(e.target.value)}
            rows={8}
            spellCheck={false}
            placeholder={"' OR '1'='1\n../../../etc/passwd\n<script>alert(1)</script>"}
            style={{ width: "100%", fontFamily: "var(--hp-mono, monospace)" }}
          />
          {vocab && (
            <>
              <div className="hp-tn-olhint">shape each payload before it is substituted</div>
              <div className="hp-tn-form">
                {Object.entries(vocab.shapes).map(([name, desc]) => (
                  <label key={name} title={desc}>
                    <input
                      type="checkbox"
                      checked={shapes.includes(name)}
                      onChange={() => toggleShape(name)}
                    />{" "}
                    {name}
                  </label>
                ))}
              </div>
            </>
          )}
          <div className="hp-tn-form">
            <button type="button" onClick={doPreview} disabled={!url.trim()}>
              preview — what would be sent, and what the gate says
            </button>
            <span className="hp-tn-olhint">
              {payloads.length} payload{payloads.length === 1 ? "" : "s"}
            </span>
          </div>
        </section>

        {preview && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">preview</div>
            <div className="hp-tn-cardsub">
              {preview.positions} position{preview.positions === 1 ? "" : "s"} ·{" "}
              <strong>{preview.planned} request(s) planned</strong>
              {preview.capped ? " · CAPPED at the ceiling — not every payload will run" : ""}
            </div>
            {preview.warnings.map((w) => (
              <p key={w} className="hp-tn-error">
                {w}
              </p>
            ))}
            <div className="hp-tn-olhint">
              the approved surface <CopyButton text={preview.argv.join(" ")} />
            </div>
            <pre className="hp-tn-oneliner">{preview.argv.join(" ")}</pre>
            {preview.sample.length > 0 && (
              <>
                <div className="hp-tn-olhint">first requests</div>
                <ul className="hp-tn-list">
                  {preview.sample.map((s, i) => (
                    <li key={`${s.position}-${i}`} className="hp-tn-row">
                      <div className="hp-tn-rowtop">
                        <span className="hp-tn-kind">
                          {s.position < 0 ? "all" : `pos ${s.position}`}
                        </span>
                        <span className="hp-tn-subs" style={{ wordBreak: "break-all" }}>
                          {s.url}
                        </span>
                      </div>
                    </li>
                  ))}
                </ul>
              </>
            )}
            {preview.gate ? (
              <p className="hp-tn-error">
                The gate would refuse this at <strong>{preview.gate.gate}</strong>:{" "}
                {preview.gate.reason}
                {preview.gate.dangerous_flags.length > 0
                  ? ` — ${preview.gate.dangerous_flags.join("; ")}`
                  : ""}
              </p>
            ) : (
              <p className="hp-tn-note">
                Nothing stands in the way at the gates — with approval set, this would run.
              </p>
            )}
          </section>
        )}

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">run it</div>
          <div className="hp-tn-form">
            <label>
              <input
                type="checkbox"
                checked={approved}
                onChange={(e) => setApproved(e.target.checked)}
              />{" "}
              I approve this job
            </label>
          </div>
          <div className="hp-tn-danger">
            <div className="hp-tn-danger-head">this sends one real request per payload</div>
            <div className="hp-tn-danger-note">
              The red-confirm below is only <em>required</em>{" "}when the gate asks for it — a
              payload set that looks like code execution trips it, ordinary injection strings do
              not. Preview first: the gate&rsquo;s answer is shown above before anything is sent.
            </div>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              I understand this sends <strong>{preview?.planned ?? payloads.length} request(s)</strong>{" "}
              of live traffic to the target from one press
            </label>
            <div className="hp-tn-danger-actions">
              <button
                type="button"
                className="hp-tn-danger-go"
                onClick={run}
                disabled={starting || !approved || !url.trim() || payloads.length === 0}
              >
                {starting ? "starting…" : "run the payload set"}
              </button>
            </div>
          </div>
        </section>

        {job && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">results · {job.id}</div>
            <div className="hp-tn-cardsub">
              <span className={`hp-tn-state ${job.state === "running" ? "is-listening" : "is-down"}`}>
                {job.state}
              </span>{" "}
              · sent <strong>{job.sent}</strong> of {job.planned} planned ·{" "}
              {job.positions} position{job.positions === 1 ? "" : "s"}
              {job.capped ? " · CAPPED" : ""}
              {job.scope_refusals > 0
                ? ` · ${job.scope_refusals} not sent (a payload moved the URL off-scope)`
                : ""}
            </div>
            {job.warnings.map((w) => (
              <p key={w} className="hp-tn-error">
                {w}
              </p>
            ))}
            {job.state === "running" && (
              <div className="hp-tn-form">
                <button type="button" className="hp-tn-stop" onClick={() => stop(job.id)}>
                  stop — not gated
                </button>
              </div>
            )}
            {job.baseline ? (
              <p className="hp-tn-note">
                baseline (every position at its original value):{" "}
                <strong>{job.baseline.status ?? "—"}</strong> · {job.baseline.size_bytes}b ·{" "}
                {job.baseline.time_ms}ms. Rows below marked <strong>differs</strong> are not like
                it — that is the signal.
              </p>
            ) : null}
            {job.results.length === 0 ? (
              <p className="hp-tn-note">No results yet.</p>
            ) : (
              <ul className="hp-tn-list">
                {job.results.map((r) => (
                  <li
                    key={`${r.index}-${r.position}`}
                    className={`hp-tn-row${r.error ? " is-down" : ""}`}
                  >
                    <div className="hp-tn-rowtop">
                      <span className="hp-tn-kind">
                        {r.position < 0 ? "all" : `p${r.position}`}
                      </span>
                      <span
                        className="hp-tn-subs"
                        style={{ flex: "1 1 260px", wordBreak: "break-all" }}
                      >
                        {r.payload}
                      </span>
                      <span className="hp-tn-state is-listening">{r.status ?? "—"}</span>
                      <span className="hp-tn-olhint">
                        {r.size_bytes}b · {r.time_ms}ms
                      </span>
                      {r.differs_from_baseline ? (
                        <span className="hp-tn-state is-starting">differs</span>
                      ) : null}
                    </div>
                    {r.error ? <div className="hp-tn-olhint">{r.error}</div> : null}
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}
      </div>
    </PageShell>
  );
}
