"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  getCacheStatus,
  listCacheJobs,
  cachePreview,
  startCache,
  startCacheConfirm,
  stopCacheJob,
  type CacheJob,
  type CachePreview,
  type CacheRequest,
} from "@/lib/api";

/**
 * The web-cache-poisoning / cache-deception detector — one probe per candidate unkeyed input from
 * one press.
 *
 * *** WHY DETECTION AND CONFIRMATION ARE SPLIT, SAID ON THE SCREEN AND NOT ONLY IN THE CODE. ***
 * DETECTION is safe-by-default: it puts a marker into one candidate unkeyed input and reports whether
 * the marker is reflected AND the response is cacheable — it plants NO cache entry and serves nothing
 * to anyone else. CONFIRMATION plants the poison — it primes the cache then fetches it back with a
 * request that never carried the marker, so the poisoned entry a fresh request receives is the same
 * one a real co-user would receive — so it is a SEPARATE approve-each that carries a plain-language
 * co-user warning. The same four gates the intruder/smuggle clear, no new gate class: human approval
 * is the bound.
 */
const ALL_INPUTS = [
  "X-Forwarded-Host",
  "X-Forwarded-Scheme",
  "X-Forwarded-Proto",
  "X-Forwarded-Port",
  "X-Host",
  "X-Forwarded-Server",
  "X-Original-URL",
  "X-Rewrite-URL",
  "X-Forwarded-For",
  "Forwarded",
  "param-cloak",
  "fat-get-body",
] as const;
const DEFAULT_INPUTS = [
  "X-Forwarded-Host",
  "X-Forwarded-Scheme",
  "X-Forwarded-Proto",
  "X-Host",
  "X-Original-URL",
  "X-Rewrite-URL",
  "param-cloak",
];

const CO_USER_WARNING =
  "CONFIRMATION MAY SERVE A POISONED RESPONSE TO OTHER USERS OF THIS CACHE. It plants a poisoned " +
  "entry (the marker request) then fetches it back with a request that never carried the marker — " +
  "the poisoned entry a fresh request receives is the same entry a real co-user would receive until " +
  "the cache expires. Only run it on a target you are authorised to poison. Detection (reflection + " +
  "cacheability) plants nothing; this stage does.";

function blankRequest(): CacheRequest {
  return {
    url: "",
    method: "GET",
    headers: [],
    body: "",
    inputs: [...DEFAULT_INPUTS],
    stage: "detect",
    deception: true,
    insecure: false,
    follow_redirects: false,
    engagement_id: null,
    session_id: null,
    use_cookie_jar: true,
    approved: false,
    dangerous_ack: false,
  };
}

/**
 * A SYNTHETIC verdict table — never a real target — so the screen renders the request box, the
 * candidate-input checklist, the per-input reflected/cacheable verdicts and a cache-deception hit on
 * first load and in the screenshot. An edge that omits X-Forwarded-Host from its cache key while the
 * origin reflects it into a redirect, and serves the account page for a `.css` path, is the textbook
 * poisoning + deception mix. Replaced the instant a real job exists.
 */
const DEMO_JOB: CacheJob = {
  id: "demo",
  state: "finished",
  stage: "detect",
  container: "hackpit-kali-open",
  started_at: "",
  finished_at: "",
  inputs: ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host", "X-Original-URL", "param-cloak"],
  candidates: ["X-Forwarded-Host", "X-Forwarded-Scheme"],
  confirmed: [],
  co_user_warning: "",
  warnings: [],
  scope_refusals: 0,
  finding_written: true,
  confirms: [],
  request: {
    ...blankRequest(),
    url: "https://shop.example/",
    method: "GET",
    approved: true,
  },
  verdicts: [
    {
      input: "X-Forwarded-Host",
      reflected: true,
      cacheable: true,
      candidate: true,
      marker: "hackpitCACHE1a2b3c4d",
      indicator: "reflected in response body; Cache-Control: public, max-age=300",
      status: 200,
      error: "",
      note:
        "marker reflected AND the response is cacheable — an unkeyed X-Forwarded-Host would be " +
        "stored and served to other requests (redirect / link rewritten to the attacker host).",
    },
    {
      input: "X-Forwarded-Scheme",
      reflected: true,
      cacheable: true,
      candidate: true,
      marker: "hackpitCACHE5e6f7a8b",
      indicator: "reflected in response header Location; Age: 42 — served from a shared cache",
      status: 302,
      error: "",
      note:
        "marker reflected into the Location redirect AND the 302 is cached (Age present) — a " +
        "poisoned open-redirect served to every user of the cache key.",
    },
    {
      input: "X-Host",
      reflected: false,
      cacheable: true,
      candidate: false,
      marker: "hackpitCACHE9c0d1e2f",
      indicator: "Cache-Control: public, max-age=300",
      status: 200,
      error: "",
      note: "cacheable but not reflected — the input does not reach the response.",
    },
    {
      input: "X-Original-URL",
      reflected: true,
      cacheable: false,
      candidate: false,
      marker: "hackpitCACHE3a4b5c6d",
      indicator: "reflected in response body; Cache-Control: no-store",
      status: 200,
      error: "",
      note: "reflected but not cacheable — no cache would store it.",
    },
    {
      input: "param-cloak",
      reflected: false,
      cacheable: false,
      candidate: false,
      marker: "hackpitCACHE7e8f9a0b",
      indicator: "Cache-Control: private",
      status: 200,
      error: "",
      note: "neither reflected nor cacheable — not a candidate.",
    },
  ],
  deceptions: [
    {
      path: "/account/foo.css",
      extension: "css",
      cached: true,
      status: 200,
      indicator: "Cache-Control: public, max-age=600",
      evidence:
        "dynamic HTML (content-type text/html) served for a .css path and it is cacheable — the " +
        "account page is now cacheable under an unauthenticated static URL.",
      error: "",
      note:
        "a dynamic page is served for a static-looking path AND stored by the cache — sensitive " +
        "content is now cacheable under an unauthenticated URL.",
    },
    {
      path: "/account/;foo.css",
      extension: "css",
      cached: false,
      status: 404,
      indicator: "no caching headers",
      evidence: "served non-HTML (status 404) — not a deception hit",
      error: "",
      note: "not a deception hit — the static path did not yield cached dynamic content.",
    },
  ],
};

export function CacheScreen() {
  const [status, setStatus] = useState<{
    container: string;
    up: boolean;
    running: number;
    detail: string;
  } | null>(null);
  const [jobs, setJobs] = useState<CacheJob[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [url, setUrl] = useState("");
  const [method, setMethod] = useState("GET");
  const [body, setBody] = useState("");
  const [inputs, setInputs] = useState<string[]>([...DEFAULT_INPUTS]);
  const [deception, setDeception] = useState(true);
  const [engagementId, setEngagementId] = useState("");
  const [useJar, setUseJar] = useState(true);
  const [approved, setApproved] = useState(false);
  const [ack, setAck] = useState(false);
  const [preview, setPreview] = useState<CachePreview | null>(null);
  const [starting, setStarting] = useState(false);

  // The confirmation stage's OWN approval — deliberately separate state from the detection approval,
  // so a confirmation can never ride a detection's checkbox. Nothing about detection sets these.
  const [confirmApproved, setConfirmApproved] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);

  const request = useCallback(
    (stage: string, ins: string[], withApproval: boolean, withAck: boolean): CacheRequest => ({
      ...blankRequest(),
      url: url.trim(),
      method,
      body,
      inputs: ins,
      stage,
      deception,
      engagement_id: engagementId.trim() || null,
      session_id: engagementId.trim() || null,
      use_cookie_jar: useJar,
      approved: withApproval,
      dangerous_ack: withAck,
    }),
    // `ins` is a parameter, not the `inputs` state — so `inputs` is deliberately NOT a dependency
    // (mirrors SmuggleScreen's `request` callback, which omits `mutations` for the same reason).
    [url, method, body, deception, engagementId, useJar]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    getCacheStatus(ctrl.signal)
      .then(setStatus)
      .catch(() => setStatus(null));
    return () => ctrl.abort();
  }, []);

  const refreshJobs = useCallback(() => {
    listCacheJobs()
      .then(setJobs)
      .catch(() => setJobs([]));
  }, []);

  useEffect(() => {
    refreshJobs();
    const t = setInterval(refreshJobs, 2000);
    return () => clearInterval(t);
  }, [refreshJobs]);

  const toggleInput = useCallback((i: string) => {
    setInputs((cur) => (cur.includes(i) ? cur.filter((x) => x !== i) : [...cur, i]));
  }, []);

  const doPreview = useCallback(async () => {
    if (!url.trim()) return;
    setError(null);
    try {
      setPreview(await cachePreview(request("detect", inputs, approved, ack)));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [url, request, inputs, approved, ack]);

  const runDetect = useCallback(async () => {
    if (!url.trim() || starting) return;
    setStarting(true);
    setError(null);
    try {
      const job = await startCache(request("detect", inputs, approved, ack));
      setSelected(job.id);
      refreshJobs();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setStarting(false);
    }
  }, [url, starting, request, inputs, approved, ack, refreshJobs]);

  const runConfirm = useCallback(
    async (input: string) => {
      if (!url.trim() || confirming) return;
      setConfirming(input);
      setError(null);
      try {
        // The confirmation is its OWN approval (confirmApproved), a single input, stage=confirm.
        const job = await startCacheConfirm(request("confirm", [input], confirmApproved, ack));
        setSelected(job.id);
        refreshJobs();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
      } finally {
        setConfirming(null);
      }
    },
    [url, confirming, request, confirmApproved, ack, refreshJobs]
  );

  const stop = useCallback(
    async (id: string) => {
      try {
        await stopCacheJob(id);
        refreshJobs();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
      }
    },
    [refreshJobs]
  );

  // The DEMO job shows until a real one exists, so the screen (and the screenshot) is never blank.
  const realJob = jobs.find((j) => j.id === selected) ?? jobs[0] ?? null;
  const job = realJob ?? DEMO_JOB;
  const isDemo = realJob === null;

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "cache" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">
            one probe per unkeyed input · safe reflection+cacheability · gated poison-plant
          </div>
          <h1 className="hp-tn-title">:cache</h1>
          <p className="hp-tn-sub">
            Probe a target for <strong>web cache poisoning</strong> — an{" "}
            <strong>unkeyed input</strong> (X-Forwarded-Host and friends, a cloaked query param, a
            fat GET body) the cache leaves out of its key while the origin still reflects it — and{" "}
            <strong>cache deception</strong> (a sensitive dynamic page cached under a static-looking
            path). <strong>Detection is safe by default</strong>: it marks one input, then checks
            whether the marker is reflected AND the response is cacheable —{" "}
            <em>it plants no cache entry</em>. <strong>Confirmation</strong> (poison-plant) is a{" "}
            <strong>separate approval</strong> because it can serve the poison to other users of the
            cache. One gated job, the same four gates the intruder clears — no new gate.
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
            The same request template is probed against each chosen candidate input. Point it at a
            page you suspect sits behind a CDN / edge cache.
          </div>
          <div className="hp-tn-form">
            <select value={method} onChange={(e) => setMethod(e.target.value)}>
              {["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://host/"
            />
          </div>
          <div className="hp-tn-form">
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={2}
              placeholder="request body (used for the baseline / fat-GET template) — optional"
              style={{ width: "100%" }}
            />
          </div>
          <div className="hp-tn-form">
            <input
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
              placeholder="engagement id (optional — enables the on-the-wire scope check)"
            />
            <label>
              <input
                type="checkbox"
                checked={useJar}
                onChange={(e) => setUseJar(e.target.checked)}
              />{" "}
              use the repeater&rsquo;s cookie jar
            </label>
            <label title="Also run the cache-deception path-confusion probes.">
              <input
                type="checkbox"
                checked={deception}
                onChange={(e) => setDeception(e.target.checked)}
              />{" "}
              also probe cache deception (path confusion)
            </label>
          </div>
        </section>

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">candidate unkeyed inputs to probe</div>
          <div className="hp-tn-cardsub">
            The X-Forwarded-* headers + a cloaked param are the safe default. Each is injected one at
            a time with a unique marker; a hit is <strong>reflected AND cacheable</strong>.
          </div>
          <div className="hp-tn-chips">
            {ALL_INPUTS.map((i) => {
              const on = inputs.includes(i);
              return (
                <button
                  key={i}
                  type="button"
                  className={`hp-tn-chip${on ? " is-on" : ""}`}
                  aria-pressed={on}
                  onClick={() => toggleInput(i)}
                >
                  {on ? "✓ " : ""}
                  {i}
                </button>
              );
            })}
          </div>
          <div className="hp-tn-form">
            <button type="button" onClick={doPreview} disabled={!url.trim()}>
              preview — what would be probed, and what the gate says
            </button>
          </div>
        </section>

        {preview && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">preview</div>
            <div className="hp-tn-cardsub">
              stage <strong>{preview.stage}</strong> ·{" "}
              <strong>{preview.inputs.join(", ") || "(default set)"}</strong>
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
          <div className="hp-tn-cardhead">run detection — safe by default</div>
          <div className="hp-tn-cardsub">
            Reflection + cacheability only. It plants no cache entry and serves nothing to another
            user &mdash; it just observes what the origin echoes and whether a cache would store it.
          </div>
          <div className="hp-tn-form">
            <label>
              <input
                type="checkbox"
                checked={approved}
                onChange={(e) => setApproved(e.target.checked)}
              />{" "}
              I approve this detection sweep
            </label>
            <label title="Only needed when the request content trips the danger gate — preview shows it.">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />{" "}
              red-confirm (only if the request content trips the danger gate)
            </label>
          </div>
          <div className="hp-tn-form">
            <button
              type="button"
              className="hp-tn-danger-go"
              onClick={runDetect}
              disabled={starting || !approved || !url.trim() || inputs.length === 0}
            >
              {starting ? "probing…" : "run detection"}
            </button>
          </div>
        </section>

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">
            verdict table · {job.id}
            {isDemo ? (
              <span className="hp-tn-olhint"> · synthetic demo (no real target)</span>
            ) : null}
          </div>
          <div className="hp-tn-cardsub">
            <span
              className={`hp-tn-state ${job.state === "running" ? "is-listening" : "is-down"}`}
            >
              {job.state}
            </span>{" "}
            · stage {job.stage} · {job.inputs.length} input(s)
            {job.finding_written ? " · written to engagement state as a finding" : ""}
            {job.scope_refusals > 0
              ? ` · ${job.scope_refusals} not sent (URL host off-scope)`
              : ""}
          </div>
          {job.warnings.map((w) => (
            <p key={w} className="hp-tn-error">
              {w}
            </p>
          ))}
          {job.state === "running" && !isDemo && (
            <div className="hp-tn-form">
              <button type="button" className="hp-tn-stop" onClick={() => stop(job.id)}>
                stop — not gated
              </button>
            </div>
          )}

          {job.verdicts.length === 0 && job.confirms.length === 0 ? (
            <p className="hp-tn-note">No detection results yet.</p>
          ) : (
            <ul className="hp-tn-list">
              {job.verdicts.map((v) => (
                <li key={v.input} className={`hp-tn-row${v.error ? " is-down" : ""}`}>
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">{v.input}</span>
                    <span
                      className={`hp-tn-state ${v.candidate ? "is-starting" : "is-listening"}`}
                    >
                      {v.candidate ? "CANDIDATE" : v.error ? "inconclusive" : "clear"}
                    </span>
                    <span className="hp-tn-olhint">
                      reflected {v.reflected ? "✓" : "✗"} · cacheable {v.cacheable ? "✓" : "✗"}
                      {v.status !== null ? ` · ${v.status}` : ""}
                    </span>
                    {v.candidate && !isDemo && (
                      <button
                        type="button"
                        className="hp-tn-danger-go"
                        onClick={() => runConfirm(v.input)}
                        disabled={confirming !== null || !confirmApproved}
                        title={
                          confirmApproved
                            ? "Attempt poison-plant confirmation for this input"
                            : "Approve confirmation below first — it can affect other cache users"
                        }
                      >
                        {confirming === v.input ? "confirming…" : "attempt confirmation"}
                      </button>
                    )}
                    {v.candidate && isDemo && (
                      <span className="hp-tn-olhint">confirm available on a real job</span>
                    )}
                  </div>
                  <div className="hp-tn-rowbody">{v.note || v.indicator || v.error}</div>
                </li>
              ))}
            </ul>
          )}

          {job.deceptions.some((d) => d.cached) && (
            <>
              <div className="hp-tn-olhint">cache deception</div>
              <ul className="hp-tn-list">
                {job.deceptions
                  .filter((d) => d.cached)
                  .map((d) => (
                    <li key={d.path} className="hp-tn-row">
                      <div className="hp-tn-rowtop">
                        <span className="hp-tn-kind">{d.path}</span>
                        <span className="hp-tn-state is-starting">CACHED DYNAMIC</span>
                        <span className="hp-tn-olhint">
                          .{d.extension}
                          {d.status !== null ? ` · ${d.status}` : ""}
                        </span>
                      </div>
                      <div className="hp-tn-rowbody">{d.evidence || d.note}</div>
                    </li>
                  ))}
              </ul>
            </>
          )}

          {job.confirms.length > 0 && (
            <>
              <div className="hp-tn-olhint">confirmation results</div>
              <ul className="hp-tn-list">
                {job.confirms.map((c) => (
                  <li key={c.input} className={`hp-tn-row${c.error ? " is-down" : ""}`}>
                    <div className="hp-tn-rowtop">
                      <span className="hp-tn-kind">{c.input}</span>
                      <span
                        className={`hp-tn-state ${c.poisoned ? "is-starting" : "is-listening"}`}
                      >
                        {c.poisoned ? "POISONED" : c.error ? "inconclusive" : "not confirmed"}
                      </span>
                      <span className="hp-tn-olhint">status {c.status ?? "—"}</span>
                    </div>
                    <div className="hp-tn-rowbody">{c.evidence || c.note || c.error}</div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">confirmation — a separate approval</div>
          <div className="hp-tn-danger">
            <div className="hp-tn-danger-head">
              this stage can serve a poisoned response to other cache users
            </div>
            <div className="hp-tn-danger-note">{CO_USER_WARNING}</div>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input
                type="checkbox"
                checked={confirmApproved}
                onChange={(e) => setConfirmApproved(e.target.checked)}
              />
              I approve <strong>confirmation</strong> and understand it may serve a{" "}
              <strong>poisoned response to another user</strong> of this cache
            </label>
            <div className="hp-tn-danger-note">
              With this approved, each <strong>CANDIDATE</strong> row above gets an{" "}
              <em>attempt confirmation</em> button. Confirmation runs one input at a time as its own
              gated job.
            </div>
          </div>
        </section>
      </div>
    </PageShell>
  );
}
