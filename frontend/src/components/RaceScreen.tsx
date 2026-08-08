"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  getRaceStatus,
  listRaceJobs,
  racePreview,
  startRace,
  stopRaceJob,
  type RaceJob,
  type RacePreview,
  type RaceRequest,
} from "@/lib/api";

/**
 * The single-packet race tester — one request, fired N times so the copies land in one instant.
 *
 * *** WHY ONE APPROVAL BUYS N SYNCHRONIZED REQUESTS, SAID ON THE SCREEN AND NOT ONLY IN THE CODE. ***
 * HackPit refuses BATCHING ACROSS APPROVALS. It has never refused one approval that produces many
 * requests, and could not: ffuf, nuclei, the ZAP active scanner and the intruder are each a single
 * press buying many. This is that same shape with a synchronized transport, gated by the same four
 * gates. The red-confirm is demanded by the GATE and not by this form — an ordinary coupon body
 * does not trip it; a body carrying a shell pattern does.
 */
const MODES = ["h2-single-packet", "h1-last-byte"] as const;

function blankRequest(): RaceRequest {
  return {
    url: "",
    method: "POST",
    headers: [],
    body: "",
    mode: "h2-single-packet",
    count: 20,
    follow_redirects: false,
    insecure: false,
    engagement_id: null,
    session_id: null,
    use_cookie_jar: true,
    approved: false,
    dangerous_ack: false,
  };
}

/**
 * A SYNTHETIC result set — never a real target — so the screen renders the request box, the
 * results table and the win-count verdict on first load and in the screenshot. A coupon-redeem
 * endpoint where 3 of 20 single-packet requests beat the "already used" check is the textbook
 * limit-overrun race. Replaced the instant a real job exists.
 */
const DEMO_JOB: RaceJob = {
  id: "demo",
  state: "finished",
  container: "hackpit-kali-open",
  started_at: "",
  finished_at: "",
  mode: "h2-single-packet",
  planned: 20,
  sent: 20,
  capped: false,
  warnings: [],
  scope_refusals: 0,
  finding_written: true,
  request: {
    ...blankRequest(),
    url: "https://shop.example/api/coupon/redeem",
    method: "POST",
    body: "code=SAVE10",
    count: 20,
    approved: true,
  },
  baseline: {
    index: -1,
    status: 409,
    size_bytes: 74,
    time_ms: 118,
    body_excerpt: '{"ok":false,"error":"coupon already redeemed"}',
    error: "",
    won: false,
  },
  results: [
    ...[0, 1, 2].map((i) => ({
      index: i,
      status: 200,
      size_bytes: 241,
      time_ms: 96 + i,
      body_excerpt: '{"ok":true,"discount":"SAVE10 applied","balance":9.0}',
      error: "",
      won: true,
    })),
    ...Array.from({ length: 17 }, (_, k) => ({
      index: 3 + k,
      status: 409,
      size_bytes: 74,
      time_ms: 92 + (k % 9),
      body_excerpt: '{"ok":false,"error":"coupon already redeemed"}',
      error: "",
      won: false,
    })),
  ],
  verdict: {
    race_detected: true,
    won: 3,
    of: 20,
    winning_status: 200,
    clusters: [
      { status: 200, size: 240, count: 3 },
      { status: 409, size: 64, count: 17 },
    ],
    note:
      "3 of 20 requests landed the rare '200' outcome that a serial baseline returns only once — " +
      "the race window let more than one through.",
  },
};

export function RaceScreen() {
  const [status, setStatus] = useState<{
    container: string;
    up: boolean;
    running: number;
    detail: string;
  } | null>(null);
  const [jobs, setJobs] = useState<RaceJob[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [url, setUrl] = useState("");
  const [method, setMethod] = useState("POST");
  const [body, setBody] = useState("");
  const [mode, setMode] = useState<string>("h2-single-packet");
  const [count, setCount] = useState("20");
  const [engagementId, setEngagementId] = useState("");
  const [useJar, setUseJar] = useState(true);
  const [approved, setApproved] = useState(false);
  const [ack, setAck] = useState(false);
  const [preview, setPreview] = useState<RacePreview | null>(null);
  const [starting, setStarting] = useState(false);

  const request = useCallback(
    (): RaceRequest => ({
      ...blankRequest(),
      url: url.trim(),
      method,
      body,
      mode,
      count: Number.parseInt(count, 10) || 20,
      engagement_id: engagementId.trim() || null,
      session_id: engagementId.trim() || null,
      use_cookie_jar: useJar,
      approved,
      dangerous_ack: ack,
    }),
    [url, method, body, mode, count, engagementId, useJar, approved, ack]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    getRaceStatus(ctrl.signal)
      .then(setStatus)
      .catch(() => setStatus(null));
    return () => ctrl.abort();
  }, []);

  const refreshJobs = useCallback(() => {
    listRaceJobs()
      .then(setJobs)
      .catch(() => setJobs([]));
  }, []);

  useEffect(() => {
    refreshJobs();
    const t = setInterval(refreshJobs, 2000);
    return () => clearInterval(t);
  }, [refreshJobs]);

  const doPreview = useCallback(async () => {
    if (!url.trim()) return;
    setError(null);
    try {
      setPreview(await racePreview(request()));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [url, request]);

  const run = useCallback(async () => {
    if (!url.trim() || starting) return;
    setStarting(true);
    setError(null);
    try {
      const job = await startRace(request());
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
        await stopRaceJob(id);
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
  const v = job.verdict;

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "race" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">one request · N copies · same instant · one approval</div>
          <h1 className="hp-tn-title">:race</h1>
          <p className="hp-tn-sub">
            Fire one request <strong>N times so the copies arrive together</strong> — HTTP/2
            single-packet or HTTP/1.1 last-byte sync — to slip inside a target&rsquo;s
            check-then-act window: limit overrun, TOCTOU, coupon reuse, one-time-token replay. It is{" "}
            <strong>one gated job</strong>, the same four gates the intruder clears and no new ones.
            Every request goes out argv-only from inside the sandbox, scope-checked on the wire.
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
            The <em>same</em> request is fired N times — there are no marked positions, because a
            race is about how many identical copies win, not about varying a parameter. Paste the
            one-time action (redeem, transfer, vote) and set N.
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
              placeholder="https://host/api/coupon/redeem"
            />
          </div>
          <div className="hp-tn-form">
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={2}
              placeholder="request body (e.g. code=SAVE10) — the one-time payload"
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
              value={count}
              onChange={(e) => setCount(e.target.value)}
              placeholder="N"
              aria-label="How many synchronized requests to fire"
            />
            <label>
              <input
                type="checkbox"
                checked={useJar}
                onChange={(e) => setUseJar(e.target.checked)}
              />{" "}
              use the repeater&rsquo;s cookie jar
            </label>
            <input
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
              placeholder="engagement id (optional — enables the on-the-wire scope check)"
            />
          </div>
          <p className="hp-tn-note">
            <strong>h2-single-packet</strong> queues all N on one HTTP/2 connection with the final
            frame withheld, then releases every final frame together — the reliable modern mode.{" "}
            <strong>h1-last-byte</strong> opens N connections, sends all but the last byte of each,
            then releases the last byte on all at once — the HTTP/1.1 fallback.
          </p>
          <div className="hp-tn-form">
            <button type="button" onClick={doPreview} disabled={!url.trim()}>
              preview — what would be fired, and what the gate says
            </button>
          </div>
        </section>

        {preview && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">preview</div>
            <div className="hp-tn-cardsub">
              mode <strong>{preview.mode}</strong> ·{" "}
              <strong>{preview.planned} synchronized request(s)</strong>
              {preview.capped ? " · CAPPED at the ceiling — N was clamped" : ""}
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
            <div className="hp-tn-danger-head">this fires N real requests in one packet</div>
            <div className="hp-tn-danger-note">
              The red-confirm below is only <em>required</em>{" "}when the gate asks for it — a request
              body that looks like code execution trips it, an ordinary coupon body does not.
              Preview first: the gate&rsquo;s answer is shown above before anything is fired.
            </div>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              I understand this fires{" "}
              <strong>{preview?.planned ?? (Number.parseInt(count, 10) || 20)} synchronized request(s)</strong>{" "}
              of live traffic at the target from one press
            </label>
            <div className="hp-tn-danger-actions">
              <button
                type="button"
                className="hp-tn-danger-go"
                onClick={run}
                disabled={starting || !approved || !url.trim()}
              >
                {starting ? "firing…" : "fire the race"}
              </button>
            </div>
          </div>
        </section>

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">
            results · {job.id}
            {isDemo ? <span className="hp-tn-olhint"> · synthetic demo (no real target)</span> : null}
          </div>
          <div className="hp-tn-cardsub">
            <span className={`hp-tn-state ${job.state === "running" ? "is-listening" : "is-down"}`}>
              {job.state}
            </span>{" "}
            · fired <strong>{job.sent}</strong> of {job.planned} · mode {job.mode}
            {job.capped ? " · CAPPED" : ""}
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

          {v && (
            <div
              className={`hp-tn-danger ${v.race_detected ? "" : ""}`}
              style={{
                borderColor: v.race_detected ? "var(--hp-danger, #ff5c5c)" : undefined,
              }}
            >
              <div className="hp-tn-danger-head">
                {v.race_detected ? (
                  <>
                    RACE WON — {v.won} of {v.of} requests landed the rare status {v.winning_status}
                    {job.finding_written ? " · written to engagement state as a High finding" : ""}
                  </>
                ) : (
                  <>no race window — the rare outcome occurred once, as a serial baseline would</>
                )}
              </div>
              <div className="hp-tn-danger-note">{v.note}</div>
              <div className="hp-tn-olhint">response clusters (rarest first)</div>
              <ul className="hp-tn-list">
                {v.clusters.map((c, i) => (
                  <li key={`${c.status}-${c.size}-${i}`} className="hp-tn-row">
                    <div className="hp-tn-rowtop">
                      <span
                        className={`hp-tn-state ${i === 0 && v.race_detected ? "is-starting" : "is-listening"}`}
                      >
                        {c.status}
                      </span>
                      <span className="hp-tn-olhint">
                        ~{c.size}b · ×{c.count}
                        {i === 0 && v.race_detected ? " · the winning outcome" : ""}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {job.baseline ? (
            <p className="hp-tn-note">
              serial baseline (one request, sent normally):{" "}
              <strong>{job.baseline.status ?? "—"}</strong> · {job.baseline.size_bytes}b ·{" "}
              {job.baseline.time_ms}ms. A row below in the winning cluster beat it — that is the
              race.
            </p>
          ) : null}

          {job.results.length === 0 ? (
            <p className="hp-tn-note">No results yet.</p>
          ) : (
            <ul className="hp-tn-list">
              {job.results.map((r) => (
                <li key={r.index} className={`hp-tn-row${r.error ? " is-down" : ""}`}>
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">#{r.index}</span>
                    <span className="hp-tn-state is-listening">{r.status ?? "—"}</span>
                    <span className="hp-tn-olhint">
                      {r.size_bytes}b · {r.time_ms}ms
                    </span>
                    {r.won ? <span className="hp-tn-state is-starting">won</span> : null}
                    {r.error ? <span className="hp-tn-olhint">{r.error}</span> : null}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </PageShell>
  );
}
