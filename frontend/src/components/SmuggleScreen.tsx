"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  getSmuggleStatus,
  listSmuggleJobs,
  smugglePreview,
  startSmuggle,
  startSmuggleConfirm,
  stopSmuggleJob,
  type SmuggleJob,
  type SmugglePreview,
  type SmuggleRequest,
} from "@/lib/api";

/**
 * The request-smuggling / desync detector — one probe per mutation from one press.
 *
 * *** WHY DETECTION AND CONFIRMATION ARE SPLIT, SAID ON THE SCREEN AND NOT ONLY IN THE CODE. ***
 * DETECTION is safe-by-default: a timing-differential probe hangs a *back-end* on bytes that never
 * come, and touches no other user's request. CONFIRMATION is socket poisoning — it can affect the
 * next request on a shared connection, possibly another user's — so it is a SEPARATE approve-each
 * that carries a plain-language co-tenant warning. The same four gates the intruder/race clear, no
 * new gate class: human approval is the bound.
 */
const ALL_MUTATIONS = [
  "CL.TE",
  "TE.CL",
  "CL.CL",
  "TE.TE",
  "CL.0",
  "H2.CL",
  "H2.TE",
  "H2.0",
] as const;
const DEFAULT_MUTATIONS = ["CL.TE", "TE.CL", "CL.0"];

const CO_TENANT_WARNING =
  "CONFIRMATION MAY AFFECT CO-TENANT REQUESTS. Socket-poisoning confirmation smuggles a partial " +
  "request onto a shared connection, so the NEXT request on that connection — possibly another " +
  "user's — can receive the poisoned response. Only run it on a target you are authorised to " +
  "desync, and expect to affect other traffic. Detection (timing) does not do this; this stage does.";

function blankRequest(): SmuggleRequest {
  return {
    url: "",
    method: "POST",
    headers: [],
    body: "",
    mutations: [...DEFAULT_MUTATIONS],
    stage: "detect",
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
 * A SYNTHETIC verdict matrix — never a real target — so the screen renders the request box, the
 * mutation checklist and the per-mutation timing verdicts on first load and in the screenshot. A
 * front-end that speaks Content-Length to a chunked back-end (CL.TE) and mishandles CL.0, while the
 * TE.CL / duplicate-CL paths stay consistent and H2 is not negotiated, is the textbook desync mix.
 * Replaced the instant a real job exists.
 */
const DEMO_JOB: SmuggleJob = {
  id: "demo",
  state: "finished",
  stage: "detect",
  container: "hackpit-kali-open",
  started_at: "",
  finished_at: "",
  mutations: ["CL.TE", "TE.CL", "CL.CL", "TE.TE", "CL.0", "H2.CL"],
  susceptible: ["CL.TE", "CL.0"],
  confirmed: [],
  co_tenant_warning: "",
  warnings: [],
  scope_refusals: 0,
  finding_written: true,
  confirms: [],
  request: {
    ...blankRequest(),
    url: "https://shop.example/",
    method: "POST",
    approved: true,
  },
  verdicts: [
    {
      mutation: "CL.TE",
      susceptible: true,
      baseline_ms: 41,
      probe_ms: 6043,
      delta_ms: 6002,
      error: "",
      note:
        "probe hung 6002ms over the baseline — a back-end waited for body bytes the ambiguous " +
        "framing never delivered, the signature of a CL.TE desync split.",
    },
    {
      mutation: "TE.CL",
      susceptible: false,
      baseline_ms: 40,
      probe_ms: 58,
      delta_ms: 18,
      error: "",
      note: "probe returned 18ms over the baseline (< 4000ms) — no desync delay observed.",
    },
    {
      mutation: "CL.CL",
      susceptible: false,
      baseline_ms: 40,
      probe_ms: 52,
      delta_ms: 12,
      error: "",
      note: "probe returned 12ms over the baseline (< 4000ms) — a single consistent parser handled it.",
    },
    {
      mutation: "TE.TE",
      susceptible: false,
      baseline_ms: 40,
      probe_ms: 61,
      delta_ms: 21,
      error: "",
      note: "probe returned 21ms over the baseline (< 4000ms) — no desync delay observed.",
    },
    {
      mutation: "CL.0",
      susceptible: true,
      baseline_ms: 41,
      probe_ms: 5210,
      delta_ms: 5169,
      error: "",
      note:
        "probe hung 5169ms over the baseline — the back-end began parsing the body as a new " +
        "request and blocked, the signature of a CL.0 desync.",
    },
    {
      mutation: "H2.CL",
      susceptible: false,
      baseline_ms: 41,
      probe_ms: 0,
      delta_ms: -41,
      error: "inconclusive — target did not negotiate HTTP/2 over ALPN",
      note: "inconclusive — target did not negotiate HTTP/2 over ALPN",
    },
  ],
};

export function SmuggleScreen() {
  const [status, setStatus] = useState<{
    container: string;
    up: boolean;
    running: number;
    detail: string;
  } | null>(null);
  const [jobs, setJobs] = useState<SmuggleJob[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [url, setUrl] = useState("");
  const [method, setMethod] = useState("POST");
  const [body, setBody] = useState("");
  const [mutations, setMutations] = useState<string[]>([...DEFAULT_MUTATIONS]);
  const [engagementId, setEngagementId] = useState("");
  const [useJar, setUseJar] = useState(true);
  const [approved, setApproved] = useState(false);
  const [ack, setAck] = useState(false);
  const [preview, setPreview] = useState<SmugglePreview | null>(null);
  const [starting, setStarting] = useState(false);

  // The confirmation stage's OWN approval — deliberately separate state from the detection approval,
  // so a confirmation can never ride a detection's checkbox. Nothing about detection sets these.
  const [confirmApproved, setConfirmApproved] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);

  const request = useCallback(
    (stage: string, muts: string[], withApproval: boolean, withAck: boolean): SmuggleRequest => ({
      ...blankRequest(),
      url: url.trim(),
      method,
      body,
      mutations: muts,
      stage,
      engagement_id: engagementId.trim() || null,
      session_id: engagementId.trim() || null,
      use_cookie_jar: useJar,
      approved: withApproval,
      dangerous_ack: withAck,
    }),
    [url, method, body, engagementId, useJar]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    getSmuggleStatus(ctrl.signal)
      .then(setStatus)
      .catch(() => setStatus(null));
    return () => ctrl.abort();
  }, []);

  const refreshJobs = useCallback(() => {
    listSmuggleJobs()
      .then(setJobs)
      .catch(() => setJobs([]));
  }, []);

  useEffect(() => {
    refreshJobs();
    const t = setInterval(refreshJobs, 2000);
    return () => clearInterval(t);
  }, [refreshJobs]);

  const toggleMutation = useCallback((m: string) => {
    setMutations((cur) => (cur.includes(m) ? cur.filter((x) => x !== m) : [...cur, m]));
  }, []);

  const doPreview = useCallback(async () => {
    if (!url.trim()) return;
    setError(null);
    try {
      setPreview(await smugglePreview(request("detect", mutations, approved, ack)));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [url, request, mutations, approved, ack]);

  const runDetect = useCallback(async () => {
    if (!url.trim() || starting) return;
    setStarting(true);
    setError(null);
    try {
      const job = await startSmuggle(request("detect", mutations, approved, ack));
      setSelected(job.id);
      refreshJobs();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setStarting(false);
    }
  }, [url, starting, request, mutations, approved, ack, refreshJobs]);

  const runConfirm = useCallback(
    async (mutation: string) => {
      if (!url.trim() || confirming) return;
      setConfirming(mutation);
      setError(null);
      try {
        // The confirmation is its OWN approval (confirmApproved), a single mutation, stage=confirm.
        const job = await startSmuggleConfirm(request("confirm", [mutation], confirmApproved, ack));
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
        await stopSmuggleJob(id);
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
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "smuggle" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">
            one probe per mutation · safe timing detection · gated confirmation
          </div>
          <h1 className="hp-tn-title">:smuggle</h1>
          <p className="hp-tn-sub">
            Probe a target for <strong>request smuggling / desync</strong> — CL.TE, TE.CL, CL.CL,
            TE.TE, CL.0 and the HTTP/2-downgrade H2.CL / H2.TE / H2.0 variants.{" "}
            <strong>Detection is safe by default</strong>: a timing-differential probe makes a
            back-end wait for bytes that never come, so a front-end/back-end split shows as a delay —{" "}
            <em>no other user&rsquo;s request is touched</em>. <strong>Confirmation</strong>{" "}
            (socket poisoning) is a <strong>separate approval</strong> because it can affect
            co-tenant traffic. One gated job, the same four gates the intruder clears — no new gate.
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
            The same request template is probed against each chosen mutation. Point it at the
            front-end you suspect sits over a different back-end parser.
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
              placeholder="request body (used for the baseline / CL.0 template) — optional"
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
          </div>
        </section>

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">mutations to probe</div>
          <div className="hp-tn-cardsub">
            The CL/TE family + CL.0 are the safe default (no HTTP/2 needed). The H2.* variants need a
            target that negotiates HTTP/2 — an inconclusive note is honest, never a fabricated hit.
          </div>
          <div className="hp-tn-chips">
            {ALL_MUTATIONS.map((m) => {
              const on = mutations.includes(m);
              return (
                <button
                  key={m}
                  type="button"
                  className={`hp-tn-chip${on ? " is-on" : ""}`}
                  aria-pressed={on}
                  onClick={() => toggleMutation(m)}
                >
                  {on ? "✓ " : ""}
                  {m}
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
              <strong>{preview.mutations.join(", ") || "(default set)"}</strong>
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
            Timing-differential only. Self-contained: it hangs a back-end on its own probe, never
            another user&rsquo;s request.
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
              disabled={starting || !approved || !url.trim() || mutations.length === 0}
            >
              {starting ? "probing…" : "run detection"}
            </button>
          </div>
        </section>

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">
            verdict matrix · {job.id}
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
            · stage {job.stage} · {job.mutations.length} mutation(s)
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
                <li
                  key={v.mutation}
                  className={`hp-tn-row${v.error ? " is-down" : ""}`}
                >
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">{v.mutation}</span>
                    <span
                      className={`hp-tn-state ${
                        v.susceptible ? "is-starting" : "is-listening"
                      }`}
                    >
                      {v.susceptible ? "SUSCEPTIBLE" : v.error ? "inconclusive" : "clear"}
                    </span>
                    <span className="hp-tn-olhint">
                      baseline {v.baseline_ms}ms · probe {v.probe_ms}ms · Δ {v.delta_ms}ms
                    </span>
                    {v.susceptible && !isDemo && (
                      <button
                        type="button"
                        className="hp-tn-danger-go"
                        onClick={() => runConfirm(v.mutation)}
                        disabled={confirming !== null || !confirmApproved}
                        title={
                          confirmApproved
                            ? "Attempt socket-poisoning confirmation for this mutation"
                            : "Approve confirmation below first — it can affect co-tenant traffic"
                        }
                      >
                        {confirming === v.mutation ? "confirming…" : "attempt confirmation"}
                      </button>
                    )}
                    {v.susceptible && isDemo && (
                      <span className="hp-tn-olhint">confirm available on a real job</span>
                    )}
                  </div>
                  <div className="hp-tn-rowbody">{v.note || v.error}</div>
                </li>
              ))}
            </ul>
          )}

          {job.confirms.length > 0 && (
            <>
              <div className="hp-tn-olhint">confirmation results</div>
              <ul className="hp-tn-list">
                {job.confirms.map((c) => (
                  <li key={c.mutation} className={`hp-tn-row${c.error ? " is-down" : ""}`}>
                    <div className="hp-tn-rowtop">
                      <span className="hp-tn-kind">{c.mutation}</span>
                      <span
                        className={`hp-tn-state ${c.confirmed ? "is-starting" : "is-listening"}`}
                      >
                        {c.confirmed ? "CONFIRMED" : c.error ? "inconclusive" : "not confirmed"}
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
            <div className="hp-tn-danger-head">this stage can affect co-tenant requests</div>
            <div className="hp-tn-danger-note">{CO_TENANT_WARNING}</div>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input
                type="checkbox"
                checked={confirmApproved}
                onChange={(e) => setConfirmApproved(e.target.checked)}
              />
              I approve <strong>confirmation</strong> and understand it may desynchronise a{" "}
              <strong>co-tenant&rsquo;s</strong> request on the shared connection
            </label>
            <div className="hp-tn-danger-note">
              With this approved, each <strong>SUSCEPTIBLE</strong> row above gets an{" "}
              <em>attempt confirmation</em> button. Confirmation runs one mutation at a time as its
              own gated job.
            </div>
          </div>
        </section>
      </div>
    </PageShell>
  );
}
