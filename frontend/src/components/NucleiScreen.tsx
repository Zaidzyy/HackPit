"use client";

import { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import Link from "next/link";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  getNucleiStatus,
  getNucleiTemplates,
  listNucleiJobs,
  nucleiPreview,
  startNucleiScan,
  stopNucleiJob,
  type NucleiJob,
  type NucleiPreview,
  type NucleiRequest,
  type NucleiStatus,
  type NucleiTemplates,
} from "@/lib/api";

/**
 * :nuclei — the bug-bounty staple, wired as ONE approved job with an ungated stop.
 *
 * *** WHY ONE APPROVAL BUYS A WHOLE SCAN, SAID ON THE SCREEN AND NOT ONLY IN THE CODE. ***
 * HackPit refuses BATCHING ACROSS APPROVALS. It has never refused one approval that produces
 * thousands of requests, and could not: ffuf, the intruder and the ZAP active scanner are each
 * one press buying thousands. A nuclei run is that same shape — one gated job, gated by the same
 * executor gates, no new ones — with an ungated stop. Every match lands as a severity-ranked
 * finding in engagement state (visible in :cockpit) and the report.
 */
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const SEV_COLOR: Record<string, string> = {
  critical: "#ff5c7a",
  high: "#f0776a",
  medium: "#f0a24a",
  low: "#7ec8a0",
  info: "#8aa4c8",
};

function lines(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function NucleiScreen() {
  const [status, setStatus] = useState<NucleiStatus | null>(null);
  const [templates, setTemplates] = useState<NucleiTemplates | null>(null);
  const [jobs, setJobs] = useState<NucleiJob[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [sessionId, setSessionId] = useState("");
  const [targetText, setTargetText] = useState("");
  const [severities, setSeverities] = useState<string[]>([]);
  const [tags, setTags] = useState<string[]>([]);
  const [rate, setRate] = useState("");
  const [approved, setApproved] = useState(false);
  const [ack, setAck] = useState(false);
  const [attachSession, setAttachSession] = useState(false);
  const [preview, setPreview] = useState<NucleiPreview | null>(null);
  const [starting, setStarting] = useState(false);

  const targets = useMemo(() => lines(targetText), [targetText]);

  const request = useCallback(
    (): NucleiRequest => ({
      targets,
      severities,
      tags,
      templates: [],
      rate_limit: Number.parseInt(rate, 10) || null,
      engagement_id: sessionId.trim() || null,
      session_id: sessionId.trim() || null,
      attach_session: attachSession,
      approved,
      dangerous_ack: ack,
    }),
    [targets, severities, tags, rate, sessionId, approved, ack, attachSession]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    getNucleiStatus(ctrl.signal).then(setStatus).catch(() => setStatus(null));
    getNucleiTemplates(ctrl.signal).then(setTemplates).catch(() => setTemplates(null));
    return () => ctrl.abort();
  }, []);

  const refreshJobs = useCallback(() => {
    listNucleiJobs(sessionId.trim() || undefined)
      .then(setJobs)
      .catch(() => setJobs([]));
  }, [sessionId]);

  // A running scan's findings grow, so this polls — `total` and `findings` come back each read.
  useEffect(() => {
    refreshJobs();
    const t = setInterval(refreshJobs, 2000);
    return () => clearInterval(t);
  }, [refreshJobs]);

  const toggle = (list: string[], set: (v: string[]) => void, v: string) =>
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  const doPreview = useCallback(() => {
    setError(null);
    nucleiPreview(request())
      .then(setPreview)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [request]);

  const run = useCallback(() => {
    if (starting) return;
    setStarting(true);
    setError(null);
    startNucleiScan(request())
      .then(() => refreshJobs())
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setStarting(false));
  }, [starting, request, refreshJobs]);

  const stop = useCallback(
    (id: string) => {
      stopNucleiJob(id)
        .then(() => refreshJobs())
        .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
    },
    [refreshJobs]
  );

  const gateLine = (gate: NucleiPreview["gate"]) =>
    gate ? (
      <p className="hp-tn-error">
        The gate would refuse this at <strong>{gate.gate}</strong>: {gate.reason}
        {gate.dangerous_flags.length > 0 ? ` — ${gate.dangerous_flags.join("; ")}` : ""}
      </p>
    ) : (
      <p className="hp-tn-note">
        Nothing stands in the way at the gates — with approval set, this would run.
      </p>
    );

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "nuclei" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">scoped target(s) · templates · findings · one approval</div>
          <h1 className="hp-tn-title">:nuclei</h1>
          <p className="hp-tn-sub">
            Point nuclei&rsquo;s template engine at the scoped target(s) and turn matches into
            engagement findings. It is <strong>one gated job</strong> — the same executor gates
            every command clears, no new ones, exactly like ffuf and the ZAP active scanner — with
            an ungated stop. Every match lands as a severity-ranked finding in{" "}
            <Link href="/cockpit">:cockpit</Link> state and the report.
          </p>
          {status && (
            <div className={`hp-tn-status ${status.up ? "is-up" : "is-down"}`}>
              <span className="hp-tn-dot" />
              {status.container}: {status.up ? "up" : "down"} · running {status.running}
              {templates?.count ? ` · ${templates.count} templates installed` : ""}
            </div>
          )}
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">the target set</div>
          <div className="hp-tn-cardsub">
            Paste target URLs or hosts (one per line, or comma-separated), or leave it blank and
            give a session id — the default set is that engagement&rsquo;s in-scope endpoints
            already in state. In engagement mode a target outside scope is refused at the target
            gate; the same inherited handrail every command gets.
          </div>
          <div className="hp-tn-form">
            <input
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              placeholder="session / engagement id (optional — seeds default targets)"
              aria-label="Session id"
              style={{ flex: "1 1 320px" }}
            />
            <input
              className="hp-tn-port"
              value={rate}
              onChange={(e) => setRate(e.target.value)}
              placeholder="rate/s"
              aria-label="Rate limit, requests per second"
            />
          </div>
          <label
            className="hp-tn-danger-why"
            style={{ display: "flex", gap: "0.4rem", alignItems: "center" }}
          >
            <input
              type="checkbox"
              checked={attachSession}
              onChange={(e) => setAttachSession(e.target.checked)}
            />
            attach session — scan as the logged-in operator (the engagement&rsquo;s stored session)
          </label>
          <div className="hp-tn-form">
            <textarea
              value={targetText}
              onChange={(e) => setTargetText(e.target.value)}
              rows={4}
              spellCheck={false}
              placeholder={"targets — one per line (blank = seed from state)\nhttp://juice-shop.local\nhttp://juice-shop.local/rest"}
              style={{ width: "100%", fontFamily: "var(--hp-mono, monospace)" }}
            />
          </div>
        </section>

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">filters</div>
          <div className="hp-tn-cardsub">
            Narrow the run by severity and template tag. Empty = every severity, every template —
            the full baked set. Filters shape the scan; they are not gates.
          </div>
          <div className="hp-tn-chips">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                type="button"
                className={`hp-tn-chip${severities.includes(s) ? " is-on" : ""}`}
                style={{ ["--sc" as string]: SEV_COLOR[s] } as CSSProperties}
                onClick={() => toggle(severities, setSeverities, s)}
              >
                {s}
              </button>
            ))}
          </div>
          {templates && templates.tags.length > 0 && (
            <div className="hp-tn-chips">
              {templates.tags.map((t) => (
                <button
                  key={t}
                  type="button"
                  className={`hp-tn-chip${tags.includes(t) ? " is-on" : ""}`}
                  onClick={() => toggle(tags, setTags, t)}
                >
                  {t}
                </button>
              ))}
            </div>
          )}
          <div className="hp-tn-form">
            <button type="button" onClick={doPreview} disabled={targets.length === 0 && !sessionId.trim()}>
              preview — the exact argv + what the gate says
            </button>
            <span className="hp-tn-olhint">
              {severities.length || "all"} severities · {tags.length || "all"} tags
            </span>
          </div>

          {preview && (
            <>
              <div className="hp-tn-olhint">
                the approved surface <CopyButton text={preview.argv.join(" ")} />
              </div>
              <pre className="hp-tn-oneliner">{preview.argv.join(" ") || "(nothing to run)"}</pre>
              {preview.targets.length > 0 && (
                <p className="hp-tn-olhint">
                  {preview.targets.length} target(s): {preview.targets.slice(0, 6).join(", ")}
                  {preview.targets.length > 6 ? " …" : ""}
                </p>
              )}
              {preview.warnings.map((w) => (
                <p key={w} className="hp-tn-error">
                  {w}
                </p>
              ))}
              {gateLine(preview.gate)}
            </>
          )}

          <div className="hp-tn-danger">
            <div className="hp-tn-danger-head">this sends real scan traffic to the target</div>
            <div className="hp-tn-danger-note">
              One approval buys the whole scan — thousands of template checks. Preview first: the
              gate&rsquo;s answer is shown above before anything runs.
            </div>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input type="checkbox" checked={approved} onChange={(e) => setApproved(e.target.checked)} />
              I approve this nuclei scan
            </label>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              I understand this scans a real target (red-confirm, when the gate asks)
            </label>
            <div className="hp-tn-danger-actions">
              <button
                type="button"
                className="hp-tn-danger-go"
                onClick={run}
                disabled={starting || !approved || (targets.length === 0 && !sessionId.trim())}
              >
                {starting ? "starting…" : "run the scan"}
              </button>
            </div>
          </div>
        </section>

        {jobs.length > 0 && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">results feed</div>
            <div className="hp-tn-cardsub">
              Findings land severity-ranked in <Link href="/cockpit">:cockpit</Link>{" "}
              state and the report. A running scan&rsquo;s count grows as templates match.
            </div>
            <ul className="hp-tn-list">
              {jobs.map((job) => (
                <li key={job.id} className={`hp-tn-row${job.refused ? " is-down" : ""}`}>
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">{job.mode || "scan"}</span>
                    <span className="hp-tn-subs" style={{ flex: "1 1 200px", wordBreak: "break-all" }}>
                      {job.targets[0] || job.id}
                      {job.targets.length > 1 ? ` +${job.targets.length - 1}` : ""}
                    </span>
                    <span className={`hp-tn-state ${job.state === "running" ? "is-listening" : "is-down"}`}>
                      {job.state}
                    </span>
                    <span className="hp-tn-olhint">
                      {job.total} finding(s) · +{job.new_findings} into state
                    </span>
                    {job.state === "running" && (
                      <button type="button" className="hp-tn-stop" onClick={() => stop(job.id)}>
                        stop — not gated
                      </button>
                    )}
                  </div>
                  {Object.keys(job.by_severity).length > 0 && (
                    <div className="hp-tn-chips">
                      {SEVERITIES.filter((s) => job.by_severity[s]).map((s) => (
                        <span
                          key={s}
                          className="hp-tn-chip is-on"
                          style={{ ["--sc" as string]: SEV_COLOR[s] } as CSSProperties}
                        >
                          {job.by_severity[s]} {s}
                        </span>
                      ))}
                    </div>
                  )}
                  {job.findings.length > 0 && (
                    <ul className="hp-tn-list">
                      {job.findings.slice(0, 40).map((f, i) => (
                        <li key={`${f.template_id}-${f.target}-${i}`} className="hp-tn-row">
                          <div className="hp-tn-rowtop">
                            <span
                              className="hp-tn-state is-starting"
                              style={{ ["--sc" as string]: SEV_COLOR[f.severity] } as CSSProperties}
                            >
                              {f.severity}
                            </span>
                            <span className="hp-tn-subs" style={{ flex: "1 1 260px", wordBreak: "break-all" }}>
                              {f.title}
                              <span className="hp-tn-olhint"> — {f.target}</span>
                            </span>
                            <span className="hp-tn-olhint">{f.template_id}</span>
                          </div>
                        </li>
                      ))}
                      {job.findings.length > 40 && (
                        <li className="hp-tn-olhint">
                          …and {job.findings.length - 40} more in :cockpit state
                        </li>
                      )}
                    </ul>
                  )}
                  {job.warnings.map((w) => (
                    <p key={w} className="hp-tn-olhint">
                      {w}
                    </p>
                  ))}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </PageShell>
  );
}
