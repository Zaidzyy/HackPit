"use client";

import { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import Link from "next/link";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  getReconStatus,
  getReconSurface,
  listReconJobs,
  reconPreview,
  startReconActive,
  startReconPassive,
  stopReconJob,
  type ReconJob,
  type ReconPreview,
  type ReconRequest,
  type ReconStatus,
  type ReconSurface,
  type RankedTarget,
} from "@/lib/api";

/**
 * :recon — the front door a bounty/pentest starts from.
 *
 * *** ONE APPROVAL BUYS A WHOLE SWEEP, SAID ON THE SCREEN AND NOT ONLY IN THE CODE. ***
 * Give it a scoped domain: a PASSIVE sweep (subfinder -> dnsx -> httpx -> gau/waybackurls/katana)
 * seeds in-scope hosts/endpoints into engagement state; an ACTIVE sweep (naabu -> nmap -sV) adds
 * services. Each sweep is ONE gated job — the same executor gates every command clears, no new
 * ones — with an ungated stop. Discovered hosts are sorted by the scope: in-scope join the live
 * set and are the only hosts the probing tools touch; out-of-scope are surfaced READ-ONLY and
 * never scanned. The ranked surface below is ADVISORY — it proposes an order and runs nothing.
 */

function scoreColor(score: number): string {
  if (score >= 90) return "#ff5c7a";
  if (score >= 50) return "#f0776a";
  if (score >= 20) return "#f0a24a";
  return "#8aa4c8";
}

export function ReconScreen() {
  const [status, setStatus] = useState<ReconStatus | null>(null);
  const [jobs, setJobs] = useState<ReconJob[]>([]);
  const [surface, setSurface] = useState<ReconSurface | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [sessionId, setSessionId] = useState("");
  const [domain, setDomain] = useState("");
  const [rate, setRate] = useState("");
  const [approved, setApproved] = useState(false);
  const [ack, setAck] = useState(false);
  const [preview, setPreview] = useState<ReconPreview | null>(null);
  const [starting, setStarting] = useState(false);

  const request = useCallback(
    (): ReconRequest => ({
      domain: domain.trim(),
      rate_limit: Number.parseInt(rate, 10) || null,
      engagement_id: sessionId.trim() || null,
      session_id: sessionId.trim() || null,
      approved,
      dangerous_ack: ack,
    }),
    [domain, rate, sessionId, approved, ack]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    getReconStatus(ctrl.signal).then(setStatus).catch(() => setStatus(null));
    return () => ctrl.abort();
  }, []);

  // Deep link: /recon?session=<id> prefills the id and auto-ranks its surface, so a handoff from
  // another surface (or a shared link) lands straight on the ranked view.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const sid = new URLSearchParams(window.location.search).get("session");
    if (!sid) return;
    setSessionId(sid);
    getReconSurface(sid).then(setSurface).catch(() => setSurface(null));
  }, []);

  const refreshJobs = useCallback(() => {
    listReconJobs(sessionId.trim() || undefined)
      .then(setJobs)
      .catch(() => setJobs([]));
  }, [sessionId]);

  // A running sweep's stages + counts grow, so this polls.
  useEffect(() => {
    refreshJobs();
    const t = setInterval(refreshJobs, 2000);
    return () => clearInterval(t);
  }, [refreshJobs]);

  const doPreview = useCallback(
    (kind: "passive" | "active") => {
      setError(null);
      reconPreview(request(), kind)
        .then(setPreview)
        .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
    },
    [request]
  );

  const run = useCallback(
    (kind: "passive" | "active") => {
      if (starting) return;
      setStarting(true);
      setError(null);
      const start = kind === "active" ? startReconActive : startReconPassive;
      start(request())
        .then(() => refreshJobs())
        .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
        .finally(() => setStarting(false));
    },
    [starting, request, refreshJobs]
  );

  const stop = useCallback(
    (id: string) => {
      stopReconJob(id)
        .then(() => refreshJobs())
        .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
    },
    [refreshJobs]
  );

  const loadSurface = useCallback(() => {
    const sid = sessionId.trim();
    if (!sid) return;
    setError(null);
    getReconSurface(sid)
      .then(setSurface)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [sessionId]);

  const gateLine = (gate: ReconPreview["gate"]) =>
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

  const canRun = useMemo(
    () => approved && (domain.trim() !== "" || sessionId.trim() !== ""),
    [approved, domain, sessionId]
  );

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "recon" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">scoped domain · recon as approved jobs · ranked surface</div>
          <h1 className="hp-tn-title">:recon</h1>
          <p className="hp-tn-sub">
            The front door a bounty/pentest starts from. Give it a scoped domain: a{" "}
            <strong>passive sweep</strong> (subfinder → dnsx → httpx → gau/waybackurls/katana) seeds
            in-scope hosts &amp; endpoints into <Link href="/cockpit">:cockpit</Link> state; an{" "}
            <strong>active sweep</strong> (naabu → nmap&nbsp;-sV) adds services. Each is{" "}
            <strong>one gated job</strong> — no new gate, just the executor&rsquo;s — with an ungated
            stop. Discovered hosts are sorted by scope; out-of-scope names are surfaced read-only and
            never scanned. Then it <strong>ranks the surface</strong> so you know what to hit first.
          </p>
          {status && (
            <div className={`hp-tn-status ${status.up ? "is-up" : "is-down"}`}>
              <span className="hp-tn-dot" />
              {status.container}: {status.up ? "up" : "down"} · running {status.running}
              {status.detail ? ` · ${status.detail}` : ""}
            </div>
          )}
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">the sweep</div>
          <div className="hp-tn-cardsub">
            Recon is engagement-bound — enter engagement mode first (its scope is what decides what
            may be scanned), then paste the engagement id and the in-scope domain. The passive sweep
            is bug-bounty safe and the default; the active sweep sends real scan traffic and is a
            second, explicit approval.
          </div>
          <div className="hp-tn-form">
            <input
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              placeholder="engagement / session id"
              aria-label="Engagement id"
              style={{ flex: "1 1 280px" }}
            />
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="in-scope domain (e.g. example.com — blank = the engagement target)"
              aria-label="Domain"
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
          <div className="hp-tn-form">
            <button type="button" onClick={() => doPreview("passive")}>
              preview passive — argv + what the gate says
            </button>
            <button type="button" onClick={() => doPreview("active")}>
              preview active
            </button>
          </div>

          {preview && (
            <>
              <div className="hp-tn-olhint">
                the approved entry command ({preview.kind}) <CopyButton text={preview.argv.join(" ")} />
              </div>
              <pre className="hp-tn-oneliner">{preview.argv.join(" ") || "(nothing to run)"}</pre>
              {preview.pipeline.length > 0 && (
                <p className="hp-tn-olhint">pipeline: {preview.pipeline.join(" → ")}</p>
              )}
              {gateLine(preview.gate)}
            </>
          )}

          <div className="hp-tn-danger">
            <div className="hp-tn-danger-head">a sweep runs recon tools against the scope</div>
            <div className="hp-tn-danger-note">
              One approval buys the whole sweep. The passive sweep queries CT logs, DNS and web
              archives and probes in-scope hosts; the active sweep port- and service-scans them.
              Preview first — the gate&rsquo;s answer is shown above before anything runs.
            </div>
            <label className="hp-tn-danger-why" style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}>
              <input type="checkbox" checked={approved} onChange={(e) => setApproved(e.target.checked)} />
              I approve this recon sweep
            </label>
            <label className="hp-tn-danger-why" style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}>
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              I understand the active sweep scans a real target (red-confirm, when the gate asks)
            </label>
            <div className="hp-tn-danger-actions">
              <button
                type="button"
                className="hp-tn-danger-go"
                onClick={() => run("passive")}
                disabled={starting || !canRun}
              >
                {starting ? "starting…" : "run passive sweep"}
              </button>
              <button
                type="button"
                className="hp-tn-danger-go"
                onClick={() => run("active")}
                disabled={starting || !canRun}
              >
                run active sweep
              </button>
            </div>
          </div>
        </section>

        {jobs.length > 0 && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">sweeps</div>
            <div className="hp-tn-cardsub">
              Each stage is one <code>docker exec</code> under the one approval. In-scope discoveries
              seed <Link href="/cockpit">:cockpit</Link> state; out-of-scope names are read-only.
            </div>
            <ul className="hp-tn-list">
              {jobs.map((job) => (
                <li key={job.id} className={`hp-tn-row${job.refused ? " is-down" : ""}`}>
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">{job.kind}</span>
                    <span className="hp-tn-subs" style={{ flex: "1 1 200px", wordBreak: "break-all" }}>
                      {job.domain || job.id}
                    </span>
                    <span className={`hp-tn-state ${job.state === "running" ? "is-listening" : "is-down"}`}>
                      {job.state}
                    </span>
                    <span className="hp-tn-olhint">
                      +{job.new_hosts} hosts · +{job.new_services} svc · +{job.new_endpoints} ep · +{job.new_findings} find
                    </span>
                    {job.state === "running" && (
                      <button type="button" className="hp-tn-stop" onClick={() => stop(job.id)}>
                        stop — not gated
                      </button>
                    )}
                  </div>
                  {job.stages.length > 0 && (
                    <div className="hp-tn-chips">
                      {job.stages.map((s, i) => (
                        <span key={`${s.tool}-${i}`} className={`hp-tn-chip${s.state === "ran" ? " is-on" : ""}`}>
                          {s.tool}
                          {s.state !== "ran" ? ` (${s.state})` : ""}
                        </span>
                      ))}
                    </div>
                  )}
                  {job.discovered_out_of_scope.length > 0 && (
                    <p className="hp-tn-olhint">
                      out of scope, read-only ({job.discovered_out_of_scope.length}):{" "}
                      {job.discovered_out_of_scope.slice(0, 8).join(", ")}
                      {job.discovered_out_of_scope.length > 8 ? " …" : ""}
                    </p>
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

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">ranked attack surface</div>
          <div className="hp-tn-cardsub">
            Advisory only — it scores the state a sweep seeded and proposes an order. It runs
            nothing. Each target hands off cleanly into <Link href="/attack-path">:attack-paths</Link>{" "}
            and <Link href="/nuclei">:nuclei</Link>.
          </div>
          <div className="hp-tn-form">
            <button type="button" onClick={loadSurface} disabled={!sessionId.trim()}>
              rank this engagement&rsquo;s surface
            </button>
            {surface && (
              <span className="hp-tn-olhint">
                {surface.counts.hosts || 0} hosts · {surface.counts.services || 0} services ·{" "}
                {surface.counts.endpoints || 0} endpoints · {surface.counts.findings || 0} findings
              </span>
            )}
          </div>
          {surface?.notes.map((n) => (
            <p key={n} className="hp-tn-olhint">
              {n}
            </p>
          ))}
          {surface && surface.targets.length > 0 && (
            <ul className="hp-tn-list">
              {surface.targets.map((t: RankedTarget, i) => (
                <li key={t.address} className="hp-tn-row">
                  <div className="hp-tn-rowtop">
                    <span
                      className="hp-tn-state is-starting"
                      style={{ ["--sc" as string]: scoreColor(t.score) } as CSSProperties}
                    >
                      #{i + 1} · {t.score}
                    </span>
                    <span className="hp-tn-subs" style={{ flex: "1 1 240px", wordBreak: "break-all" }}>
                      {t.address}
                      {t.hostname && t.hostname !== t.address ? (
                        <span className="hp-tn-olhint"> — {t.hostname}</span>
                      ) : null}
                    </span>
                    <span className="hp-tn-olhint">
                      {t.open_services} svc · {t.param_endpoints.length} param-ep · {t.findings} find
                    </span>
                  </div>
                  <div className="hp-tn-chips">
                    {t.reasons.map((r) => (
                      <span key={r} className="hp-tn-chip is-on">
                        {r}
                      </span>
                    ))}
                  </div>
                  {t.services.length > 0 && (
                    <p className="hp-tn-olhint">services: {t.services.join(" · ")}</p>
                  )}
                  {t.cve_stacks.length > 0 && (
                    <p className="hp-tn-olhint">cve-worthy: {t.cve_stacks.join(" · ")}</p>
                  )}
                  {t.nuclei_targets.length > 0 && (
                    <p className="hp-tn-olhint">
                      hand off {t.nuclei_targets.length} endpoint(s) to{" "}
                      <Link href="/nuclei">:nuclei</Link>{" "}
                      <CopyButton text={t.nuclei_targets.join("\n")} />{" · "}
                      compose a path in <Link href="/attack-path">:attack-paths</Link>
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </PageShell>
  );
}
