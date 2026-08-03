"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  getProxyStatus,
  ingestScanAlerts,
  listProxies,
  listScans,
  proxyHistory,
  scanAlerts,
  startProxy,
  startScan,
  stopProxy,
  stopScan,
  type CapturedExchange,
  type Proxy,
  type ProxyStatus,
  type Scan,
  type ScanAlert,
} from "@/lib/api";

/**
 * The recording proxy — ZAP inside a sandbox, capturing what your tools send.
 *
 * The flow: start the proxy (approval + red-confirm) → run a tool with `proxy: true` → its
 * requests and responses land here. The daemon binds 127.0.0.1 INSIDE the container and no port
 * is published, so its API is unreachable from this machine; HackPit reads it through
 * `docker exec`, which is the same gated channel everything else uses.
 *
 * Bodies are shown RAW on purpose. This is your own engagement traffic, and the request that
 * matters is usually the one carrying the token. Redaction applies when a REPORT is rendered.
 *
 * BUILD #14 PART 3 ADDED THE SECOND HALF: the scan panel. Everything above it records;
 * `Attack this endpoint` is the ONE control on this page that sends attack traffic, and it is
 * the only one with a red-confirm. The aim comes from the captured traffic table — that is the
 * whole point of the feature, since ZAP itself refuses to scan a URL it has never seen.
 */
export function ProxyScreen() {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [proxies, setProxies] = useState<Proxy[]>([]);
  const [history, setHistory] = useState<CapturedExchange[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  // start form
  const [port, setPort] = useState("");
  const [engagementId, setEngagementId] = useState("");
  const [approved, setApproved] = useState(false);
  const [ack, setAck] = useState(false);
  const [starting, setStarting] = useState(false);

  // scan form + results (build #14 part 3)
  const [scans, setScans] = useState<Scan[]>([]);
  const [alerts, setAlerts] = useState<ScanAlert[]>([]);
  const [scanTarget, setScanTarget] = useState("");
  const [recurse, setRecurse] = useState(false);
  const [scanApproved, setScanApproved] = useState(false);
  const [scanAck, setScanAck] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [sessionId, setSessionId] = useState("");
  const [ingested, setIngested] = useState<string | null>(null);

  const refresh = useCallback(() => {
    getProxyStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
    listProxies()
      .then(setProxies)
      .catch(() => setProxies([]));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const live = proxies.find((p) => p.status !== "down") ?? null;

  const loadHistory = useCallback(() => {
    if (!live) return;
    proxyHistory(live.container, live.port)
      .then(setHistory)
      .catch(() => setHistory([]));
  }, [live]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const start = useCallback(async () => {
    if (starting) return;
    setStarting(true);
    setError(null);
    try {
      await startProxy({
        port: port.trim() ? Number(port) : undefined,
        engagement_id: engagementId.trim() || null,
        approved,
        dangerous_ack: ack,
      });
      refresh();
    } catch (e) {
      // The gate's own words, not a generic banner: the operator needs to know WHICH gate
      // refused and why, the same discipline the tunnels screen follows.
      const detail = e instanceof ApiError ? e.message : String(e);
      setError(detail);
    } finally {
      setStarting(false);
    }
  }, [starting, port, engagementId, approved, ack, refresh]);

  const stop = useCallback(
    async (pid: string) => {
      setError(null);
      try {
        await stopProxy(pid);
        refresh();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
      }
    },
    [refresh]
  );

  /* ---- the scanner (build #14 part 3) --------------------------------------- */
  const loadScans = useCallback(() => {
    if (!live) return;
    listScans(live.container, live.port)
      .then(setScans)
      .catch(() => setScans([]));
  }, [live]);

  const loadAlerts = useCallback(() => {
    if (!live) return;
    scanAlerts(live.container, live.port)
      .then(setAlerts)
      .catch(() => setAlerts([]));
  }, [live]);

  // Poll while a scan is in flight. Counts are OBSERVED from ZAP on every tick — `requests` is
  // real attack traffic already sent, which is exactly the number an operator wants moving in
  // front of them while deciding whether to hit stop.
  const anyRunning = scans.some((s) => s.progress < 100 && /RUNNING|PAUSED/i.test(s.state));
  useEffect(() => {
    if (!live || !anyRunning) return;
    const t = setInterval(() => {
      loadScans();
      loadAlerts();
    }, 3000);
    return () => clearInterval(t);
  }, [live, anyRunning, loadScans, loadAlerts]);

  const beginScan = useCallback(async () => {
    if (scanning) return;
    setScanning(true);
    setError(null);
    try {
      await startScan({
        target_url: scanTarget.trim(),
        port: live?.port,
        recurse,
        engagement_id: engagementId.trim() || null,
        approved: scanApproved,
        dangerous_ack: scanAck,
      });
      // Do NOT clear the confirms on success. They are per-scan, and re-ticking them for the
      // next one is the point — a checkbox that stays ticked is a confirm nobody reads.
      setScanApproved(false);
      setScanAck(false);
      loadScans();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setScanning(false);
    }
  }, [scanning, scanTarget, live, recurse, engagementId, scanApproved, scanAck, loadScans]);

  const haltScan = useCallback(
    async (scanId: string) => {
      if (!live) return;
      setError(null);
      try {
        await stopScan(scanId, live.container, live.port);
        loadScans();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
      }
    },
    [live, loadScans]
  );

  const ingest = useCallback(async () => {
    if (!live || !sessionId.trim()) return;
    setError(null);
    try {
      const counts = await ingestScanAlerts({
        session_id: sessionId.trim(),
        container: live.container,
        port: live.port,
      });
      setIngested(
        `${counts.findings} finding(s) and ${counts.endpoints} endpoint(s) from ${counts.alerts} alert(s)`
      );
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [live, sessionId]);


  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "proxy" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">record · replay · actively scan what you touched</div>
          <h1 className="hp-tn-title">:proxy</h1>
          <p className="hp-tn-sub">
            Record what your tools send, then attack exactly that. ZAP runs inside the sandbox on
            127.0.0.1 with no published port, so its API is unreachable from this machine —
            HackPit reads it through the same gated <code>docker exec</code> channel everything
            else uses.
          </p>
          {status && (
            <div className={`hp-tn-status ${status.live > 0 ? "is-up" : "is-down"}`}>
              <span className="hp-tn-dot" />
              lab {status.lab_sandbox}: {status.lab_running ? "up" : "down"} · engagement{" "}
              {status.engage_sandbox}: {status.engage_running ? "up" : "down"} · live{" "}
              {status.live}
            </div>
          )}
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        {/* ---- start / stop --------------------------------------------------- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">{live ? "running" : "start the recording proxy"}</div>

          {live ? (
            <>
              <ul className="hp-tn-list">
                <li className={`hp-tn-row ${live.status === "down" ? "is-down" : ""}`}>
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">{live.container}</span>
                    <span className="hp-tn-subs">:{live.port}</span>
                    {/* OBSERVED after the settle window, never assumed from a successful POST. */}
                    <span className={`hp-tn-state is-${live.status}`}>{live.status}</span>
                    <span className="hp-tn-olhint">{live.captured} captured</span>
                    <button type="button" className="hp-tn-stop" onClick={() => stop(live.id)}>
                      stop
                    </button>
                  </div>
                  <div className="hp-tn-note">{live.liveness || "—"}</div>
                </li>
              </ul>
              <p className="hp-tn-note">
                Point a tool at it by sending <code>proxy: true</code> with the run. A tool with
                no known proxy flag runs <strong>uncaptured</strong> and says so — it is never
                silently dropped.
              </p>
            </>
          ) : (
            <>
              <div className="hp-tn-form">
                <input
                  className="hp-tn-port"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  placeholder={String(status?.default_port ?? 8090)}
                  inputMode="numeric"
                  aria-label="Proxy port"
                />
                <input
                  value={engagementId}
                  onChange={(e) => setEngagementId(e.target.value)}
                  placeholder="engagement id — blank for the isolated lab"
                  aria-label="Engagement id"
                />
              </div>

              {/* TWO SEPARATE, NEVER PRE-TICKED CHECKBOXES. Both default false on the backend, so
                  an omitted field is a refusal rather than a silent grant. */}
              <div className="hp-tn-check">
                <label className="hp-tn-olhint" style={{ display: "flex", gap: "0.4rem" }}>
                  <input
                    type="checkbox"
                    checked={approved}
                    onChange={(e) => setApproved(e.target.checked)}
                  />
                  I approve starting this proxy
                </label>
              </div>
              <div className="hp-tn-danger">
                <div className="hp-tn-danger-head">it records credentials in cleartext</div>
                <label
                  className="hp-tn-danger-why"
                  style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
                >
                  <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                  I understand this records <strong>full request and response bodies</strong> —
                  passwords, session tokens and payloads in cleartext
                </label>
                <div className="hp-tn-danger-actions">
                  <button
                    type="button"
                    className="hp-tn-danger-go"
                    onClick={start}
                    disabled={starting || !approved || !ack}
                  >
                    {starting ? "starting…" : "start the proxy"}
                  </button>
                </div>
              </div>
            </>
          )}
        </section>

        {/* ---- history -------------------------------------------------------- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">captured traffic</div>
          <div className="hp-tn-form">
            <button type="button" onClick={loadHistory} disabled={!live}>
              refresh
            </button>
          </div>
          {history.length === 0 ? (
            <p className="hp-tn-note">
              Nothing captured yet. Run a tool with <code>proxy: true</code> while the proxy is up.
            </p>
          ) : (
            <ul className="hp-tn-list">
              {history.map((ex) => (
                <li key={ex.id} className="hp-tn-row">
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">{ex.request.method}</span>
                    <span
                      className="hp-tn-subs"
                      style={{ flex: "1 1 320px", wordBreak: "break-all" }}
                    >
                      {ex.request.url}
                    </span>
                    <span className="hp-tn-state is-listening">{ex.response.status ?? "—"}</span>
                    <span className="hp-tn-olhint">
                      {ex.response.size_bytes}b · {ex.response.time_ms}ms
                    </span>
                    {/* Aims the scanner; it does NOT start one. The confirms below are still
                        required — a one-click path from a row to live attack traffic is exactly
                        the shape a red-confirm exists to prevent. */}
                    <button type="button" onClick={() => setScanTarget(ex.request.url)}>
                      aim scanner
                    </button>
                    <button type="button" onClick={() => setOpen(open === ex.id ? null : ex.id)}>
                      {open === ex.id ? "hide" : "detail"}
                    </button>
                  </div>

                  {open === ex.id ? (
                    <div className="hp-tn-oneliner">
                      <div className="hp-tn-olhint">
                        request <CopyButton text={ex.request.url} />
                      </div>
                      <pre>
                        {ex.request.headers.map((h) => `${h.name}: ${h.value}`).join("\n") || "—"}
                      </pre>
                      {ex.request.body ? <pre>{ex.request.body}</pre> : null}
                      <div className="hp-tn-olhint">response</div>
                      <pre>
                        {ex.response.headers.map((h) => `${h.name}: ${h.value}`).join("\n") || "—"}
                      </pre>
                      {ex.response.body ? <pre>{ex.response.body.slice(0, 4000)}</pre> : null}
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* ---- the ACTIVE SCANNER (build #14 part 3) --------------------------- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">attack a captured endpoint</div>
          <div className="hp-tn-cardsub">
            ZAP only attacks a URL it has already seen, so aim it from the captured traffic above
            — a URL that never went through the proxy is refused.
          </div>

          <div className="hp-tn-form">
            <input
              value={scanTarget}
              onChange={(e) => setScanTarget(e.target.value)}
              placeholder="http://host:3000/rest/products/search?q=x"
              aria-label="Scan target URL"
            />
          </div>
          <div className="hp-tn-check">
            <label className="hp-tn-olhint" style={{ display: "flex", gap: "0.4rem" }}>
              <input
                type="checkbox"
                checked={recurse}
                onChange={(e) => setRecurse(e.target.checked)}
              />
              also attack everything below this URL (same host — more traffic, not more reach)
            </label>
          </div>

          {/* Separate from the proxy's own confirms, and never pre-ticked. Starting a recording
              proxy and launching an attack are different decisions. */}
          <div className="hp-tn-check">
            <label className="hp-tn-olhint" style={{ display: "flex", gap: "0.4rem" }}>
              <input
                type="checkbox"
                checked={scanApproved}
                onChange={(e) => setScanApproved(e.target.checked)}
              />
              I approve this scan
            </label>
          </div>
          <div className="hp-tn-danger">
            <div className="hp-tn-danger-head">this sends real attack traffic</div>
            <div className="hp-tn-danger-note">
              SQLi, XSS and command-injection payloads at every parameter. Measured:{" "}
              <strong>376 requests against one endpoint</strong>, which found a live SQL injection.
            </div>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input
                type="checkbox"
                checked={scanAck}
                onChange={(e) => setScanAck(e.target.checked)}
              />
              I understand this <strong>actively attacks</strong> the target and that I am
              authorised to do so
            </label>
            <div className="hp-tn-danger-actions">
              <button
                type="button"
                className="hp-tn-danger-go"
                onClick={beginScan}
                disabled={scanning || !live || !scanTarget.trim() || !scanApproved || !scanAck}
              >
                {scanning ? "starting…" : "attack this endpoint"}
              </button>
            </div>
          </div>

          <div className="hp-tn-oneliner">
            <div className="hp-tn-olhint">scans</div>
            <div className="hp-tn-form">
              <button type="button" onClick={loadScans} disabled={!live}>
                refresh
              </button>
            </div>
            {scans.length === 0 ? (
              <p className="hp-tn-note">No scans yet.</p>
            ) : (
              <ul className="hp-tn-list">
                {scans.map((s) => (
                  <li key={s.id} className="hp-tn-row">
                    <div className="hp-tn-rowtop">
                      <span className="hp-tn-kind">scan {s.id}</span>
                      <span
                        className="hp-tn-subs"
                        style={{ flex: "1 1 280px", wordBreak: "break-all" }}
                      >
                        {s.target_url || "—"}
                      </span>
                      <span
                        className={`hp-tn-state ${
                          /RUNNING|PAUSED/i.test(s.state) ? "is-starting" : "is-down"
                        }`}
                      >
                        {s.state} {s.progress}%
                      </span>
                      {/* Attack requests actually SENT — the number that matters when deciding
                          whether to hit stop. */}
                      <span className="hp-tn-olhint">
                        {s.requests} requests · {s.alerts} alerts
                      </span>
                      {/* Ungated on purpose — the panic button must never sit behind a confirm. */}
                      <button type="button" className="hp-tn-stop" onClick={() => haltScan(s.id)}>
                        stop
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        {/* ---- alerts ---------------------------------------------------------- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">alerts</div>
          <div className="hp-tn-cardsub">
            Everything ZAP is holding — including <strong>passive</strong> findings raised just by
            traffic passing through the proxy, with no scan involved.
          </div>
          <div className="hp-tn-form">
            <button type="button" onClick={loadAlerts} disabled={!live}>
              refresh
            </button>
          </div>

          {alerts.length === 0 ? (
            <p className="hp-tn-note">No alerts.</p>
          ) : (
            <>
              <ul className="hp-tn-list">
                {alerts.map((a) => (
                  <li key={`${a.id}-${a.plugin_id}-${a.url}`} className="hp-tn-row">
                    <div className="hp-tn-rowtop">
                      <span
                        className={`hp-tn-state ${
                          /high|critical/i.test(a.risk) ? "is-starting" : "is-down"
                        }`}
                      >
                        {a.risk}
                      </span>
                      <span className="hp-tn-kind">{a.name}</span>
                      <span className="hp-tn-olhint">
                        {a.param ? `param ${a.param} · ` : ""}plugin {a.plugin_id || "—"}
                      </span>
                    </div>
                    <div className="hp-tn-subs" style={{ wordBreak: "break-all" }}>
                      {a.url}
                    </div>
                  </li>
                ))}
              </ul>

              <div className="hp-tn-form">
                <input
                  value={sessionId}
                  onChange={(e) => setSessionId(e.target.value)}
                  placeholder="session id — to record these as findings"
                  aria-label="Session id"
                />
                <button type="button" onClick={ingest} disabled={!live || !sessionId.trim()}>
                  record as findings
                </button>
              </div>
              {ingested ? <p className="hp-tn-note">Recorded {ingested}.</p> : null}
            </>
          )}
        </section>
      </div>
    </PageShell>
  );
}
