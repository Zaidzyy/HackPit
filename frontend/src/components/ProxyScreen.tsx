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
      <h1>:proxy</h1>
      <p className="hp-note">
        Record what your tools send. ZAP runs inside the sandbox on 127.0.0.1 with no published
        port, so its API is unreachable from this machine — HackPit reads it through the same
        gated <code>docker exec</code> channel everything else uses.
      </p>
      {error ? <div className="hp-card hp-error">{error}</div> : null}

      {/* ---- status rail ---------------------------------------------------- */}
      <section className="hp-card">
        <h2>Sandboxes</h2>
        {status ? (
          <ul className="hp-kv">
            <li>
              <span>lab</span>
              <span>
                {status.lab_sandbox} — {status.lab_running ? "up" : "down"}
              </span>
            </li>
            <li>
              <span>engagement</span>
              <span>
                {status.engage_sandbox} — {status.engage_running ? "up" : "down"}
              </span>
            </li>
            <li>
              <span>live proxies</span>
              <span>{status.live}</span>
            </li>
          </ul>
        ) : (
          <p>Status unavailable — is the stack up?</p>
        )}
      </section>

      {/* ---- start / stop --------------------------------------------------- */}
      <section className="hp-card">
        <h2>{live ? "Running" : "Start the proxy"}</h2>

        {live ? (
          <>
            <ul className="hp-kv">
              <li>
                <span>container</span>
                <span>{live.container}</span>
              </li>
              <li>
                <span>port</span>
                <span>{live.port}</span>
              </li>
              <li>
                <span>status</span>
                {/* OBSERVED, never assumed from a successful POST. */}
                <span>{live.status}</span>
              </li>
              <li>
                <span>observed</span>
                <span>{live.liveness || "—"}</span>
              </li>
              <li>
                <span>captured</span>
                <span>{live.captured}</span>
              </li>
            </ul>
            <p className="hp-note">
              Point a tool at it by sending <code>proxy: true</code> with the run. A tool with no
              known proxy flag runs <strong>uncaptured</strong> and says so — it is never
              silently dropped.
            </p>
            <button type="button" onClick={() => stop(live.id)}>
              Stop the proxy
            </button>
          </>
        ) : (
          <>
            <label>
              Port
              <input
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder={String(status?.default_port ?? 8090)}
                inputMode="numeric"
              />
            </label>
            <label>
              Engagement id (leave blank for the isolated lab)
              <input
                value={engagementId}
                onChange={(e) => setEngagementId(e.target.value)}
                placeholder="lab"
              />
            </label>

            {/* TWO SEPARATE, NEVER PRE-TICKED CHECKBOXES. Both default false on the backend, so
                an omitted field is a refusal rather than a silent grant. */}
            <label className="hp-check">
              <input
                type="checkbox"
                checked={approved}
                onChange={(e) => setApproved(e.target.checked)}
              />
              I approve starting this proxy
            </label>
            <label className="hp-check hp-danger">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              I understand this records <strong>full request and response bodies</strong> —
              passwords, session tokens and payloads in cleartext
            </label>

            <button type="button" onClick={start} disabled={starting || !approved || !ack}>
              {starting ? "Starting…" : "Start the proxy"}
            </button>
          </>
        )}
      </section>

      {/* ---- history -------------------------------------------------------- */}
      <section className="hp-card">
        <h2>Captured traffic</h2>
        <button type="button" onClick={loadHistory} disabled={!live}>
          Refresh
        </button>
        {history.length === 0 ? (
          <p className="hp-note">
            Nothing captured yet. Run a tool with <code>proxy: true</code> while the proxy is up.
          </p>
        ) : (
          <table className="hp-table">
            <thead>
              <tr>
                <th>Method</th>
                <th>URL</th>
                <th>Status</th>
                <th>Size</th>
                <th>ms</th>
                <th>Aim</th>
              </tr>
            </thead>
            <tbody>
              {history.map((ex) => (
                <tr key={ex.id} onClick={() => setOpen(open === ex.id ? null : ex.id)}>
                  <td>{ex.request.method}</td>
                  <td className="hp-url">{ex.request.url}</td>
                  <td>{ex.response.status ?? "—"}</td>
                  <td>{ex.response.size_bytes}</td>
                  <td>{ex.response.time_ms}</td>
                  <td>
                    {/* Aims the scanner; it does NOT start one. The confirms below are still
                        required — a one-click path from a table row to live attack traffic is
                        exactly the shape a red-confirm exists to prevent. */}
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setScanTarget(ex.request.url);
                      }}
                    >
                      Aim scanner
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {open
          ? history
              .filter((ex) => ex.id === open)
              .map((ex) => (
                <div key={ex.id} className="hp-card">
                  <h3>
                    {ex.request.method} {ex.request.url}
                    <CopyButton text={ex.request.url} />
                  </h3>
                  <h4>Request headers</h4>
                  <pre>
                    {ex.request.headers.map((h) => `${h.name}: ${h.value}`).join("\n") || "—"}
                  </pre>
                  {ex.request.body ? (
                    <>
                      <h4>Request body</h4>
                      <pre>{ex.request.body}</pre>
                    </>
                  ) : null}
                  <h4>Response headers</h4>
                  <pre>
                    {ex.response.headers.map((h) => `${h.name}: ${h.value}`).join("\n") || "—"}
                  </pre>
                  {ex.response.body ? (
                    <>
                      <h4>Response body</h4>
                      <pre>{ex.response.body.slice(0, 4000)}</pre>
                    </>
                  ) : null}
                </div>
              ))
          : null}
      </section>

      {/* ---- the ACTIVE SCANNER (build #14 part 3) --------------------------- */}
      <section className="hp-card">
        <h2>Attack a captured endpoint</h2>
        <p className="hp-note">
          This sends <strong>real attack traffic</strong> — SQLi, XSS and command-injection
          payloads at every parameter. Measured: <strong>376 requests against one endpoint</strong>,
          which found a live SQL injection. ZAP will only attack a URL it has already seen, so aim
          it from the captured traffic above; a URL that never went through the proxy is refused.
        </p>

        <label>
          Target URL (must be in the captured traffic)
          <input
            value={scanTarget}
            onChange={(e) => setScanTarget(e.target.value)}
            placeholder="http://host:3000/rest/products/search?q=x"
          />
        </label>
        <label className="hp-check">
          <input
            type="checkbox"
            checked={recurse}
            onChange={(e) => setRecurse(e.target.checked)}
          />
          Also attack everything below this URL in the tree (same host — more traffic, not more
          reach)
        </label>

        {/* Separate from the proxy's own confirms, and never pre-ticked. Starting a recording
            proxy and launching an attack are different decisions. */}
        <label className="hp-check">
          <input
            type="checkbox"
            checked={scanApproved}
            onChange={(e) => setScanApproved(e.target.checked)}
          />
          I approve this scan
        </label>
        <label className="hp-check hp-danger">
          <input
            type="checkbox"
            checked={scanAck}
            onChange={(e) => setScanAck(e.target.checked)}
          />
          I understand this <strong>actively attacks</strong> the target and that I am authorised
          to do so
        </label>

        <button
          type="button"
          onClick={beginScan}
          disabled={scanning || !live || !scanTarget.trim() || !scanApproved || !scanAck}
        >
          {scanning ? "Starting…" : "Attack this endpoint"}
        </button>

        <h3>Scans</h3>
        <button type="button" onClick={loadScans} disabled={!live}>
          Refresh
        </button>
        {scans.length === 0 ? (
          <p className="hp-note">No scans yet.</p>
        ) : (
          <table className="hp-table">
            <thead>
              <tr>
                <th>id</th>
                <th>Target</th>
                <th>State</th>
                <th>Progress</th>
                {/* Attack requests actually SENT. The number that matters when deciding to stop. */}
                <th>Requests</th>
                <th>Alerts</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td>{s.id}</td>
                  <td className="hp-url">{s.target_url || "—"}</td>
                  <td>{s.state}</td>
                  <td>{s.progress}%</td>
                  <td>{s.requests}</td>
                  <td>{s.alerts}</td>
                  <td>
                    {/* Ungated on purpose — this is the panic button while requests are in
                        flight, so it must never be behind a confirm. */}
                    <button type="button" onClick={() => haltScan(s.id)}>
                      Stop
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* ---- alerts ---------------------------------------------------------- */}
      <section className="hp-card">
        <h2>Alerts</h2>
        <p className="hp-note">
          Everything ZAP is holding — including <strong>passive</strong> findings raised just by
          traffic passing through the proxy, with no scan involved.
        </p>
        <button type="button" onClick={loadAlerts} disabled={!live}>
          Refresh
        </button>

        {alerts.length === 0 ? (
          <p className="hp-note">No alerts.</p>
        ) : (
          <>
            <table className="hp-table">
              <thead>
                <tr>
                  <th>Risk</th>
                  <th>Name</th>
                  <th>URL</th>
                  <th>Param</th>
                  <th>Plugin</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={`${a.id}-${a.plugin_id}-${a.url}`}>
                    <td>{a.risk}</td>
                    <td>{a.name}</td>
                    <td className="hp-url">{a.url}</td>
                    <td>{a.param || "—"}</td>
                    <td>{a.plugin_id || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <label>
              Session id (to record these as findings in engagement state)
              <input
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
                placeholder="session id"
              />
            </label>
            <button type="button" onClick={ingest} disabled={!live || !sessionId.trim()}>
              Record as findings
            </button>
            {ingested ? <p className="hp-note">Recorded {ingested}.</p> : null}
          </>
        )}
      </section>
    </PageShell>
  );
}
