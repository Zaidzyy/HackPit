"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  getProxyStatus,
  listProxies,
  proxyHistory,
  startProxy,
  stopProxy,
  type CapturedExchange,
  type Proxy,
  type ProxyStatus,
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
    </PageShell>
  );
}
