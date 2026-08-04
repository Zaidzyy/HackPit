"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  clearAuthContexts,
  deleteBypassHeader,
  getAuthContext,
  getProxyStatus,
  ingestScanAlerts,
  listProxies,
  listScanPolicies,
  listScans,
  proxyHistory,
  scanAlerts,
  setAuthContext,
  setBypassHeader,
  spiderStatus,
  startProxy,
  startScan,
  startSpider,
  stopProxy,
  stopScan,
  stopSpider,
  syncBypassHeaders,
  type AuthContext,
  type CapturedExchange,
  type HistoryPage,
  type Proxy,
  type ProxyStatus,
  type Scan,
  type ScanAlert,
  type ScanPolicy,
  type Spider,
} from "@/lib/api";

/**
 * The recording proxy — ZAP inside a sandbox, capturing what your tools send.
 *
 * The flow: start the proxy (approval + red-confirm) → run a tool with `proxy: true` → its
 * requests and responses land here. By default the daemon binds 127.0.0.1 INSIDE the container
 * and no port exists, so its API is unreachable from this machine; HackPit reads it through
 * `docker exec`, the same gated channel everything else uses.
 *
 * Bodies are shown RAW on purpose. This is your own engagement traffic, and the request that
 * matters is usually the one carrying the token. Redaction applies when a REPORT is rendered.
 *
 * THIS PAGE NOW CARRIES THREE CONTROLS THAT DO DIFFERENT THINGS, AND EACH SAYS WHICH:
 *
 *   publish (#15 part 1)   binds the daemon wide inside its container so a published host port
 *                          can reach it — the point being that a REAL BROWSER gets through
 *                          where a bare HTTP client is refused outright. It publishes nothing
 *                          on its own; :exposure opens the host port, and the API stays
 *                          key-protected so what a port exposes is the proxy, not scan control.
 *   crawl   (#15 part 2)   drives Chromium around the site through this same ZAP, inheriting
 *                          the session you logged in with by hand. Sends NO payloads.
 *   attack  (#14 part 3)   the active scanner. THE one control here that sends attack traffic.
 *
 * The last two both carry a red-confirm and the copy is deliberately different, because they
 * are dangerous for different reasons: one clicks buttons, the other sends injection payloads.
 * A confirm whose stated reason is false is what teaches an operator the text is noise.
 */
export function ProxyScreen() {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [proxies, setProxies] = useState<Proxy[]>([]);
  // THE WHOLE PAGE, not just the rows. A message the backend's parser could not read used to
  // vanish from the array with nothing saying it existed, so 200 exchanges of which 50 were
  // unparseable arrived as 150 and read as less traffic. `dropped` and `read_ok` are why this
  // holds an object.
  const [historyPage, setHistoryPage] = useState<HistoryPage | null>(null);
  const history: CapturedExchange[] = historyPage?.exchanges ?? [];
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  // start form
  const [port, setPort] = useState("");
  const [engagementId, setEngagementId] = useState("");
  const [approved, setApproved] = useState(false);
  const [ack, setAck] = useState(false);
  const [starting, setStarting] = useState(false);
  const [publish, setPublish] = useState(false);

  // the browser-driven crawl (build #15 part 2)
  const [spider, setSpider] = useState<Spider | null>(null);
  const [crawlTarget, setCrawlTarget] = useState("");
  const [crawlDepth, setCrawlDepth] = useState("5");
  const [crawlMinutes, setCrawlMinutes] = useState("10");
  const [crawlApproved, setCrawlApproved] = useState(false);
  const [crawlAck, setCrawlAck] = useState(false);
  const [crawling, setCrawling] = useState(false);

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
  const [scanPolicy, setScanPolicy] = useState("targeted-web");
  const [policies, setPolicies] = useState<ScanPolicy[]>([]);

  // the WAF-bypass header (build #18 item 1). THE VALUE IS WRITE-ONLY: it is typed here, POSTed
  // once, and cleared from this component's state immediately. No route returns it, so there is
  // nothing to read back — what comes back is the NAME and what ZAP holds.
  const [headerName, setHeaderName] = useState("");
  const [headerValue, setHeaderValue] = useState("");
  const [headerNames, setHeaderNames] = useState<string[]>([]);
  const [headerBusy, setHeaderBusy] = useState(false);
  const [headerNote, setHeaderNote] = useState<string | null>(null);

  // the authenticated context (build #18 items 6 and 7)
  const [ctxTarget, setCtxTarget] = useState("");
  const [loggedIn, setLoggedIn] = useState("");
  const [loggedOut, setLoggedOut] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [loginBody, setLoginBody] = useState("");
  const [credSession, setCredSession] = useState("");
  const [credPrincipal, setCredPrincipal] = useState("");
  const [authCtx, setAuthCtx] = useState<AuthContext | null>(null);
  const [ctxBusy, setCtxBusy] = useState(false);

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
      .then(setHistoryPage)
      // `null`, NOT an empty page. A failed fetch and a daemon that captured nothing are
      // different facts, and the panel below says which — the whole reason this route stopped
      // answering with a bare list.
      .catch(() => setHistoryPage(null));
  }, [live]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  useEffect(() => {
    listScanPolicies()
      .then(setPolicies)
      .catch(() => setPolicies([]));
  }, []);

  const saveBypassHeader = useCallback(async () => {
    const engagement = live?.engagement_id ?? engagementId.trim();
    if (!engagement || !headerName.trim() || !headerValue.trim() || headerBusy) return;
    setHeaderBusy(true);
    setHeaderNote(null);
    try {
      const stored = await setBypassHeader({
        engagement_id: engagement,
        name: headerName.trim(),
        value: headerValue,
      });
      // CLEARED THE MOMENT IT IS SENT. Leaving it in a React state field would keep a credential
      // in the tab's memory for the rest of the session for no benefit — nothing reads it back.
      setHeaderValue("");
      setHeaderName("");
      setHeaderNames(stored.bypass_header_names);
      if (live) {
        const held = await syncBypassHeaders(live.container, live.port, engagement);
        setHeaderNames(held.installed);
        setHeaderNote(
          held.installed.length
            ? `ZAP holds: ${held.installed.join(", ")} (read back from its replacer rules)`
            : "stored, but ZAP reports holding NO rule — the install did not take"
        );
      } else {
        setHeaderNote("stored. It installs when you start a proxy under this engagement.");
      }
    } catch (e) {
      // ApiError already carries the gate + reason in its message (see errorMessage in api.ts).
      setHeaderNote(e instanceof ApiError ? e.message : String(e));
    } finally {
      setHeaderBusy(false);
    }
  }, [live, engagementId, headerName, headerValue, headerBusy]);

  const dropBypassHeader = useCallback(
    async (name: string) => {
      const engagement = live?.engagement_id ?? engagementId.trim();
      if (!engagement) return;
      setHeaderBusy(true);
      try {
        const left = await deleteBypassHeader(engagement, name);
        setHeaderNames(left.bypass_header_names);
        if (live) await syncBypassHeaders(live.container, live.port, engagement);
        setHeaderNote(`removed ${name}`);
      } catch (e) {
        setHeaderNote(String(e));
      } finally {
        setHeaderBusy(false);
      }
    },
    [live, engagementId]
  );

  const applyAuthContext = useCallback(async () => {
    if (!ctxTarget.trim() || ctxBusy) return;
    setCtxBusy(true);
    try {
      const held = await setAuthContext({
        target_url: ctxTarget.trim(),
        port: live?.port,
        engagement_id: live?.engagement_id ?? engagementId.trim() ?? null,
        logged_in_regex: loggedIn,
        logged_out_regex: loggedOut,
        login_url: loginUrl,
        login_body: loginBody,
        credential:
          loginUrl.trim() && credSession.trim() && credPrincipal.trim()
            ? {
                session_id: credSession.trim(),
                kind: "password",
                principal: credPrincipal.trim(),
              }
            : null,
      });
      setAuthCtx(held);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setCtxBusy(false);
    }
  }, [
    ctxTarget, ctxBusy, live, engagementId, loggedIn, loggedOut,
    loginUrl, loginBody, credSession, credPrincipal,
  ]);

  const readAuthContext = useCallback(async () => {
    if (!live || !ctxTarget.trim()) return;
    try {
      setAuthCtx(await getAuthContext(live.container, live.port, ctxTarget.trim()));
    } catch {
      setAuthCtx(null);
    }
  }, [live, ctxTarget]);

  const dropAuthContexts = useCallback(async () => {
    if (!live) return;
    await clearAuthContexts(live.container, live.port).catch(() => undefined);
    setAuthCtx(null);
  }, [live]);

  const start = useCallback(async () => {
    if (starting) return;
    setStarting(true);
    setError(null);
    try {
      await startProxy({
        port: port.trim() ? Number(port) : undefined,
        engagement_id: engagementId.trim() || null,
        publish,
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
  }, [starting, port, engagementId, publish, approved, ack, refresh]);

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
        scan_policy: scanPolicy,
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
  }, [
    scanning, scanTarget, live, recurse, scanPolicy, engagementId,
    scanApproved, scanAck, loadScans,
  ]);

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

  /* ---- the browser-driven crawl (build #15 part 2) -------------------------- */
  const loadSpider = useCallback(() => {
    if (!live) return;
    spiderStatus(live.container, live.port)
      .then(setSpider)
      .catch(() => setSpider(null));
  }, [live]);

  // Poll while a crawl is running. `captured` climbing is the evidence a browser really ran —
  // ZAP's setOptionBrowserId answers OK for browsers it cannot launch, so a rising count is
  // worth more than any success response.
  const crawlRunning = (spider?.state ?? "").toLowerCase() === "running";
  useEffect(() => {
    if (!live || !crawlRunning) return;
    const t = setInterval(loadSpider, 3000);
    return () => clearInterval(t);
  }, [live, crawlRunning, loadSpider]);

  const beginCrawl = useCallback(async () => {
    if (crawling) return;
    setCrawling(true);
    setError(null);
    try {
      const started = await startSpider({
        target_url: crawlTarget.trim(),
        port: live?.port,
        max_depth: Number(crawlDepth) || undefined,
        max_duration_minutes: Number(crawlMinutes) || undefined,
        engagement_id: engagementId.trim() || null,
        approved: crawlApproved,
        dangerous_ack: crawlAck,
      });
      setSpider(started);
      // Per-crawl confirms, cleared on success so the next one has to be ticked again. A
      // checkbox that stays ticked is a confirm nobody reads.
      setCrawlApproved(false);
      setCrawlAck(false);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setCrawling(false);
    }
  }, [
    crawling, crawlTarget, live, crawlDepth, crawlMinutes, engagementId,
    crawlApproved, crawlAck,
  ]);

  const haltCrawl = useCallback(async () => {
    if (!live) return;
    setError(null);
    try {
      setSpider(await stopSpider(live.container, live.port));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [live]);

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
          <div className="hp-ap-kicker">record · crawl with a browser · attack what you touched</div>
          <h1 className="hp-tn-title">:proxy</h1>
          <p className="hp-tn-sub">
            Record what your tools send, crawl the rest with a real browser, then attack exactly
            that. ZAP runs inside the sandbox; by default it binds 127.0.0.1 with no published
            port and HackPit reads it through the gated <code>docker exec</code> channel. Publish
            it and a browser on this machine can use it too — the API still refuses anyone
            without a key, so what a published port exposes is the proxy, not scan control.
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
              {live.published ? (
                <p className="hp-tn-note">
                  Bound <code>{live.bind_host}</code> inside <code>{live.container}</code>, so a
                  published host port can reach it.{" "}
                  <strong>Publishing the host port is a separate step</strong> — write and apply
                  the <code>zap-proxy</code> profile on <a href="/exposure">:exposure</a>, then
                  point your browser at that address. The API stays key-protected; what a
                  published port exposes is the <em>proxy</em>, not scan control.
                </p>
              ) : (
                <p className="hp-tn-note">
                  Bound <code>{live.bind_host}</code> inside the container — reachable only
                  through <code>docker exec</code>. A browser on this machine cannot use it;
                  restart with <em>publish</em> ticked if that is what you want.
                </p>
              )}
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
                  onChange={(e) => {
                    setEngagementId(e.target.value);
                    // Clearing the engagement makes `publish` meaningless — the lab network has
                    // no route for a published port and the backend refuses it. Dropping the
                    // tick avoids a checked-but-disabled control the operator cannot untick.
                    if (!e.target.value.trim()) setPublish(false);
                  }}
                  placeholder="engagement id — blank for the isolated lab"
                  aria-label="Engagement id"
                />
              </div>

              {/* PUBLISH. Not a gate field — it changes what the daemon binds INSIDE its
                  container, which is what a published host port needs in order to reach
                  anything. Engagement-only: the lab network has no gateway, so a published port
                  there has no route and the backend refuses it. */}
              <div className="hp-tn-check">
                <label className="hp-tn-olhint" style={{ display: "flex", gap: "0.4rem" }}>
                  <input
                    type="checkbox"
                    checked={publish}
                    onChange={(e) => setPublish(e.target.checked)}
                    disabled={!engagementId.trim()}
                  />
                  let a browser on this machine use it (needs an engagement)
                </label>
              </div>
              {publish ? (
                <p className="hp-tn-note">
                  This binds the daemon wide <em>inside its container</em>. It publishes nothing
                  by itself — apply the <code>zap-proxy</code> profile on{" "}
                  <a href="/exposure">:exposure</a> to open the host port. Do that and a real
                  browser gets through where a bare HTTP client is refused outright.
                </p>
              ) : null}

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
          {historyPage ? (
            <div className="hp-tn-cardsub">
              showing {historyPage.returned} of {historyPage.total} captured
              {historyPage.window_start > 0
                ? ` (window starts at ${historyPage.window_start})`
                : ""}
              {historyPage.dropped > 0 ? (
                <>
                  {" — "}
                  <strong>
                    {historyPage.dropped} row{historyPage.dropped === 1 ? "" : "s"} could not be
                    parsed and are missing from this list
                  </strong>
                  . The traffic happened; it is the reading of it that failed, so a shorter list
                  here is not less traffic.
                </>
              ) : null}
            </div>
          ) : null}
          <div className="hp-tn-form">
            <button type="button" onClick={loadHistory} disabled={!live}>
              refresh
            </button>
          </div>
          {historyPage && !historyPage.read_ok ? (
            <p className="hp-tn-error">
              The ZAP API did not answer, so this is <strong>&ldquo;we could not read it&rdquo;</strong>{" "}
              and not &ldquo;nothing was captured&rdquo;. A backend restart loses the API key; the
              reader recovers it from the daemon&rsquo;s own argv, so an unreadable daemon usually
              means it is gone.
            </p>
          ) : null}
          {history.length === 0 ? (
            <p className="hp-tn-note">
              {historyPage
                ? "Nothing captured yet. Run a tool with proxy: true while the proxy is up."
                : "No history read yet — start a proxy, then press refresh."}
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

        {/* ---- the WAF-BYPASS HEADER (build #18 item 1) ------------------------ */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">WAF bypass header</div>
          <div className="hp-tn-cardsub">
            Programs that invite testing and then buy an edge that refuses it issue researchers a
            header that skips the WAF. Measured on a live target:{" "}
            <strong>36 of 39 scanner requests came back 403 AkamaiGHost</strong> — those payloads
            never reached the application, so the zero findings were not evidence about the
            application at all. Set here, it is injected on{" "}
            <strong>every request that leaves through this proxy</strong>: your browser, the
            crawl, and the scanner alike.
          </div>
          <div className="hp-tn-cardsub">
            The value is a <strong>credential and is write-only</strong>. It is sent once, cleared
            from this page immediately, and no endpoint returns it — what comes back is the name
            and what ZAP reports holding. It is removed when the proxy stops and when the
            engagement exits, because ZAP persists its configuration and a rule left behind would
            keep sending your credential to whatever the next engagement points this proxy at.
          </div>

          <div className="hp-tn-form">
            <input
              value={headerName}
              onChange={(e) => setHeaderName(e.target.value)}
              placeholder="X-Bug-Bounty"
              aria-label="Bypass header name"
            />
            <input
              type="password"
              value={headerValue}
              onChange={(e) => setHeaderValue(e.target.value)}
              placeholder="the value the program issued"
              aria-label="Bypass header value"
            />
            <button
              type="button"
              onClick={saveBypassHeader}
              disabled={
                headerBusy ||
                !headerName.trim() ||
                !headerValue.trim() ||
                !(live?.engagement_id ?? engagementId.trim())
              }
            >
              {headerBusy ? "storing…" : "store + install"}
            </button>
          </div>

          {!(live?.engagement_id ?? engagementId.trim()) ? (
            <p className="hp-tn-note">
              A bypass header belongs to an engagement, because it belongs to a program. Enter an
              engagement id above, or start the proxy under one.
            </p>
          ) : null}
          {headerNote ? <p className="hp-tn-note">{headerNote}</p> : null}

          {headerNames.length ? (
            <ul className="hp-tn-list">
              {headerNames.map((name) => (
                <li key={name} className="hp-tn-row">
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">{name}</span>
                    <span className="hp-tn-subs" style={{ flex: "1 1 240px" }}>
                      value held by the backend — never returned to this page
                    </span>
                    <button
                      type="button"
                      className="hp-tn-stop"
                      onClick={() => dropBypassHeader(name)}
                      disabled={headerBusy}
                    >
                      remove
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="hp-tn-note">No bypass header stored for this engagement.</p>
          )}
        </section>

        {/* ---- the AUTHENTICATED CONTEXT (build #18 items 6 and 7) ------------- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">scan behind a login</div>
          <div className="hp-tn-cardsub">
            <strong>The hard part already happened.</strong> Logging in by hand through this proxy
            put a live session inside ZAP. What is missing is telling the scanner what that
            session <em>means</em> — without a context it scans as an anonymous client and reports
            zero findings off a login page, which reads exactly like a secure application.
          </div>
          <div className="hp-tn-cardsub">
            <strong>Tier 2</strong> is the two indicator boxes and needs{" "}
            <strong>no credentials at all</strong>. <strong>Tier 3</strong> adds automatic
            re-login and is the three below it — the password is never typed here: you name a
            credential already captured in the vault and the backend resolves it.
          </div>

          <div className="hp-tn-form">
            <input
              value={ctxTarget}
              onChange={(e) => setCtxTarget(e.target.value)}
              placeholder="https://host/any/page — its ORIGIN becomes the context"
              aria-label="Context target URL"
            />
          </div>
          <div className="hp-tn-form">
            <input
              value={loggedIn}
              onChange={(e) => setLoggedIn(e.target.value)}
              placeholder="logged-IN regex, e.g. Logout|Sign out"
              aria-label="Logged in indicator"
            />
            <input
              value={loggedOut}
              onChange={(e) => setLoggedOut(e.target.value)}
              placeholder="logged-OUT regex, e.g. name=.password.|Sign in"
              aria-label="Logged out indicator"
            />
          </div>

          <div className="hp-tn-olhint">
            Tier 3 — leave blank for Tier 2, which is a complete and useful result
          </div>
          <div className="hp-tn-form">
            <input
              value={loginUrl}
              onChange={(e) => setLoginUrl(e.target.value)}
              placeholder="login POST url"
              aria-label="Login URL"
            />
            <input
              value={loginBody}
              onChange={(e) => setLoginBody(e.target.value)}
              placeholder="username={%username%}&password={%password%}"
              aria-label="Login request body"
            />
          </div>
          <div className="hp-tn-form">
            <input
              value={credSession}
              onChange={(e) => setCredSession(e.target.value)}
              placeholder="vault session id"
              aria-label="Credential session id"
            />
            <input
              value={credPrincipal}
              onChange={(e) => setCredPrincipal(e.target.value)}
              placeholder="account name"
              aria-label="Credential principal"
            />
            <button type="button" onClick={applyAuthContext} disabled={ctxBusy || !ctxTarget.trim()}>
              {ctxBusy ? "applying…" : "apply context"}
            </button>
            <button type="button" onClick={readAuthContext} disabled={!live || !ctxTarget.trim()}>
              read back
            </button>
            <button type="button" className="hp-tn-stop" onClick={dropAuthContexts} disabled={!live}>
              clear all
            </button>
          </div>

          {authCtx ? (
            authCtx.context_id ? (
              <div className="hp-tn-oneliner">
                <div className="hp-tn-olhint">
                  what ZAP HOLDS — read back, never echoed from what was sent
                </div>
                <pre>
                  {[
                    `tier            ${authCtx.tier}`,
                    `context         ${authCtx.context_name} (id ${authCtx.context_id})`,
                    `included        ${authCtx.included.join(", ") || "—"}`,
                    `session method  ${authCtx.session_method || "—"}`,
                    `auth method     ${authCtx.auth_method || "— (Tier 2: none needed)"}`,
                    `logged-in       ${authCtx.logged_in_regex || "—"}`,
                    `logged-out      ${authCtx.logged_out_regex || "—"}`,
                    `user            ${authCtx.user_name || "— (Tier 2 uses your own session)"}`,
                  ].join("\n")}
                </pre>
                {authCtx.warnings.map((w) => (
                  <div key={w} className="hp-tn-note">
                    warning: {w}
                  </div>
                ))}
              </div>
            ) : (
              <p className="hp-tn-note">
                ZAP holds no context for that target. That is an ordinary scan, not an error — it
                is exactly how every scan before this build ran.
              </p>
            )
          ) : null}
        </section>

        {/* ---- the BROWSER CRAWL (build #15 part 2) ---------------------------- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">crawl it with a real browser</div>
          <div className="hp-tn-cardsub">
            Chromium drives the site through this same ZAP, so it{" "}
            <strong>inherits whatever session you established by hand</strong> — log in through
            the proxy first and the crawl covers the logged-in application. Everything it finds
            lands in the captured traffic above, ready for the scanner below.
          </div>

          <div className="hp-tn-form">
            <input
              value={crawlTarget}
              onChange={(e) => setCrawlTarget(e.target.value)}
              placeholder="https://host/ — where the browser starts"
              aria-label="Crawl start URL"
            />
            <input
              className="hp-tn-port"
              value={crawlDepth}
              onChange={(e) => setCrawlDepth(e.target.value)}
              inputMode="numeric"
              aria-label="Max crawl depth"
              placeholder="depth"
            />
            <input
              className="hp-tn-port"
              value={crawlMinutes}
              onChange={(e) => setCrawlMinutes(e.target.value)}
              inputMode="numeric"
              aria-label="Max crawl duration in minutes"
              placeholder="mins"
            />
          </div>
          <p className="hp-tn-note">
            Depth and duration are part of the command you approve, not settings applied
            afterwards — a crawler that picks its own bounds is a command that has stopped
            describing what runs.
          </p>

          <div className="hp-tn-check">
            <label className="hp-tn-olhint" style={{ display: "flex", gap: "0.4rem" }}>
              <input
                type="checkbox"
                checked={crawlApproved}
                onChange={(e) => setCrawlApproved(e.target.checked)}
              />
              I approve this crawl
            </label>
          </div>

          {/* The red-confirm, and its copy is DELIBERATELY NOT the scanner's. No injection
              payloads are sent here. The hazard is that a real browser clicks things. */}
          <div className="hp-tn-danger">
            <div className="hp-tn-danger-head">this drives a real browser that clicks things</div>
            <div className="hp-tn-danger-note">
              It sends <strong>no injection payloads</strong> — that is the scanner below. What
              it does is click every control it can reach, which on a live site can submit a
              form, empty a basket, trigger an email or place an order.
            </div>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input
                type="checkbox"
                checked={crawlAck}
                onChange={(e) => setCrawlAck(e.target.checked)}
              />
              I understand a browser will <strong>interact with</strong> this site, and I am
              authorised to let it
            </label>
            <div className="hp-tn-danger-actions">
              <button
                type="button"
                className="hp-tn-danger-go"
                onClick={beginCrawl}
                disabled={
                  crawling || !live || !crawlTarget.trim() || !crawlApproved || !crawlAck
                }
              >
                {crawling ? "starting…" : "crawl with a browser"}
              </button>
            </div>
          </div>

          <div className="hp-tn-oneliner">
            <div className="hp-tn-olhint">crawl</div>
            <div className="hp-tn-form">
              <button type="button" onClick={loadSpider} disabled={!live}>
                refresh
              </button>
              {/* Ungated on purpose — a browser is mid-click on a live site. */}
              <button
                type="button"
                className="hp-tn-stop"
                onClick={haltCrawl}
                disabled={!live || !crawlRunning}
              >
                stop
              </button>
            </div>
            {spider ? (
              <ul className="hp-tn-list">
                <li className="hp-tn-row">
                  <div className="hp-tn-rowtop">
                    <span className={`hp-tn-state ${crawlRunning ? "is-starting" : "is-down"}`}>
                      {spider.state || "stopped"}
                    </span>
                    <span
                      className="hp-tn-subs"
                      style={{ flex: "1 1 280px", wordBreak: "break-all" }}
                    >
                      {spider.target_url || "—"}
                    </span>
                    <span className="hp-tn-olhint">
                      {spider.results} URLs · {spider.captured} captured
                    </span>
                  </div>
                  {/* READ BACK from ZAP, never echoed from what we set: setOptionBrowserId
                      answers OK for browsers it cannot launch. An OK is not a result. */}
                  <div className="hp-tn-note">
                    browser {spider.browser_id || "—"} (as ZAP reports it) · depth{" "}
                    {spider.max_depth || "—"} · limit {spider.max_duration_minutes || "—"} min
                  </div>
                </li>
              </ul>
            ) : (
              <p className="hp-tn-note">No crawl yet.</p>
            )}
          </div>
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

          {/* SCAN POLICY (build #18 item 3). It changes HOW MANY requests go out, not whether
              the scan may happen — an unknown name falls back to the default rather than
              refusing, so this select can never be the thing that blocks a scan. */}
          <div className="hp-tn-form">
            <select
              value={scanPolicy}
              onChange={(e) => setScanPolicy(e.target.value)}
              aria-label="Scan policy"
            >
              {policies.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name}
                  {Object.keys(p.disabled_scanners).length
                    ? ` — ${Object.keys(p.disabled_scanners).length} rules off`
                    : " — every rule"}
                </option>
              ))}
            </select>
          </div>
          {policies
            .filter((p) => p.name === scanPolicy)
            .map((p) => (
              <div key={p.name} className="hp-tn-oneliner">
                <div className="hp-tn-olhint">{p.description}</div>
                {Object.entries(p.disabled_scanners).length ? (
                  <ul className="hp-tn-list">
                    {Object.entries(p.disabled_scanners).map(([id, why]) => (
                      <li key={id} className="hp-tn-row">
                        <div className="hp-tn-rowtop">
                          <span className="hp-tn-kind">{id}</span>
                          <span className="hp-tn-subs" style={{ flex: "1 1 320px" }}>
                            {why}
                          </span>
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ))}

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
