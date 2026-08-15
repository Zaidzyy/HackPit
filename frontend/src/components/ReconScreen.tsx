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
  getDiscoverStatus,
  discoverPreview,
  startDiscover,
  listDiscoverJobs,
  stopDiscoverJob,
  getJsReconStatus,
  jsReconPreview,
  startJsRecon,
  listJsReconJobs,
  stopJsReconJob,
  type DiscoverJob,
  type DiscoverPreview,
  type DiscoverRequest,
  type DiscoverStatus,
  type DiscoveredEndpoint,
  type DiscoveredParam,
  type JsReconJob,
  type JsReconPreview,
  type JsReconRequest,
  type JsReconStatus,
  type MinedEndpoint,
  type MinedSecret,
  type RecoveredSource,
  type ReconJob,
  type ReconPreview,
  type ReconRequest,
  type ReconStatus,
  type ReconSurface,
  type RankedTarget,
} from "@/lib/api";

/**
 * :recon — the front door a bounty/pentest starts from, with two views.
 *
 * *** ONE APPROVAL BUYS A WHOLE JOB, SAID ON THE SCREEN AND NOT ONLY IN THE CODE. ***
 * SWEEP + RANK: a PASSIVE sweep (subfinder → dnsx → httpx → gau/waybackurls/katana) seeds
 * in-scope hosts/endpoints; an ACTIVE sweep (naabu → nmap -sV) adds services; then it RANKS.
 * DISCOVERY: arjun mines an endpoint's HIDDEN params, ffuf/feroxbuster its HIDDEN paths,
 * paramspider its HISTORICAL params. Each is ONE gated job — the same executor gates every
 * command clears, no new ones — with an ungated stop. Discovered params/endpoints are
 * SUGGESTIONS handed to :intruder / :nuclei / :repeater (each row pre-fills that surface);
 * the discovery job is the only thing approved — the attack itself is still approve-each.
 * SCOPE-SAFE BY CONSTRUCTION: the target host is scope-locked before the job runs and every
 * discovered URL/param is scope-filtered before it lands.
 */

function scoreColor(score: number): string {
  if (score >= 90) return "#ff5c7a";
  if (score >= 50) return "#f0776a";
  if (score >= 20) return "#f0a24a";
  return "#8aa4c8";
}

/** Synthetic data for the /recon?demo=1 discovery view — fake params/paths, never a real target. */
const DEMO_DISCOVER_JOBS: DiscoverJob[] = [
  {
    id: "demo-params",
    mode: "params",
    state: "finished",
    argv: ["arjun", "-u", "https://api.demo.example.com/v2/account", "-m", "GET"],
    url: "https://api.demo.example.com/v2/account",
    domain: "",
    container: "hackpit-engage-sandbox",
    started_at: "",
    finished_at: "",
    stages: [{ tool: "arjun", argv: [], state: "ran", note: "GET params on https://api.demo.example.com/v2/account" }],
    params: [
      {
        url: "https://api.demo.example.com/v2/account",
        method: "GET",
        params: ["id", "debug", "role", "view"],
        interesting: ["id", "debug", "role"],
        tag: "discovery",
        intruder_url: "https://api.demo.example.com/v2/account?id=[[FUZZ]]",
        nuclei_target: "https://api.demo.example.com/v2/account",
        repeater_url: "https://api.demo.example.com/v2/account",
      },
      {
        url: "https://api.demo.example.com/v2/orders",
        method: "GET",
        params: ["oid", "include"],
        interesting: ["oid", "include"],
        tag: "discovery",
        intruder_url: "https://api.demo.example.com/v2/orders?oid=[[FUZZ]]",
        nuclei_target: "https://api.demo.example.com/v2/orders",
        repeater_url: "https://api.demo.example.com/v2/orders",
      },
    ],
    endpoints: [],
    discovered_out_of_scope: ["cdn.thirdparty.net"],
    new_endpoints: 2,
    new_findings: 1,
    words_in_surface: 0,
    capped: false,
    output_tail: "",
    warnings: [],
    refused: "",
    refused_gate: "",
  },
  {
    id: "demo-content",
    mode: "content",
    state: "finished",
    argv: ["ffuf", "-u", "https://demo.example.com/", "-w", "admin", "-w", "backup", "-w", ".git/config"],
    url: "https://demo.example.com/",
    domain: "",
    container: "hackpit-engage-sandbox",
    started_at: "",
    finished_at: "",
    stages: [{ tool: "ffuf", argv: [], state: "ran", note: "6 words · https://demo.example.com/" }],
    params: [],
    endpoints: [
      {
        url: "https://demo.example.com/admin",
        status: 200,
        length: 4211,
        interesting: true,
        tag: "discovery",
        nuclei_target: "https://demo.example.com/admin",
        repeater_url: "https://demo.example.com/admin",
      },
      {
        url: "https://demo.example.com/.git/config",
        status: 200,
        length: 311,
        interesting: true,
        tag: "discovery",
        nuclei_target: "https://demo.example.com/.git/config",
        repeater_url: "https://demo.example.com/.git/config",
      },
      {
        url: "https://demo.example.com/about",
        status: 200,
        length: 1980,
        interesting: false,
        tag: "discovery",
        nuclei_target: "https://demo.example.com/about",
        repeater_url: "https://demo.example.com/about",
      },
    ],
    discovered_out_of_scope: [],
    new_endpoints: 3,
    new_findings: 2,
    words_in_surface: 6,
    capped: false,
    output_tail: "",
    warnings: [],
    refused: "",
    refused_gate: "",
  },
];

/** Synthetic data for /recon?view=jsrecon&demo=1 — fake endpoints/keys, never a real target's secrets. */
const DEMO_JSRECON_JOBS: JsReconJob[] = [
  {
    id: "demo-jsrecon",
    state: "finished",
    argv: ["js-mine", "--mine", "-u", "https://app.demo.example.com", "--maps", "--verify"],
    target: "https://app.demo.example.com",
    container: "hackpit-engage-sandbox",
    started_at: "",
    finished_at: "",
    stages: [
      { tool: "js-mine", argv: [], state: "ran", note: "collected 4 JS URL(s) from app.demo.example.com" },
      { tool: "js-mine", argv: [], state: "ran", note: "mined 6 endpoint(s), 3 secret(s)" },
    ],
    js_urls_mined: [
      "https://app.demo.example.com/static/app.4f2c.js",
      "https://app.demo.example.com/static/vendor.9a1b.js",
    ],
    endpoints: [
      {
        url: "https://app.demo.example.com/api/v2/account?id=1&role=admin",
        params: ["id", "role"],
        source_url: "https://app.demo.example.com/static/app.4f2c.js",
        tag: "js",
        nuclei_target: "https://app.demo.example.com/api/v2/account",
        repeater_url: "https://app.demo.example.com/api/v2/account?id=1&role=admin",
      },
      {
        url: "https://api.demo.example.com/internal/v2/orders?oid=7&include=items",
        params: ["oid", "include"],
        source_url: "https://app.demo.example.com/static/app.4f2c.js",
        tag: "js",
        nuclei_target: "https://api.demo.example.com/internal/v2/orders",
        repeater_url: "https://api.demo.example.com/internal/v2/orders?oid=7&include=items",
      },
      {
        url: "https://app.demo.example.com/api/v2/admin/flags",
        params: [],
        source_url: "https://app.demo.example.com/static/vendor.9a1b.js",
        tag: "js",
        nuclei_target: "https://app.demo.example.com/api/v2/admin/flags",
        repeater_url: "https://app.demo.example.com/api/v2/admin/flags",
      },
    ],
    secrets: [
      {
        type: "aws-access-key-id",
        source_url: "https://app.demo.example.com/static/app.4f2c.js",
        verified: true,
        masked: "AKIA…LE (20 chars)",
        loot_file: "/loot/demo/jsrecon-demo-secrets.txt",
      },
      {
        type: "stripe-secret-key",
        source_url: "https://app.demo.example.com/static/app.4f2c.js",
        verified: true,
        masked: "sk_l…67 (32 chars)",
        loot_file: "/loot/demo/jsrecon-demo-secrets.txt",
      },
      {
        type: "generic-api-key",
        source_url: "https://app.demo.example.com/static/vendor.9a1b.js",
        verified: false,
        masked: "abcd…89 (32 chars)",
        loot_file: "/loot/demo/jsrecon-demo-secrets.txt",
      },
    ],
    recovered_sources: [
      {
        js_url: "https://app.demo.example.com/static/app.4f2c.js",
        map_url: "https://app.demo.example.com/static/app.4f2c.js.map",
        recovered_sources: ["src/api/client.ts", "src/config/keys.ts", "src/admin/flags.ts"],
        comments: ["// TODO remove hardcoded key before ship", "// internal admin flags endpoint"],
      },
    ],
    discovered_out_of_scope: ["cdn.thirdparty.net"],
    new_endpoints: 6,
    new_findings: 3,
    secrets_found: 3,
    verified_secrets: 2,
    loot_file: "/loot/demo/jsrecon-demo-secrets.txt",
    output_tail: "",
    warnings: [],
    refused: "",
    refused_gate: "",
  },
];

type View = "recon" | "discovery" | "jsrecon";
type Mode = "params" | "content" | "historical";

export function ReconScreen() {
  const [view, setView] = useState<View>("recon");
  const [demo, setDemo] = useState(false);

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

  // --- discovery view state ---
  const [discStatus, setDiscStatus] = useState<DiscoverStatus | null>(null);
  const [discJobs, setDiscJobs] = useState<DiscoverJob[]>([]);
  const [discMode, setDiscMode] = useState<Mode>("params");
  const [url, setUrl] = useState("");
  const [method, setMethod] = useState("GET");
  const [tool, setTool] = useState("ffuf");
  const [wordsText, setWordsText] = useState("");
  const [wordlist, setWordlist] = useState("");
  const [extText, setExtText] = useState("");
  const [paramWordlist, setParamWordlist] = useState("");
  const [discApproved, setDiscApproved] = useState(false);
  const [discImpersonate, setDiscImpersonate] = useState(false);
  const [discAttachSession, setDiscAttachSession] = useState(false);
  const [discAck, setDiscAck] = useState(false);
  const [discPreview, setDiscPreview] = useState<DiscoverPreview | null>(null);
  const [discStarting, setDiscStarting] = useState(false);

  // --- js recon view state ---
  const [jsStatus, setJsStatus] = useState<JsReconStatus | null>(null);
  const [jsJobs, setJsJobs] = useState<JsReconJob[]>([]);
  const [jsTarget, setJsTarget] = useState("");
  const [jsUrlsText, setJsUrlsText] = useState("");
  const [jsIncludeState, setJsIncludeState] = useState(true);
  const [jsMaps, setJsMaps] = useState(true);
  const [jsVerify, setJsVerify] = useState(true);
  const [jsAttachSession, setJsAttachSession] = useState(false);
  const [jsApproved, setJsApproved] = useState(false);
  const [jsAck, setJsAck] = useState(false);
  const [jsPreview, setJsPreview] = useState<JsReconPreview | null>(null);
  const [jsStarting, setJsStarting] = useState(false);

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

  const words = useMemo(
    () => wordsText.split(/\r?\n/).map((w) => w.trim()).filter(Boolean),
    [wordsText]
  );

  const discRequest = useCallback(
    (): DiscoverRequest => ({
      mode: discMode,
      url: url.trim(),
      domain: domain.trim(),
      method,
      tool,
      words,
      wordlist: wordlist.trim(),
      extensions: extText.split(",").map((e) => e.trim()).filter(Boolean),
      param_wordlist: paramWordlist.trim(),
      rate_limit: Number.parseInt(rate, 10) || null,
      impersonate: discImpersonate,
      attach_session: discAttachSession,
      engagement_id: sessionId.trim() || null,
      session_id: sessionId.trim() || null,
      approved: discApproved,
      dangerous_ack: discAck,
    }),
    [discMode, url, domain, method, tool, words, wordlist, extText, paramWordlist, rate, discImpersonate, discAttachSession, sessionId, discApproved, discAck]
  );

  const jsUrls = useMemo(
    () => jsUrlsText.split(/\r?\n/).map((u) => u.trim()).filter(Boolean),
    [jsUrlsText]
  );

  const jsRequest = useCallback(
    (): JsReconRequest => ({
      target: jsTarget.trim(),
      js_urls: jsUrls,
      include_state: jsIncludeState,
      maps: jsMaps,
      verify: jsVerify,
      attach_session: jsAttachSession,
      rate_limit: Number.parseInt(rate, 10) || null,
      engagement_id: sessionId.trim() || null,
      session_id: sessionId.trim() || null,
      approved: jsApproved,
      dangerous_ack: jsAck,
    }),
    [jsTarget, jsUrls, jsIncludeState, jsMaps, jsVerify, jsAttachSession, rate, sessionId, jsApproved, jsAck]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    getReconStatus(ctrl.signal).then(setStatus).catch(() => setStatus(null));
    getDiscoverStatus(ctrl.signal).then(setDiscStatus).catch(() => setDiscStatus(null));
    getJsReconStatus(ctrl.signal).then(setJsStatus).catch(() => setJsStatus(null));
    return () => ctrl.abort();
  }, []);

  // Deep link: /recon?session=<id> prefills the id and auto-ranks; ?view=discovery opens the
  // discovery view; ?demo=1 shows synthetic discovered data. All state is set inside a microtask
  // callback (not the effect body) so the lint baseline is not disturbed.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const sid = params.get("session");
    const viewParam = params.get("view");
    const isDemo = params.has("demo");
    // ?view= picks the tab; a bare ?demo=1 (no view) opens the discovery demo, as before.
    const wantView: View | null =
      viewParam === "jsrecon" ? "jsrecon"
        : viewParam === "discovery" ? "discovery"
          : isDemo ? "discovery" : null;
    Promise.resolve().then(() => {
      if (sid) setSessionId(sid);
      if (wantView) setView(wantView);
      if (isDemo) setDemo(true);
      if (sid && !isDemo) getReconSurface(sid).then(setSurface).catch(() => setSurface(null));
    });
  }, []);

  const refreshJobs = useCallback(() => {
    listReconJobs(sessionId.trim() || undefined)
      .then(setJobs)
      .catch(() => setJobs([]));
  }, [sessionId]);

  const refreshDiscJobs = useCallback(() => {
    if (demo) return;
    listDiscoverJobs(sessionId.trim() || undefined)
      .then(setDiscJobs)
      .catch(() => setDiscJobs([]));
  }, [sessionId, demo]);

  const refreshJsJobs = useCallback(() => {
    if (demo) return;
    listJsReconJobs(sessionId.trim() || undefined)
      .then(setJsJobs)
      .catch(() => setJsJobs([]));
  }, [sessionId, demo]);

  // A running sweep/job's stages + counts grow, so this polls.
  useEffect(() => {
    refreshJobs();
    refreshDiscJobs();
    refreshJsJobs();
    const t = setInterval(() => {
      refreshJobs();
      refreshDiscJobs();
      refreshJsJobs();
    }, 2000);
    return () => clearInterval(t);
  }, [refreshJobs, refreshDiscJobs, refreshJsJobs]);

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

  const doDiscPreview = useCallback(() => {
    setError(null);
    discoverPreview(discRequest())
      .then(setDiscPreview)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [discRequest]);

  const runDiscover = useCallback(() => {
    if (discStarting) return;
    setDiscStarting(true);
    setError(null);
    startDiscover(discRequest())
      .then(() => refreshDiscJobs())
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setDiscStarting(false));
  }, [discStarting, discRequest, refreshDiscJobs]);

  const stopDisc = useCallback(
    (id: string) => {
      stopDiscoverJob(id)
        .then(() => refreshDiscJobs())
        .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
    },
    [refreshDiscJobs]
  );

  const doJsPreview = useCallback(() => {
    setError(null);
    jsReconPreview(jsRequest())
      .then(setJsPreview)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [jsRequest]);

  const runJs = useCallback(() => {
    if (jsStarting) return;
    setJsStarting(true);
    setError(null);
    startJsRecon(jsRequest())
      .then(() => refreshJsJobs())
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setJsStarting(false));
  }, [jsStarting, jsRequest, refreshJsJobs]);

  const stopJs = useCallback(
    (id: string) => {
      stopJsReconJob(id)
        .then(() => refreshJsJobs())
        .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
    },
    [refreshJsJobs]
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

  const canDiscover = useMemo(() => {
    if (!discApproved) return false;
    if (discMode === "historical") return domain.trim() !== "" || sessionId.trim() !== "";
    return url.trim() !== "";
  }, [discApproved, discMode, domain, url, sessionId]);

  const canJsRun = useMemo(() => {
    if (!jsApproved) return false;
    return (
      jsTarget.trim() !== "" ||
      jsUrls.length > 0 ||
      (jsIncludeState && sessionId.trim() !== "")
    );
  }, [jsApproved, jsTarget, jsUrls, jsIncludeState, sessionId]);

  const shownDiscJobs = demo ? DEMO_DISCOVER_JOBS : discJobs;
  const shownJsJobs = demo ? DEMO_JSRECON_JOBS : jsJobs;
  const activeStatus =
    view === "discovery" ? discStatus : view === "jsrecon" ? jsStatus : status;

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "recon" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">scoped domain · recon + discovery as approved jobs · ranked surface</div>
          <h1 className="hp-tn-title">:recon</h1>
          <p className="hp-tn-sub">
            The front door a bounty/pentest starts from. <strong>Sweep &amp; rank</strong> a scoped
            domain into <Link href="/cockpit">:cockpit</Link> state, or run{" "}
            <strong>parameter / content discovery</strong> to mine an endpoint&rsquo;s hidden params
            (arjun), hidden paths (ffuf / feroxbuster) and historical params (paramspider). Each is{" "}
            <strong>one gated job</strong> — no new gate, just the executor&rsquo;s — with an ungated
            stop. Discoveries are <strong>suggestions handed to :intruder / :nuclei / :repeater</strong>,
            never auto-fired; only in-scope items ever land, by construction.
          </p>
          {activeStatus && (
            <div className={`hp-tn-status ${activeStatus.up ? "is-up" : "is-down"}`}>
              <span className="hp-tn-dot" />
              {activeStatus.container}: {activeStatus.up ? "up" : "down"} · running {activeStatus.running}
              {activeStatus.detail ? ` · ${activeStatus.detail}` : ""}
            </div>
          )}
          <div className="hp-tn-chips" style={{ marginTop: "0.6rem" }}>
            <button
              type="button"
              className={`hp-tn-chip${view === "recon" ? " is-on" : ""}`}
              onClick={() => setView("recon")}
            >
              sweep + rank
            </button>
            <button
              type="button"
              className={`hp-tn-chip${view === "discovery" ? " is-on" : ""}`}
              onClick={() => setView("discovery")}
            >
              parameter / content discovery
            </button>
            <button
              type="button"
              className={`hp-tn-chip${view === "jsrecon" ? " is-on" : ""}`}
              onClick={() => setView("jsrecon")}
            >
              js recon → secrets
            </button>
          </div>
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        {view === "recon" && (
          <>
            <section className="hp-tn-card">
              <div className="hp-tn-cardhead">the sweep</div>
              <div className="hp-tn-cardsub">
                Recon is engagement-bound — enter engagement mode first (its scope is what decides
                what may be scanned), then paste the engagement id and the in-scope domain. The
                passive sweep is bug-bounty safe and the default; the active sweep sends real scan
                traffic and is a second, explicit approval.
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
                  Each stage is one <code>docker exec</code> under the one approval. In-scope
                  discoveries seed <Link href="/cockpit">:cockpit</Link> state; out-of-scope names are
                  read-only.
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
                Advisory only — it scores the state a sweep (or discovery) seeded and proposes an
                order. It runs nothing. Each target hands off cleanly into{" "}
                <Link href="/attack-path">:attack-paths</Link> and <Link href="/nuclei">:nuclei</Link>.
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
          </>
        )}

        {view === "discovery" && (
          <>
            <section className="hp-tn-card">
              <div className="hp-tn-cardhead">the discovery job</div>
              <div className="hp-tn-cardsub">
                Engagement-bound, exactly like a sweep. Point <strong>params</strong> (arjun) or{" "}
                <strong>content</strong> (ffuf / feroxbuster) at ONE in-scope url — its host is
                scope-locked before anything runs — or mine <strong>historical</strong> params
                (paramspider) for an in-scope domain. One approval buys the whole job; the discovered
                items are handed to :intruder / :nuclei / :repeater, never fired here.
              </div>
              <div className="hp-tn-chips">
                {(["params", "content", "historical"] as Mode[]).map((m) => (
                  <button
                    key={m}
                    type="button"
                    className={`hp-tn-chip${discMode === m ? " is-on" : ""}`}
                    onClick={() => setDiscMode(m)}
                  >
                    {m === "params" ? "params · arjun" : m === "content" ? "content · ffuf/ferox" : "historical · paramspider"}
                  </button>
                ))}
              </div>
              <div className="hp-tn-form">
                <input
                  value={sessionId}
                  onChange={(e) => setSessionId(e.target.value)}
                  placeholder="engagement / session id"
                  aria-label="Engagement id"
                  style={{ flex: "1 1 260px" }}
                />
                {discMode === "historical" ? (
                  <input
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    placeholder="in-scope domain (blank = the engagement target)"
                    aria-label="Domain"
                    style={{ flex: "1 1 340px" }}
                  />
                ) : (
                  <input
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="in-scope url (e.g. https://api.example.com/v2/account)"
                    aria-label="Target URL"
                    style={{ flex: "1 1 340px" }}
                  />
                )}
                <input
                  className="hp-tn-port"
                  value={rate}
                  onChange={(e) => setRate(e.target.value)}
                  placeholder="rate/s"
                  aria-label="Rate limit, requests per second"
                />
              </div>

              {discMode === "params" && (
                <div className="hp-tn-form">
                  {(["GET", "POST", "JSON"]).map((mth) => (
                    <button
                      key={mth}
                      type="button"
                      className={`hp-tn-chip${method === mth ? " is-on" : ""}`}
                      onClick={() => setMethod(mth)}
                    >
                      {mth}
                    </button>
                  ))}
                  <input
                    value={paramWordlist}
                    onChange={(e) => setParamWordlist(e.target.value)}
                    placeholder="arjun wordlist path (blank = arjun's bundled list)"
                    aria-label="Arjun parameter wordlist"
                    style={{ flex: "1 1 320px" }}
                  />
                </div>
              )}

              {discMode === "content" && (
                <>
                  <div className="hp-tn-form">
                    {(["ffuf", "feroxbuster"]).map((tl) => (
                      <button
                        key={tl}
                        type="button"
                        className={`hp-tn-chip${tool === tl ? " is-on" : ""}`}
                        onClick={() => setTool(tl)}
                      >
                        {tl}
                      </button>
                    ))}
                    <input
                      value={extText}
                      onChange={(e) => setExtText(e.target.value)}
                      placeholder="extensions (php,bak,old)"
                      aria-label="Extensions"
                      style={{ flex: "1 1 200px" }}
                    />
                    <input
                      value={wordlist}
                      onChange={(e) => setWordlist(e.target.value)}
                      placeholder="baked wordlist path (used when the box below is empty)"
                      aria-label="Wordlist path"
                      style={{ flex: "1 1 320px" }}
                    />
                  </div>
                  <textarea
                    value={wordsText}
                    onChange={(e) => setWordsText(e.target.value)}
                    placeholder={"the WORD LIST, one per line — every word rides in the approved surface\nadmin\nlogin\nbackup\n.git/config"}
                    aria-label="Content-discovery word list"
                    rows={5}
                    style={{ width: "100%", fontFamily: "var(--font-mono, monospace)", marginTop: "0.4rem" }}
                  />
                  <p className="hp-tn-olhint">
                    {words.length} word(s) — the whole list is in the approved surface, intruder-style,
                    so a word carrying a shell metacharacter cannot hide behind a &ldquo;…and N
                    more&rdquo;.
                  </p>
                </>
              )}

              <div className="hp-tn-form">
                <button type="button" onClick={doDiscPreview}>
                  preview — the argv the gate reads
                </button>
              </div>

              {discPreview && (
                <>
                  <div className="hp-tn-olhint">
                    the approved command ({discPreview.mode})
                    {discPreview.words_in_surface > 0 ? ` · ${discPreview.words_in_surface} words in surface` : ""}
                    {discPreview.capped ? " · CAPPED" : ""} <CopyButton text={discPreview.argv.join(" ")} />
                  </div>
                  <pre className="hp-tn-oneliner">{discPreview.argv.join(" ") || "(nothing to run)"}</pre>
                  {gateLine(discPreview.gate)}
                </>
              )}

              <div className="hp-tn-danger">
                <div className="hp-tn-danger-head">a discovery job sends many requests to one in-scope target</div>
                <div className="hp-tn-danger-note">
                  One approval buys the whole job — arjun/ffuf/feroxbuster probe the in-scope url
                  (paramspider only queries archives). The target host is scope-locked before anything
                  runs. Preview first — the gate&rsquo;s answer is shown above.
                </div>
                {discMode !== "historical" && (
                  <label
                    className="hp-tn-danger-why"
                    style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
                    title="Route the tool through the in-sandbox JA3 MITM proxy (curl_cffi/Chrome fingerprint) so a Cloudflare/Akamai-fronted target serves it instead of 403-ing a plain fuzzer. Beats JA3, not a JS challenge."
                  >
                    <input
                      type="checkbox"
                      checked={discImpersonate}
                      onChange={(e) => setDiscImpersonate(e.target.checked)}
                    />
                    impersonate browser (WAF bypass — routes through the JA3 proxy)
                  </label>
                )}
                {discMode !== "historical" && (
                  <label
                    className="hp-tn-danger-why"
                    style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
                    title="Run the tool AS the logged-in operator — merge the engagement's stored session (saved in :repeater) as auth headers, so content/params behind login are discovered. Ignored for historical."
                  >
                    <input
                      type="checkbox"
                      checked={discAttachSession}
                      onChange={(e) => setDiscAttachSession(e.target.checked)}
                    />
                    attach session (authenticated discovery)
                  </label>
                )}
                <label className="hp-tn-danger-why" style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}>
                  <input type="checkbox" checked={discApproved} onChange={(e) => setDiscApproved(e.target.checked)} />
                  I approve this discovery job
                </label>
                <label className="hp-tn-danger-why" style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}>
                  <input type="checkbox" checked={discAck} onChange={(e) => setDiscAck(e.target.checked)} />
                  I understand this probes a real target (red-confirm, when the gate asks)
                </label>
                <div className="hp-tn-danger-actions">
                  <button
                    type="button"
                    className="hp-tn-danger-go"
                    onClick={runDiscover}
                    disabled={discStarting || !canDiscover}
                  >
                    {discStarting ? "starting…" : "run discovery job"}
                  </button>
                </div>
              </div>
            </section>

            <section className="hp-tn-card">
              <div className="hp-tn-cardhead">
                discoveries{demo ? " · demo data" : ""}
              </div>
              <div className="hp-tn-cardsub">
                Every row is <strong>tagged discovery</strong> and carries a pre-filled hand-off — the
                attack itself is still approve-each on the surface it lands on. Discovered params also
                raise their host&rsquo;s rank in the sweep &amp; rank view.
              </div>
              {shownDiscJobs.length === 0 && (
                <p className="hp-tn-olhint">
                  no discovery jobs yet — run one above, or open <code>/recon?demo=1</code> to see the
                  hand-offs.
                </p>
              )}
              <ul className="hp-tn-list">
                {shownDiscJobs.map((job) => (
                  <li key={job.id} className={`hp-tn-row${job.refused ? " is-down" : ""}`}>
                    <div className="hp-tn-rowtop">
                      <span className="hp-tn-kind">{job.mode}</span>
                      <span className="hp-tn-subs" style={{ flex: "1 1 220px", wordBreak: "break-all" }}>
                        {job.url || job.domain || job.id}
                      </span>
                      <span className={`hp-tn-state ${job.state === "running" ? "is-listening" : "is-down"}`}>
                        {job.state}
                      </span>
                      <span className="hp-tn-olhint">
                        +{job.new_endpoints} ep · +{job.new_findings} find
                        {job.words_in_surface ? ` · ${job.words_in_surface} words` : ""}
                        {job.capped ? " · CAPPED" : ""}
                      </span>
                      {job.state === "running" && !demo && (
                        <button type="button" className="hp-tn-stop" onClick={() => stopDisc(job.id)}>
                          stop — not gated
                        </button>
                      )}
                    </div>

                    {job.params.map((p: DiscoveredParam) => (
                      <div key={p.url} className="hp-tn-row" style={{ marginTop: "0.4rem" }}>
                        <div className="hp-tn-rowtop">
                          <span className="hp-tn-kind">{p.method}</span>
                          <span className="hp-tn-subs" style={{ flex: "1 1 240px", wordBreak: "break-all" }}>
                            {p.url}
                          </span>
                          <span className="hp-tn-olhint">{p.params.length} param(s)</span>
                        </div>
                        <div className="hp-tn-chips">
                          {p.params.map((name) => (
                            <span
                              key={name}
                              className={`hp-tn-chip${p.interesting.includes(name) ? " is-on" : ""}`}
                            >
                              {name}
                            </span>
                          ))}
                        </div>
                        <p className="hp-tn-olhint">
                          send to{" "}
                          <Link href="/intruder">:intruder</Link> <CopyButton text={p.intruder_url} />
                          {" · "}
                          <Link href="/nuclei">:nuclei</Link> <CopyButton text={p.nuclei_target} />
                          {" · "}
                          <Link href="/repeater">:repeater</Link> <CopyButton text={p.repeater_url} />
                        </p>
                      </div>
                    ))}

                    {job.endpoints.map((e: DiscoveredEndpoint) => (
                      <div key={e.url} className="hp-tn-row" style={{ marginTop: "0.4rem" }}>
                        <div className="hp-tn-rowtop">
                          <span className={`hp-tn-chip${e.interesting ? " is-on" : ""}`}>
                            {e.interesting ? "★" : "·"}
                          </span>
                          <span className="hp-tn-subs" style={{ flex: "1 1 260px", wordBreak: "break-all" }}>
                            {e.url}
                          </span>
                          <span className="hp-tn-olhint">
                            {e.status ?? "—"}{e.length != null ? ` · ${e.length}B` : ""}
                          </span>
                        </div>
                        <p className="hp-tn-olhint">
                          send to{" "}
                          <Link href="/nuclei">:nuclei</Link> <CopyButton text={e.nuclei_target} />
                          {" · "}
                          <Link href="/repeater">:repeater</Link> <CopyButton text={e.repeater_url} />
                        </p>
                      </div>
                    ))}

                    {job.discovered_out_of_scope.length > 0 && (
                      <p className="hp-tn-olhint">
                        out of scope, dropped ({job.discovered_out_of_scope.length}):{" "}
                        {job.discovered_out_of_scope.slice(0, 8).join(", ")}
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
          </>
        )}

        {view === "jsrecon" && (
          <>
            <section className="hp-tn-card">
              <div className="hp-tn-cardhead">the JS-recon job</div>
              <div className="hp-tn-cardsub">
                Engagement-bound, exactly like a sweep. Give an in-scope <strong>page/host</strong> to
                collect JavaScript from, paste <strong>JS URLs</strong> you already found, and/or mine
                the <code>.js</code> endpoints already in this session&rsquo;s state. One approval fetches
                the in-scope JS, mines <strong>endpoints, parameters and secrets / API keys</strong> out
                of the bundles (and their source maps), feeds endpoints into the ranked surface and writes
                secrets to <strong>loot</strong> — the finding never carries the value. Only in-scope JS is
                fetched and only in-scope mined hosts land, by construction.
              </div>
              <div className="hp-tn-form">
                <input
                  value={sessionId}
                  onChange={(e) => setSessionId(e.target.value)}
                  placeholder="engagement / session id"
                  aria-label="Engagement id"
                  style={{ flex: "1 1 260px" }}
                />
                <input
                  value={jsTarget}
                  onChange={(e) => setJsTarget(e.target.value)}
                  placeholder="collect JS from (e.g. https://app.example.com — blank = only the URLs below / state)"
                  aria-label="Collection target"
                  style={{ flex: "1 1 360px" }}
                />
                <input
                  className="hp-tn-port"
                  value={rate}
                  onChange={(e) => setRate(e.target.value)}
                  placeholder="rate/s"
                  aria-label="Rate limit, requests per second"
                />
              </div>
              <textarea
                value={jsUrlsText}
                onChange={(e) => setJsUrlsText(e.target.value)}
                placeholder={"explicit in-scope JS URLs, one per line (optional)\nhttps://app.example.com/static/app.4f2c.js"}
                aria-label="JS URLs"
                rows={3}
                style={{ width: "100%", fontFamily: "var(--font-mono, monospace)", marginTop: "0.4rem" }}
              />
              <div className="hp-tn-chips">
                <button
                  type="button"
                  className={`hp-tn-chip${jsIncludeState ? " is-on" : ""}`}
                  onClick={() => setJsIncludeState((v) => !v)}
                >
                  mine .js already in state
                </button>
                <button
                  type="button"
                  className={`hp-tn-chip${jsMaps ? " is-on" : ""}`}
                  onClick={() => setJsMaps((v) => !v)}
                >
                  unpack source maps
                </button>
                <button
                  type="button"
                  className={`hp-tn-chip${jsVerify ? " is-on" : ""}`}
                  onClick={() => setJsVerify((v) => !v)}
                >
                  verify keys (trufflehog)
                </button>
                <button
                  type="button"
                  className={`hp-tn-chip${jsAttachSession ? " is-on" : ""}`}
                  onClick={() => setJsAttachSession((v) => !v)}
                  title="Fetch JS AS the logged-in operator — the engagement's stored session (saved in :repeater) authenticates the fetch, so login-gated bundles are mined."
                >
                  attach session (authenticated)
                </button>
              </div>

              <div className="hp-tn-form">
                <button type="button" onClick={doJsPreview}>
                  preview — the argv the gate reads
                </button>
              </div>

              {jsPreview && (
                <>
                  <div className="hp-tn-olhint">
                    the approved command <CopyButton text={jsPreview.argv.join(" ")} />
                  </div>
                  <pre className="hp-tn-oneliner">{jsPreview.argv.join(" ") || "(nothing to run)"}</pre>
                  {gateLine(jsPreview.gate)}
                </>
              )}

              <div className="hp-tn-danger">
                <div className="hp-tn-danger-head">a JS-recon job fetches a target&rsquo;s JavaScript and mines it</div>
                <div className="hp-tn-danger-note">
                  One approval buys the whole job — it collects the in-scope JS, fetches each bundle (and
                  its source map) and mines endpoints/params/secrets. Only in-scope JS is fetched, by
                  construction. Preview first — the gate&rsquo;s answer is shown above.
                </div>
                <label className="hp-tn-danger-why" style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}>
                  <input type="checkbox" checked={jsApproved} onChange={(e) => setJsApproved(e.target.checked)} />
                  I approve this JS-recon job
                </label>
                <label className="hp-tn-danger-why" style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}>
                  <input type="checkbox" checked={jsAck} onChange={(e) => setJsAck(e.target.checked)} />
                  I understand this fetches a real target&rsquo;s JS (red-confirm, when the gate asks)
                </label>
                <div className="hp-tn-danger-actions">
                  <button
                    type="button"
                    className="hp-tn-danger-go"
                    onClick={runJs}
                    disabled={jsStarting || !canJsRun}
                  >
                    {jsStarting ? "starting…" : "run JS-recon job"}
                  </button>
                </div>
              </div>
            </section>

            <section className="hp-tn-card">
              <div className="hp-tn-cardhead">mined from JavaScript{demo ? " · demo data" : ""}</div>
              <div className="hp-tn-cardsub">
                Endpoints/params are <strong>tagged source <code>js</code></strong> and seed the ranked
                surface (they raise their host&rsquo;s rank in sweep &amp; rank). Secrets/API keys are
                written to a <strong>loot file</strong> and become Findings — a{" "}
                <strong>trufflehog-verified</strong> key is High; the value is never shown here, only a
                masked preview.
              </div>
              {shownJsJobs.length === 0 && (
                <p className="hp-tn-olhint">
                  no JS-recon jobs yet — run one above, or open{" "}
                  <code>/recon?view=jsrecon&amp;demo=1</code> to see the mined view.
                </p>
              )}
              <ul className="hp-tn-list">
                {shownJsJobs.map((job) => (
                  <li key={job.id} className={`hp-tn-row${job.refused ? " is-down" : ""}`}>
                    <div className="hp-tn-rowtop">
                      <span className="hp-tn-kind">js recon</span>
                      <span className="hp-tn-subs" style={{ flex: "1 1 220px", wordBreak: "break-all" }}>
                        {job.target || `${job.js_urls_mined.length} JS URL(s)`}
                      </span>
                      <span className={`hp-tn-state ${job.state === "running" ? "is-listening" : "is-down"}`}>
                        {job.state}
                      </span>
                      <span className="hp-tn-olhint">
                        +{job.new_endpoints} ep · {job.secrets_found} secret(s) · {job.verified_secrets} verified · +{job.new_findings} find
                      </span>
                      {job.state === "running" && !demo && (
                        <button type="button" className="hp-tn-stop" onClick={() => stopJs(job.id)}>
                          stop — not gated
                        </button>
                      )}
                    </div>

                    {job.secrets.length > 0 && (
                      <div className="hp-tn-row" style={{ marginTop: "0.4rem" }}>
                        <div className="hp-tn-cardhead" style={{ fontSize: "0.85rem" }}>
                          secrets found → loot {job.loot_file ? <code>{job.loot_file}</code> : null}
                        </div>
                        {job.secrets.map((s: MinedSecret, i) => (
                          <div key={`${s.type}-${i}`} className="hp-tn-rowtop">
                            <span className={`hp-tn-state ${s.verified ? "is-listening" : "is-starting"}`}>
                              {s.verified ? "VERIFIED" : "unverified"}
                            </span>
                            <span className="hp-tn-kind">{s.type}</span>
                            <span className="hp-tn-subs" style={{ flex: "1 1 200px", wordBreak: "break-all" }}>
                              {s.masked} <span className="hp-tn-olhint">— value in loot, never shown</span>
                            </span>
                            <span className="hp-tn-olhint" style={{ wordBreak: "break-all" }}>
                              {s.source_url}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}

                    {job.endpoints.map((e: MinedEndpoint) => (
                      <div key={e.url} className="hp-tn-row" style={{ marginTop: "0.4rem" }}>
                        <div className="hp-tn-rowtop">
                          <span className="hp-tn-kind">js</span>
                          <span className="hp-tn-subs" style={{ flex: "1 1 260px", wordBreak: "break-all" }}>
                            {e.url}
                          </span>
                          <span className="hp-tn-olhint">{e.params.length} param(s)</span>
                        </div>
                        {e.params.length > 0 && (
                          <div className="hp-tn-chips">
                            {e.params.map((name) => (
                              <span key={name} className="hp-tn-chip is-on">
                                {name}
                              </span>
                            ))}
                          </div>
                        )}
                        <p className="hp-tn-olhint">
                          send to{" "}
                          <Link href="/nuclei">:nuclei</Link> <CopyButton text={e.nuclei_target} />
                          {" · "}
                          <Link href="/repeater">:repeater</Link> <CopyButton text={e.repeater_url} />
                        </p>
                      </div>
                    ))}

                    {job.recovered_sources.map((r: RecoveredSource) => (
                      <div key={r.js_url} className="hp-tn-row" style={{ marginTop: "0.4rem" }}>
                        <p className="hp-tn-olhint" style={{ wordBreak: "break-all" }}>
                          source map recovered from {r.js_url} — {r.recovered_sources.length} original
                          source path(s)
                        </p>
                        <div className="hp-tn-chips">
                          {r.recovered_sources.slice(0, 12).map((src) => (
                            <span key={src} className="hp-tn-chip">
                              {src}
                            </span>
                          ))}
                        </div>
                        {r.comments.map((c) => (
                          <p key={c} className="hp-tn-olhint">
                            {c}
                          </p>
                        ))}
                      </div>
                    ))}

                    {job.discovered_out_of_scope.length > 0 && (
                      <p className="hp-tn-olhint">
                        out of scope, dropped ({job.discovered_out_of_scope.length}):{" "}
                        {job.discovered_out_of_scope.slice(0, 8).join(", ")}
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
          </>
        )}
      </div>
    </PageShell>
  );
}
