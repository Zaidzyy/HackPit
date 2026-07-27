"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  generateImplant,
  getObfuscationStatus,
  getSliverStatus,
  listDnsListeners,
  listImplants,
  listSliverServers,
  previewImplant,
  startDnsListener,
  startSliverServer,
  stopDnsListener,
  stopSliverServer,
  type DnsListener,
  type Implant,
  type ImplantBody,
  type ImplantPreview,
  type ObfuscationStatus,
  type SliverServer,
  type SliverStatus,
} from "@/lib/api";

/**
 * C2 + covert channel — Sliver implants and DNS tunnels.
 *
 * TWO FOOTINGS, and the panel keeps them visibly apart:
 *
 *  · SERVER / LISTENER LIFECYCLE is HUMAN-ONLY. A Sliver server and a dnscat2/iodine listener
 *    are OPERATOR INFRASTRUCTURE on the operator's own sandbox: no target, nothing belonging
 *    to the client is touched, so clicking start IS the approval and there is no gate. What
 *    makes that safe is that nothing autonomous can reach either one (source-scan locked).
 *
 *  · IMPLANT GENERATION is a GATED COMMAND. Preview first — pure, it shows the literal argv
 *    and which gate would refuse it without running anything — then approve. A payload
 *    generator trips the danger heuristic, so the build comes back as an explicit RED CONFIRM
 *    you re-confirm. It ONLY generates: nothing here delivers or executes the artifact.
 *
 * `<listener>` is YOUR callback address and is never substituted with the target. The DNS
 * listener's pre-shared key never crosses the API boundary — the client one-liner arrives with
 * it masked as `***`, and you substitute the key you chose.
 */
export function C2Screen() {
  const [sliver, setSliver] = useState<SliverStatus | null>(null);
  const [servers, setServers] = useState<SliverServer[]>([]);
  const [implants, setImplants] = useState<Implant[]>([]);
  const [dns, setDns] = useState<ObfuscationStatus | null>(null);
  const [listeners, setListeners] = useState<DnsListener[]>([]);
  const [error, setError] = useState<string | null>(null);

  // --- sliver server form ---
  const [port, setPort] = useState("");
  const [engagementId, setEngagementId] = useState("");
  const [startingServer, setStartingServer] = useState(false);

  // --- implant build form ---
  const [ios, setIos] = useState("windows");
  const [arch, setArch] = useState("amd64");
  const [fmt, setFmt] = useState("exe");
  const [transport, setTransport] = useState("mtls");
  const [listener, setListener] = useState("<listener>");
  const [target, setTarget] = useState("");
  const [preview, setPreview] = useState<ImplantPreview | null>(null);
  const [dangerReason, setDangerReason] = useState<string | null>(null);
  const [building, setBuilding] = useState(false);

  // --- dns tunnel form ---
  const [kind, setKind] = useState("dnscat2");
  const [zone, setZone] = useState("");
  const [secret, setSecret] = useState("");
  const [tunnelNet, setTunnelNet] = useState("10.99.53.1/24");
  const [startingListener, setStartingListener] = useState(false);

  const refresh = useCallback(() => {
    getSliverStatus()
      .then(setSliver)
      .catch(() => setSliver(null));
    listSliverServers()
      .then(setServers)
      .catch(() => setServers([]));
    listImplants()
      .then(setImplants)
      .catch(() => setImplants([]));
    getObfuscationStatus()
      .then(setDns)
      .catch(() => setDns(null));
    listDnsListeners()
      .then(setListeners)
      .catch(() => setListeners([]));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const implantBody = useCallback(
    (approved: boolean, ack: boolean): ImplantBody => ({
      os: ios,
      arch,
      fmt,
      transport,
      listener: listener.trim() || "<listener>",
      target: target.trim(),
      engagement_id: engagementId.trim() || null,
      approved,
      dangerous_ack: ack,
    }),
    [ios, arch, fmt, transport, listener, target, engagementId]
  );

  const startServer = useCallback(async () => {
    if (startingServer) return;
    setStartingServer(true);
    setError(null);
    try {
      await startSliverServer({
        port: port.trim() ? Number(port) : null,
        engagement_id: engagementId.trim() || null,
      });
      refresh();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setStartingServer(false);
    }
  }, [port, engagementId, startingServer, refresh]);

  const stopServer = useCallback(
    async (sid: string) => {
      try {
        await stopSliverServer(sid);
      } finally {
        refresh();
      }
    },
    [refresh]
  );

  /** PURE preview — the exact argv a build would run, and the gate that would refuse it. */
  const doPreview = useCallback(async () => {
    setError(null);
    setDangerReason(null);
    try {
      // approved=false on purpose: the preview is a dry read of the gates, not a request.
      setPreview(await previewImplant(implantBody(false, false)));
    } catch (e) {
      setPreview(null);
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [implantBody]);

  /** Build one implant. `ack` re-sends after the danger gate's red confirm. */
  const build = useCallback(
    async (ack: boolean) => {
      if (building) return;
      setBuilding(true);
      setError(null);
      try {
        await generateImplant(implantBody(true, ack));
        setDangerReason(null);
        refresh();
      } catch (e) {
        const msg = e instanceof ApiError ? e.message : String(e);
        // The danger gate is a RED CONFIRM, not a failure — surface it as one.
        if (msg.startsWith("[danger]")) setDangerReason(msg.replace(/^\[danger\]\s*/, ""));
        else setError(msg);
      } finally {
        setBuilding(false);
      }
    },
    [implantBody, building, refresh]
  );

  const startListener = useCallback(async () => {
    if (!zone.trim() || startingListener) return;
    setStartingListener(true);
    setError(null);
    try {
      await startDnsListener({
        kind,
        zone: zone.trim(),
        tunnel_net: tunnelNet.trim() || "10.99.53.1/24",
        secret: secret.trim() || null,
        engagement_id: engagementId.trim() || null,
      });
      refresh();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setStartingListener(false);
    }
  }, [kind, zone, tunnelNet, secret, engagementId, startingListener, refresh]);

  const stopListener = useCallback(
    async (lid: string) => {
      try {
        await stopDnsListener(lid);
      } finally {
        refresh();
      }
    },
    [refresh]
  );

  const sliverUp = sliver?.up ?? false;
  const dnsUp = dns?.up ?? false;

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "c2" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">sliver c2 · dns tunnel · operator infrastructure</div>
          <h1 className="hp-tn-title">:c2</h1>
          <p className="hp-tn-sub">
            Your own C2 server and covert channel, on your own box. Starting a server or a
            tunnel listener is <b>human-only</b> — it has no target, so there is nothing to
            scope-check. Building an implant is a <b>gated command</b>: preview the exact argv,
            then approve it, then re-confirm the red warning. It only generates —{" "}
            <b>nothing here delivers or runs what it builds</b>.
          </p>
          <div className={`hp-tn-status ${sliverUp ? "is-up" : "is-down"}`}>
            <span className="hp-tn-dot" />
            {sliverUp
              ? `sliver ready · ${sliver?.live_servers ?? 0}/${sliver?.max_live_servers ?? 0} servers · ${sliver?.implants ?? 0} implants`
              : `engage sandbox down — bring the stack up (${sliver?.detail || "not running"})`}
          </div>
          <div className={`hp-tn-status ${dnsUp ? "is-up" : "is-down"}`}>
            <span className="hp-tn-dot" />
            {dnsUp
              ? `dns tunnel ready · ${dns?.live_listeners ?? 0}/${dns?.max_live_listeners ?? 0} listeners`
              : `engage sandbox down (${dns?.detail || "not running"})`}
          </div>
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        {/* ---- sliver server (HUMAN-ONLY) ---- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">sliver server — human-only</div>
          <p className="hp-tn-cardsub">
            The daemon runs in your engage sandbox. No target, no gate: clicking start is the
            approval. Create your listener from the Sliver console — its address is what an
            implant&rsquo;s <code>&lt;listener&gt;</code> placeholder stands in for.
          </p>
          <div className="hp-tn-form">
            <input
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="port (optional — 31337)"
              aria-label="port"
              className="hp-tn-port"
            />
            <input
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
              placeholder="engagement id (tags the audit trail; also picks the build mode)"
              aria-label="engagement id"
            />
            <button type="button" onClick={startServer} disabled={startingServer}>
              {startingServer ? "starting…" : "start server ▸"}
            </button>
          </div>
          {servers.length > 0 && (
            <ul className="hp-tn-list">
              {servers.map((s) => (
                <li key={s.id} className={`hp-tn-row is-${s.status}`}>
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">sliver</span>
                    <span className={`hp-tn-state is-${s.status}`}>{s.status}</span>
                    <span className="hp-tn-subs">
                      {s.container}:{s.port}
                    </span>
                    <button
                      type="button"
                      className="hp-tn-stop"
                      onClick={() => stopServer(s.id)}
                      disabled={s.status === "down"}
                    >
                      stop
                    </button>
                  </div>
                  <p className="hp-tn-note">{s.setup_note}</p>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* ---- implant build (GATED) ---- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">build an implant — gated</div>
          <p className="hp-tn-cardsub">
            <code>&lt;listener&gt;</code> is <b>your</b> callback address and is never
            substituted with the target — the target below exists only to be scope-checked. The
            artifact path is chosen by the server, in the engagement&rsquo;s loot tree.
          </p>
          <div className="hp-tn-form">
            <select value={ios} onChange={(e) => setIos(e.target.value)} aria-label="os">
              <option value="windows">windows</option>
              <option value="linux">linux</option>
              <option value="darwin">darwin</option>
            </select>
            <select value={arch} onChange={(e) => setArch(e.target.value)} aria-label="arch">
              <option value="amd64">amd64</option>
              <option value="386">386</option>
              <option value="arm64">arm64</option>
            </select>
            <select value={fmt} onChange={(e) => setFmt(e.target.value)} aria-label="format">
              <option value="exe">exe</option>
              <option value="shared">shared (dll)</option>
              <option value="service">service</option>
              <option value="shellcode">shellcode</option>
            </select>
            <select
              value={transport}
              onChange={(e) => setTransport(e.target.value)}
              aria-label="transport"
            >
              <option value="mtls">mtls</option>
              <option value="https">https</option>
              <option value="dns">dns</option>
              <option value="wg">wg</option>
            </select>
            <input
              value={listener}
              onChange={(e) => setListener(e.target.value)}
              placeholder="<listener> — YOUR callback address, verbatim"
              aria-label="listener"
            />
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="declared target — scope-checked, never written into the implant"
              aria-label="target"
            />
            <button type="button" onClick={doPreview} disabled={!target.trim()}>
              preview argv
            </button>
          </div>

          {preview && (
            <div className="hp-tn-routeout">
              <div className="hp-code hp-tn-olcode">
                <div className="hp-code-bar">
                  <span className="hp-code-lang">would run</span>
                  <CopyButton text={preview.argv.join(" ")} />
                </div>
                <pre className="hp-code-pre">
                  <code>{preview.argv.join(" ")}</code>
                </pre>
              </div>
              <p className="hp-tn-note">
                Pure preview — nothing ran.{" "}
                {preview.rejected
                  ? `The [${preview.rejected.gate}] gate would refuse this: ${preview.rejected.reason}`
                  : "Every gate clears for this build."}
              </p>
            </div>
          )}

          {/* RED CONFIRM — the backend's danger gate refused; re-confirm to proceed. */}
          {dangerReason && (
            <div className="hp-cs-danger" role="alert">
              <b>This builds a beacon that runs on someone else&rsquo;s machine.</b>
              <span className="hp-cs-danger-why">{dangerReason}</span>
              <span className="hp-cs-danger-why">
                It is written to the loot tree and left there — HackPit will not deliver or run
                it. Confirm to build it.
              </span>
              <button
                type="button"
                className="hp-cs-confirm"
                onClick={() => build(true)}
                disabled={building}
              >
                {building ? "building…" : "I understand — build it"}
              </button>
            </div>
          )}
          {!dangerReason && (
            <button
              type="button"
              className="hp-tn-addscope"
              onClick={() => build(false)}
              disabled={building || !target.trim()}
            >
              {building ? "building…" : "approve & build →"}
            </button>
          )}

          {implants.length > 0 && (
            <ul className="hp-tn-list">
              {implants.map((i) => (
                <li key={i.id} className={`hp-tn-row is-${i.status === "generated" ? "listening" : "down"}`}>
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">
                      {i.os}/{i.arch}/{i.fmt}
                    </span>
                    <span className={`hp-tn-state is-${i.status === "generated" ? "listening" : "down"}`}>
                      {i.status}
                    </span>
                    <span className="hp-tn-subs">{i.artifact_path}</span>
                  </div>
                  <p className="hp-tn-note">
                    mode <b>{i.mode}</b> · transport {i.transport} · callback{" "}
                    <code>{i.listener}</code> · run <code>{i.run_id}</code>
                    {i.detail ? ` · ${i.detail}` : ""}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* ---- dns tunnel listener (HUMAN-ONLY) ---- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">dns tunnel listener — human-only</div>
          <p className="hp-tn-cardsub">
            The authoritative server for a zone <b>you</b> control and have had delegated. The
            client half runs on the far side and you carry it across by hand — HackPit cannot
            reach a machine it has not compromised, and does not try. Your pre-shared key is
            never returned by the API: the line below shows it as <code>***</code>.
          </p>
          <div className="hp-tn-form">
            <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="kind">
              <option value="dnscat2">dnscat2 (encrypted C2 over DNS)</option>
              <option value="iodine">iodine (IP-over-DNS · louder)</option>
            </select>
            <input
              value={zone}
              onChange={(e) => setZone(e.target.value)}
              placeholder="<tunnel-zone> — a zone YOU control, e.g. t.operator.example"
              aria-label="zone"
            />
            <input
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder="pre-shared key, 8+ chars (required for iodine)"
              minLength={8}
              aria-label="secret"
              type="password"
            />
            {kind === "iodine" && (
              <input
                value={tunnelNet}
                onChange={(e) => setTunnelNet(e.target.value)}
                placeholder="<tunnel-net> — the tunnel's OWN private range"
                aria-label="tunnel net"
              />
            )}
            <button
              type="button"
              onClick={startListener}
              disabled={startingListener || !zone.trim()}
            >
              {startingListener ? "starting…" : "start listener ▸"}
            </button>
          </div>

          {listeners.length > 0 && (
            <ul className="hp-tn-list">
              {listeners.map((l) => (
                <li key={l.id} className={`hp-tn-row is-${l.status}`}>
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">{l.kind}</span>
                    <span className={`hp-tn-state is-${l.status}`}>{l.status}</span>
                    <span className="hp-tn-subs">
                      {l.zone}
                      {l.tunnel_net ? ` · ${l.tunnel_net}` : ""}
                    </span>
                    <button
                      type="button"
                      className="hp-tn-stop"
                      onClick={() => stopListener(l.id)}
                      disabled={l.status === "down"}
                    >
                      stop
                    </button>
                  </div>
                  <div className="hp-tn-oneliner">
                    <div className="hp-tn-olhint">
                      run BY HAND on the host you already have execution on (substitute your own
                      key for ***):
                    </div>
                    <div className="hp-code hp-tn-olcode">
                      <div className="hp-code-bar">
                        <span className="hp-code-lang">client</span>
                        <CopyButton text={l.client_command} />
                      </div>
                      <pre className="hp-code-pre">
                        <code>{l.client_command}</code>
                      </pre>
                    </div>
                    <p className="hp-tn-note">{l.setup_note}</p>
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
