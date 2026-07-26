"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  addPivotSubnet,
  getTunnelsStatus,
  listTunnels,
  routeCommand,
  startTunnel,
  stopTunnel,
  type RouteResult,
  type Tunnel,
  type TunnelsStatus,
} from "@/lib/api";

/**
 * Pivot / tunnel routing — chisel + ligolo-ng.
 *
 * The flow (option 1): start a listener in the sandbox → paste the one-liner on the
 * compromised host → the internal subnet reaches you. A command to that subnet is REWRITTEN
 * (proxychains prefix, VISIBLE) before you approve it, and the subnet enters scope only when
 * you add it by hand. Starting/stopping a listener is human-only; nothing here is autonomous.
 */
export function TunnelsScreen() {
  const [status, setStatus] = useState<TunnelsStatus | null>(null);
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [error, setError] = useState<string | null>(null);

  // start form
  const [kind, setKind] = useState("chisel");
  const [lhost, setLhost] = useState("");
  const [port, setPort] = useState("");
  const [subnets, setSubnets] = useState("");
  const [engagementId, setEngagementId] = useState("");
  const [starting, setStarting] = useState(false);

  // route preview
  const [rCmd, setRCmd] = useState("nmap -sV");
  const [rHost, setRHost] = useState("");
  const [route, setRoute] = useState<RouteResult | null>(null);

  const refresh = useCallback(() => {
    getTunnelsStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
    listTunnels()
      .then(setTunnels)
      .catch(() => setTunnels([]));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const start = useCallback(async () => {
    if (!lhost.trim() || starting) return;
    setStarting(true);
    setError(null);
    try {
      await startTunnel({
        kind,
        lhost: lhost.trim(),
        listen_port: port.trim() ? Number(port) : null,
        subnets: subnets
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        engagement_id: engagementId.trim() || null,
      });
      refresh();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setStarting(false);
    }
  }, [kind, lhost, port, subnets, engagementId, starting, refresh]);

  const stop = useCallback(
    async (tid: string) => {
      try {
        await stopTunnel(tid);
      } finally {
        refresh();
      }
    },
    [refresh]
  );

  const preview = useCallback(async () => {
    if (!rHost.trim()) return;
    const [command, ...args] = rCmd.trim().split(/\s+/);
    try {
      const res = await routeCommand({ command, args, host: rHost.trim() });
      setRoute(res);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [rCmd, rHost]);

  const addSubnet = useCallback(
    async (cidr: string) => {
      if (!engagementId.trim()) {
        setError("Set an engagement id above to add a subnet to its scope.");
        return;
      }
      try {
        await addPivotSubnet(engagementId.trim(), cidr);
        setError(null);
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
      }
    },
    [engagementId]
  );

  const up = status?.up ?? false;

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "tunnels" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">pivot · chisel · ligolo-ng</div>
          <h1 className="hp-tn-title">:tunnels</h1>
          <p className="hp-tn-sub">
            Route through a compromised host into an internal subnet. Start a listener, paste the
            one-liner on the box you own, then commands to that subnet are rewritten to run through
            the tunnel — you approve the exact string, prefix and all.
          </p>
          <div className={`hp-tn-status ${up ? "is-up" : "is-down"}`}>
            <span className="hp-tn-dot" />
            {up
              ? `engage sandbox ready · ${status?.live_tunnels ?? 0} live`
              : `engage sandbox down — bring the stack up (${status?.detail || "not running"})`}
          </div>
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        {/* ---- start a tunnel ---- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">start a tunnel</div>
          <div className="hp-tn-form">
            <select value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Kind">
              <option value="chisel">chisel (SOCKS · proxychains)</option>
              <option value="ligolo">ligolo-ng (interface · ip route)</option>
            </select>
            <input
              value={lhost}
              onChange={(e) => setLhost(e.target.value)}
              placeholder="lhost — your VPN IP the victim connects back to"
              aria-label="lhost"
            />
            <input
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="port (optional)"
              aria-label="port"
              className="hp-tn-port"
            />
            <input
              value={subnets}
              onChange={(e) => setSubnets(e.target.value)}
              placeholder="internal subnets — 172.16.0.0/24, 10.10.0.0/16"
              aria-label="subnets"
            />
            <input
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
              placeholder="engagement id (for scope amendment)"
              aria-label="engagement id"
            />
            <button type="button" onClick={start} disabled={starting || !lhost.trim()}>
              {starting ? "starting…" : "start ▸"}
            </button>
          </div>
        </section>

        {/* ---- live tunnels ---- */}
        {tunnels.length > 0 && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">tunnels</div>
            <ul className="hp-tn-list">
              {tunnels.map((t) => (
                <li key={t.id} className={`hp-tn-row is-${t.status}`}>
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">{t.kind}</span>
                    <span className={`hp-tn-state is-${t.status}`}>{t.status}</span>
                    <span className="hp-tn-subs">{t.subnets.join(", ") || "no subnet set"}</span>
                    <button
                      type="button"
                      className="hp-tn-stop"
                      onClick={() => stop(t.id)}
                      disabled={t.status === "down"}
                    >
                      stop
                    </button>
                  </div>
                  <div className="hp-tn-oneliner">
                    <div className="hp-tn-olhint">paste on the compromised host:</div>
                    <div className="hp-code hp-tn-olcode">
                      <div className="hp-code-bar">
                        <span className="hp-code-lang">agent</span>
                        <CopyButton text={t.agent_command} />
                      </div>
                      <pre className="hp-code-pre">
                        <code>{t.agent_command}</code>
                      </pre>
                    </div>
                    <p className="hp-tn-note">{t.setup_note}</p>
                    {t.subnets.map((s) => (
                      <button
                        key={s}
                        type="button"
                        className="hp-tn-addscope"
                        onClick={() => addSubnet(s)}
                        title="Deliberately add this subnet to the engagement scope"
                      >
                        + add {s} to scope (by hand)
                      </button>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          </section>
        )}

        {/* ---- route preview (rewrite-before-approval) ---- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">route a command</div>
          <p className="hp-tn-cardsub">
            See how a command to an internal host is rewritten before you approve it. Pure preview
            — nothing runs.
          </p>
          <div className="hp-tn-routeform">
            <input
              value={rCmd}
              onChange={(e) => setRCmd(e.target.value)}
              placeholder="command — nmap -sV"
              aria-label="command"
            />
            <input
              value={rHost}
              onChange={(e) => setRHost(e.target.value)}
              placeholder="target host — 172.16.0.10"
              aria-label="host"
            />
            <button type="button" onClick={preview} disabled={!rHost.trim()}>
              route
            </button>
          </div>
          {route && (
            <div className="hp-tn-routeout">
              {route.routed ? (
                <>
                  <div className="hp-tn-routebadge">routed via tunnel {route.tunnel?.id}</div>
                  <div className="hp-code hp-tn-olcode">
                    <div className="hp-code-bar">
                      <span className="hp-code-lang">approve this</span>
                      <CopyButton text={[route.command, ...route.args].join(" ")} />
                    </div>
                    <pre className="hp-code-pre">
                      <code>{[route.command, ...route.args].join(" ")}</code>
                    </pre>
                  </div>
                  <p className="hp-tn-note">{route.note}</p>
                </>
              ) : (
                <p className="hp-tn-note">
                  No live tunnel reaches that host — the command is unchanged. Start a tunnel whose
                  subnet covers it first.
                </p>
              )}
            </div>
          )}
        </section>
      </div>
    </PageShell>
  );
}
