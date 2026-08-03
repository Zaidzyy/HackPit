"use client";

import { useCallback, useEffect, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  applyExposureProfile,
  deleteExposureProfile,
  deleteRemoteExposure,
  deployRedirector,
  getExposure,
  getRemoteExposure,
  stopRedirector,
  writeExposureProfile,
  writeRemoteExposure,
  type ExposureStatus,
  type RedirectorDeployResult,
  type RemoteExposureStatus,
} from "@/lib/api";

/**
 * :exposure — where a callback lands (build #13 parts 1 and 4).
 *
 * Two destinations, and they are genuinely different operations rather than one with a flag:
 *
 *   * LOCAL — publish container ports on an interface of this machine. Applying it recreates
 *     the container, which kills every listener, session and background job inside it, so it
 *     is approval-gated.
 *   * REMOTE — publish on the VPS configured on the :oob screen, by shipping a bounded
 *     forwarder there. This is a PUBLIC listener that relays into this machine; the panel says
 *     so in those words, because a row of green ticks would be describing something else.
 *
 * Nothing here carries an address to the deploy. The remote buttons send an approval and
 * nothing else — the host comes from the canary config store and the ports from the saved
 * profile, both resolved server-side.
 *
 * Part 1 shipped its four endpoints with no caller at all; this screen is where they finally
 * get one, which is the gap build #12 existed to close.
 */
export function ExposureScreen() {
  const [local, setLocal] = useState<ExposureStatus | null>(null);
  const [remote, setRemote] = useState<RemoteExposureStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [deployed, setDeployed] = useState<RedirectorDeployResult | null>(null);

  // shared port selection
  const [kinds, setKinds] = useState<string[]>([]);
  const [extraPort, setExtraPort] = useState("");
  const [extraProto, setExtraProto] = useState<"tcp" | "udp">("tcp");
  const [extra, setExtra] = useState<[number, string][]>([]);
  const [engagement, setEngagement] = useState("");

  // local only
  const [ip, setIp] = useState("");
  const [container, setContainer] = useState("engage-sandbox");
  const [ackWildcard, setAckWildcard] = useState(false);

  // both
  const [ackPublic, setAckPublic] = useState(false);
  const [approved, setApproved] = useState(false);

  const refresh = useCallback(
    () =>
      Promise.all([
        getExposure().then(setLocal).catch(() => setLocal(null)),
        getRemoteExposure().then(setRemote).catch(() => setRemote(null)),
      ]).then(() => undefined),
    []
  );

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = useCallback(async (label: string, fn: () => Promise<void>) => {
    setBusy(label);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : `${label} failed`);
    } finally {
      setBusy(null);
    }
  }, []);

  const body = useCallback(
    () => ({
      ip: ip.trim(),
      container,
      kinds,
      extra,
      engagement: engagement.trim() || null,
      ack_wildcard: ackWildcard,
      ack_public: ackPublic,
    }),
    [ip, container, kinds, extra, engagement, ackWildcard, ackPublic]
  );

  const toggleKind = useCallback((kind: string) => {
    setKinds((prev) => (prev.includes(kind) ? prev.filter((k) => k !== kind) : [...prev, kind]));
  }, []);

  const addExtra = useCallback(() => {
    const port = Number(extraPort);
    if (!port || port < 1 || port > 65535) return;
    setExtra((prev) =>
      prev.some(([p, q]) => p === port && q === extraProto) ? prev : [...prev, [port, extraProto]]
    );
    setExtraPort("");
  }, [extraPort, extraProto]);

  const saveLocal = useCallback(
    () => run("save-local", async () => { await writeExposureProfile(body()); await refresh(); }),
    [run, body, refresh]
  );
  const applyLocal = useCallback(
    () =>
      run("apply-local", async () => {
        await applyExposureProfile({ ...body(), approved });
        await refresh();
      }),
    [run, body, approved, refresh]
  );
  const clearLocal = useCallback(
    () => run("clear-local", async () => { await deleteExposureProfile(); await refresh(); }),
    [run, refresh]
  );

  const saveRemote = useCallback(
    () => run("save-remote", async () => { await writeRemoteExposure(body()); await refresh(); }),
    [run, body, refresh]
  );
  const clearRemote = useCallback(
    () => run("clear-remote", async () => { await deleteRemoteExposure(); await refresh(); }),
    [run, refresh]
  );
  const deploy = useCallback(
    () =>
      run("deploy", async () => {
        setDeployed(await deployRedirector(approved));
        await refresh();
      }),
    [run, approved, refresh]
  );
  const stop = useCallback(
    () =>
      run("stop", async () => {
        setDeployed(await stopRedirector(approved));
        await refresh();
      }),
    [run, approved, refresh]
  );

  const describe = deployed?.describe ?? remote?.describe;

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "exposure" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">reverse shells · sliver · chisel · ligolo · dns tunnels</div>
          <h1 className="hp-tn-title">:exposure</h1>
          <p className="hp-tn-sub">
            Where a callback lands. A target dialling you needs a port published somewhere it can
            route to — an interface on this machine when it can reach you, or a redirector on
            your own VPS when it cannot. Nothing here is published by default, and nothing is
            published by writing a profile.
          </p>
          {local && (
            <div className="hp-tn-status">
              <span className="hp-tn-dot" />
              local: {local.state}
              {local.note ? ` — ${local.note}` : ""}
            </div>
          )}
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        {/* ---- ports (shared by both destinations) ------------------------ */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">1 · which ports</div>
          <div className="hp-tn-form">
            {Object.entries(local?.kinds ?? {}).map(([kind, spec]) => (
              <label key={kind} className="hp-tn-olhint" style={{ display: "flex", gap: "0.4rem" }}>
                <input
                  type="checkbox"
                  checked={kinds.includes(kind)}
                  onChange={() => toggleKind(kind)}
                  aria-label={`Publish ${kind}`}
                />
                {kind} ({spec.port}/{spec.proto})
              </label>
            ))}
            <input
              className="hp-tn-port"
              value={extraPort}
              onChange={(e) => setExtraPort(e.target.value)}
              placeholder="port"
              aria-label="Extra port"
            />
            <select
              className="hp-tn-input"
              value={extraProto}
              onChange={(e) => setExtraProto(e.target.value as "tcp" | "udp")}
              aria-label="Protocol"
            >
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
            <button className="hp-tn-stop" onClick={addExtra} disabled={!extraPort.trim()}>
              add
            </button>
            <input
              className="hp-tn-input"
              value={engagement}
              onChange={(e) => setEngagement(e.target.value)}
              placeholder="engagement (recorded for audit; scopes nothing)"
              aria-label="Engagement"
            />
          </div>
          <p className="hp-tn-olhint">
            {extra.length > 0
              ? `extra: ${extra.map(([p, q]) => `${p}/${q}`).join(", ")} · `
              : ""}
            A plain reverse shell is not one of the known kinds — add 443 or 4444 above. Ranges
            are refused: one typo publishes hundreds of ports and the summary stops being
            readable, which is the whole point of it.
          </p>
        </section>

        {/* ---- local ------------------------------------------------------ */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">2a · local — an interface on this machine</div>
          <div className="hp-tn-form">
            <input
              className="hp-tn-input"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="bind address (e.g. 192.168.13.1) or 0.0.0.0"
              aria-label="Bind address"
            />
            <select
              className="hp-tn-input"
              value={container}
              onChange={(e) => setContainer(e.target.value)}
              aria-label="Container"
            >
              {(local?.exposable ?? ["engage-sandbox", "kali-open"]).map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
            <label className="hp-tn-olhint" style={{ display: "flex", gap: "0.4rem" }}>
              <input
                type="checkbox"
                checked={ackWildcard}
                onChange={(e) => setAckWildcard(e.target.checked)}
                aria-label="Acknowledge a wildcard bind"
              />
              I know 0.0.0.0 binds every interface
            </label>
            <button className="hp-tn-start" onClick={saveLocal} disabled={busy !== null}>
              {busy === "save-local" ? "…" : "write profile"}
            </button>
            <button className="hp-tn-stop" onClick={applyLocal} disabled={busy !== null || !approved}>
              {busy === "apply-local" ? "…" : "apply (recreates container)"}
            </button>
            <button className="hp-tn-stop" onClick={clearLocal} disabled={busy !== null}>
              clear
            </button>
          </div>
          <p className="hp-tn-olhint">
            Applying recreates the container, which kills every listener, session and background
            job inside it — hence the approval below. The lab sandbox is never in this list: its
            network is internal, and publishing a port would break the isolation gate that
            refuses every lab command.
          </p>
          {local && local.expected.length > 0 && (
            <p className="hp-tn-olhint">
              expected: {local.expected.map(([p, q]) => `${p}/${q}`).join(", ")} · observed state{" "}
              <strong>{local.state}</strong>
            </p>
          )}
        </section>

        {/* ---- remote ----------------------------------------------------- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">2b · remote — a redirector on your VPS</div>
          <p className="hp-tn-olhint">
            For a target that cannot route to you at all. A bounded forwarder runs on the VPS
            configured on the <code>:oob</code> screen, accepts on a public port, and relays down
            a reverse tunnel you dial outward. It forwards to one loopback port and nowhere else.
          </p>
          <div className="hp-tn-form">
            <label className="hp-tn-olhint" style={{ display: "flex", gap: "0.4rem" }}>
              <input
                type="checkbox"
                checked={ackPublic}
                onChange={(e) => setAckPublic(e.target.checked)}
                aria-label="Acknowledge a public listener"
              />
              I understand this is a public listener that relays into this machine
            </label>
            <button className="hp-tn-start" onClick={saveRemote} disabled={busy !== null || !ackPublic}>
              {busy === "save-remote" ? "…" : "save remote profile"}
            </button>
            <button className="hp-tn-stop" onClick={clearRemote} disabled={busy !== null}>
              forget
            </button>
          </div>

          {remote?.note && <p className="hp-tn-olhint">{remote.note}</p>}

          {remote?.profile && (
            <>
              <div className="hp-tn-form">
                <label className="hp-tn-olhint" style={{ display: "flex", gap: "0.4rem" }}>
                  <input
                    type="checkbox"
                    checked={approved}
                    onChange={(e) => setApproved(e.target.checked)}
                    aria-label="Approve"
                  />
                  I approve this action
                </label>
                <button className="hp-tn-start" onClick={deploy} disabled={busy !== null || !approved}>
                  {busy === "deploy" ? "shipping…" : "deploy + start"}
                </button>
                <button className="hp-tn-stop" onClick={stop} disabled={busy !== null || !approved}>
                  {busy === "stop" ? "stopping…" : "stop redirector"}
                </button>
              </div>
              {deployed && (
                <ul className="hp-tn-list">
                  {deployed.steps.map((s) => (
                    <li key={s.step} className="hp-tn-row">
                      <div className="hp-tn-rowtop">
                        <span className="hp-tn-kind">
                          {s.exit_code === 0 ? "✓" : "✗"} {s.step}
                        </span>
                        <span className="hp-tn-subs">
                          {(s.stdout || s.stderr || "").trim().slice(0, 200) ||
                            `exit ${s.exit_code}`}
                        </span>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </section>

        {/* ---- what it exposes, and the tunnel you have to run ------------- */}
        {describe && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">3 · what this exposes, and how to reach it</div>
            <div className="hp-tn-error">{describe.exposure}</div>
            <p className="hp-tn-olhint">{describe.aup}</p>
            <p className="hp-tn-olhint">{describe.not_authenticated}</p>

            <div className="hp-tn-cardhead">the reverse tunnel — run this HERE</div>
            <div className="hp-tn-oneliner">
              <pre className="hp-tn-pre">{describe.reverse_tunnel.join(" ")}</pre>
              <CopyButton text={describe.reverse_tunnel.join(" ")} />
            </div>
            <p className="hp-tn-olhint">
              HackPit renders this and does not run it — it is a long-lived outbound process on
              your machine, and starting it deliberately is the approval. Until it is up, the
              redirector accepts connections and drops them.
            </p>

            {describe.udp_bridges.length > 0 && (
              <>
                <div className="hp-tn-cardhead">udp needs a socat bridge (ssh -R carries tcp only)</div>
                {describe.udp_bridges.map((b) => (
                  <div key={`${b.port}-${b.where}`} className="hp-tn-oneliner">
                    <pre className="hp-tn-pre">{b.command}</pre>
                    <CopyButton text={b.command} />
                    <div className="hp-tn-olhint">
                      {b.where} — {b.why}
                    </div>
                  </div>
                ))}
              </>
            )}

            <div className="hp-tn-cardhead">take it down</div>
            <div className="hp-tn-oneliner">
              <pre className="hp-tn-pre">{describe.teardown}</pre>
              <CopyButton text={describe.teardown} />
            </div>
          </section>
        )}
      </div>
    </PageShell>
  );
}
