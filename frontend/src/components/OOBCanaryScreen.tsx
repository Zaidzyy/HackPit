"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  deleteOOBConfig,
  deployOOB,
  deregisterInteractsh,
  getOOB,
  listOOBTokens,
  mintOOBToken,
  pollOOB,
  registerInteractsh,
  saveOOBConfig,
  setOOBAutopoll,
  verifyOOB,
  type OOBCheck,
  type OOBDeployResult,
  type OOBMintResult,
  type OOBPayload,
  type OOBPollResult,
  type OOBStatus,
  type OOBToken,
  type OOBVerifyResult,
} from "@/lib/api";

/** send-to-repeater hands a payload across screens through sessionStorage; RepeaterScreen reads
 *  and clears this key on mount. The same channel HackPitShell uses for its entered flag. */
const REPEATER_SEED_KEY = "hp-repeater-seed";

/**
 * :oob — the out-of-band canary panel (build #13 part 3, spec §3.5).
 *
 * Whole classes of vulnerability are unconfirmable without an internet-reachable listener,
 * because the callback IS the entire proof: blind SSRF, blind XXE, blind RCE with no output,
 * DNS-exfil SQLi, JNDI. This screen configures that listener, ships it, proves it works, mints
 * the tokens that go into payloads, and reads the hits back as findings.
 *
 * Three things about it are deliberate and worth knowing before editing:
 *
 *   * The read secret is WRITE-ONLY. It is never returned by the API, so the field is always
 *     blank on load and leaving it blank on save keeps the stored value.
 *   * Deploy carries NO destination. The button sends `{approved}` and nothing else — the
 *     server resolves the VPS from its own config store, which is what makes the deploy
 *     host-locked. Do not add a host field here; there is no parameter for it.
 *   * NOT-RUN is rendered as its own status, never as a pass. Two of verify's three checks run
 *     anywhere; the third needs real NS delegation and says so.
 */
export function OOBCanaryScreen() {
  const [status, setStatus] = useState<OOBStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  // configure form
  const [zone, setZone] = useState("");
  const [host, setHost] = useState("");
  const [answerIp, setAnswerIp] = useState("");
  const [sshUser, setSshUser] = useState("root");
  const [sshPort, setSshPort] = useState("22");
  const [sshKeyPath, setSshKeyPath] = useState("");
  const [httpPort, setHttpPort] = useState("80");
  const [secret, setSecret] = useState("");

  // actions
  const [approved, setApproved] = useState(false);
  const [deployed, setDeployed] = useState<OOBDeployResult | null>(null);
  const [verified, setVerified] = useState<OOBVerifyResult | null>(null);
  const [polled, setPolled] = useState<OOBPollResult | null>(null);

  // mint
  const [engagementId, setEngagementId] = useState("");
  const [stepId, setStepId] = useState("");
  const [note, setNote] = useState("");
  const [vulnClass, setVulnClass] = useState("");
  const [minted, setMinted] = useState<OOBMintResult | null>(null);
  const [tokenList, setTokenList] = useState<OOBToken[]>([]);

  // interact.sh backend (zero-infrastructure)
  const [interactshServer, setInteractshServer] = useState("");
  const [interactshAuth, setInteractshAuth] = useState("");

  const router = useRouter();

  /** Every setState here lands in a `.then` callback, never in the effect body — that is the
   *  accepted pattern in frontend/AGENTS.md, and writing it as an `async` function whose body
   *  the effect calls directly is what pushes the eslint baseline up. Returns the promise so
   *  the actions below can await it. */
  const refresh = useCallback(
    () =>
      getOOB()
        .then((next) => {
          setStatus(next);
          if (next.config) {
            setZone(next.config.zone);
            setHost(next.config.host);
            setAnswerIp(next.config.answer_ip);
            setSshUser(next.config.ssh_user);
            setSshPort(String(next.config.ssh_port));
            setSshKeyPath(next.config.ssh_key_path);
            setHttpPort(String(next.config.http_port));
          }
        })
        .catch(() => setStatus(null)),
    []
  );

  useEffect(() => {
    void refresh();
  }, [refresh]);

  /** Every action runs through here so exactly one is in flight and errors read the same. */
  const run = useCallback(
    async (label: string, fn: () => Promise<void>) => {
      setBusy(label);
      setError(null);
      try {
        await fn();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : `${label} failed`);
      } finally {
        setBusy(null);
      }
    },
    []
  );

  const save = useCallback(
    () =>
      run("save", async () => {
        await saveOOBConfig({
          zone: zone.trim(),
          host: host.trim(),
          answer_ip: answerIp.trim(),
          ssh_user: sshUser.trim() || "root",
          ssh_port: Number(sshPort) || 22,
          ssh_key_path: sshKeyPath.trim(),
          http_port: Number(httpPort) || 80,
          read_secret: secret,
        });
        setSecret("");
        await refresh();
      }),
    [run, zone, host, answerIp, sshUser, sshPort, sshKeyPath, httpPort, secret, refresh]
  );

  const forget = useCallback(
    () =>
      run("forget", async () => {
        await deleteOOBConfig();
        setDeployed(null);
        setVerified(null);
        await refresh();
      }),
    [run, refresh]
  );

  const deploy = useCallback(
    () =>
      run("deploy", async () => {
        setDeployed(await deployOOB(approved));
        await refresh();
      }),
    [run, approved, refresh]
  );

  const verify = useCallback(
    () => run("verify", async () => setVerified(await verifyOOB())),
    [run]
  );

  const poll = useCallback(
    () =>
      run("poll", async () => {
        setPolled(await pollOOB());
        await refresh();
      }),
    [run, refresh]
  );

  const mint = useCallback(
    () =>
      run("mint", async () => {
        const result = await mintOOBToken({
          engagement_id: engagementId.trim(),
          step_id: stepId.trim() || null,
          note: note.trim(),
          vuln_class: vulnClass || null,
        });
        setMinted(result);
        const listed = await listOOBTokens(engagementId.trim());
        setTokenList(listed.tokens);
      }),
    [run, engagementId, stepId, note, vulnClass]
  );

  const registerIsh = useCallback(
    () =>
      run("register-ish", async () => {
        await registerInteractsh({
          server: interactshServer.trim() || undefined,
          auth_token: interactshAuth.trim() || undefined,
        });
        setInteractshAuth("");
        await refresh();
      }),
    [run, interactshServer, interactshAuth, refresh]
  );

  const deregisterIsh = useCallback(
    () =>
      run("deregister-ish", async () => {
        await deregisterInteractsh();
        await refresh();
      }),
    [run, refresh]
  );

  const toggleAutopoll = useCallback(
    (enabled: boolean, interval: number) =>
      run("autopoll", async () => {
        await setOOBAutopoll({ enabled, interval });
        await refresh();
      }),
    [run, refresh]
  );

  /** Hand a rendered payload to the repeater: stash it, then navigate. RepeaterScreen seeds its
   *  URL (for http(s):// payloads) or body from this on mount. Delivery stays a human action —
   *  the operator still clicks Send there; nothing is sent from here. */
  const sendToRepeater = useCallback(
    (payload: string) => {
      try {
        sessionStorage.setItem(REPEATER_SEED_KEY, payload);
      } catch {
        /* private mode / storage disabled — the repeater just opens empty */
      }
      router.push("/repeater");
    },
    [router]
  );

  const config = status?.config ?? null;
  const interactsh = status?.interactsh ?? null;
  const autopoll = status?.autopoll ?? null;
  const anyBackend = Boolean(config) || Boolean(interactsh);

  /** One payload row, reused for both backends: the technique, the one-liner, copy + send. */
  const renderPayload = (p: OOBPayload) => (
    <li key={p.id} className="hp-tn-row">
      <div className="hp-tn-rowtop">
        <span className="hp-tn-kind">{p.vuln_class}</span>
        <span className="hp-tn-subs">
          {p.title} — {p.sink}
        </span>
      </div>
      <div className="hp-tn-oneliner">
        <pre className="hp-tn-pre">{p.payload}</pre>
        <CopyButton text={p.payload} />
        <button
          className="hp-tn-stop"
          onClick={() => sendToRepeater(p.payload)}
          title="Open the repeater with this payload pre-filled — you still click Send there"
        >
          → repeater
        </button>
      </div>
      <div className="hp-tn-olhint">
        A hit proves: {p.proves}
        {p.note ? ` · ${p.note}` : ""}
      </div>
    </li>
  );

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "oob canary" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">blind SSRF · blind XXE · blind RCE · DNS-exfil SQLi · JNDI</div>
          <h1 className="hp-tn-title">:oob canary</h1>
          <p className="hp-tn-sub">
            An internet-reachable listener you own, so a blind vulnerability can be{" "}
            <em>confirmed</em> instead of written up as unconfirmed. HackPit mints a token,
            renders it into the payload you paste, and correlates the callback back to the step
            that caused it. It does not buy the domain or create the server — you do that once,
            then everything here is buttons.
          </p>
          <div className="hp-tn-status">
            <span className="hp-tn-dot" />
            {config
              ? `${config.zone} → ${config.host}:${config.http_port} · ${
                  config.has_secret ? "read secret set" : "⚠ no read secret"
                } · cursor ${config.cursor}${
                  config.deployed_at ? ` · last shipped ${config.deployed_at.slice(0, 19)}` : " · never deployed"
                }`
              : "no canary configured yet"}
          </div>
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        {/* ---- configure -------------------------------------------------- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">1 · configure</div>
          <div className="hp-tn-form">
            <input
              className="hp-tn-input"
              value={zone}
              onChange={(e) => setZone(e.target.value)}
              placeholder="delegated zone (e.g. oob.example.net)"
              aria-label="Zone"
            />
            <input
              className="hp-tn-input"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="VPS address (the box you already own)"
              aria-label="VPS host"
            />
            <input
              className="hp-tn-input"
              value={answerIp}
              onChange={(e) => setAnswerIp(e.target.value)}
              placeholder="answer IP (blank = the VPS address)"
              aria-label="Answer IP"
            />
            <input
              className="hp-tn-port"
              value={httpPort}
              onChange={(e) => setHttpPort(e.target.value)}
              placeholder="80"
              aria-label="HTTP port"
            />
            <input
              className="hp-tn-input"
              value={sshUser}
              onChange={(e) => setSshUser(e.target.value)}
              placeholder="ssh user"
              aria-label="SSH user"
            />
            <input
              className="hp-tn-port"
              value={sshPort}
              onChange={(e) => setSshPort(e.target.value)}
              placeholder="22"
              aria-label="SSH port"
            />
            <input
              className="hp-tn-input"
              value={sshKeyPath}
              onChange={(e) => setSshKeyPath(e.target.value)}
              placeholder="path to a private key already on this machine"
              aria-label="SSH key path"
            />
            <input
              className="hp-tn-input"
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={
                config?.has_secret ? "read secret (blank keeps the stored one)" : "read secret (16+ chars)"
              }
              aria-label="Read secret"
              autoComplete="new-password"
            />
          </div>
          {/* CONFIGURE above, ACT below — the same shared divider :exposure uses. */}
          <div className="hp-tn-actions">
            <span className="hp-tn-actions-label">act</span>
            <button
              className="hp-tn-start"
              onClick={save}
              disabled={busy !== null || !zone.trim() || !host.trim()}
            >
              {busy === "save" ? "saving…" : "save"}
            </button>
            {config && (
              <button className="hp-tn-stop" onClick={forget} disabled={busy !== null}>
                {busy === "forget" ? "…" : "forget"}
              </button>
            )}
          </div>
          <p className="hp-tn-note">
            The read secret is write-only: stored server-side, never sent back to this page. The
            SSH key is a <em>path</em> — HackPit never stores a private key. &ldquo;Forget&rdquo;
            removes HackPit&rsquo;s knowledge of the canary; a server already running on the VPS
            keeps running.
          </p>
        </section>

        {/* ---- NS delegation --------------------------------------------- */}
        {status?.ns && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">2 · delegate the zone at your registrar</div>
            <div className="hp-tn-oneliner">
              <pre className="hp-tn-pre">{status.ns.zonefile}</pre>
              <CopyButton text={status.ns.zonefile} />
            </div>
            <p className="hp-tn-note">
              Add these to the <strong>{status.ns.parent_zone}</strong> zone. {status.ns.warning}
            </p>
          </section>
        )}

        {/* ---- deploy ----------------------------------------------------- */}
        {config && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">3 · deploy</div>
            <p className="hp-tn-note">
              Ships <code>oob/server.py</code> to <code>{config.ssh_user}@{config.host}</code> and
              starts it. This is a remote-execution path and starts a listener on the public
              internet, so it needs an explicit approval every time. The button sends no
              destination — the server reads it from its own config.
            </p>
            <div className="hp-tn-form">
              <label className="hp-tn-olhint" style={{ display: "flex", gap: "0.5rem" }}>
                <input
                  type="checkbox"
                  checked={approved}
                  onChange={(e) => setApproved(e.target.checked)}
                  aria-label="Approve this deploy"
                />
                I approve this deploy
              </label>
            </div>
            <div className="hp-tn-actions">
              <span className="hp-tn-actions-label">act</span>
              <button
                className="hp-tn-start"
                onClick={deploy}
                disabled={busy !== null || !approved}
              >
                {busy === "deploy" ? "shipping…" : "deploy + start"}
              </button>
            </div>
            {deployed && (
              <ul className="hp-tn-list">
                {deployed.steps.map((s) => (
                  <li key={s.step} className="hp-tn-row">
                    <div className="hp-tn-rowtop">
                      <span className="hp-tn-kind">{s.exit_code === 0 ? "✓" : "✗"} {s.step}</span>
                      <span className="hp-tn-subs">
                        {(s.stdout || s.stderr || "").trim().slice(0, 200) || `exit ${s.exit_code}`}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {/* ---- interact.sh — the zero-infrastructure backend --------------- */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">interact.sh · zero-infrastructure backend</div>
          <p className="hp-tn-note">
            No VPS and no domain: register with ProjectDiscovery&rsquo;s public OOB service and
            paste its host into a payload. Callbacks land in engagement state exactly like the
            self-hosted canary — the difference is they <em>transit a third party</em>, which is
            why the owned backend above still exists. Run both; paste whichever fits.
          </p>
          {interactsh ? (
            <>
              <ul className="hp-tn-list">
                <li className="hp-tn-row">
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">✓ registered</span>
                    <span className="hp-tn-subs">
                      {interactsh.server} · id {interactsh.correlation_prefix} ·{" "}
                      {interactsh.generated} payload{interactsh.generated === 1 ? "" : "s"} generated
                      {interactsh.last_poll ? ` · last poll ${interactsh.last_poll.slice(0, 19)}` : ""}
                    </span>
                  </div>
                </li>
              </ul>
              <div className="hp-tn-actions">
                <span className="hp-tn-actions-label">act</span>
                <button className="hp-tn-stop" onClick={deregisterIsh} disabled={busy !== null}>
                  {busy === "deregister-ish" ? "forgetting…" : "deregister + forget"}
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="hp-tn-form">
                <input
                  className="hp-tn-input"
                  value={interactshServer}
                  onChange={(e) => setInteractshServer(e.target.value)}
                  placeholder={`interact.sh server (default ${status?.interactsh_default_server ?? "oast.fun"})`}
                  aria-label="interact.sh server"
                />
                <input
                  className="hp-tn-input"
                  value={interactshAuth}
                  onChange={(e) => setInteractshAuth(e.target.value)}
                  placeholder="auth token (only for a self-hosted interactsh-server)"
                  aria-label="interact.sh auth token"
                />
              </div>
              <div className="hp-tn-actions">
                <span className="hp-tn-actions-label">act</span>
                <button className="hp-tn-start" onClick={registerIsh} disabled={busy !== null}>
                  {busy === "register-ish" ? "registering…" : "register a session"}
                </button>
              </div>
            </>
          )}
        </section>

        {/* ---- auto-poll --------------------------------------------------- */}
        {anyBackend && autopoll && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">auto-poll · file callbacks automatically</div>
            <p className="hp-tn-note">
              A background sweep reads your own callbacks from both backends and files the
              correlated ones as findings, so they appear without clicking <em>poll</em>. This is
              read-only automation — it sends nothing and runs no command; a human still approves
              every action against a target. Interval is floored at 30s.
            </p>
            <div className="hp-tn-actions">
              <span className="hp-tn-actions-label">act</span>
              <button
                className={autopoll.enabled ? "hp-tn-stop" : "hp-tn-start"}
                onClick={() => toggleAutopoll(!autopoll.enabled, autopoll.interval)}
                disabled={busy !== null}
              >
                {busy === "autopoll"
                  ? "saving…"
                  : autopoll.enabled
                    ? `on · every ${autopoll.interval}s — turn off`
                    : "off — turn on"}
              </button>
            </div>
          </section>
        )}

        {/* ---- verify ------------------------------------------------------ */}
        {anyBackend && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">verify · are the canaries working?</div>
            <p className="hp-tn-note">
              Every link in this chain fails <em>silently</em> — a payload that produces no hit
              looks the same whether the target was not vulnerable or the zone was never
              delegated. Each check reports itself; a check that cannot run here says so rather
              than counting as a pass.
            </p>
            <button className="hp-tn-start" onClick={verify} disabled={busy !== null}>
              {busy === "verify" ? "checking…" : "run the checks"}
            </button>
            {verified && (
              <ul className="hp-tn-list">
                {verified.checks.map((c: OOBCheck) => (
                  <li key={c.check} className="hp-tn-row">
                    <div className="hp-tn-rowtop">
                      <span className="hp-tn-kind">
                        {c.status === "pass" ? "✓" : c.status === "fail" ? "✗" : "◌"} {c.check}
                      </span>
                      <span className="hp-tn-subs">
                        {c.status === "not-run" ? "NOT-RUN — " : ""}
                        {c.detail}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {/* ---- mint + payloads --------------------------------------------- */}
        {anyBackend && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">mint a token, take the payload</div>
            <div className="hp-tn-form">
              <input
                className="hp-tn-input"
                value={engagementId}
                onChange={(e) => setEngagementId(e.target.value)}
                placeholder="engagement id"
                aria-label="Engagement id"
              />
              <input
                className="hp-tn-input"
                value={stepId}
                onChange={(e) => setStepId(e.target.value)}
                placeholder="step id (optional)"
                aria-label="Step id"
              />
              <input
                className="hp-tn-input"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="what this is testing — it becomes the finding title"
                aria-label="Note"
              />
              <select
                className="hp-tn-input"
                value={vulnClass}
                onChange={(e) => setVulnClass(e.target.value)}
                aria-label="Vulnerability class"
              >
                <option value="">every class</option>
                {(status?.vuln_classes ?? []).map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
            <div className="hp-tn-actions">
              <span className="hp-tn-actions-label">act</span>
              <button
                className="hp-tn-start"
                onClick={mint}
                disabled={busy !== null || !engagementId.trim()}
              >
                {busy === "mint" ? "minting…" : "mint + render"}
              </button>
            </div>
            {minted?.backends.self_hosted && (
              <>
                <p className="hp-tn-olhint">
                  self-hosted · {minted.backends.self_hosted.token.token}.
                  {minted.backends.self_hosted.zone}
                </p>
                <ul className="hp-tn-list">
                  {minted.backends.self_hosted.payloads.map(renderPayload)}
                </ul>
              </>
            )}
            {minted?.backends.interactsh && (
              <>
                <p className="hp-tn-olhint">interact.sh · {minted.backends.interactsh.host}</p>
                <ul className="hp-tn-list">
                  {minted.backends.interactsh.payloads.map(renderPayload)}
                </ul>
              </>
            )}
            {tokenList.length > 0 && (
              <p className="hp-tn-olhint">
                {tokenList.length} token{tokenList.length === 1 ? "" : "s"} minted for this
                engagement · newest {tokenList[0].token}
              </p>
            )}
          </section>
        )}

        {/* ---- poll -------------------------------------------------------- */}
        {anyBackend && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">collect callbacks</div>
            <p className="hp-tn-note">
              Sweeps BOTH backends, correlates each hit back to the step that minted its token, and
              files the correlated ones as findings. Hits that cannot be attributed are listed
              rather than dropped — &ldquo;something arrived I could not place&rdquo; is a different
              fact from &ldquo;nothing arrived&rdquo;. Auto-poll does this on a timer.
            </p>
            <button className="hp-tn-start" onClick={poll} disabled={busy !== null}>
              {busy === "poll" ? "polling…" : "poll now"}
            </button>
            {polled && (
              <>
                <p className="hp-tn-olhint">
                  {polled.hits.length} hit{polled.hits.length === 1 ? "" : "s"} read · {polled.filed}{" "}
                  filed as findings
                  {polled.self_hosted ? ` · self-hosted cursor ${polled.self_hosted.cursor}` : ""}
                  {polled.interactsh ? ` · interact.sh ${polled.interactsh.hits}` : ""}
                  {polled.unfiled.length > 0 ? ` · ${polled.unfiled.length} unattributed` : ""}
                </p>
                {polled.errors.length > 0 && (
                  <ul className="hp-tn-list">
                    {polled.errors.map((e) => (
                      <li key={e.backend} className="hp-tn-row">
                        <div className="hp-tn-rowtop">
                          <span className="hp-tn-kind">✗ {e.backend}</span>
                          <span className="hp-tn-subs">{e.reason}</span>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
                <ul className="hp-tn-list">
                  {polled.hits.map((h, i) => (
                    <li key={`${h.backend ?? "sh"}-${h.seq ?? h.token ?? i}`} className="hp-tn-row">
                      <div className="hp-tn-rowtop">
                        <span className="hp-tn-kind">
                          {h.correlated ? "✓" : "?"} {h.kind}
                          {h.backend === "interactsh" ? " · interact.sh" : ""}
                        </span>
                        <span className="hp-tn-subs">
                          {h.kind === "dns" ? h.qname : `${h.method} ${h.path}`} from {h.source_ip}{" "}
                          at {h.at.slice(0, 19)}
                          {h.correlated ? ` — ${h.note || h.step_id || h.engagement_id}` : " — not minted here"}
                        </span>
                      </div>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </section>
        )}

        {!anyBackend && (
          <p className="hp-tn-sub">
            No backend is set up yet. Either register an interact.sh session above (zero
            infrastructure), or — for a private, owned canary — fill in a VPS you own and a domain
            you can add NS records to, then delegate, deploy and verify in order.
          </p>
        )}
      </div>
    </PageShell>
  );
}
