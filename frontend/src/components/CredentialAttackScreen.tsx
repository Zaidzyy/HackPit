"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  crackPreview,
  getCredentialsPlan,
  getCredentialsStatus,
  listCredJobs,
  sprayPreview,
  startCrack,
  startSpray,
  stopCredJob,
  type CrackPreview,
  type CrackRequest,
  type CredJob,
  type CredPlan,
  type CredStatus,
  type SprayPreview,
  type SprayRequest,
} from "@/lib/api";

/**
 * :credentials — spray captured/OSINT creds, crack captured hashes. The payoff of the whole
 * state model, wired as ONE approved job with an ungated stop.
 *
 * *** WHY ONE APPROVAL BUYS A WHOLE SPRAY, SAID ON THE SCREEN AND NOT ONLY IN THE CODE. ***
 * HackPit refuses BATCHING ACROSS APPROVALS. It has never refused one approval that produces
 * many attempts, and could not: ffuf, nuclei, the ZAP scanner and the intruder are each one
 * press buying thousands. A spray of 300 accounts is that same shape — one gated job, gated by
 * the same executor gates, no new ones. The stop button is the ungated panic switch.
 *
 * A hit is not just a line here: it writes a VALIDATED credential + a high finding into
 * engagement state (visible in :cockpit) and marks the matching principal OWNED in :ad-graph,
 * which opens new frontier edges. That is the loop closing.
 */
const SERVICES = [
  "smb",
  "winrm",
  "ldap",
  "ssh",
  "mssql",
  "rdp",
  "ftp",
  "kerberos",
  "http-form",
] as const;

function blankSpray(): SprayRequest {
  return {
    service: "smb",
    target: "",
    usernames: [],
    passwords: [],
    domain: "",
    http_form: "",
    delay: 0,
    stop_on_lockouts: 0,
    engagement_id: null,
    session_id: null,
    approved: false,
    dangerous_ack: false,
  };
}

function lines(text: string): string[] {
  return text
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function CredentialAttackScreen() {
  const [status, setStatus] = useState<CredStatus | null>(null);
  const [jobs, setJobs] = useState<CredJob[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [engagementId, setEngagementId] = useState("");

  // --- spray form ---
  const [service, setService] = useState<string>("smb");
  const [target, setTarget] = useState("");
  const [userText, setUserText] = useState("");
  const [passText, setPassText] = useState("");
  const [domain, setDomain] = useState("");
  const [httpForm, setHttpForm] = useState("");
  const [delay, setDelay] = useState("0");
  const [stopOn, setStopOn] = useState("0");
  const [sprayApproved, setSprayApproved] = useState(false);
  const [sprayAck, setSprayAck] = useState(false);
  const [sPreview, setSPreview] = useState<SprayPreview | null>(null);
  const [sprayStarting, setSprayStarting] = useState(false);

  // --- crack form ---
  const [wordlist, setWordlist] = useState("/usr/share/wordlists/rockyou.txt");
  const [plan, setPlan] = useState<CredPlan | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [crackApproved, setCrackApproved] = useState(false);
  const [cPreview, setCPreview] = useState<CrackPreview | null>(null);
  const [crackStarting, setCrackStarting] = useState(false);

  const usernames = useMemo(() => lines(userText), [userText]);
  const passwords = useMemo(() => lines(passText), [passText]);

  const sprayRequest = useCallback(
    (): SprayRequest => ({
      ...blankSpray(),
      service,
      target: target.trim(),
      usernames,
      passwords,
      domain: domain.trim(),
      http_form: httpForm.trim(),
      delay: Number.parseInt(delay, 10) || 0,
      stop_on_lockouts: Number.parseInt(stopOn, 10) || 0,
      engagement_id: engagementId.trim() || null,
      session_id: engagementId.trim() || null,
      approved: sprayApproved,
      dangerous_ack: sprayAck,
    }),
    [service, target, usernames, passwords, domain, httpForm, delay, stopOn, engagementId, sprayApproved, sprayAck]
  );

  const crackRequest = useCallback(
    (): CrackRequest => ({
      principals: picked,
      wordlist: wordlist.trim() || "/usr/share/wordlists/rockyou.txt",
      rule: "",
      engagement_id: engagementId.trim() || null,
      session_id: engagementId.trim() || null,
      approved: crackApproved,
      dangerous_ack: false,
    }),
    [picked, wordlist, engagementId, crackApproved]
  );

  useEffect(() => {
    const ctrl = new AbortController();
    getCredentialsStatus(ctrl.signal)
      .then(setStatus)
      .catch(() => setStatus(null));
    return () => ctrl.abort();
  }, []);

  const refreshJobs = useCallback(() => {
    listCredJobs(engagementId.trim() || undefined)
      .then(setJobs)
      .catch(() => setJobs([]));
  }, [engagementId]);

  // A running job's hits grow, so this polls — `attempts` and `hits` come back on every read.
  useEffect(() => {
    refreshJobs();
    const t = setInterval(refreshJobs, 2000);
    return () => clearInterval(t);
  }, [refreshJobs]);

  // Seed the user list and the crack plan from captured engagement state.
  const seedFromState = useCallback(() => {
    const sid = engagementId.trim();
    if (!sid) {
      setError("enter an engagement id first — creds are seeded from that engagement's state");
      return;
    }
    setError(null);
    getCredentialsPlan(sid, wordlist.trim())
      .then((p) => {
        setPlan(p);
        setPicked(p.crackable.flatMap((g) => g.principals));
        if (p.usernames.length > 0) {
          setUserText((cur) => (cur.trim() ? cur : p.usernames.join("\n")));
        }
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [engagementId, wordlist]);

  const doSprayPreview = useCallback(() => {
    if (!target.trim()) return;
    setError(null);
    sprayPreview(sprayRequest())
      .then(setSPreview)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [target, sprayRequest]);

  const doCrackPreview = useCallback(() => {
    setError(null);
    crackPreview(crackRequest())
      .then(setCPreview)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [crackRequest]);

  const runSpray = useCallback(() => {
    if (sprayStarting) return;
    setSprayStarting(true);
    setError(null);
    startSpray(sprayRequest())
      .then(() => refreshJobs())
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setSprayStarting(false));
  }, [sprayStarting, sprayRequest, refreshJobs]);

  const runCrack = useCallback(() => {
    if (crackStarting) return;
    setCrackStarting(true);
    setError(null);
    startCrack(crackRequest())
      .then(() => refreshJobs())
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setCrackStarting(false));
  }, [crackStarting, crackRequest, refreshJobs]);

  const stop = useCallback(
    (id: string) => {
      stopCredJob(id)
        .then(() => refreshJobs())
        .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
    },
    [refreshJobs]
  );

  const gateLine = (gate: SprayPreview["gate"]) =>
    gate ? (
      <p className="hp-tn-error">
        The gate would refuse this at <strong>{gate.gate}</strong>: {gate.reason}
        {gate.dangerous_flags.length > 0 ? ` — ${gate.dangerous_flags.join("; ")}` : ""}
      </p>
    ) : (
      <p className="hp-tn-note">Nothing stands in the way at the gates — with approval set, this would run.</p>
    );

  const crackableCount = plan?.crackable.reduce((n, g) => n + g.hashes, 0) ?? 0;

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "credentials" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">spray captured creds · crack captured hashes · one approval</div>
          <h1 className="hp-tn-title">:credentials</h1>
          <p className="hp-tn-sub">
            Take the credentials and hashes already in engagement state and <strong>use them</strong>:
            spray a user/password list across a service, or crack captured hashes with a wordlist.
            Each is <strong>one gated job</strong> — the same executor gates every command clears,
            no new ones — with an ungated stop. A hit writes a validated credential and a finding
            back into state and marks the matching principal <strong>owned</strong> in{" "}
            <Link href="/cockpit/ad">:ad-graph</Link>.
          </p>
          {status && (
            <div className={`hp-tn-status ${status.up ? "is-up" : "is-down"}`}>
              <span className="hp-tn-dot" />
              {status.container}: {status.up ? "up" : "down"} · running {status.running}
            </div>
          )}
        </header>

        {error && <div className="hp-tn-error">{error}</div>}

        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">the engagement</div>
          <div className="hp-tn-cardsub">
            Credential attacks run inside an <strong>active engagement</strong> — the open,
            loot-mounted sandbox where the secret lists live and a real target is reachable. Enter
            its id, then seed the user list and crack plan from what that engagement has captured.
          </div>
          <div className="hp-tn-form">
            <input
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
              placeholder="engagement id"
              aria-label="Engagement id"
            />
            <button type="button" onClick={seedFromState} disabled={!engagementId.trim()}>
              seed from captured state
            </button>
            {plan && (
              <span className="hp-tn-olhint">
                {plan.usernames.length} account(s) · {crackableCount} crackable hash(es)
              </span>
            )}
          </div>
        </section>

        {/* --- SPRAY ------------------------------------------------------------ */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">spray</div>
          <div className="hp-tn-cardsub">
            Try a user list against a password list on one service. The lists are written to a loot
            file and referenced by path — <strong>no secret goes on the command line</strong>. The
            delay and lockout-stop are operator knobs, not gates: a slower spray is a quieter spray.
          </div>
          <div className="hp-tn-form">
            <select value={service} onChange={(e) => setService(e.target.value)} aria-label="Service">
              {SERVICES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="target host / IP" />
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="domain / realm (optional)" />
          </div>
          {service === "http-form" && (
            <div className="hp-tn-form">
              <input
                value={httpForm}
                onChange={(e) => setHttpForm(e.target.value)}
                placeholder="hydra form: /login:user=^USER^&pass=^PASS^:F=incorrect"
                style={{ width: "100%" }}
              />
            </div>
          )}
          <div className="hp-tn-form">
            <textarea
              value={userText}
              onChange={(e) => setUserText(e.target.value)}
              rows={5}
              spellCheck={false}
              placeholder={"users — one per line\nadministrator\njsmith"}
              style={{ width: "100%", fontFamily: "var(--hp-mono, monospace)" }}
            />
            <textarea
              value={passText}
              onChange={(e) => setPassText(e.target.value)}
              rows={5}
              spellCheck={false}
              placeholder={"passwords — one per line\nSummer2024!\nWelcome1"}
              style={{ width: "100%", fontFamily: "var(--hp-mono, monospace)" }}
            />
          </div>
          <div className="hp-tn-form">
            <input
              className="hp-tn-port"
              value={delay}
              onChange={(e) => setDelay(e.target.value)}
              placeholder="delay s"
              aria-label="Delay between attempts, seconds"
            />
            <input
              className="hp-tn-port"
              value={stopOn}
              onChange={(e) => setStopOn(e.target.value)}
              placeholder="stop on N lockouts"
              aria-label="Stop after N lockouts"
            />
            <button type="button" onClick={doSprayPreview} disabled={!target.trim()}>
              preview — the exact argv + what the gate says
            </button>
            <span className="hp-tn-olhint">
              {usernames.length} user(s) · {passwords.length} password(s)
            </span>
          </div>

          {sPreview && (
            <>
              <div className="hp-tn-olhint">
                the approved surface <CopyButton text={sPreview.argv.join(" ")} />
              </div>
              <pre className="hp-tn-oneliner">{sPreview.argv.join(" ") || "(nothing to run)"}</pre>
              {sPreview.warnings.map((w) => (
                <p key={w} className="hp-tn-error">
                  {w}
                </p>
              ))}
              {gateLine(sPreview.gate)}
            </>
          )}

          <div className="hp-tn-danger">
            <div className="hp-tn-danger-head">this sends real login attempts to the target</div>
            <div className="hp-tn-danger-note">
              One approval buys the whole spray — {usernames.length * passwords.length || 0} attempt(s).
              Preview first: the gate&rsquo;s answer is shown above before anything runs.
            </div>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input type="checkbox" checked={sprayApproved} onChange={(e) => setSprayApproved(e.target.checked)} />
              I approve this spray job
            </label>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input type="checkbox" checked={sprayAck} onChange={(e) => setSprayAck(e.target.checked)} />
              I understand this authenticates against a real service (red-confirm, when the gate asks)
            </label>
            <div className="hp-tn-danger-actions">
              <button
                type="button"
                className="hp-tn-danger-go"
                onClick={runSpray}
                disabled={sprayStarting || !sprayApproved || !target.trim() || usernames.length === 0 || passwords.length === 0}
              >
                {sprayStarting ? "starting…" : "run the spray"}
              </button>
            </div>
          </div>
        </section>

        {/* --- CRACK ------------------------------------------------------------ */}
        <section className="hp-tn-card">
          <div className="hp-tn-cardhead">crack</div>
          <div className="hp-tn-cardsub">
            Hand captured hashes to hashcat with a wordlist. The hashes come from state and are
            written to a loot file — <strong>never the argv</strong>. The mode is detected from each
            hash&rsquo;s shape. A crack recovers the <em>account</em>, not just the plaintext: it
            adds a password credential for the principal and keeps the hash for pass-the-hash.
          </div>
          <div className="hp-tn-form">
            <input value={wordlist} onChange={(e) => setWordlist(e.target.value)} placeholder="wordlist path" style={{ flex: "1 1 320px" }} />
            <button type="button" onClick={doCrackPreview}>
              preview — the hashcat run(s) + what the gate says
            </button>
          </div>
          {plan && plan.crackable.length > 0 ? (
            <ul className="hp-tn-list">
              {plan.crackable.map((g) => (
                <li key={g.mode} className="hp-tn-row">
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">-m {g.mode}</span>
                    <span className="hp-tn-subs" style={{ flex: "1 1 260px" }}>
                      {g.name} — {g.principals.join(", ")}
                    </span>
                    <span className="hp-tn-olhint">{g.hashes} hash(es)</span>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="hp-tn-note">
              No crackable hashes seeded yet — enter an engagement id above and press
              &ldquo;seed from captured state&rdquo;.
            </p>
          )}

          {cPreview && (
            <>
              {cPreview.groups.map((g) => (
                <pre key={g.mode} className="hp-tn-oneliner">
                  {g.argv.join(" ")}
                </pre>
              ))}
              {cPreview.warnings.map((w) => (
                <p key={w} className="hp-tn-error">
                  {w}
                </p>
              ))}
              {gateLine(cPreview.gate)}
            </>
          )}

          <div className="hp-tn-danger">
            <div className="hp-tn-danger-head">this runs an offline crack in the sandbox</div>
            <div className="hp-tn-danger-note">
              One approval buys the whole run — {crackableCount} hash(es) against the wordlist.
            </div>
            <label
              className="hp-tn-danger-why"
              style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}
            >
              <input type="checkbox" checked={crackApproved} onChange={(e) => setCrackApproved(e.target.checked)} />
              I approve this crack job
            </label>
            <div className="hp-tn-danger-actions">
              <button
                type="button"
                className="hp-tn-danger-go"
                onClick={runCrack}
                disabled={crackStarting || !crackApproved || crackableCount === 0}
              >
                {crackStarting ? "starting…" : "run the crack"}
              </button>
            </div>
          </div>
        </section>

        {/* --- RESULTS FEED ---------------------------------------------------- */}
        {jobs.length > 0 && (
          <section className="hp-tn-card">
            <div className="hp-tn-cardhead">results feed</div>
            <div className="hp-tn-cardsub">
              New credentials and findings land in <Link href="/cockpit">:cockpit</Link> state;
              owned principals open new edges in <Link href="/cockpit/ad">:ad-graph</Link>.
            </div>
            <ul className="hp-tn-list">
              {jobs.map((job) => (
                <li key={job.id} className={`hp-tn-row${job.refused ? " is-down" : ""}`}>
                  <div className="hp-tn-rowtop">
                    <span className="hp-tn-kind">{job.kind}</span>
                    <span className="hp-tn-subs" style={{ flex: "1 1 200px", wordBreak: "break-all" }}>
                      {job.target || job.id}
                    </span>
                    <span className={`hp-tn-state ${job.state === "running" ? "is-listening" : "is-down"}`}>
                      {job.state}
                    </span>
                    <span className="hp-tn-olhint">
                      {job.hits.length} hit(s) · +{job.new_credentials} cred / +{job.new_findings} finding
                      {job.lockouts > 0 ? ` · ${job.lockouts} lockout(s)` : ""}
                    </span>
                    {job.state === "running" && (
                      <button type="button" className="hp-tn-stop" onClick={() => stop(job.id)}>
                        stop — not gated
                      </button>
                    )}
                  </div>
                  {job.owned.length > 0 && (
                    <div className="hp-tn-olhint">
                      marked owned in :ad-graph → {job.owned.join(", ")}
                    </div>
                  )}
                  {job.hits.length > 0 && (
                    <ul className="hp-tn-list">
                      {job.hits.map((h, i) => (
                        <li key={`${h.principal}-${i}`} className="hp-tn-row">
                          <div className="hp-tn-rowtop">
                            <span className="hp-tn-state is-starting">{h.admin ? "admin" : "valid"}</span>
                            <span className="hp-tn-subs">
                              {h.domain ? `${h.domain}\\` : ""}
                              {h.principal}
                            </span>
                            <span className="hp-tn-olhint">{h.note}</span>
                          </div>
                        </li>
                      ))}
                    </ul>
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
      </div>
    </PageShell>
  );
}
