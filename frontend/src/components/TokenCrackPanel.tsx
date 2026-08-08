"use client";

import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  getTokenCrackStatus,
  listTokenCrackJobs,
  startTokenCrack,
  stopTokenCrackJob,
  tokenCrackPreview,
  type TokenCrackJob,
  type TokenCrackPreview,
  type TokenCrackStatus,
} from "@/lib/api";
import { CopyButton } from "./CopyButton";

/**
 * JWT WEAK-SECRET CRACK — the one gated job of the workbench.
 *
 * *** ONE APPROVAL BUYS THE WHOLE CRACK, gated by the same four gates, no new gate. *** The token
 * is written to a loot file (never the argv); a recovered secret goes to loot (never this record)
 * and lands a high finding in engagement state. The stop button is the ungated panic switch. A
 * crack names no host, so it needs an ACTIVE ENGAGEMENT — the lab sandbox has no loot mount.
 */
export function TokenCrackPanel({
  token,
  engagementId,
  sessionId,
}: {
  token: string;
  engagementId?: string | null;
  sessionId?: string | null;
}) {
  const [status, setStatus] = useState<TokenCrackStatus | null>(null);
  const [jobs, setJobs] = useState<TokenCrackJob[]>([]);
  const [wordlist, setWordlist] = useState("/usr/share/wordlists/rockyou.txt");
  const [approved, setApproved] = useState(false);
  const [ack, setAck] = useState(false);
  const [preview, setPreview] = useState<TokenCrackPreview | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, j] = await Promise.all([
        getTokenCrackStatus(),
        listTokenCrackJobs(sessionId || undefined),
      ]);
      setStatus(s);
      setJobs(j);
    } catch {
      /* the banner just stays as it was — a status poll must not throw into the UI */
    }
  }, [sessionId]);

  useEffect(() => {
    // Status poll: setState lives in refresh()'s async body (post-await), but Next 16's
    // set-state-in-effect flags calling a setState-carrying callback from an effect regardless
    // of the await. Deliberate — keep the counted lint baseline at 11 (frontend/AGENTS.md).
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
  }, [refresh]);

  const req = useCallback(
    () => ({
      token: token.trim(),
      wordlist,
      engagement_id: engagementId ?? null,
      session_id: sessionId ?? null,
      approved,
      dangerous_ack: ack,
    }),
    [token, wordlist, engagementId, sessionId, approved, ack]
  );

  const runPreview = useCallback(async () => {
    if (!token.trim()) return;
    setError(null);
    try {
      setPreview(await tokenCrackPreview(req()));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setPreview(null);
    }
  }, [req, token]);

  const runCrack = useCallback(async () => {
    if (!token.trim()) return;
    setError(null);
    try {
      await startTokenCrack(req());
      await refresh();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }, [req, token, refresh]);

  const stop = useCallback(
    async (id: string) => {
      try {
        await stopTokenCrackJob(id);
        await refresh();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
      }
    },
    [refresh]
  );

  return (
    <div className="hp-tk-crack">
      <div className="hp-tn-cardsub">
        weak-secret crack — <code>hashcat -m 16500</code> over a wordlist, as one gated job
      </div>
      <p className="hp-tn-note">
        Only <strong>HS256/384/512</strong> tokens have a symmetric secret a wordlist can recover.
        A crack names no host, so it needs an <strong>active engagement</strong> (the lab sandbox
        has no loot mount). A recovered secret is written to loot and lands a high finding — then
        re-sign the token above with it.
      </p>
      {status ? (
        <p className="hp-tn-note">
          engagement sandbox {status.ready ? "ready" : "not running"} · {status.running} crack
          {status.running === 1 ? "" : "s"} running
        </p>
      ) : null}

      <div className="hp-tn-form">
        <input
          value={wordlist}
          onChange={(e) => setWordlist(e.target.value)}
          placeholder="wordlist path in the sandbox"
        />
        <label className="hp-tn-check">
          <input type="checkbox" checked={approved} onChange={(e) => setApproved(e.target.checked)} />
          approve
        </label>
        <label className="hp-tn-check">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          red-confirm
        </label>
        <button type="button" onClick={runPreview} disabled={!token.trim()}>
          preview
        </button>
        <button
          type="button"
          className="hp-tn-start"
          onClick={runCrack}
          disabled={!token.trim() || !approved}
        >
          crack weak secret
        </button>
        <button type="button" onClick={refresh}>
          refresh
        </button>
      </div>
      {error ? <p className="hp-tn-error">{error}</p> : null}

      {preview ? (
        <div className="hp-tk-out">
          <div className="hp-tn-form">
            <span className={`hp-gql-status ${preview.crackable ? "is-ok" : "is-bad"}`}>
              {preview.alg || "no alg"}
            </span>
            <CopyButton text={preview.argv.join(" ")} />
          </div>
          {!preview.crackable ? (
            <p className="hp-tn-note-warn">
              This alg has no symmetric secret — only HS* is crackable this way. Try alg confusion.
            </p>
          ) : null}
          {preview.gate ? (
            <p className="hp-tn-note-warn">
              gate: <strong>{preview.gate.gate}</strong> — {preview.gate.reason}
            </p>
          ) : (
            <p className="hp-tn-note">gates pass — this run is approved.</p>
          )}
        </div>
      ) : null}

      {jobs.length ? (
        <div className="hp-gql-fields">
          {jobs.map((j) => (
            <div key={j.id} className="hp-gql-field">
              <span className={`hp-gql-status ${j.cracked ? "is-ok" : j.state === "running" ? "is-disabled" : "is-bad"}`}>
                {j.cracked ? "CRACKED" : j.state}
              </span>
              <span className="hp-gql-fieldname">{j.id}</span>
              <span className="hp-gql-fieldtype">
                {j.alg}
                {j.cracked ? ` · secret ${j.secret_len} chars → loot` : ""}
                {j.new_findings ? ` · ${j.new_findings} finding` : ""}
              </span>
              {j.state === "running" ? (
                <button type="button" className="hp-tn-stop" onClick={() => stop(j.id)}>
                  stop
                </button>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
