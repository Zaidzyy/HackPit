"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  getSessionEngineStatus,
  listNamedSessions,
  openNamedSession,
  captureNamedSession,
  runInNamedSession,
  sendNamedSessionInput,
  pollNamedSessionJobs,
  consumeNamedSessionJob,
  killNamedSession,
  type SessionEngineStatus,
  type NamedSession,
  type SessionCapture,
  type SessionJob,
} from "@/lib/api";

/**
 * Named persistent sessions — the tmux engine, HUMAN-DRIVEN.
 *
 * A THIRD open-sandbox surface alongside the raw pty: named, parallel, persistent sessions
 * with per-session cwd, AUTOMATIC INTERACTIVE-PROMPT DETECTION (msfconsole / sliver /
 * evil-winrm / REPLs), a background lifecycle with a notify-once completion, and
 * wedge/pipe-degradation recovery. Ported from Decepticon's tools/bash (Apache-2.0).
 *
 * The load-bearing rule: INPUT IS HUMAN-ONLY. Both running a command and answering an
 * interactive prompt are the operator's actions — the orchestrator has no path here.
 */
export function SessionEngine() {
  const [status, setStatus] = useState<SessionEngineStatus | null>(null);
  const [sessions, setSessions] = useState<NamedSession[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [cap, setCap] = useState<SessionCapture | null>(null);
  const [newName, setNewName] = useState("");
  const [cmd, setCmd] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [notes, setNotes] = useState<SessionJob[]>([]);
  // A ref mirror of `active` so the single poll interval reads the current selection without
  // being torn down and recreated on every tab switch. Synced in an effect (never in render).
  const capRef = useRef<string | null>(null);
  useEffect(() => {
    capRef.current = active;
  }, [active]);

  const refreshStatus = useCallback(() => {
    getSessionEngineStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  const refreshSessions = useCallback(() => {
    listNamedSessions()
      .then((s) => {
        setSessions(s);
        // Auto-focus the first session when none is selected, so opening the screen with a
        // live session in flight lands you on it (and its prompt-detection banner) directly.
        if (s.length) setActive((cur) => cur ?? s[0].name);
      })
      .catch(() => setSessions([]));
  }, []);

  useEffect(() => {
    refreshStatus();
    refreshSessions();
  }, [refreshStatus, refreshSessions]);

  // Poll the ACTIVE session's capture + the cross-session job notifications on a timer. The
  // state writes happen in the interval callback (async), never in the effect body, so this
  // adds no react-hooks/set-state-in-effect to the accepted baseline.
  useEffect(() => {
    const tick = () => {
      const name = capRef.current;
      if (name) {
        captureNamedSession(name)
          .then((c) => {
            if (capRef.current === name) setCap(c);
          })
          .catch(() => {});
      }
      pollNamedSessionJobs()
        .then((jobs) => {
          if (jobs.length) setNotes((prev) => [...prev, ...jobs]);
        })
        .catch(() => {});
    };
    const id = setInterval(tick, 1500);
    tick();
    return () => clearInterval(id);
  }, []);

  const openSession = useCallback(async () => {
    const name = newName.trim();
    if (!name) return;
    setErr("");
    setBusy(true);
    try {
      const s = await openNamedSession(name);
      setNewName("");
      setActive(s.name);
      setCap(null);
      refreshSessions();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "could not open the session");
    } finally {
      setBusy(false);
    }
  }, [newName, refreshSessions]);

  const run = useCallback(
    async (background: boolean) => {
      const name = active;
      const line = cmd.trim();
      if (!name || !line) return;
      setErr("");
      setBusy(true);
      try {
        await runInNamedSession(name, line, background);
        setCmd("");
        const c = await captureNamedSession(name);
        setCap(c);
        refreshSessions();
      } catch (e) {
        setErr(e instanceof Error ? e.message : "the command was refused");
      } finally {
        setBusy(false);
      }
    },
    [active, cmd, refreshSessions]
  );

  // The is_input path: answer an interactive prompt. HUMAN-ONLY, same as run().
  const sendLine = useCallback(async () => {
    const name = active;
    const line = cmd;
    if (!name || !line) return;
    setErr("");
    setBusy(true);
    try {
      await sendNamedSessionInput(name, line, true);
      setCmd("");
      const c = await captureNamedSession(name);
      setCap(c);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "the input was refused");
    } finally {
      setBusy(false);
    }
  }, [active, cmd]);

  const kill = useCallback(
    async (name: string) => {
      setBusy(true);
      try {
        await killNamedSession(name);
        if (active === name) {
          setActive(null);
          setCap(null);
        }
        refreshSessions();
      } catch {
        /* a kill that cannot reach docker still marks the session gone server-side */
      } finally {
        setBusy(false);
      }
    },
    [active, refreshSessions]
  );

  const dismissNote = useCallback((job: SessionJob) => {
    setNotes((prev) => prev.filter((j) => j.job_id !== job.job_id));
    consumeNamedSessionJob(job.session, job.job_id).catch(() => {});
  }, []);

  const ready = !!status?.ready;
  const awaiting = cap?.prompt?.awaiting_input ?? false;
  const activeSession = sessions.find((s) => s.name === active) ?? null;

  return (
    <div className="hp-ns">
      {/* availability banner — full reach, NOT isolated (there is no isolation to claim) */}
      <div
        className={`hp-ck-banner ${ready ? "hp-kali-warnbanner" : "hp-ck-warn"}`}
        role="status"
      >
        {status ? (
          ready ? (
            <>
              <span className="hp-kali-dot" /> tmux sessions in <b>{status.container}</b> · full
              network reach · <b>NOT isolated</b> · human-only · {status.live}/{status.max_live}{" "}
              live · auto-background at {status.auto_background_seconds}s
            </>
          ) : (
            <>
              <span className="hp-ck-dot" /> not ready — {status.detail || "open sandbox unavailable"}.
              Bring the stack up:{" "}
              <code>docker compose -f docker/docker-compose.yml up -d</code>
            </>
          )
        ) : (
          <>connecting to backend…</>
        )}
      </div>

      {/* background-job completion notifications — inlined once, then dismissable */}
      {notes.length > 0 && (
        <div className="hp-ns-jobs">
          {notes.map((j) => (
            <div key={j.job_id} className="hp-ns-job hp-ns-job-done">
              <span className="hp-ns-jobdot" />
              <span className="hp-ns-jobcmd">
                <b>[{j.session}]</b> <code>{j.command}</code> finished
                {j.rc !== null && ` (rc ${j.rc})`}
              </span>
              <button type="button" className="hp-ns-jobdismiss" onClick={() => dismissNote(j)}>
                dismiss
              </button>
            </div>
          ))}
        </div>
      )}

      {/* session tabs */}
      <div className="hp-ns-tabs">
        {sessions.map((s) => (
          <button
            key={s.name}
            type="button"
            className={`hp-ns-tab ${s.name === active ? "hp-ns-tab-on" : ""}`}
            onClick={() => {
              setActive(s.name);
              setCap(null);
            }}
          >
            <span
              className={`hp-ns-tab-dot ${
                s.state !== "active"
                  ? "hp-ns-dot-dead"
                  : s.awaiting_input
                    ? "hp-ns-dot-wait"
                    : "hp-ns-dot-live"
              }`}
            />
            {s.name}
            {s.program && s.program !== "shell" && (
              <span className="hp-ns-tab-prog">{s.program}</span>
            )}
          </button>
        ))}
        <div className="hp-ns-new">
          <input
            className="hp-ns-newinput"
            placeholder="new session name"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") openSession();
            }}
            disabled={!ready || busy}
          />
          <button
            type="button"
            className="hp-ns-newbtn"
            onClick={openSession}
            disabled={!ready || busy || !newName.trim()}
          >
            + open
          </button>
        </div>
      </div>

      {err && <div className="hp-ns-err">{err}</div>}

      {!active ? (
        <div className="hp-ns-empty">
          {ready
            ? "Open a named session above, then run interactive tools (msfconsole, sliver-client, evil-winrm) or long scans — the engine detects when a tool is waiting for you."
            : "The open sandbox is not running."}
        </div>
      ) : (
        <>
          {/* THE PROMPT-DETECTION BANNER — the headline feature */}
          <div
            className={`hp-ns-banner ${
              awaiting ? "hp-ns-banner-wait" : "hp-ns-banner-idle"
            }`}
            role="status"
          >
            {awaiting ? (
              <>
                <span className="hp-ns-banner-dot" />
                <b>interactive — send input</b>
                {cap?.prompt?.program && ` · ${cap.prompt.program}`}
                {cap?.prompt?.line && (
                  <code className="hp-ns-prompt-line">{cap.prompt.line}</code>
                )}
              </>
            ) : (
              <>
                <span className="hp-ns-banner-dot" />
                {cap?.prompt?.kind === "running"
                  ? "running — output streaming"
                  : "idle — ready for a command"}
              </>
            )}
          </div>

          {/* per-session facts */}
          <div className="hp-ns-meta">
            <span className="hp-ns-meta-item">
              cwd <code>{activeSession?.cwd ?? cap?.name ?? "~"}</code>
            </span>
            <span className="hp-ns-meta-item">
              program <b>{activeSession?.program ?? "shell"}</b>
            </span>
            <span className="hp-ns-meta-item">
              state <b>{activeSession?.state ?? cap?.state ?? "?"}</b>
            </span>
            <span className="hp-ns-meta-spacer" />
            <button
              type="button"
              className="hp-ns-kill"
              onClick={() => active && kill(active)}
              disabled={busy}
            >
              kill session
            </button>
          </div>

          {/* the live capture */}
          <pre className="hp-ns-out">
            {cap?.output || "…"}
            {cap?.saved_path && (
              <span className="hp-ns-saved">
                {"\n"}[full output saved to {cap.saved_path}]
              </span>
            )}
          </pre>

          {/* the HUMAN's input box — run a command, or answer a prompt */}
          <div className="hp-ns-form">
            <input
              className="hp-ns-input"
              placeholder={awaiting ? "answer the prompt…" : "command to run…"}
              value={cmd}
              onChange={(e) => setCmd(e.target.value)}
              onKeyDown={(e) => {
                if (e.key !== "Enter") return;
                if (awaiting) sendLine();
                else run(false);
              }}
              disabled={busy}
            />
            {awaiting ? (
              <button
                type="button"
                className="hp-ns-send"
                onClick={sendLine}
                disabled={busy || !cmd}
              >
                send line
              </button>
            ) : (
              <>
                <button
                  type="button"
                  className="hp-ns-run"
                  onClick={() => run(false)}
                  disabled={busy || !cmd.trim()}
                >
                  run
                </button>
                <button
                  type="button"
                  className="hp-ns-bg"
                  onClick={() => run(true)}
                  disabled={busy || !cmd.trim()}
                  title="Detach: returns immediately and notifies on completion"
                >
                  run in background
                </button>
              </>
            )}
          </div>

          {/* background-job tracker for this session */}
          {activeSession && activeSession.background_jobs.length > 0 && (
            <div className="hp-ns-jobs">
              {activeSession.background_jobs.map((j) => (
                <div
                  key={j.job_id}
                  className={`hp-ns-job ${
                    j.state === "running" ? "hp-ns-job-run" : "hp-ns-job-done"
                  }`}
                >
                  <span className="hp-ns-jobdot" />
                  <span className="hp-ns-jobcmd">
                    <code>{j.command}</code>
                  </span>
                  <span className="hp-ns-jobstate">
                    {j.state}
                    {j.rc !== null && ` · rc ${j.rc}`}
                  </span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
