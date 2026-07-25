"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { PageShell } from "./PageShell";
import {
  ApiError,
  getSessionStatus,
  killSession,
  startSession,
  streamSession,
  writeSessionStdin,
  type SessionEvent,
  type SessionInfo,
  type SessionStatus,
} from "@/lib/api";

/**
 * The live SESSION panel — catch a shell and drive it by hand.
 *
 * ONE session at a time, typed into by a human. This is not a C2 dashboard: there is no
 * beacon list, no implant management, no pivoting.
 *
 * TWO GATES, both enforced server-side:
 *  - STARTING is a GATED COMMAND. The start button sends approved=true (clicking it IS
 *    the approval) and the backend runs the same gates a one-shot command clears. A
 *    listener trips the danger heuristic, which comes back as a 403 the panel surfaces
 *    as an explicit RED CONFIRM — you re-confirm before it starts. Nothing is pre-ticked.
 *  - STDIN is *** HUMAN-ONLY ***. The input line below is the only thing that calls
 *    writeSessionStdin, and it fires on a human keypress. Never wire it to anything
 *    automated — the backend locks that with a source scan, and this panel must stay
 *    honest to the same rule.
 *
 * The header states the MODE and TARGET at all times, so it is never ambiguous whether
 * you are driving a shell in the isolated lab or on a real engagement target.
 */

type Line = { seq: number; kind: SessionEvent["type"]; text: string };

const LAB_TARGET = "hackpit-lab-target";

export function CockpitSession() {
  const [status, setStatus] = useState<SessionStatus | null>(null);
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [lines, setLines] = useState<Line[]>([]);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** Set when the backend's danger gate refused — the operator must re-confirm. */
  const [dangerReason, setDangerReason] = useState<string | null>(null);

  // start form
  const [command, setCommand] = useState("nc");
  const [argsText, setArgsText] = useState("-lvnp 4444");
  const [target, setTarget] = useState(LAB_TARGET);
  const [engagementId, setEngagementId] = useState("");
  const [engagementSession, setEngagementSession] = useState("");

  // live input
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState<number | null>(null);

  const streamCtrl = useRef<AbortController | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    getSessionStatus(ctrl.signal)
      .then(setStatus)
      .catch(() => setStatus(null));
    return () => ctrl.abort();
  }, []);

  useEffect(() => () => streamCtrl.current?.abort(), []);

  // Keep the scrollback pinned to newest output.
  useEffect(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [lines]);

  const isLive = session?.state === "active";
  const isEngagement = session?.mode === "engagement";

  /** Subscribe to a session's output stream. Read-only — never writes to the process. */
  const attach = useCallback((sid: string) => {
    streamCtrl.current?.abort();
    const ctrl = new AbortController();
    streamCtrl.current = ctrl;

    streamSession(
      sid,
      (ev) => {
        if (ctrl.signal.aborted) return;
        const text =
          ev.type === "start"
            ? `— session started · ${String(ev.command ?? "")} ${(
                (ev.args as string[]) ?? []
              ).join(" ")} —`
            : ev.line ?? ev.reason ?? (ev.type === "exit" ? `— exited (${ev.code ?? "?"}) —` : "");
        if (text) setLines((prev) => [...prev, { seq: ev.seq, kind: ev.type, text }]);
        if (ev.type === "exit" || ev.type === "killed") {
          setSession((prev) =>
            prev && prev.sid === sid
              ? { ...prev, state: ev.type === "killed" ? "killed" : "exited" }
              : prev
          );
        }
      },
      -1,
      ctrl.signal
    ).catch(() => {
      /* stream ended or aborted — final state comes from the exit event / kill call */
    });
  }, []);

  /** Start a session. `ack` re-sends after the danger gate's red confirm. */
  const doStart = useCallback(
    (ack: boolean) => {
      if (starting) return;
      const cmd = command.trim();
      const tgt = target.trim();
      if (!cmd || !tgt) return;

      setStarting(true);
      setError(null);
      if (!ack) setDangerReason(null);

      startSession({
        command: cmd,
        args: argsText.trim() ? argsText.trim().split(/\s+/) : [],
        target: tgt,
        // Clicking START is the human approval. There is no approve-all.
        approved: true,
        dangerous_ack: ack,
        engagement_id: engagementId.trim() || null,
        session_id: engagementSession.trim() || null,
      })
        .then((info) => {
          setSession(info);
          setLines([]);
          setDangerReason(null);
          attach(info.sid);
          setTimeout(() => inputRef.current?.focus(), 50);
        })
        .catch((err: unknown) => {
          const msg = err instanceof ApiError ? err.message : "Could not start the session.";
          // The danger gate is a RED CONFIRM, not a failure — surface it as one.
          if (msg.startsWith("[danger]")) setDangerReason(msg.replace(/^\[danger\]\s*/, ""));
          else setError(msg);
        })
        .finally(() => {
          setStarting(false);
          getSessionStatus()
            .then(setStatus)
            .catch(() => {});
        });
    },
    [starting, command, argsText, target, engagementId, engagementSession, attach]
  );

  /** *** HUMAN-ONLY *** — fires on the operator's Enter keypress and nothing else. */
  const send = useCallback(() => {
    const data = input;
    if (!session || !isLive) return;
    setInput("");
    setHistIdx(null);
    if (data.trim()) {
      setHistory((prev) => (prev[prev.length - 1] === data ? prev : [...prev, data]));
    }
    writeSessionStdin(session.sid, data).catch((err: unknown) => {
      setError(err instanceof ApiError ? err.message : "Input was not delivered.");
    });
  }, [input, session, isLive]);

  const doKill = useCallback(() => {
    if (!session) return;
    killSession(session.sid)
      .then((info) => setSession(info))
      .catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : "Could not kill the session.");
      });
  }, [session]);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter") {
        e.preventDefault();
        send();
        return;
      }
      if (e.key === "ArrowUp") {
        if (!history.length) return;
        e.preventDefault();
        const idx = histIdx === null ? history.length - 1 : Math.max(0, histIdx - 1);
        setHistIdx(idx);
        setInput(history[idx]);
      } else if (e.key === "ArrowDown") {
        if (histIdx === null) return;
        e.preventDefault();
        const idx = histIdx + 1;
        if (idx >= history.length) {
          setHistIdx(null);
          setInput("");
        } else {
          setHistIdx(idx);
          setInput(history[idx]);
        }
      }
    },
    [send, history, histIdx]
  );

  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "session" }]}>
      <div className="hp-kali">
        <header className="hp-kali-head">
          <div className="hp-ap-kicker">human-only stdin · one live session</div>
          <h1 className="hp-kali-title">:session</h1>
          <p className="hp-kali-sub">
            Start a listener, catch a shell that <b>stays alive</b>, and type into it over
            time. Starting is a <b>gated command</b> — approved once, with the same
            red-confirm any listener gets. Once live, <b>only you</b> can type into it:
            the agent has no path to a session&rsquo;s input.
          </p>
        </header>

        {/* MODE BANNER — always visible, never ambiguous which box you are driving. */}
        {session ? (
          <div
            className={`hp-ck-banner ${isEngagement ? "hp-cs-realbanner" : "hp-ck-ok"}`}
            role="status"
          >
            <span className={isEngagement ? "hp-kali-dot" : "hp-ck-dot"} />
            {isEngagement ? (
              <>
                <b>REAL-TARGET ENGAGEMENT</b> · driving <b>{session.target}</b> · sandbox{" "}
                {session.container} · <b>no isolation floor</b> — you are on a real host
              </>
            ) : (
              <>
                <b>ISOLATED LAB</b> · driving <b>{session.target}</b> · sandbox{" "}
                {session.container} · egress-less
              </>
            )}
            <span className="hp-cs-state"> · {session.state}</span>
          </div>
        ) : (
          <div className="hp-ck-banner" role="status">
            {status ? (
              <>
                no live session · {status.live}/{status.max_live} slots used · idle timeout{" "}
                {Math.round(status.idle_timeout_seconds / 60)}m
              </>
            ) : (
              <>connecting to backend…</>
            )}
          </div>
        )}

        {/* START FORM — shown until a session exists (or after one ends). */}
        {!isLive && (
          <section className="hp-cs-start">
            <div className="hp-cs-row">
              <label className="hp-cs-field">
                <span>command</span>
                <input
                  value={command}
                  onChange={(e) => setCommand(e.target.value)}
                  spellCheck={false}
                  autoComplete="off"
                  disabled={starting}
                />
              </label>
              <label className="hp-cs-field hp-cs-grow">
                <span>args</span>
                <input
                  value={argsText}
                  onChange={(e) => setArgsText(e.target.value)}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="-lvnp 4444"
                  disabled={starting}
                />
              </label>
            </div>
            <div className="hp-cs-row">
              <label className="hp-cs-field hp-cs-grow">
                <span>bind target</span>
                <input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  spellCheck={false}
                  autoComplete="off"
                  disabled={starting}
                />
              </label>
              <label className="hp-cs-field">
                <span>engagement id (optional)</span>
                <input
                  value={engagementId}
                  onChange={(e) => setEngagementId(e.target.value)}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="lab if empty"
                  disabled={starting}
                />
              </label>
              <label className="hp-cs-field">
                <span>record to session</span>
                <input
                  value={engagementSession}
                  onChange={(e) => setEngagementSession(e.target.value)}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder="engagement id"
                  disabled={starting}
                />
              </label>
            </div>

            <p className="hp-cs-hint">
              Leave <b>engagement id</b> empty for the <b>isolated lab</b>. Filling it binds
              the session to that engagement&rsquo;s <b>real target</b> and its scope-lock —
              there is no isolation floor there.
            </p>

            {/* RED CONFIRM — the backend's danger gate refused; re-confirm to proceed. */}
            {dangerReason && (
              <div className="hp-cs-danger" role="alert">
                <b>This starts a shell-catcher.</b>
                <span className="hp-cs-danger-why">{dangerReason}</span>
                <span className="hp-cs-danger-why">
                  It will reach whatever the {engagementId.trim() ? "engagement" : "lab"} sandbox
                  can reach. Confirm to start it.
                </span>
                <button
                  type="button"
                  className="hp-cs-confirm"
                  onClick={() => doStart(true)}
                  disabled={starting}
                >
                  {starting ? "starting…" : "I understand — start it"}
                </button>
              </div>
            )}

            {error && <p className="hp-cv-error">{error}</p>}

            {!dangerReason && (
              <button
                type="button"
                className="hp-cs-go"
                onClick={() => doStart(false)}
                disabled={starting || !command.trim() || !target.trim()}
              >
                {starting ? "starting…" : "approve & start session →"}
              </button>
            )}
            {session && !isLive && (
              <p className="hp-cs-hint">
                Last session <code>{session.sid}</code> {session.state}
                {session.exit_code !== null ? ` (exit ${session.exit_code})` : ""} · transcript
                recorded as run <code>{session.run_id}</code>.
              </p>
            )}
          </section>
        )}

        {/* TERMINAL */}
        {session && (
          <section className="hp-ck-out-wrap">
            <div className="hp-ck-out-bar">
              <span className="hp-ck-out-lights" aria-hidden>
                <i />
                <i />
                <i />
              </span>
              <span className="hp-ck-out-title">
                {isEngagement ? "engagement" : "lab"} · {session.target} ·{" "}
                {isLive ? "live" : session.state}
              </span>
              {isLive && (
                <button
                  type="button"
                  className="hp-cs-kill"
                  onClick={doKill}
                  title="Terminate this session and flush its transcript"
                >
                  kill
                </button>
              )}
            </div>

            <div className="hp-ck-out" ref={outRef}>
              {lines.length === 0 && (
                <span className="hp-ck-empty">waiting for output…</span>
              )}
              {lines.map((l) => (
                <div
                  key={l.seq}
                  className={
                    l.kind === "stdin"
                      ? "hp-ck-line hp-cs-in"
                      : l.kind === "stderr"
                        ? "hp-ck-line hp-ck-stderr"
                        : l.kind === "error" || l.kind === "killed"
                          ? "hp-ck-line hp-ck-err"
                          : l.kind === "start" || l.kind === "exit"
                            ? "hp-ck-line hp-ck-meta"
                            : "hp-ck-line hp-ck-stdout"
                  }
                >
                  {l.kind === "stdin" && (
                    <span className="hp-kali-prompt" aria-hidden>
                      ${" "}
                    </span>
                  )}
                  {l.text}
                </div>
              ))}
            </div>

            {/* HUMAN input line — the only caller of writeSessionStdin. */}
            <div className="hp-kali-inputline">
              <span className="hp-kali-prompt" aria-hidden>
                {isEngagement ? "engagement" : "lab"}:{session.target}$
              </span>
              <input
                ref={inputRef}
                className="hp-kali-input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={onKeyDown}
                placeholder={isLive ? "type into the live session…" : "session is not live"}
                spellCheck={false}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                aria-label="Live session input"
                disabled={!isLive}
              />
              {isLive && (
                <span className="hp-ck-cursor" aria-hidden>
                  ▋
                </span>
              )}
            </div>
          </section>
        )}

        <p className="hp-kali-note">
          Starting a session runs through the <b>same gates</b> as any other command
          (approve-each, heuristic red-confirm, mode gate, argv-only) — it is not a new
          capability, just a command that stays alive. Once live, its input is{" "}
          <b>human-only</b>: the orchestrator/loop may <i>propose</i> starting a session, but
          nothing automated can type into one. The full transcript is recorded against the
          engagement and tagged with its mode. This is a <b>localhost-only</b> dev tool with
          no auth — an exposed instance would hand a stranger a live shell.
        </p>
      </div>
    </PageShell>
  );
}
