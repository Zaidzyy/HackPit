"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { PageShell } from "./PageShell";
import {
  ApiError,
  getKaliStatus,
  startKaliShell,
  runInKaliShell,
  closeKaliShell,
  type KaliStatus,
  type KaliCommandResult,
} from "@/lib/api";

/**
 * :kali — a HUMAN-ONLY interactive shell into the OPEN (full-network-reach) sandbox.
 *
 * Unlike :cockpit (argv-only, lab-locked, isolated, heuristic red-confirm), this runs whatever you type as
 * `sh -c` inside a SEPARATE, intentionally NON-isolated container that reaches the
 * internet, the host and the LAN. The target container is hardcoded server-side (this
 * UI sends no target). There is no isolation here — the safety that remains is that it
 * is HUMAN-driven only (no autonomous path to it), disposable, and audited. Every
 * command + its output is recorded to the engagement session.
 */

type Block = {
  id: number;
  command: string;
  running: boolean;
  result?: KaliCommandResult;
  error?: string;
};

/** Per-command time budget. This used to be a hardcoded 60s with no override at all,
 *  which made :kali useless for the long-running work a full shell is actually for.
 *  The backend clamps to its own 3600s ceiling, so nothing here means "unbounded". */
const KALI_TIMEOUT_CHOICES = [
  { label: "3 min", seconds: 180 },
  { label: "10 min", seconds: 600 },
  { label: "30 min", seconds: 1800 },
  { label: "1 hour", seconds: 3600 },
] as const;

export function KaliShell() {
  const [status, setStatus] = useState<KaliStatus | null>(null);
  const [command, setCommand] = useState("");
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [running, setRunning] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState<number | null>(null);
  // Index into KALI_TIMEOUT_CHOICES — how long the next command may run.
  const [timeoutIdx, setTimeoutIdx] = useState(0);

  const idRef = useRef(0);
  const ctrlRef = useRef<AbortController | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  // The ONE persistent shell this panel drives. State (cd/env/jobs) lives in it across
  // commands; it is lazily started on the first command and reset on demand / disconnect.
  const shellRef = useRef<string | null>(null);
  const [shellSid, setShellSid] = useState<string | null>(null);

  const refreshStatus = useCallback((signal?: AbortSignal) => {
    getKaliStatus(signal)
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    refreshStatus(ctrl.signal);
    return () => ctrl.abort();
  }, [refreshStatus]);

  useEffect(() => () => ctrlRef.current?.abort(), []);

  // Keep the scrollback pinned to the newest output.
  useEffect(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [blocks]);

  const ready = status?.ready ?? false;

  const submit = useCallback(() => {
    const cmd = command.trim();
    if (!cmd || running) return;

    const id = ++idRef.current;
    setBlocks((prev) => [...prev, { id, command: cmd, running: true }]);
    setHistory((prev) => (prev[prev.length - 1] === cmd ? prev : [...prev, cmd]));
    setHistIdx(null);
    setCommand("");
    setRunning(true);

    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;

    // Persistent shell: reuse the existing one so cd/env/jobs carry across commands; start
    // one lazily on the first command. If the shell was reaped or exited (the human typed
    // `exit`), start a fresh one transparently.
    const ensureShell = async (): Promise<string> => {
      if (shellRef.current) return shellRef.current;
      const info = await startKaliShell(null, ctrl.signal);
      shellRef.current = info.sid;
      setShellSid(info.sid);
      return info.sid;
    };

    ensureShell()
      .then((sid) =>
        runInKaliShell(sid, cmd, KALI_TIMEOUT_CHOICES[timeoutIdx].seconds, ctrl.signal)
      )
      .then((result) => {
        if (ctrl.signal.aborted) return;
        setBlocks((prev) =>
          prev.map((b) => (b.id === id ? { ...b, running: false, result } : b))
        );
        // The shell exited (e.g. `exit`) — drop the sid so the next command opens a new one.
        if (result.shell_closed) {
          shellRef.current = null;
          setShellSid(null);
        }
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        // A 409 usually means the shell is gone (reaped / sandbox restarted) — clear it so
        // the next command starts fresh, and surface the reason on this block.
        if (err instanceof ApiError && err.status === 409) {
          shellRef.current = null;
          setShellSid(null);
        }
        const msg = err instanceof ApiError ? err.message : "Command failed to run.";
        setBlocks((prev) =>
          prev.map((b) => (b.id === id ? { ...b, running: false, error: msg } : b))
        );
      })
      .finally(() => {
        if (ctrl.signal.aborted) return;
        setRunning(false);
        // Isolation could change between commands — re-pull the banner state.
        refreshStatus();
        inputRef.current?.focus();
      });
  }, [command, running, refreshStatus, timeoutIdx]);

  // Reset the shell: close the live one and clear the scrollback, so the next command opens
  // a clean shell (fresh cwd/env). Used when the operator wants a blank slate.
  const resetShell = useCallback(() => {
    const sid = shellRef.current;
    shellRef.current = null;
    setShellSid(null);
    setBlocks([]);
    if (sid) closeKaliShell(sid).catch(() => {});
    inputRef.current?.focus();
  }, []);

  // Close the persistent shell when the panel unmounts — don't leak a container process.
  useEffect(
    () => () => {
      const sid = shellRef.current;
      if (sid) closeKaliShell(sid).catch(() => {});
    },
    []
  );

  // Up/Down walk the command history (a terminal affordance).
  const onKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter") {
        e.preventDefault();
        submit();
        return;
      }
      if (e.key === "ArrowUp") {
        if (!history.length) return;
        e.preventDefault();
        const idx = histIdx === null ? history.length - 1 : Math.max(0, histIdx - 1);
        setHistIdx(idx);
        setCommand(history[idx]);
      } else if (e.key === "ArrowDown") {
        if (histIdx === null) return;
        e.preventDefault();
        const idx = histIdx + 1;
        if (idx >= history.length) {
          setHistIdx(null);
          setCommand("");
        } else {
          setHistIdx(idx);
          setCommand(history[idx]);
        }
      }
    },
    [submit, history, histIdx]
  );

  return (
    <PageShell crumbs={[{ label: "kali · transcript" }]}>
      <div className="hp-kali">
        <header className="hp-kali-head">
          <div className="hp-ap-kicker">human-only · full network reach · NOT isolated</div>
          <h1 className="hp-kali-title">:kali · transcript</h1>
          <p className="hp-kali-sub">
            The <b>transcript variant</b> of <code>:kali</code> — a full interactive shell in
            a sandbox with <b>full network reach</b> (the internet, this host, and your LAN).
            Whatever you type runs there: pipes, redirects, your whole toolkit. There is no
            allowlist and <b>no isolation</b> — <b>you</b> are the operator. The container is
            fixed and disposable, and this is a human-only terminal.
          </p>
          <p className="hp-kali-sub hp-kali-xref">
            Every command here is delimited server-side, so you get a clean, escape-free
            transcript per command — the record a report or audit is built from, and why
            full-screen tools can&apos;t render in this view. For <code>vim</code>,{" "}
            <code>top</code>, an interactive <code>msfconsole</code> or a raw{" "}
            <code>evil-winrm</code> shell, use the main{" "}
            <Link href="/terminal" className="hp-pty-xlink">
              :kali
            </Link>{" "}
            shell — a real PTY into this same sandbox.
          </p>
        </header>

        {/* readiness banner — availability only; makes NO isolation claim (there is none) */}
        <div
          className={`hp-ck-banner ${ready ? "hp-kali-warnbanner" : "hp-ck-warn"}`}
          role="status"
        >
          {status ? (
            ready ? (
              <>
                <span className="hp-kali-dot" /> shell <b>{status.container}</b> · full
                network reach · <b>NOT isolated</b> · human-only
              </>
            ) : (
              <>
                <span className="hp-ck-dot" /> not ready —{" "}
                {status.detail || "open sandbox unavailable"}. Bring the stack up:{" "}
                <code>docker compose -f docker/docker-compose.yml up -d</code>
              </>
            )
          ) : (
            <>connecting to backend…</>
          )}
        </div>

        {/* terminal */}
        <section className="hp-ck-out-wrap">
          <div className="hp-ck-out-bar">
            <span className="hp-ck-out-lights" aria-hidden>
              <i />
              <i />
              <i />
            </span>
            <span className="hp-ck-out-title">
              {running ? "sandbox · running" : "sandbox · :kali shell"}
            </span>
            {shellSid && (
              <span
                className="hp-kali-persist"
                title="One long-lived shell — cd, environment and background jobs persist across commands."
              >
                ● persistent
              </span>
            )}
            {shellSid && (
              <button
                type="button"
                className="hp-kali-clear"
                onClick={resetShell}
                disabled={running}
                title="Close this shell and start fresh — resets cwd, environment and jobs"
              >
                reset shell
              </button>
            )}
            {blocks.length > 0 && (
              <button
                type="button"
                className="hp-kali-clear"
                onClick={() => setBlocks([])}
                disabled={running}
                title="Clear the scrollback (does not affect recorded runs)"
              >
                clear
              </button>
            )}
          </div>

          <div className="hp-ck-out" ref={outRef}>
            {blocks.length === 0 && (
              <span className="hp-ck-empty">
                type a command and press Enter — it runs inside{" "}
                {status?.container ?? "the open sandbox"}…
              </span>
            )}

            {blocks.map((b) => (
              <div key={b.id} className="hp-kali-block">
                <div className="hp-ck-line hp-kali-cmd">
                  <span className="hp-kali-prompt" aria-hidden>
                    kali@sandbox:~$
                  </span>{" "}
                  {b.command}
                </div>
                {b.running && (
                  <div className="hp-ck-line hp-ck-meta">running…</div>
                )}
                {b.error && (
                  <div className="hp-ck-line hp-ck-err">✕ {b.error}</div>
                )}
                {b.result && (
                  <>
                    {b.result.stdout && (
                      <div className="hp-ck-line hp-ck-stdout">
                        {b.result.stdout}
                      </div>
                    )}
                    {b.result.stderr && (
                      <div className="hp-ck-line hp-ck-stderr">
                        {b.result.stderr}
                      </div>
                    )}
                    <div className="hp-ck-line hp-kali-exit">
                      {b.result.timed_out ? (
                        <span className="hp-ck-exitn">timed out</span>
                      ) : (
                        <span
                          className={
                            b.result.exit_code === 0
                              ? "hp-ck-exit0"
                              : "hp-ck-exitn"
                          }
                        >
                          exit {b.result.exit_code ?? "?"}
                        </span>
                      )}
                      {b.result.truncated && (
                        <span className="hp-kali-trunc"> · output truncated</span>
                      )}
                    </div>
                  </>
                )}
              </div>
            ))}
          </div>

          {/* prompt input */}
          <div className="hp-kali-inputline">
            <span className="hp-kali-prompt" aria-hidden>
              kali@sandbox:~$
            </span>
            <input
              ref={inputRef}
              className="hp-kali-input"
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder={ready ? "id · ls -la · curl https://example.com" : "sandbox not ready"}
              spellCheck={false}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              aria-label="Sandbox shell command"
              disabled={running || !ready}
            />
            {running && (
              <span className="hp-ck-cursor" aria-hidden>
                ▋
              </span>
            )}
          </div>

          {/* Time budget. Nothing about containment changes with it: the container is
              still hardcoded server-side and every command is still recorded. */}
          <div className="hp-ck-budget">
            <span className="hp-ck-budget-label">time budget</span>
            <div className="hp-ck-budget-opts">
              {KALI_TIMEOUT_CHOICES.map((choice, i) => (
                <button
                  key={choice.seconds}
                  type="button"
                  className={`hp-ck-budget-opt${i === timeoutIdx ? " hp-on" : ""}`}
                  onClick={() => setTimeoutIdx(i)}
                  disabled={running}
                >
                  {choice.label}
                </button>
              ))}
            </div>
          </div>
        </section>

        <p className="hp-kali-note">
          One <b>persistent shell</b> inside <b>{status?.container ?? "the open sandbox"}</b>:{" "}
          <code>cd</code>, exported variables and background jobs carry across commands (a{" "}
          <code>nc -lvnp 4444 &amp;</code> keeps listening, <code>cd /loot</code> holds). It has{" "}
          <b>full network reach</b> — the internet, this host, and your LAN are all reachable
          (that is the intent, not a bug). Every command is recorded to the engagement
          session. This is a <b>localhost-only</b> dev tool with no auth: because the shell
          reaches your host and LAN, it <b>must not</b> be exposed off localhost without
          authentication. (No full-screen apps like <code>vim</code>/<code>top</code> — this
          is a line shell, not a terminal.)
        </p>
      </div>
    </PageShell>
  );
}
