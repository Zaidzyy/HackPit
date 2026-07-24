"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { PageShell } from "./PageShell";
import {
  ApiError,
  getKaliStatus,
  runKali,
  type KaliStatus,
  type KaliResult,
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
  result?: KaliResult;
  error?: string;
};

export function KaliShell() {
  const [status, setStatus] = useState<KaliStatus | null>(null);
  const [command, setCommand] = useState("");
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [running, setRunning] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState<number | null>(null);

  const idRef = useRef(0);
  const ctrlRef = useRef<AbortController | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

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

    runKali({ command: cmd }, ctrl.signal)
      .then((result) => {
        if (ctrl.signal.aborted) return;
        setBlocks((prev) =>
          prev.map((b) => (b.id === id ? { ...b, running: false, result } : b))
        );
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        const msg =
          err instanceof ApiError ? err.message : "Command failed to run.";
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
  }, [command, running, refreshStatus]);

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
    <PageShell crumbs={[{ label: "kali" }]}>
      <div className="hp-kali">
        <header className="hp-kali-head">
          <div className="hp-ap-kicker">human-only · full network reach · NOT isolated</div>
          <h1 className="hp-kali-title">:kali</h1>
          <p className="hp-kali-sub">
            A full interactive shell in a sandbox with <b>full network reach</b> — it
            reaches the internet, this host, and your LAN. Whatever you type runs there:
            pipes, redirects, your whole toolkit. There is no allowlist and{" "}
            <b>no isolation</b> here — <b>you</b> are the operator. The container is
            fixed and disposable, and this is a human-only terminal.
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
        </section>

        <p className="hp-kali-note">
          Runs as <code>sh -c</code> inside <b>{status?.container ?? "the open sandbox"}</b>,
          which has <b>full network reach</b> — the internet, this host, and your LAN are
          all reachable (that is the intent, not a bug). Every command is recorded to the
          engagement session. This is a <b>localhost-only</b> dev tool with no auth: because
          the shell now reaches your host and LAN, it <b>must not</b> be exposed off
          localhost without authentication.
        </p>
      </div>
    </PageShell>
  );
}
