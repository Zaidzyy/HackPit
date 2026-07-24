"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { PageShell } from "./PageShell";
import {
  ApiError,
  getCockpitStatus,
  runKali,
  type CockpitStatus,
  type KaliResult,
} from "@/lib/api";

/**
 * :kali — a HUMAN-ONLY interactive shell into the isolated lab sandbox.
 *
 * Unlike :cockpit (allowlisted, recon-only, per-command approval), this runs whatever
 * you type as `sh -c` inside the sandbox — a full shell, pipes and all. That is safe
 * ONLY because the sandbox is egress-less, hardened and disposable, and the target
 * container is hardcoded server-side (this UI sends no target). Isolation is re-checked
 * on the backend before every command; if it isn't provably isolated, nothing runs.
 *
 * The command input is driven by a person at this terminal — there is no autonomous
 * path to it. Every command + its output is recorded to the engagement session.
 */

type Block = {
  id: number;
  command: string;
  running: boolean;
  result?: KaliResult;
  error?: string;
};

export function KaliShell() {
  const [status, setStatus] = useState<CockpitStatus | null>(null);
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
    getCockpitStatus(signal)
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
          <div className="hp-ap-kicker">human-only · isolated sandbox</div>
          <h1 className="hp-kali-title">:kali</h1>
          <p className="hp-kali-sub">
            A full interactive shell <b>inside the isolated lab sandbox</b>. Whatever
            you type runs there — pipes, redirects, your whole toolkit. There is no
            allowlist here: <b>you</b> are the operator. The sandbox is egress-less and
            disposable, and the target container is fixed — commands can only ever reach
            that one contained box.
          </p>
        </header>

        {/* isolation / readiness banner — same gate the cockpit shows */}
        <div
          className={`hp-ck-banner ${ready ? "hp-ck-ok" : "hp-ck-warn"}`}
          role="status"
        >
          {status ? (
            ready ? (
              <>
                <span className="hp-ck-dot" /> sandbox <b>{status.sandbox}</b> isolated
                · egress blocked · shell contained to this box
              </>
            ) : (
              <>
                <span className="hp-ck-dot" /> not ready —{" "}
                {status.detail || "sandbox unavailable"}. Bring the stack up:{" "}
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
                {status?.sandbox ?? "the sandbox"}…
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
              placeholder={ready ? "id · ls -la · nmap hackpit-lab-target" : "sandbox not ready"}
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
          Runs as <code>sh -c</code> inside <b>{status?.sandbox ?? "the sandbox"}</b>.
          Egress is blocked, so reaching the internet (e.g.{" "}
          <code>curl https://example.com</code>) simply fails — that is the containment,
          not a filter. Every command is recorded to the engagement session. Local dev
          tool: not for exposure without auth.
        </p>
      </div>
    </PageShell>
  );
}
