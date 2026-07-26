"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PageShell } from "./PageShell";
import { CockpitEngagement } from "./CockpitEngagement";
import {
  ApiError,
  attachCockpitStream,
  execCockpitBackground,
  execCockpitStream,
  getCockpitAllowlist,
  getCockpitStatus,
  type CockpitAllowlist,
  type CockpitStatus,
  type ExecEvent,
} from "@/lib/api";

/** Per-run time budget. The old flat 180s could not finish the arsenal's own first
 *  template (`nmap -p- --min-rate 2000`), let alone a full nuclei run. The backend clamps
 *  to its own 3600s ceiling, so nothing here can mean "unbounded". */
const TIMEOUT_CHOICES = [
  { label: "3 min", seconds: 180 },
  { label: "10 min", seconds: 600 },
  { label: "30 min", seconds: 1800 },
  { label: "1 hour", seconds: 3600 },
] as const;

function fmtDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.round(seconds / 60);
  return m < 60 ? `${m} min` : `${Math.round(m / 60)} h`;
}

/** Sensible starting args per command (recon-only, lab-target only). The user can
 *  edit these before approving. `-sT -Pn` keeps nmap unprivileged (the sandbox
 *  drops all capabilities, so a SYN/ping scan would fail). */
const PRESET_ARGS: Record<string, string> = {
  nmap: "-sT -Pn -p 3000,80,22 hackpit-lab-target",
  curl: "-sSI http://hackpit-lab-target:3000/",
  whatweb: "--color=never http://hackpit-lab-target:3000",
};

type Line = { kind: "stdout" | "stderr" | "meta" | "err"; text: string };

/**
 * Cockpit surface. Pick (or type) a command, review it, APPROVE &
 * RUN (the human control point), and watch its output stream live from the
 * isolated sandbox. Every command is gated server-side (allowlist + lab-only
 * target + explicit approval + isolation); the UI just makes the approval real.
 */
export function CockpitScreen({
  embedded = false,
  sessionId = null,
}: { embedded?: boolean; sessionId?: string | null } = {}) {
  const [allow, setAllow] = useState<CockpitAllowlist | null>(null);
  const [status, setStatus] = useState<CockpitStatus | null>(null);
  const [command, setCommand] = useState("nmap");
  const [argsText, setArgsText] = useState(PRESET_ARGS.nmap ?? "");
  const [lines, setLines] = useState<Line[]>([]);
  const [running, setRunning] = useState(false);
  const [exitCode, setExitCode] = useState<number | null>(null);
  // Index into TIMEOUT_CHOICES — how long THIS command may run.
  const [timeoutIdx, setTimeoutIdx] = useState(0);
  // Detached: the run survives leaving this page and can be reattached by run_id.
  const [detached, setDetached] = useState(false);
  const [backgroundRunId, setBackgroundRunId] = useState<string | null>(null);

  // Bumped after each recorded run so the engagement panel re-pulls its runs.
  const [engToken, setEngToken] = useState(0);

  const ctrlRef = useRef<AbortController | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);

  const refreshStatus = useCallback((signal?: AbortSignal) => {
    getCockpitStatus(signal)
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    getCockpitAllowlist(ctrl.signal)
      .then((a) => {
        setAllow(a);
        if (a.commands.length && !a.commands.some((c) => c.name === command)) {
          setCommand(a.commands[0].name);
          setArgsText(PRESET_ARGS[a.commands[0].name] ?? "");
        }
      })
      .catch(() => setAllow(null));
    refreshStatus(ctrl.signal);
    return () => ctrl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshStatus]);

  useEffect(() => () => ctrlRef.current?.abort(), []);

  // Keep the output pinned to the newest line.
  useEffect(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [lines]);

  const selectCommand = useCallback((name: string) => {
    setCommand(name);
    setArgsText(PRESET_ARGS[name] ?? "");
  }, []);

  const args = useMemo(
    () => argsText.trim().split(/\s+/).filter(Boolean),
    [argsText]
  );

  const preview = `${command} ${args.join(" ")}`.trim();
  const ready = status?.ready ?? false;

  const approveAndRun = useCallback(() => {
    if (running || !ready || args.length === 0) return;

    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;

    setRunning(true);
    setExitCode(null);
    setLines([{ kind: "meta", text: `$ ${preview}` }]);

    const push = (line: Line) => setLines((prev) => [...prev, line]);

    // The per-run timeout the operator chose. The backend clamps to its own ceiling, so a
    // silly value here can never mean "no timeout"; the executor's watchdog still bounds it.
    const timeoutSeconds = TIMEOUT_CHOICES[timeoutIdx].seconds;

    const onEvent = (ev: ExecEvent) => {
        switch (ev.type) {
          case "start":
            push({ kind: "meta", text: `▶ run ${ev.run_id} → ${ev.target}` });
            break;
          case "stdout":
            push({ kind: "stdout", text: ev.line });
            break;
          case "stderr":
            push({ kind: "stderr", text: ev.line });
            break;
          case "rejected":
            push({ kind: "err", text: `✕ rejected [${ev.gate}] — ${ev.reason}` });
            break;
          case "error":
            push({ kind: "err", text: `✕ ${ev.reason}` });
            break;
          case "exit":
            setExitCode(ev.code);
            push({ kind: "meta", text: `■ exit ${ev.code}` });
            break;
        }
    };

    const finish = () => {
      if (ctrl.signal.aborted) return;
      setRunning(false);
      // The run is now persisted against the engagement — nudge the panel to
      // re-pull the recorded runs.
      setEngToken((t) => t + 1);
    };
    const fail = (err: unknown) => {
      if (ctrl.signal.aborted) return;
      push({
        kind: "err",
        text: err instanceof ApiError ? err.message : "Execution failed.",
      });
    };

    const payload = {
      command,
      args,
      approved: true,
      session_id: sessionId,
      timeout_seconds: timeoutSeconds,
    };

    if (detached) {
      // DETACHED: the command outlives this request. We get a run_id back immediately and
      // then attach to the replayable stream, so closing the tab or reloading loses
      // nothing — reattaching replays the whole transcript. Approval is unchanged: the
      // gates ran before this returned, and a refusal is still a 403 with nothing run.
      execCockpitBackground(payload, ctrl.signal)
        .then((acc) => {
          setBackgroundRunId(acc.run_id);
          push({
            kind: "meta",
            text: `▷ detached as ${acc.run_id} — up to ${fmtDuration(acc.timeout_seconds)}; safe to leave this page`,
          });
          return attachCockpitStream(acc.run_id, onEvent, ctrl.signal);
        })
        .catch(fail)
        .finally(finish);
      return;
    }

    execCockpitStream(payload, onEvent, ctrl.signal).catch(fail).finally(finish);
  }, [running, ready, args, command, preview, sessionId, timeoutIdx, detached]);

  const inner = (
      <div className="hp-ck">
        <header className="hp-ck-head">
          {embedded ? (
            <h2 className="hp-ck-title hp-ck-title-sm">Live execution</h2>
          ) : (
            <h1 className="hp-ck-title">:cockpit</h1>
          )}
          <p className="hp-ck-sub">
            Human-approved execution against the isolated lab. One command at a
            time — you approve, it runs in the sandbox, output streams here.
          </p>
        </header>

        {/* readiness / isolation banner */}
        <div
          className={`hp-ck-banner ${ready ? "hp-ck-ok" : "hp-ck-warn"}`}
          role="status"
        >
          {status ? (
            ready ? (
              <>
                <span className="hp-ck-dot" /> sandbox <b>{status.sandbox}</b>{" "}
                isolated · target locked to <b>{status.lab_target}</b>
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

        {/* command builder */}
        <section className="hp-ck-builder">
          <label className="hp-ck-field">
            <span>command</span>
            <select
              value={command}
              onChange={(e) => selectCommand(e.target.value)}
              disabled={!allow || running}
            >
              {(allow?.commands ?? [{ name: command, description: "" }]).map((c) => (
                <option key={c.name} value={c.name}>
                  {c.name} — {("description" in c && c.description) || ""}
                </option>
              ))}
            </select>
          </label>

          <label className="hp-ck-field hp-ck-args">
            <span>arguments (must target {allow?.lab_target ?? "the lab"})</span>
            <input
              type="text"
              value={argsText}
              onChange={(e) => setArgsText(e.target.value)}
              spellCheck={false}
              disabled={running}
            />
          </label>

          {/* Time budget + detach. Neither changes what is ALLOWED to run — approval is
              still per command and every gate fires exactly as before. They change only how
              long the command gets and whether its output survives leaving this page. */}
          <div className="hp-ck-budget">
            <span className="hp-ck-budget-label">time budget</span>
            <div className="hp-ck-budget-opts">
              {TIMEOUT_CHOICES.map((choice, i) => (
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
            <label className="hp-ck-detach" title="Run detached: the command keeps going server-side and its output can be replayed by run id, so reloading or leaving this page loses nothing.">
              <input
                type="checkbox"
                checked={detached}
                onChange={(e) => setDetached(e.target.checked)}
                disabled={running}
              />
              <span>run detached</span>
            </label>
          </div>

          <div className="hp-ck-run">
            <code className="hp-ck-preview">{preview}</code>
            <button
              type="button"
              className="hp-ck-approve"
              onClick={approveAndRun}
              disabled={running || !ready || args.length === 0}
              title={
                ready ? "Approve and run this command" : "Sandbox not ready"
              }
            >
              {running ? "running…" : "APPROVE & RUN"}
            </button>
          </div>
          {backgroundRunId && (
            <p className="hp-ck-note">
              Detached run <code>{backgroundRunId}</code> — its output replays from the start
              every time you reattach, so a reload loses nothing.
            </p>
          )}
          <p className="hp-ck-note">
            Any command may run, but only against <b>{allow?.lab_target ?? "the lab"}</b>{" "}
            in the isolated sandbox. Approval is per command — there is no autonomous mode —
            and commands that run arbitrary code need an extra confirm.
          </p>
        </section>

        {/* live output */}
        <section className="hp-ck-out-wrap">
          <div className="hp-ck-out-bar">
            <span className="hp-ck-out-lights" aria-hidden>
              <i />
              <i />
              <i />
            </span>
            <span className="hp-ck-out-title">
              {running ? "sandbox · streaming" : "sandbox · terminal"}
            </span>
            {exitCode !== null && (
              <span className={exitCode === 0 ? "hp-ck-exit0" : "hp-ck-exitn"}>
                exit {exitCode}
              </span>
            )}
          </div>
          <div className="hp-ck-out" ref={outRef}>
            {lines.length === 0 ? (
              <span className="hp-ck-empty">
                approve a command to see live output…
              </span>
            ) : (
              <>
                {lines.map((l, i) => (
                <div key={i} className={`hp-ck-line hp-ck-${l.kind}`}>
                  {l.text || " "}
                </div>
                ))}
                {running && (
                  <div className="hp-ck-line hp-ck-cursor" aria-hidden>
                    ▋
                  </div>
                )}
              </>
            )}
          </div>
        </section>

        {/* engagement — recorded runs + report (only for a composed path) */}
        {sessionId && (
          <CockpitEngagement
            key={sessionId}
            sessionId={sessionId}
            refreshToken={engToken}
          />
        )}
      </div>
  );

  if (embedded) return inner;
  return <PageShell crumbs={[{ label: "cockpit" }]}>{inner}</PageShell>;
}
