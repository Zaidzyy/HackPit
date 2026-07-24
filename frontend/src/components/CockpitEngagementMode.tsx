"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  enterEngagement,
  execCockpitStream,
  exitEngagement,
  getEngagementStatus,
  type EngagementRecord,
  type EngagementStatus,
  type ExecEvent,
} from "@/lib/api";

/**
 * REAL-TARGET engagement mode — the SUPERVISED, highest-risk surface.
 *
 * This is deliberately NOT the guided loop: there is no auto-propose, no batch, no
 * approve-all. You enter engagement mode explicitly (naming the real target + acknowledging
 * you are authorized), then run ONE command at a time, reading and approving each yourself.
 * The active mode + scope are always shown. Execution goes to a SCOPE-LOCKED sandbox: a
 * default-deny egress firewall allows ONLY the engagement's authorized scope (your own machine
 * and out-of-scope networks are NOT reachable). Because the floor is network-enforced, the
 * guided loop may DRAFT commands, but human approval of EVERY command is still required.
 */

type Line = { kind: "stdout" | "stderr" | "meta" | "err"; text: string };

export function CockpitEngagementMode({
  sessionId = null,
  onRunRecorded,
}: {
  sessionId?: string | null;
  onRunRecorded?: () => void;
}) {
  const [status, setStatus] = useState<EngagementStatus | null>(null);
  const [active, setActive] = useState<EngagementRecord | null>(null);

  // enter form
  const [target, setTarget] = useState("");
  const [auth, setAuth] = useState("");
  const [entering, setEntering] = useState(false);
  const [enterErr, setEnterErr] = useState<string | null>(null);

  // command surface
  const [command, setCommand] = useState("nmap");
  const [argsText, setArgsText] = useState("");
  const [dangerAck, setDangerAck] = useState(false);
  const [running, setRunning] = useState(false);
  const [exitCode, setExitCode] = useState<number | null>(null);
  const [lines, setLines] = useState<Line[]>([]);

  const ctrlRef = useRef<AbortController | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);

  const refresh = useCallback((signal?: AbortSignal) => {
    getEngagementStatus(signal)
      .then((s) => {
        setStatus(s);
        setActive(s.active[0] ?? null);
      })
      .catch(() => setStatus(null));
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    refresh(ctrl.signal);
    return () => ctrl.abort();
  }, [refresh]);
  useEffect(() => () => ctrlRef.current?.abort(), []);
  useEffect(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [lines]);

  const args = useMemo(
    () => argsText.trim().split(/\s+/).filter(Boolean),
    [argsText]
  );
  const preview = `${command} ${args.join(" ")}`.trim();
  const ready = status?.ready ?? false;

  const doEnter = useCallback(() => {
    const t = target.trim();
    const a = auth.trim();
    if (!t || !a || entering) return;
    setEntering(true);
    setEnterErr(null);
    enterEngagement(t, a, sessionId)
      .then((rec) => {
        setActive(rec);
        setArgsText(rec.target); // seed the first command with the target
        refresh();
      })
      .catch((err: unknown) =>
        setEnterErr(err instanceof ApiError ? err.message : "Couldn’t enter engagement mode.")
      )
      .finally(() => setEntering(false));
  }, [target, auth, entering, sessionId, refresh]);

  const doExit = useCallback(() => {
    if (!active) return;
    exitEngagement(active.engagement_id)
      .catch(() => {})
      .finally(() => {
        setActive(null);
        setLines([]);
        setExitCode(null);
        refresh();
      });
  }, [active, refresh]);

  const approveAndRun = useCallback(() => {
    if (!active || running || args.length === 0) return;
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    setRunning(true);
    setExitCode(null);
    setLines([{ kind: "meta", text: `$ ${preview}` }]);
    const push = (l: Line) => setLines((prev) => [...prev, l]);

    execCockpitStream(
      {
        command,
        args,
        approved: true,
        dangerous_ack: dangerAck,
        engagement_id: active.engagement_id,
        session_id: sessionId,
      },
      (ev: ExecEvent) => {
        switch (ev.type) {
          case "start":
            push({ kind: "meta", text: `▶ run ${ev.run_id} → ${ev.target} [${ev.mode ?? "?"}]` });
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
      },
      ctrl.signal
    )
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        push({ kind: "err", text: err instanceof ApiError ? err.message : "Execution failed." });
      })
      .finally(() => {
        if (ctrl.signal.aborted) return;
        setRunning(false);
        setDangerAck(false); // re-confirm consciously for the next command
        onRunRecorded?.();
      });
  }, [active, running, args, command, preview, dangerAck, sessionId, onRunRecorded]);

  // ---- NOT ENTERED: the deliberate, warned entry ---------------------------- //
  if (!active) {
    return (
      <div className="hp-eng">
        <div className="hp-eng-warn" role="alert">
          <p className="hp-eng-warn-head">⚠ You are about to leave the isolated lab.</p>
          <p>
            Engagement mode runs against a <b>real target</b> you name as the <b>scope</b> (a
            single host or a CIDR). On entry the sandbox is <b>SCOPE-LOCKED</b>: a default-deny
            egress firewall allows <b>only</b> that scope — <b>your own machine and out-of-scope
            networks are NOT reachable</b>. You are responsible for authorization and for staying
            in scope. Because the floor is network-enforced, the guided loop may <b>draft</b>
            commands here, but <b>human approval of every command is still required</b> — the loop
            never fires on its own. No autonomous mode, no batch, no approve-all.
          </p>
        </div>

        <div className="hp-eng-enter">
          <label className="hp-ck-field">
            <span>authorized scope — a single host/URL or a CIDR you may test</span>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. scanme.nmap.org  or  10.10.10.0/24"
              spellCheck={false}
              autoComplete="off"
              disabled={entering}
            />
          </label>
          <label className="hp-ck-field">
            <span>authorization acknowledgement (required)</span>
            <input
              type="text"
              value={auth}
              onChange={(e) => setAuth(e.target.value)}
              placeholder="I am authorized to test this target and will stay in scope."
              spellCheck={false}
              autoComplete="off"
              disabled={entering}
            />
          </label>
          <button
            type="button"
            className="hp-ck-approve is-danger"
            onClick={doEnter}
            disabled={entering || !target.trim() || !auth.trim()}
            title="Deliberately enter real-target engagement mode"
          >
            {entering ? "entering…" : "ENTER ENGAGEMENT MODE →"}
          </button>
          {enterErr && <p className="hp-cv-error">{enterErr}</p>}
        </div>

        <div
          className={`hp-ck-banner ${ready ? "hp-ck-warn" : "hp-ck-warn"}`}
          role="status"
        >
          {status ? (
            ready ? (
              <>
                <span className="hp-ck-dot" /> engagement sandbox <b>{status.sandbox}</b> ready ·
                <b> SCOPE-LOCKED</b> · egress reaches the authorized scope only · human-approve-each
              </>
            ) : (
              <>
                <span className="hp-ck-dot" /> engagement sandbox not running —{" "}
                {status.detail || "bring it up"}.{" "}
                <code>docker compose -f docker/docker-compose.yml up -d --build</code>
              </>
            )
          ) : (
            <>connecting to backend…</>
          )}
        </div>
      </div>
    );
  }

  // ---- ENTERED: always-shown mode indicator + manual approve-each ----------- //
  return (
    <div className="hp-eng hp-eng-live">
      <div className="hp-eng-mode" role="status">
        <span className="hp-eng-mode-tag">ENGAGEMENT · REAL TARGET</span>
        <span className="hp-eng-mode-target">
          scope-locked to <b>{active.target}</b>
        </span>
        <span className="hp-eng-wall-ok">
          {ready ? "SCOPE-LOCKED · off-scope + your machine unreachable" : "sandbox not running"}
        </span>
        <button type="button" className="hp-loop-stop" onClick={doExit}>
          exit engagement
        </button>
      </div>

      <p className="hp-ck-note">
        Egress is <b>scope-locked</b> to <b>{active.target}</b> — your own machine and out-of-scope
        networks are not reachable. The guided loop may <b>draft</b> commands, but <b>you approve
        every command</b> before it runs — the loop never fires on its own, and there is no batch
        or approve-all.
      </p>

      <section className="hp-ck-builder">
        <label className="hp-ck-field">
          <span>command</span>
          <input
            type="text"
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            spellCheck={false}
            disabled={running}
          />
        </label>
        <label className="hp-ck-field hp-ck-args">
          <span>arguments (must reference {active.target})</span>
          <input
            type="text"
            value={argsText}
            onChange={(e) => setArgsText(e.target.value)}
            spellCheck={false}
            disabled={running}
          />
        </label>

        <label className="hp-eng-ack">
          <input
            type="checkbox"
            checked={dangerAck}
            onChange={(e) => setDangerAck(e.target.checked)}
          />
          <span>
            Confirm dangerous commands (interpreters, shells, frameworks) for this run — needed
            only if the server flags it.
          </span>
        </label>

        <div className="hp-ck-run">
          <code className="hp-ck-preview">{preview}</code>
          <button
            type="button"
            className="hp-ck-approve is-danger"
            onClick={approveAndRun}
            disabled={running || !ready || args.length === 0}
            title={ready ? "Approve and run against the real target" : "Engagement sandbox not running"}
          >
            {running ? "running…" : "APPROVE & RUN (REAL TARGET)"}
          </button>
        </div>
      </section>

      <section className="hp-ck-out-wrap">
        <div className="hp-ck-out-bar">
          <span className="hp-ck-out-lights" aria-hidden>
            <i />
            <i />
            <i />
          </span>
          <span className="hp-ck-out-title">
            {running ? "engagement · streaming" : "engagement · terminal"}
          </span>
          {exitCode !== null && (
            <span className={exitCode === 0 ? "hp-ck-exit0" : "hp-ck-exitn"}>
              exit {exitCode}
            </span>
          )}
        </div>
        <div className="hp-ck-out" ref={outRef}>
          {lines.length === 0 ? (
            <span className="hp-ck-empty">approve a command to see live output…</span>
          ) : (
            <>
              {lines.map((l, i) => (
                <div key={i} className={`hp-ck-line hp-ck-${l.kind}`}>
                  {l.text || " "}
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
    </div>
  );
}
