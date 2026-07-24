"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ApiError,
  execCockpitStream,
  loopPropose,
  type ExecEvent,
  type LoopProposal,
} from "@/lib/api";

/**
 * The guided orchestrator loop (docs/cockpit-loop.md), human-gated.
 *
 * The agent PROPOSES the next single recon command; the human APPROVES it; it runs
 * through the M1 executor (execCockpitStream — recon/lab/isolated, four gates); the
 * result is recorded and fed back; the agent proposes the next. It PAUSES for approval
 * at every step — nothing runs without an explicit approve. skip / stop are always
 * available. There is no auto-run and no "approve all".
 *
 * This component only proposes + streams the M1 executor; it has no other way to run
 * anything (and no path to the :kali shell). onStepDone / onStepActive let the parent
 * light the kill-chain map as the loop advances.
 */

type Phase = "idle" | "proposing" | "awaiting" | "running" | "done" | "error";
type Line = { kind: "stdout" | "stderr" | "meta" | "err"; text: string };

const cmdline = (p: LoopProposal) => `${p.command} ${p.args.join(" ")}`.trim();

export function CockpitLoop({
  sessionId,
  onStepActive,
  onStepDone,
  onRunRecorded,
}: {
  sessionId: string;
  onStepActive?: (stepId: string | null) => void;
  onStepDone?: (stepId: string | null) => void;
  onRunRecorded?: () => void;
}) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [proposal, setProposal] = useState<LoopProposal | null>(null);
  const [dangerAck, setDangerAck] = useState(false);
  const [doneReason, setDoneReason] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lines, setLines] = useState<Line[]>([]);
  const [exitCode, setExitCode] = useState<number | null>(null);
  const [stepCount, setStepCount] = useState(0);

  const avoidRef = useRef<string[]>([]);
  const ctrlRef = useRef<AbortController | null>(null);
  const outRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => () => ctrlRef.current?.abort(), []);
  useEffect(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [lines]);

  const propose = useCallback(() => {
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    setPhase("proposing");
    setError(null);
    setProposal(null);
    setDangerAck(false); // every new proposal must be re-confirmed if dangerous
    onStepActive?.(null);

    loopPropose(sessionId, avoidRef.current, ctrl.signal)
      .then((res) => {
        if (ctrl.signal.aborted) return;
        if (res.done || !res.proposal) {
          setDoneReason(res.reason ?? "the agent proposed no further step");
          setPhase("done");
          return;
        }
        setProposal(res.proposal);
        setPhase("awaiting");
        onStepActive?.(res.proposal.step_id);
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        setError(
          err instanceof ApiError ? err.message : "Couldn’t get a proposal."
        );
        setPhase("error");
      });
  }, [sessionId, onStepActive]);

  const start = useCallback(() => {
    avoidRef.current = [];
    setStepCount(0);
    setLines([]);
    setDoneReason(null);
    propose();
  }, [propose]);

  const approve = useCallback(() => {
    if (!proposal || !proposal.gate_ok || phase !== "awaiting") return;
    const danger = proposal.dangerous_flags ?? [];
    if (danger.length > 0 && !dangerAck) return; // dangerous flags need the explicit confirm
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;

    const stepId = proposal.step_id;
    setPhase("running");
    setExitCode(null);
    setLines([{ kind: "meta", text: `$ ${cmdline(proposal)}` }]);
    const push = (l: Line) => setLines((prev) => [...prev, l]);

    execCockpitStream(
      {
        command: proposal.command,
        args: proposal.args,
        approved: true,
        dangerous_ack: dangerAck, // true only after the explicit confirm; ignored if none
        session_id: sessionId,
        step_id: stepId ?? undefined,
      },
      (ev: ExecEvent) => {
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
      },
      ctrl.signal
    )
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        push({
          kind: "err",
          text: err instanceof ApiError ? err.message : "Execution failed.",
        });
      })
      .finally(() => {
        if (ctrl.signal.aborted) return;
        setStepCount((c) => c + 1);
        onStepDone?.(stepId);
        onRunRecorded?.();
        // Feed the result back → next proposal. This still PAUSES at awaiting-approval;
        // nothing runs without another explicit approve.
        propose();
      });
  }, [proposal, phase, dangerAck, sessionId, onStepDone, onRunRecorded, propose]);

  const skip = useCallback(() => {
    if (proposal) avoidRef.current = [...avoidRef.current, cmdline(proposal)];
    propose();
  }, [proposal, propose]);

  const stop = useCallback(() => {
    ctrlRef.current?.abort();
    onStepActive?.(null);
    setDoneReason("stopped by you");
    setPhase("done");
  }, [onStepActive]);

  const active = phase === "proposing" || phase === "awaiting" || phase === "running";

  return (
    <div className="hp-loop">
      <header className="hp-loop-head">
        <div className="hp-loop-head-main">
          <h2 className="hp-ck-title hp-ck-title-sm">Guided loop</h2>
          <p className="hp-ck-sub">
            The agent proposes each recon step; <b>you approve every command</b> before
            it runs in the isolated sandbox. It adapts to each result and proposes the
            next. Nothing runs without your approval.
          </p>
        </div>
        <div className="hp-loop-status" role="status">
          <span className={`hp-loop-pill hp-loop-${phase}`}>{phase}</span>
          {stepCount > 0 && (
            <span className="hp-loop-count">{stepCount} run{stepCount === 1 ? "" : "s"}</span>
          )}
          {active && (
            <button type="button" className="hp-loop-stop" onClick={stop}>
              stop
            </button>
          )}
        </div>
      </header>

      {phase === "idle" && (
        <div className="hp-loop-idle">
          <button type="button" className="hp-ck-approve" onClick={start}>
            Start the loop →
          </button>
          <span className="hp-loop-idle-note">
            The agent will propose the first recon step for your approval.
          </span>
        </div>
      )}

      {phase === "proposing" && (
        <div className="hp-loop-thinking">
          <span className="hp-loop-spinner" aria-hidden />
          the agent is thinking — choosing the next recon step…
        </div>
      )}

      {phase === "error" && (
        <div className="hp-loop-idle">
          <p className="hp-cv-error">{error}</p>
          <button type="button" className="hp-ck-approve" onClick={propose}>
            try again
          </button>
        </div>
      )}

      {phase === "done" && (
        <div className="hp-loop-done" role="status">
          <span className="hp-loop-done-check" aria-hidden>■</span>
          Loop ended — {doneReason}. The recorded runs and the report are below.
          <button type="button" className="hp-loop-restart" onClick={start}>
            run again
          </button>
        </div>
      )}

      {/* the proposal — shown while awaiting approval or during the run */}
      {proposal && (phase === "awaiting" || phase === "running") && (() => {
        const danger = proposal.dangerous_flags ?? [];
        const isDanger = danger.length > 0;
        const canApprove = proposal.gate_ok && (!isDanger || dangerAck);
        return (
        <section
          className={`hp-loop-proposal${proposal.gate_ok ? "" : " is-blocked"}${
            isDanger ? " is-danger" : ""
          }`}
        >
          <div className="hp-loop-proposal-head">
            <span className="hp-loop-proposal-tag" aria-hidden>
              agent proposes
            </span>
            {proposal.step_id && (
              <span className="hp-loop-proposal-step">{proposal.step_id}</span>
            )}
          </div>
          {proposal.rationale && (
            <p className="hp-loop-rationale">{proposal.rationale}</p>
          )}
          <code className={`hp-loop-cmd${isDanger ? " is-danger" : ""}`}>
            {cmdline(proposal)}
          </code>

          {!proposal.gate_ok && (
            <p className="hp-loop-gatewarn">
              ✕ this proposal can’t run — {proposal.gate_reason}. Skip it or stop.
            </p>
          )}

          {/* dangerous flags: detected, shown RED, require an explicit confirm to approve */}
          {isDanger && (
            <div className="hp-loop-danger" role="alert">
              <p className="hp-loop-danger-head">
                ⚠ dangerous {danger.length === 1 ? "flag" : "flags"} detected —{" "}
                <span className="hp-loop-danger-flags">{danger.join("  ·  ")}</span>
              </p>
              <p className="hp-loop-danger-note">
                {danger.length === 1 ? "This flag runs" : "These flags run"} code, touch the
                target’s OS/filesystem, or load arbitrary scripts. Nothing is blocked — but
                approving is a conscious choice, not an accident.
              </p>
              {phase === "awaiting" && (
                <label className="hp-loop-danger-ack">
                  <input
                    type="checkbox"
                    checked={dangerAck}
                    onChange={(e) => setDangerAck(e.target.checked)}
                  />
                  <span>
                    Yes, run <b>{danger.join(", ")}</b> against the isolated lab.
                  </span>
                </label>
              )}
            </div>
          )}

          {phase === "awaiting" && (
            <div className="hp-loop-controls">
              <button
                type="button"
                className={`hp-ck-approve${isDanger ? " is-danger" : ""}`}
                onClick={approve}
                disabled={!canApprove}
                title={
                  !proposal.gate_ok
                    ? "Blocked by a safety gate — cannot run"
                    : isDanger && !dangerAck
                    ? "Confirm the dangerous flag(s) above to enable approval"
                    : "Approve and run this command in the sandbox"
                }
              >
                {isDanger ? "APPROVE (DANGEROUS) & RUN" : "APPROVE & RUN"}
              </button>
              <button type="button" className="hp-loop-skip" onClick={skip}>
                skip
              </button>
              <button type="button" className="hp-loop-skip" onClick={stop}>
                stop
              </button>
            </div>
          )}
        </section>
        );
      })()}

      {/* live / last output */}
      {lines.length > 0 && (
        <section className="hp-ck-out-wrap hp-loop-out">
          <div className="hp-ck-out-bar">
            <span className="hp-ck-out-lights" aria-hidden>
              <i />
              <i />
              <i />
            </span>
            <span className="hp-ck-out-title">
              {phase === "running" ? "sandbox · streaming" : "sandbox · last run"}
            </span>
            {exitCode !== null && (
              <span className={exitCode === 0 ? "hp-ck-exit0" : "hp-ck-exitn"}>
                exit {exitCode}
              </span>
            )}
          </div>
          <div className="hp-ck-out" ref={outRef}>
            {lines.map((l, i) => (
              <div key={i} className={`hp-ck-line hp-ck-${l.kind}`}>
                {l.text || " "}
              </div>
            ))}
            {phase === "running" && (
              <div className="hp-ck-line hp-ck-cursor" aria-hidden>
                ▋
              </div>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
