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
type Line = { kind: "stdout" | "stderr" | "meta" | "err" | "disc"; text: string };

const cmdline = (p: LoopProposal) => `${p.command} ${p.args.join(" ")}`.trim();

export function CockpitLoop({
  sessionId,
  engagementId = null,
  scopeLabel = null,
  onStepActive,
  onStepDone,
  onRunRecorded,
}: {
  sessionId: string;
  /** When set, the agent DRAFTS against this engagement's real target + authorized scope, and
   *  approved proposals run in REAL-TARGET engagement mode (routing through
   *  _validate_engagement: target -> approval -> danger). Omit for lab mode. */
  engagementId?: string | null;
  /** The authorized scope, shown so the operator can see what the agent may draft against. */
  scopeLabel?: string | null;
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

    // In engagement mode the proposer drafts against the REAL target + its authorized scope
    // (not the lab). It still only DRAFTS — the approve click below is what runs anything.
    loopPropose(sessionId, avoidRef.current, ctrl.signal, engagementId)
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
  }, [sessionId, engagementId, onStepActive]);

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
        approved: true, // set ONLY here, after the human clicked approve on this proposal
        dangerous_ack: dangerAck, // true only after the explicit confirm; ignored if none
        session_id: sessionId,
        step_id: stepId ?? undefined,
        // In engagement mode this routes the run through _validate_engagement (target ->
        // approval -> danger). The loop DRAFTS; this only fires on the human's click.
        engagement_id: engagementId ?? undefined,
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
          case "discovered":
            // Engagement only: hosts this run revealed, sorted by the authorized scope. The
            // in-scope ones become pivots the next draft may use; out-of-scope ones never do.
            if (ev.in_scope.length)
              push({ kind: "disc", text: `+ in scope: ${ev.in_scope.join(", ")}` });
            if (ev.out_of_scope.length)
              push({
                kind: "disc",
                text: `· seen, OUT of scope (not added): ${ev.out_of_scope.join(", ")}`,
              });
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
  }, [proposal, phase, dangerAck, sessionId, engagementId, onStepDone, onRunRecorded, propose]);

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

  // ONE-KEYSTROKE APPROVE (step 11). Per-command approval is unchanged — every command
  // still needs an explicit human act — this just lets that act be a keystroke on
  // single-target work where the volume is low:
  //   Enter → approve & run the shown proposal
  //   S     → skip it
  //   Esc   → stop the loop
  // A DANGEROUS proposal never fires on Enter: approve() itself returns early until the
  // explicit danger confirm is checked, so you cannot approve a reverse shell by reflex.
  // Shortcuts are ignored while focus is in a text field (you are editing the command),
  // so typing an argument never triggers a run.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      const tag = el?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || el?.isContentEditable) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      if (e.key === "Enter" && phase === "awaiting" && proposal?.gate_ok) {
        e.preventDefault();
        approve();
      } else if ((e.key === "s" || e.key === "S") && phase === "awaiting") {
        e.preventDefault();
        skip();
      } else if (e.key === "Escape" && active) {
        e.preventDefault();
        stop();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [phase, proposal, approve, skip, stop, active]);

  return (
    <div className="hp-loop">
      <header className="hp-loop-head">
        <div className="hp-loop-head-main">
          <h2 className="hp-ck-title hp-ck-title-sm">Guided loop</h2>
          <p className="hp-ck-sub">
            The agent proposes each step; <b>you approve every command</b> before it runs
            {engagementId
              ? " against the fully-open real target"
              : " in the isolated sandbox"}
            . It adapts to each result and proposes the next. Nothing runs without your
            approval.
            {engagementId && scopeLabel && (
              <>
                {" "}
                It drafts against your authorized scope: <code>{scopeLabel}</code>.
              </>
            )}
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
              <p className="hp-loop-danger-head">⚠ flagged as dangerous</p>
              <ul className="hp-loop-danger-flags">
                {danger.map((reason, i) => (
                  <li key={i}>{reason}</li>
                ))}
              </ul>
              <p className="hp-loop-danger-note">
                This command can run arbitrary code, open a shell, or reach out over the
                network. Nothing is blocked —{" "}
                {engagementId
                  ? "but this sandbox is FULLY OPEN and the target is real, so approving is a deliberate act"
                  : "the sandbox is isolated — but approving is a conscious choice, not an accident"}
                .
              </p>
              {phase === "awaiting" && (
                <label className="hp-loop-danger-ack">
                  <input
                    type="checkbox"
                    checked={dangerAck}
                    onChange={(e) => setDangerAck(e.target.checked)}
                  />
                  <span>
                    {engagementId
                      ? "Yes, I mean to run this against the real, authorized target."
                      : "Yes, I mean to run this against the isolated lab."}
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
                {!isDanger && <kbd className="hp-loop-kbd">⏎</kbd>}
              </button>
              <button type="button" className="hp-loop-skip" onClick={skip}>
                skip <kbd className="hp-loop-kbd">S</kbd>
              </button>
              <button type="button" className="hp-loop-skip" onClick={stop}>
                stop <kbd className="hp-loop-kbd">Esc</kbd>
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
