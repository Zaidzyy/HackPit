"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ApiError,
  execCockpitStream,
  getStepAlternative,
  loopPropose,
  submitLoopAnswer,
  startReconActive,
  startDiscover,
  startJsRecon,
  startNucleiScan,
  repeaterSend,
  startIntruder,
  type ExecEvent,
  type LoopProposal,
} from "@/lib/api";
import { AlternativeDisclosure } from "./AlternativeDisclosure";
import { ModelRetry } from "./ModelRetry";

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
  goal = null,
  target = null,
  scopeText = null,
  onStepActive,
  onStepDone,
  onRunRecorded,
  onAgentNote,
}: {
  sessionId: string;
  /** When set, the agent DRAFTS against this engagement's real target + authorized scope, and
   *  approved proposals run in REAL-TARGET engagement mode (routing through
   *  _validate_engagement: target -> approval -> danger). Omit for lab mode. */
  engagementId?: string | null;
  /** The authorized scope, shown so the operator can see what the agent may draft against. */
  scopeLabel?: string | null;
  /** The engagement goal + target + scope, threaded through only so the on-tap SECOND OPINION
   *  can weigh a proposed command against a KB alternative. Advisory; drives nothing. When goal
   *  is absent the disclosure is simply not shown. */
  goal?: string | null;
  target?: string | null;
  scopeText?: string | null;
  onStepActive?: (stepId: string | null) => void;
  onStepDone?: (stepId: string | null) => void;
  onRunRecorded?: () => void;
  /** The loop left a conversational NOTE on this proposal (thinking out loud / a doubt). Fired
   *  so a parent can surface it in the chat pane. The note is also persisted server-side. */
  onAgentNote?: (note: string) => void;
}) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [proposal, setProposal] = useState<LoopProposal | null>(null);
  const [dangerAck, setDangerAck] = useState(false);
  // The engagement target-lock is a handrail: an off-scope proposal WARNS and runs only when
  // this explicit override is ticked (mirrors dangerAck). Lab proposals never set it.
  const [scopeOverride, setScopeOverride] = useState(false);
  const [doneReason, setDoneReason] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // HTTP status of the last failure, so the error UI can offer a model swap only when the
  // failure is actually a model failure (503 = the backend's mapping of llm.LLMError).
  const [errStatus, setErrStatus] = useState<number | undefined>(undefined);
  // ASK-THE-OPERATOR: the answer being typed for a kind==="ask" proposal, and whether it's in
  // flight. Submitting stores it as context and continues the loop; it runs nothing.
  const [answer, setAnswer] = useState("");
  const [answering, setAnswering] = useState(false);
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
    setErrStatus(undefined);
    setProposal(null);
    setDangerAck(false); // every new proposal must be re-confirmed if dangerous
    setScopeOverride(false); // and the scope override is re-ticked consciously per proposal
    setAnswer(""); // a new proposal — clear any half-typed answer to a prior ask
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
        // The loop may have left a note for the operator — surface it in the chat pane.
        if (res.proposal.note) onAgentNote?.(res.proposal.note);
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        setError(
          err instanceof ApiError ? err.message : "Couldn’t get a proposal."
        );
        setErrStatus(err instanceof ApiError ? err.status : undefined);
        setPhase("error");
      });
  }, [sessionId, engagementId, onStepActive, onAgentNote]);

  const start = useCallback(() => {
    avoidRef.current = [];
    setStepCount(0);
    setLines([]);
    setDoneReason(null);
    propose();
  }, [propose]);

  const approve = useCallback(() => {
    if (!proposal || phase !== "awaiting") return;
    // The pre-check can fail for one recoverable reason in engagement mode: the target is off the
    // program scope. That is a HANDRAIL, not a wall — it runs with the explicit scope override.
    // Any other gate_ok=false (or lab mode) stays non-runnable.
    const scopeBlocked =
      !!engagementId && !proposal.gate_ok && /scope/i.test(proposal.gate_reason || "");
    if (!proposal.gate_ok && !(scopeBlocked && scopeOverride)) return;
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
        scope_override: scopeOverride, // true only after the explicit off-scope override tick
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
  }, [proposal, phase, dangerAck, scopeOverride, sessionId, engagementId, onStepDone, onRunRecorded, propose]);

  // Submit an answer to a kind==="ask" proposal: store it (plain context, not the vault) and
  // continue the loop so the next proposal sees it. Runs NOTHING — there is no command here.
  const submitAnswer = useCallback(() => {
    if (!proposal || proposal.kind !== "ask" || answering || !answer.trim()) return;
    setAnswering(true);
    submitLoopAnswer(sessionId, answer.trim(), proposal.ask_label ?? "")
      .then(() => {
        setAnswer("");
        onRunRecorded?.(); // the answer landed in engagement context
        propose(); // continue — the next draft reads the answer from the prompt
      })
      .catch(() => {
        /* leave the text so the operator can retry */
      })
      .finally(() => setAnswering(false));
  }, [proposal, answering, answer, sessionId, onRunRecorded, propose]);

  // Approve a kind==="surface" proposal: route it to that surface's OWN gated endpoint (which
  // re-checks scope/approval/danger), then advance the loop. The proposer executed nothing; this
  // dispatch fires only on the human's approve. The surface ingests to state, so the next propose
  // sees what it found.
  const runSurface = useCallback(() => {
    if (!proposal || proposal.kind !== "surface" || phase !== "awaiting") return;
    const surface = proposal.surface ?? "";
    const p = (proposal.surface_params ?? {}) as Record<string, unknown>;
    const ids = {
      engagement_id: engagementId ?? null,
      session_id: sessionId,
      approved: true, // set ONLY here, on the human's approve
      dangerous_ack: true, // the loop approve IS the confirm; the surface re-gates anyway
    };
    const stepId = proposal.step_id;
    const str = (v: unknown, d = "") => (typeof v === "string" ? v : d);
    const arr = (v: unknown) => (Array.isArray(v) ? (v as string[]) : undefined);
    setPhase("running");
    setExitCode(null);
    setLines([{ kind: "meta", text: `▶ run :${surface} ${JSON.stringify(p)}` }]);
    const push = (l: Line) => setLines((prev) => [...prev, l]);

    let call: Promise<{ id?: string }>;
    switch (surface) {
      case "recon":
        call = startReconActive({ domain: str(p.domain), ...ids });
        break;
      case "discover":
        call = startDiscover({
          mode: str(p.mode, "params"),
          url: str(p.url),
          domain: str(p.domain),
          method: str(p.method, "GET"),
          tool: str(p.tool),
          words: arr(p.words) ?? [],
          wordlist: str(p.wordlist),
          extensions: arr(p.extensions) ?? [],
          impersonate: Boolean(p.impersonate),
          attach_session: Boolean(p.attach_session),
          ...ids,
        });
        break;
      case "jsrecon":
        call = startJsRecon({
          target: p.target ? str(p.target) : undefined,
          js_urls: arr(p.js_urls),
          include_state: p.include_state === undefined ? true : Boolean(p.include_state),
          attach_session: Boolean(p.attach_session),
          ...ids,
        });
        break;
      case "nuclei":
        call = startNucleiScan({
          targets: arr(p.targets) ?? [],
          severities: arr(p.severities) ?? ["low", "medium", "high", "critical"],
          tags: arr(p.tags) ?? [],
          templates: arr(p.templates) ?? [],
          attach_session: Boolean(p.attach_session),
          ...ids,
        });
        break;
      case "repeater":
        // The send stays human-approved: this fires on YOUR approve, through the same /repeater/send
        // route a manual send uses. RepeaterRequest has no gate fields — the click is the approval.
        call = repeaterSend({
          method: str(p.method, "GET"),
          url: str(p.url),
          headers: Array.isArray(p.headers)
            ? (p.headers as { name: string; value: string }[])
            : [],
          body: str(p.body),
          follow_redirects: Boolean(p.follow_redirects),
          insecure: Boolean(p.insecure),
          http2: false,
          impersonate: Boolean(p.impersonate),
          attach_session: Boolean(p.attach_session),
          engagement_id: engagementId ?? null,
          session_id: sessionId,
        });
        break;
      case "intruder":
        call = startIntruder({
          url: str(p.url),
          method: str(p.method, "GET"),
          headers: Array.isArray(p.headers)
            ? (p.headers as { name: string; value: string }[])
            : [],
          body: str(p.body),
          payloads: arr(p.payloads) ?? [],
          mode: str(p.mode, "sniper"),
          shapes: [],
          follow_redirects: false,
          insecure: false,
          impersonate: Boolean(p.impersonate),
          delay_ms: typeof p.delay_ms === "number" ? p.delay_ms : 0,
          use_cookie_jar: true,
          attach_session: Boolean(p.attach_session),
          ...ids,
        });
        break;
      default:
        push({ kind: "err", text: `unknown surface: ${surface}` });
        setPhase("awaiting");
        return;
    }
    call
      .then((j) =>
        push({
          kind: "meta",
          text: `■ :${surface} job started${j?.id ? ` (${j.id})` : ""} — results land in state`,
        })
      )
      .catch((err: unknown) =>
        push({ kind: "err", text: err instanceof ApiError ? err.message : `:${surface} failed` })
      )
      .finally(() => {
        setStepCount((c) => c + 1);
        onStepDone?.(stepId);
        onRunRecorded?.();
        propose();
      });
  }, [proposal, phase, sessionId, engagementId, onStepDone, onRunRecorded, propose]);

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
        <ModelRetry
          error={error ?? "The proposer is unavailable."}
          status={errStatus}
          onRetry={propose}
        />
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
        // ASK THE OPERATOR: a proposal that is a QUESTION, not a command. Render an input +
        // "submit & continue" instead of approve/run — submitting stores the answer as context
        // and re-proposes. There is no command here, so nothing can be approved or executed.
        if (proposal.kind === "ask") {
          return (
            <section className="hp-loop-proposal hp-loop-ask">
              <div className="hp-loop-proposal-head">
                <span className="hp-loop-proposal-tag hp-loop-ask-tag" aria-hidden>
                  agent asks you
                </span>
                {proposal.step_id && (
                  <span className="hp-loop-proposal-step">{proposal.step_id}</span>
                )}
              </div>
              {proposal.rationale && (
                <p className="hp-loop-rationale">{proposal.rationale}</p>
              )}
              <p className="hp-loop-ask-instructions">{proposal.ask_instructions}</p>
              {phase === "awaiting" && (
                <>
                  <textarea
                    className="hp-loop-ask-input"
                    value={answer}
                    onChange={(e) => setAnswer(e.target.value)}
                    placeholder={
                      proposal.ask_label
                        ? `paste the ${proposal.ask_label} here…`
                        : "type your answer…"
                    }
                    rows={3}
                    spellCheck={false}
                    disabled={answering}
                  />
                  <p className="hp-loop-ask-note">
                    Stored as plain context and fed to the next step — a secret you paste here is
                    sent to the model. Nothing runs.
                  </p>
                  <div className="hp-loop-controls">
                    <button
                      type="button"
                      className="hp-ck-approve"
                      onClick={submitAnswer}
                      disabled={answering || !answer.trim()}
                    >
                      {answering ? "submitting…" : "submit answer & continue"}
                    </button>
                    <button type="button" className="hp-loop-skip" onClick={skip}>
                      skip <kbd className="hp-loop-kbd">S</kbd>
                    </button>
                    <button type="button" className="hp-loop-skip" onClick={stop}>
                      stop <kbd className="hp-loop-kbd">Esc</kbd>
                    </button>
                  </div>
                </>
              )}
            </section>
          );
        }
        // RUN A SURFACE: a proposal to run a first-class HackPit surface (a gated job) instead of a
        // raw command. Approve routes it to the surface's OWN gates; nothing runs until you click.
        if (proposal.kind === "surface") {
          return (
            <section className="hp-loop-proposal hp-loop-ask">
              <div className="hp-loop-proposal-head">
                <span className="hp-loop-proposal-tag hp-loop-ask-tag" aria-hidden>
                  run surface :{proposal.surface}
                </span>
                {proposal.step_id && (
                  <span className="hp-loop-proposal-step">{proposal.step_id}</span>
                )}
              </div>
              {proposal.rationale && <p className="hp-loop-rationale">{proposal.rationale}</p>}
              <pre
                className="hp-loop-ask-instructions"
                style={{ whiteSpace: "pre-wrap", fontFamily: "monospace", fontSize: "12px" }}
              >
                {`:${proposal.surface} ${JSON.stringify(proposal.surface_params ?? {})}`}
              </pre>
              <p className="hp-loop-ask-note">
                Runs the <b>:{proposal.surface}</b> surface through its own gates (scope · approval ·
                danger) and ingests results into state. Nothing runs until you approve.
              </p>
              {phase === "awaiting" && (
                <div className="hp-loop-controls">
                  <button type="button" className="hp-ck-approve" onClick={runSurface}>
                    approve &amp; run surface ⏎
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
        }
        const danger = proposal.dangerous_flags ?? [];
        const isDanger = danger.length > 0;
        // Engagement off-scope is a HANDRAIL: the pre-check fails but the operator can override.
        const scopeBlocked =
          !!engagementId && !proposal.gate_ok && /scope/i.test(proposal.gate_reason || "");
        const canApprove =
          (proposal.gate_ok || (scopeBlocked && scopeOverride)) && (!isDanger || dangerAck);
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

          {!proposal.gate_ok && !scopeBlocked && (
            <p className="hp-loop-gatewarn">
              ✕ this proposal can’t run — {proposal.gate_reason}. Skip it or stop.
            </p>
          )}

          {/* off-scope: a HANDRAIL, not a wall — warn + a one-tick override (reuses danger styles) */}
          {scopeBlocked && (
            <div className="hp-loop-danger" role="alert">
              <p className="hp-loop-danger-head">⚠ off your program scope</p>
              <p className="hp-loop-danger-note">
                {proposal.gate_reason}. The scope lock only warns — tick to run it anyway; you’re
                asserting you’re authorized for this host.
              </p>
              {phase === "awaiting" && (
                <label className="hp-loop-danger-ack">
                  <input
                    type="checkbox"
                    checked={scopeOverride}
                    onChange={(e) => setScopeOverride(e.target.checked)}
                  />
                  <span>Override scope for this command.</span>
                </label>
              )}
            </div>
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

          {phase === "awaiting" && goal && goal.trim() && (
            <div className="hp-loop-alt">
              <AlternativeDisclosure
                fetcher={() =>
                  getStepAlternative({
                    goal,
                    target,
                    scope_text: scopeText ?? scopeLabel,
                    step_title: proposal.rationale || proposal.step_id || proposal.command,
                    step_cmd: cmdline(proposal),
                  })
                }
              />
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
                  scopeBlocked && !scopeOverride
                    ? "Off your program scope — tick 'override scope' above to run it"
                    : !proposal.gate_ok && !scopeBlocked
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
