"use client";

import { useCallback, useRef, useState } from "react";
import {
  ApiError,
  cloudOrchestrateAdvance,
  cloudOrchestratePropose,
  execCockpitStream,
  type CloudProposal,
  type ExecEvent,
} from "@/lib/api";

type Line = { kind: "meta" | "stdout" | "stderr" | "err"; text: string };

/**
 * CLOUD IAM ORCHESTRATION — the agent proposes the next edge to abuse; the human approves each one.
 * The cloud parallel to CockpitADOrchestrator. The safety model is the whole point of this panel,
 * so it is visible in the UI rather than only in the backend:
 *
 * * The agent PROPOSES. It picked an edge from the graph's real frontier (an INDEX), and the
 *   command came from the KB-grounded technique catalog — not from the model. Nothing has run when
 *   a proposal appears.
 * * EVERY step is an individual, explicit approval. There is no batch and no run-the-whole-path —
 *   `approved: true` is set in exactly one place in this file, inside the click handler for this
 *   one step.
 * * Destructive IAM abuse (attaching admin, minting keys, overwriting code) shows a red confirm.
 * * The walk NEVER auto-advances. After a successful run the operator asks for the next proposal.
 *
 * Execution goes through `execCockpitStream` — the same gated executor every other cockpit command
 * uses. This panel adds no execution path of its own.
 */
export function CockpitCloudOrchestrator({
  graphId,
  owned,
  traversed,
  engagementId = null,
  scopeLabel = null,
  sessionId = null,
  onAdvanced,
}: {
  graphId: string;
  owned: string[];
  traversed: string[];
  engagementId?: string | null;
  scopeLabel?: string | null;
  sessionId?: string | null;
  onAdvanced?: (next: { owned: string[]; traversed: string[] }, edgeKind: string) => void;
}) {
  const [proposal, setProposal] = useState<CloudProposal | null>(null);
  const [reason, setReason] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [thinking, setThinking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [ack, setAck] = useState(false);
  const [running, setRunning] = useState(false);
  const [lines, setLines] = useState<Line[]>([]);
  const [advanced, setAdvanced] = useState<string | null>(null);
  const [skipped, setSkipped] = useState<string[]>([]);

  const ctrlRef = useRef<AbortController | null>(null);
  const runIdRef = useRef<string | null>(null);

  const engagement = !!engagementId;

  const ask = useCallback(
    async (avoid: string[] = skipped) => {
      setThinking(true);
      setError(null);
      setProposal(null);
      setReason(null);
      setAdvanced(null);
      setLines([]);
      setAck(false);
      try {
        const res = await cloudOrchestratePropose({
          graph_id: graphId,
          owned,
          traversed,
          engagement_id: engagementId,
          avoid,
        });
        setDone(res.done);
        setProposal(res.proposal);
        setReason(res.reason);
      } catch (err: unknown) {
        setError(err instanceof ApiError ? err.message : "Couldn’t reach the reasoning model.");
      } finally {
        setThinking(false);
      }
    },
    [graphId, owned, traversed, engagementId, skipped]
  );

  /** APPROVE THIS ONE STEP. The only place `approved: true` is set in this file. */
  const approveAndRun = useCallback(() => {
    if (!proposal || running) return;
    if (!proposal.runnable) return;
    if (proposal.requires_confirm && !ack) return; // red confirm not given — refuse to send

    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    runIdRef.current = null;
    setRunning(true);
    setLines([{ kind: "meta", text: `$ ${proposal.command} ${proposal.args.join(" ")}` }]);
    const push = (l: Line) => setLines((prev) => [...prev, l]);

    execCockpitStream(
      {
        command: proposal.command,
        args: proposal.args,
        approved: true, // set ONLY here, for THIS step, after the operator clicked approve
        dangerous_ack: ack,
        engagement_id: engagementId ?? undefined,
        session_id: sessionId ?? undefined,
      },
      (ev: ExecEvent) => {
        switch (ev.type) {
          case "start":
            runIdRef.current = ev.run_id;
            push({ kind: "meta", text: `▶ run ${ev.run_id} → ${ev.target} [${ev.mode ?? "?"}]` });
            break;
          case "stdout":
            push({ kind: "stdout", text: ev.line });
            break;
          case "stderr":
            push({ kind: "stderr", text: ev.line });
            break;
          case "rejected":
            push({ kind: "err", text: `✕ refused at the ${ev.gate} gate — ${ev.reason}` });
            break;
          case "error":
            push({ kind: "err", text: `✕ ${ev.reason}` });
            break;
          case "exit":
            push({ kind: "meta", text: `■ exit ${ev.code}` });
            if (ev.code === 0 && runIdRef.current) {
              // The walk advances only on a run that was approved AND succeeded — the backend
              // re-checks both against the recorded run before moving.
              cloudOrchestrateAdvance({
                graph_id: graphId,
                owned,
                traversed,
                source: proposal.edge.source,
                target: proposal.edge.target,
                kind: proposal.edge.kind,
                session_id: sessionId,
                run_id: runIdRef.current,
              })
                .then((res) => {
                  setAdvanced(
                    res.objective_reached
                      ? `objective reached — you now control ${res.owned_label}`
                      : `you now control ${res.owned_label} · ${res.remaining_frontier} edges reachable`
                  );
                  onAdvanced?.(res.state, proposal.edge.kind);
                })
                .catch(() => {
                  push({ kind: "err", text: "✕ the step ran but the walk did not advance" });
                });
            }
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
        setAck(false); // the confirm is per-step; it never carries to the next one
      });
  }, [proposal, running, ack, engagementId, sessionId, graphId, owned, traversed, onAdvanced]);

  const skip = useCallback(() => {
    if (!proposal) return;
    const key = `${proposal.edge.source}|${proposal.edge.target}|${proposal.edge.kind}`;
    const next = [...skipped, key];
    setSkipped(next);
    void ask(next);
  }, [proposal, skipped, ask]);

  const p = proposal;
  const blocked = !!p && (!p.runnable || !p.gate_ok);
  const needsAck = !!p && p.requires_confirm;
  // the card reads RED for either reason: the gate will demand a confirm, OR it is a destructive
  // abuse we could not resolve and therefore cannot gate at all.
  const looksDestructive = !!p && (needsAck || p.destructive_unresolved || p.destructive_technique);

  return (
    <section className="hp-ado" aria-label="Cloud IAM orchestration">
      <header className="hp-ado-head">
        <span className="hp-ado-kicker">agent · reasons over the graph</span>
        <h3 className="hp-ado-title">Next step</h3>
        <span className={`hp-ado-mode is-${engagement ? "engagement" : "lab"}`}>
          {engagement ? `engagement · real account${scopeLabel ? ` · ${scopeLabel}` : ""}` : "lab · isolated"}
        </span>
      </header>

      <p className="hp-ado-contract">
        The agent <b>proposes an edge</b> (an index into the real frontier) — it never authors a
        command and never runs anything. You approve <b>every</b> step individually; there is no
        batch and no run-the-whole-path. Destructive IAM abuse needs a second, explicit confirm.
      </p>

      {!p && !thinking && !done && (
        <button type="button" className="hp-ado-ask" onClick={() => void ask()}>
          ask the agent for the next step →
        </button>
      )}

      {thinking && <p className="hp-ado-thinking">reading the graph…</p>}
      {error && <p className="hp-ado-err">{error}</p>}
      {done && <p className="hp-ado-done">{reason ?? "nothing further to propose."}</p>}
      {!p && !done && reason && !thinking && <p className="hp-ado-err">{reason}</p>}

      {p && (
        <div className={`hp-ado-card${looksDestructive ? " is-destructive" : ""}`}>
          <div className="hp-ado-edge">
            <span className="hp-ado-principal">{p.edge.source_label}</span>
            <span className="hp-ado-arrow">—{p.edge.kind}→</span>
            <span className="hp-ado-principal is-target">{p.edge.target_label}</span>
          </div>

          {p.rationale && <p className="hp-ado-why">{p.rationale}</p>}
          <p className="hp-ado-prov">
            proposed by the agent · command from{" "}
            {p.technique.grounded && p.technique.entry_id ? (
              <>
                your KB — <b>{p.technique.entry_title}</b>
              </>
            ) : (
              <>the technique catalog ({p.technique.title})</>
            )}
          </p>

          {p.runnable ? (
            <pre className="hp-ado-cmd">
              <code>
                {p.command} {p.args.join(" ")}
              </code>
            </pre>
          ) : p.destructive_unresolved ? (
            <p className="hp-ado-unresolved">
              ⚠ <b>Destructive abuse, no command resolved.</b> The technique for this edge
              ({p.technique.title}) did not come back with a runnable command, so there is nothing
              to send to the gates. Anything you run here by hand will change a real account — work
              it out yourself and run it through the executor deliberately.
            </p>
          ) : (
            <p className="hp-ado-inherit">
              This edge is inherited rights — there is no command to run. Advance it by hand once you
              have confirmed the membership.
            </p>
          )}

          {!p.gate_ok && p.runnable && (
            <p className="hp-ado-blocked">⚠ this would be refused before it ran — {p.gate_reason}</p>
          )}

          {needsAck && (
            <label className="hp-ado-ack">
              <input
                type="checkbox"
                checked={ack}
                onChange={(e) => setAck(e.target.checked)}
                disabled={running}
              />
              <span>
                <b>Destructive on a real account.</b> {p.dangerous_flags.join("; ")}. I have read
                this command and I am authorized to run it against this account.
              </span>
            </label>
          )}

          <div className="hp-ado-actions">
            <button
              type="button"
              className="hp-ado-approve"
              disabled={running || blocked || (needsAck && !ack)}
              onClick={approveAndRun}
              title={
                needsAck && !ack
                  ? "Tick the destructive confirm first"
                  : "Approve and run THIS step through the gated executor"
              }
            >
              {running ? "running…" : "approve & run this step"}
            </button>
            <button type="button" className="hp-ado-skip" disabled={running} onClick={skip}>
              skip · propose another
            </button>
          </div>

          {lines.length > 0 && (
            <div className="hp-ado-out">
              {lines.map((l, i) => (
                <div key={i} className={`hp-ado-line is-${l.kind}`}>
                  {l.text}
                </div>
              ))}
            </div>
          )}

          {advanced && (
            <div className="hp-ado-advanced">
              <p>✓ {advanced}</p>
              {/* NEVER an auto-advance: the next proposal is always asked for by hand. */}
              <button type="button" className="hp-ado-ask" onClick={() => void ask()}>
                ask for the next step →
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
