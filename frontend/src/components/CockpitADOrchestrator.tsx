"use client";

import { useCallback, useRef, useState } from "react";
import {
  ApiError,
  adOrchestrateAdvance,
  adOrchestratePropose,
  execCockpitStream,
  getADAlternative,
  listWindowsProfiles,
  type ADProposal,
  type ExecEvent,
  type WindowsProfile,
} from "@/lib/api";
import { AlternativeDisclosure } from "./AlternativeDisclosure";
import { ModelRetry } from "./ModelRetry";

type Line = { kind: "meta" | "stdout" | "stderr" | "err"; text: string };

/**
 * AD ORCHESTRATION — the agent proposes the next edge to abuse; the human approves each one.
 *
 * The safety model is the whole point of this panel, so it is visible in the UI rather than
 * only in the backend:
 *
 * * The agent PROPOSES. It picked an edge from the graph's real frontier, and the command came
 *   from the KB-grounded technique catalog — not from the model. Nothing has run when a
 *   proposal appears.
 * * EVERY step is an individual, explicit approval. There is no batch, no approve-all, and no
 *   "run the whole path" — one proposal, one decision, every time. `approved: true` is set in
 *   exactly one place in this file: inside the click handler for this one step.
 * * Destructive abuse needs a SECOND confirm. When the executor will demand `dangerous_ack`
 *   the approve button is locked behind a red checkbox the operator has to tick deliberately.
 * * The walk NEVER auto-advances. After a successful run the operator is shown what it gained
 *   and asks for the next proposal by hand.
 *
 * Execution goes through `execCockpitStream` — the same gated executor every other cockpit
 * command uses. This panel adds no execution path of its own.
 */
export function CockpitADOrchestrator({
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
  /** Called after a step succeeded and the walk advanced — the parent lights the edge. */
  onAdvanced?: (next: { owned: string[]; traversed: string[] }, edgeKind: string) => void;
}) {
  const [proposal, setProposal] = useState<ADProposal | null>(null);
  const [reason, setReason] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [thinking, setThinking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errStatus, setErrStatus] = useState<number | undefined>(undefined);

  const [ack, setAck] = useState(false);
  const [running, setRunning] = useState(false);
  const [lines, setLines] = useState<Line[]>([]);
  const [advanced, setAdvanced] = useState<string | null>(null);
  const [skipped, setSkipped] = useState<string[]>([]);

  // Windows targets — pick one to run the abuse ON the box over WinRM (native PowerView /
  // Rubeus / Mimikatz variant); leave unset to run the Linux (impacket/evil-winrm) command
  // through the sandbox. Loaded once; the picker only appears when a profile exists.
  const [winProfiles, setWinProfiles] = useState<WindowsProfile[]>([]);
  const [winProfileId, setWinProfileId] = useState<string>("");

  const ctrlRef = useRef<AbortController | null>(null);
  const runIdRef = useRef<string | null>(null);

  const engagement = !!engagementId;

  const ask = useCallback(
    async (avoid: string[] = skipped) => {
      setThinking(true);
      setError(null);
      setErrStatus(undefined);
      setProposal(null);
      setReason(null);
      setAdvanced(null);
      setLines([]);
      setAck(false);
      // Load the Windows-target list here (NOT in an effect) so the panel still runs nothing
      // on mount — the picker only appears once a proposal exists, which `ask` produces.
      listWindowsProfiles()
        .then(setWinProfiles)
        .catch(() => setWinProfiles([]));
      try {
        const res = await adOrchestratePropose({
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
        setError(
          err instanceof ApiError ? err.message : "Couldn’t reach the reasoning model."
        );
        setErrStatus(err instanceof ApiError ? err.status : undefined);
      } finally {
        setThinking(false);
      }
    },
    [graphId, owned, traversed, engagementId, skipped]
  );

  /** APPROVE THIS ONE STEP. The only place `approved: true` is set in this file. */
  const approveAndRun = useCallback(() => {
    if (!proposal || running) return;
    // Run ON a Windows target (native variant over WinRM) when one is picked and the edge has
    // a native command; otherwise run the Linux command through the sandbox. The confirm /
    // runnable checks follow whichever command will actually run.
    const onWindows = !!winProfileId && !!proposal.windows_command;
    const cmd = onWindows ? proposal.windows_command : proposal.command;
    const cmdArgs = onWindows ? proposal.windows_args : proposal.args;
    const runnable = onWindows ? proposal.windows_runnable : proposal.runnable;
    const needsConfirm = onWindows
      ? proposal.windows_requires_confirm
      : proposal.requires_confirm;
    if (!runnable) return;
    if (needsConfirm && !ack) return; // red confirm not given — refuse to send

    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    runIdRef.current = null;
    setRunning(true);
    setLines([{ kind: "meta", text: `$ ${cmd} ${cmdArgs.join(" ")}` }]);
    const push = (l: Line) => setLines((prev) => [...prev, l]);

    execCockpitStream(
      {
        command: cmd,
        args: cmdArgs,
        approved: true, // set ONLY here, for THIS step, after the operator clicked approve
        dangerous_ack: ack,
        engagement_id: engagementId ?? undefined,
        windows_profile_id: onWindows ? winProfileId : undefined,
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
              // The walk advances only on a run that was approved AND succeeded — the
              // backend re-checks both against the recorded run before moving.
              adOrchestrateAdvance({
                graph_id: graphId,
                owned,
                traversed,
                source: proposal.edge.source,
                target: proposal.edge.target,
                kind: proposal.edge.kind,
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
  }, [proposal, running, ack, engagementId, sessionId, graphId, owned, traversed, winProfileId, onAdvanced]);

  const skip = useCallback(() => {
    if (!proposal) return;
    const key = `${proposal.edge.source}|${proposal.edge.target}|${proposal.edge.kind}`;
    const next = [...skipped, key];
    setSkipped(next);
    void ask(next);
  }, [proposal, skipped, ask]);

  const p = proposal;
  // Windows execution is chosen when a target is picked AND the edge has a native variant.
  const onWin = !!p && !!winProfileId && !!p.windows_command;
  const effCommand = p ? (onWin ? p.windows_command : p.command) : "";
  const effArgs = p ? (onWin ? p.windows_args : p.args) : [];
  const effRunnable = !!p && (onWin ? p.windows_runnable : p.runnable);
  const effFlags = p ? (onWin ? p.windows_dangerous_flags : p.dangerous_flags) : [];
  // For a Windows run the target-lock is structural (the profile host), so the Linux scope
  // pre-check (gate_ok) does not apply — only runnability blocks it.
  const blocked = !!p && (onWin ? !p.windows_runnable : !p.runnable || !p.gate_ok);
  const needsAck = !!p && (onWin ? p.windows_requires_confirm : p.requires_confirm);
  // the card reads RED for either reason: the gate will demand a confirm, OR it is a
  // destructive abuse we could not resolve and therefore cannot gate at all.
  const looksDestructive = !!p && (needsAck || p.destructive_unresolved);

  return (
    <section className="hp-ado" aria-label="AD orchestration">
      <header className="hp-ado-head">
        <span className="hp-ado-kicker">agent · reasons over the graph</span>
        <h3 className="hp-ado-title">Next step</h3>
        <span className={`hp-ado-mode is-${engagement ? "engagement" : "lab"}`}>
          {engagement ? `engagement · real domain${scopeLabel ? ` · ${scopeLabel}` : ""}` : "lab · isolated"}
        </span>
      </header>

      <p className="hp-ado-contract">
        The agent <b>proposes</b> — it never runs anything. You approve <b>every</b> step
        individually; there is no batch and no run-the-whole-path. Destructive abuse needs a
        second, explicit confirm.
      </p>

      {!p && !thinking && !done && (
        <button type="button" className="hp-ado-ask" onClick={() => void ask()}>
          ask the agent for the next step →
        </button>
      )}

      {thinking && <p className="hp-ado-thinking">reading the graph…</p>}
      {error && (
        <ModelRetry error={error} status={errStatus} onRetry={() => void ask()} />
      )}
      {done && <p className="hp-ado-done">{reason ?? "nothing further to propose."}</p>}
      {!p && !done && reason && !thinking && <p className="hp-ado-err">{reason}</p>}

      {p && (
        <div className={`hp-ado-card${looksDestructive ? " is-destructive" : ""}`}>
          <div className="hp-ado-edge">
            <span className="hp-ado-principal">{p.edge.source_label}</span>
            <span className="hp-ado-arrow">
              —{p.edge.kind}→
            </span>
            <span className="hp-ado-principal is-target">{p.edge.target_label}</span>
          </div>

          {/* PROVENANCE — why this edge, and where the command came from. */}
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

          {effRunnable ? (
            <pre className="hp-ado-cmd">
              <code>
                {effCommand} {effArgs.join(" ")}
              </code>
              {onWin && <span className="hp-ado-prov"> · runs on the Windows target over WinRM</span>}
            </pre>
          ) : p.destructive_unresolved ? (
            /* A DESTRUCTIVE abuse we could not resolve a command for. There is no executor
               gate to lean on — there is nothing to send to it — so this must never read as
               the benign "nothing to run" case. */
            <p className="hp-ado-unresolved">
              ⚠ <b>Destructive abuse, no command resolved.</b> The technique for this edge
              ({p.technique.title}) did not come back with a runnable command, so there is
              nothing to send to the gates. Anything you run here by hand will change a real
              domain — work it out yourself and run it through the executor deliberately.
            </p>
          ) : (
            <p className="hp-ado-inherit">
              This edge is inherited rights — there is no command to run. Advance it by hand
              once you have confirmed the membership.
            </p>
          )}

          {!p.gate_ok && p.runnable && (
            <p className="hp-ado-blocked">
              ⚠ this would be refused before it ran — {p.gate_reason}
            </p>
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
                <b>Destructive on a real domain.</b>{" "}
                {effFlags.join("; ")}. I have read this command and I am authorized to
                run it against this domain.
              </span>
            </label>
          )}

          {winProfiles.length > 0 && p.windows_command && (
            <label className="hp-ado-prov" style={{ display: "block", margin: "0.4rem 0" }}>
              run on:{" "}
              <select
                value={winProfileId}
                onChange={(e) => setWinProfileId(e.target.value)}
                disabled={running}
                aria-label="Execution target"
              >
                <option value="">Linux sandbox (impacket / evil-winrm)</option>
                {winProfiles.map((w) => (
                  <option key={w.profile_id} value={w.profile_id}>
                    {w.name} — {w.host} (WinRM · native)
                  </option>
                ))}
              </select>
            </label>
          )}

          {effCommand && (
            <AlternativeDisclosure
              fetcher={() =>
                getADAlternative({
                  title: p.technique.title ?? "",
                  cmd: effCommand,
                  entry_id: p.technique.entry_id ?? "",
                  context: `${p.edge.source} —${p.edge.kind}→ ${p.edge.target}`,
                })
              }
            />
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
            <button
              type="button"
              className="hp-ado-skip"
              disabled={running}
              onClick={skip}
            >
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
