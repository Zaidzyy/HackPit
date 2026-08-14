"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { PageShell } from "./PageShell";
import { CockpitAttackMap } from "./CockpitAttackMap";
import { CockpitScreen } from "./CockpitScreen";
import { CockpitLoop } from "./CockpitLoop";
import { CockpitEngagement } from "./CockpitEngagement";
import { CockpitState } from "./CockpitState";
import { CockpitEngagementMode } from "./CockpitEngagementMode";
import { EngagementAssistant } from "./EngagementAssistant";
import { ComposingLoader } from "./ComposingLoader";
import { CockpitResume } from "./CockpitResume";
import { ModelRetry } from "./ModelRetry";
import { LLMSettingsModal } from "./LLMSettingsModal";
import { ModelBadge } from "./ModelBadge";
import { TargetTypeChips } from "./TargetTypeChips";
import {
  ApiError,
  composeAttackPath,
  createSession,
  getLLMConfig,
  getSession,
  type AttackPath,
  type ChatTurn,
  type LLMConfig,
} from "@/lib/api";

const PLACEHOLDER =
  "Plot a target — e.g. “web app bug bounty”, “HTB Windows AD box”, “Linux host”";

/**
 * The Cockpit command-center view. It opens as just a header + plot bar: nothing
 * else is shown until you compose a path. Once a real attack-path composes, the
 * kill-chain map (the "watch it think" centerpiece) and the M1 live-execution
 * panel (approve → sandbox → stream) reveal in with the composed data.
 */
export function CockpitView() {
  const [goal, setGoal] = useState("");
  const [targetType, setTargetType] = useState<string | null>(null);
  const [scopeText, setScopeText] = useState("");
  const [scopeOpen, setScopeOpen] = useState(false);
  const [path, setPath] = useState<AttackPath | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errStatus, setErrStatus] = useState<number | undefined>(undefined);
  const [config, setConfig] = useState<LLMConfig | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [execMode, setExecMode] = useState<"loop" | "manual">("loop");
  // Which SANDBOX the exec surface targets: the isolated lab (default) or a real-target
  // engagement (real target, FULLY OPEN egress — loop may draft, human approves every command).
  const [targetMode, setTargetMode] = useState<"lab" | "engagement">("lab");
  const [engToken, setEngToken] = useState(0);
  // Loop progress, lifted so the kill-chain map can light nodes as steps complete.
  const [activeStep, setActiveStep] = useState<string | null>(null);
  const [doneSteps, setDoneSteps] = useState<Set<string>>(new Set());
  // TALK-TO-ME: the chat pane's seed history, and a pulse the guided loop fires when it leaves
  // a note. `noteSignal.ts` changes per note so the drawer appends it exactly once.
  const [chatHistory, setChatHistory] = useState<ChatTurn[]>([]);
  const [noteSignal, setNoteSignal] = useState<{ note: string; ts: number } | null>(null);
  const reduced = useReducedMotion();

  const ctrlRef = useRef<AbortController | null>(null);
  useEffect(() => () => ctrlRef.current?.abort(), []);

  // Load current LLM config for the model badge (same /llm-config the attack-path
  // screen reads — changing it here affects both).
  useEffect(() => {
    const ctrl = new AbortController();
    getLLMConfig(ctrl.signal)
      .then(setConfig)
      .catch(() => setConfig(null));
    return () => ctrl.abort();
  }, []);

  // Seed the chat pane from the session's persisted transcript (loop notes + prior chat)
  // whenever the session changes, so a resumed engagement shows its history. Live notes and
  // replies then append on top; the backend persists both so this seed stays authoritative.
  useEffect(() => {
    if (!sessionId) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- deliberate: clear on no session
      setChatHistory([]);
      return;
    }
    const ctrl = new AbortController();
    getSession(sessionId, ctrl.signal)
      .then((s) => setChatHistory(s.chat_history ?? []))
      .catch(() => {});
    return () => ctrl.abort();
  }, [sessionId]);

  const compose = useCallback(
    (e?: React.FormEvent) => {
      e?.preventDefault();
      const g = goal.trim();
      if (g.length < 3 || loading) return;

      ctrlRef.current?.abort();
      const ctrl = new AbortController();
      ctrlRef.current = ctrl;

      setLoading(true);
      setError(null);
      setErrStatus(undefined);

      composeAttackPath(g, targetType, scopeText.trim() || null, ctrl.signal)
        .then((p) => {
          if (ctrl.signal.aborted) return;
          setPath(p);
          setLoading(false);
          // reset loop progress for the new plan
          setActiveStep(null);
          setDoneSteps(new Set());
          // Persist the composed path as an engagement so every cockpit run
          // below can be recorded against it. Non-fatal: if this fails the map
          // still shows; execution just won't be recorded to a session.
          setSessionId(null);
          createSession(p, ctrl.signal)
            .then((s) => {
              if (!ctrl.signal.aborted) setSessionId(s.id);
            })
            .catch(() => {
              /* recording unavailable — map + exec still work */
            });
        })
        .catch((err: unknown) => {
          if (ctrl.signal.aborted) return;
          setLoading(false);
          setError(
            err instanceof ApiError ? err.message : "Couldn’t plot an attack path."
          );
          setErrStatus(err instanceof ApiError ? err.status : undefined);
        });
    },
    [goal, targetType, scopeText, loading]
  );

  // Resume a saved engagement WITHOUT re-plotting: load its stored path + session id straight
  // into the exec surface, exactly as compose() does on a fresh plot. Same engine, no new plan.
  const resumeInto = useCallback((p: AttackPath, sid: string) => {
    ctrlRef.current?.abort();
    setPath(p);
    setSessionId(sid);
    setError(null);
    setErrStatus(undefined);
    setLoading(false);
    setActiveStep(null);
    setDoneSteps(new Set());
  }, []);

  // Sections reveal in once a path exists; skip the motion under reduced-motion.
  const reveal = reduced
    ? {}
    : {
        initial: { opacity: 0, y: 14 },
        animate: { opacity: 1, y: 0 },
        transition: { duration: 0.5, ease: "easeOut" as const },
      };

  return (
    <PageShell crumbs={[{ label: "cockpit" }]}>
      <div className="hp-cv">
        <header className="hp-cv-head">
          <div className="hp-ap-kicker">grounded plan · live execution</div>
          <h1 className="hp-cv-title">:cockpit</h1>
          <p className="hp-cv-sub">
            Plot an attack path, then run it — approved, one command at a time,
            against the isolated lab.
          </p>
          <Link href="/cockpit/ad" className="hp-cv-adlink">
            🌐 AD attack-path graph — BloodHound → route to Domain Admin →
          </Link>
          <Link href="/cockpit/cloud" className="hp-cv-adlink">
            ☁️ Cloud IAM privesc graph — ScoutSuite/Prowler → route to admin →
          </Link>
          <Link href="/cockpit/killchain" className="hp-cv-adlink">
            ⛓️ cross-domain kill-chain — web → cloud → on-prem AD, stitched to Domain Admin →
          </Link>
          <Link href="/cockpit/session" className="hp-cv-adlink">
            ⌁ live session — catch a shell and drive it by hand →
          </Link>
          <Link href="/repeater" className="hp-cv-adlink">
            ⇌ HTTP repeater — compose, send, replay and diff requests →
          </Link>
          <Link href="/tunnels" className="hp-cv-adlink">
            ⇢ pivot / tunnels — route through a compromised host (chisel · ligolo) →
          </Link>
          <Link href="/c2" className="hp-cv-adlink">
            ◉ c2 / covert channel — sliver implants · dns tunnels (human-only, gated build) →
          </Link>
          <Link href="/windows" className="hp-cv-adlink">
            ⊞ windows targets — drive a Windows/AD box over WinRM (CRTP · OSCP AD) →
          </Link>
        </header>

        <section className="hp-cv-map-section">
          <form className="hp-cv-plot" onSubmit={compose}>
            <span className="hp-cv-plot-prompt" aria-hidden>
              &gt;
            </span>
            <input
              className="hp-cv-plot-input"
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              placeholder={PLACEHOLDER}
              spellCheck={false}
              autoComplete="off"
              aria-label="Plot an attack path"
              disabled={loading}
            />
            <button
              type="submit"
              className="hp-cv-plot-go"
              disabled={loading || goal.trim().length < 3}
            >
              {loading ? "plotting…" : "plot path →"}
            </button>
          </form>

          <div className="hp-cv-chips">
            <TargetTypeChips
              value={targetType}
              onChange={setTargetType}
              disabled={loading}
            />
          </div>

          <div className="hp-ap-scope hp-cv-scope">
            <button
              type="button"
              className="hp-ap-scope-toggle"
              aria-expanded={scopeOpen}
              onClick={() => setScopeOpen((o) => !o)}
              disabled={loading}
            >
              <span className="hp-ap-scope-sign" aria-hidden>
                {scopeOpen ? "−" : "+"}
              </span>
              Scope / Rules of Engagement{" "}
              <span className="hp-ap-scope-opt">(optional)</span>
              {!scopeOpen && scopeText.trim() && (
                <span className="hp-ap-scope-dot" title="scope text entered" />
              )}
            </button>
            {scopeOpen && (
              <textarea
                className="hp-ap-scope-text"
                value={scopeText}
                onChange={(e) => setScopeText(e.target.value)}
                placeholder={
                  "Paste in-scope / out-of-scope hosts and paths, or the program’s Rules of Engagement.\n" +
                  "The profiler uses it to prioritise the right bug classes and drop out-of-scope steps."
                }
                rows={5}
                spellCheck={false}
                disabled={loading}
                aria-label="Scope / Rules of Engagement"
              />
            )}
          </div>

          {/* Resume a saved engagement without re-plotting — a peer to the plot bar. Only shows
              on the entry screen (before a path exists) and only when there is something to
              resume; CockpitResume renders nothing otherwise. */}
          {!path && !loading && <CockpitResume onResume={resumeInto} />}

          <ModelBadge
            config={config}
            onOpenSettings={() => setSettingsOpen(true)}
          />

          {/* The SAME composing animation the Companion's composer shows — same
              phases, same model note — because plot-path calls the same backend
              and passes through the same stages. Previously the cockpit sat on
              the "plot a path to begin" hint for the whole compose, which read
              as though nothing were happening. */}
          {loading && <ComposingLoader config={config} />}

          {error && !loading && (
            <ModelRetry
              error={error}
              status={errStatus}
              onRetry={() => compose()}
              onModelChanged={() =>
                getLLMConfig()
                  .then(setConfig)
                  .catch(() => {})
              }
            />
          )}

          {!path && !error && !loading && (
            <p className="hp-cv-hint">plot a path to begin</p>
          )}

          {path && (
            <motion.div className="hp-cv-map-frame" {...reveal}>
              <CockpitAttackMap
                path={path}
                activeStepId={execMode === "loop" ? activeStep : null}
                doneStepIds={execMode === "loop" ? doneSteps : undefined}
              />
            </motion.div>
          )}
        </section>

        {path && (
          <motion.section
            className="hp-cv-exec-section"
            {...reveal}
            transition={
              reduced
                ? undefined
                : { duration: 0.5, ease: "easeOut", delay: 0.12 }
            }
          >
            {/* Target mode — ALWAYS shown, so it is never ambiguous whether commands
                run against the isolated lab or a real target. Engagement is deliberate. */}
            <div
              className={`hp-cv-targetmode is-${targetMode}`}
              role="tablist"
              aria-label="Target"
            >
              <button
                type="button"
                role="tab"
                aria-selected={targetMode === "lab"}
                className={targetMode === "lab" ? "is-on" : undefined}
                onClick={() => setTargetMode("lab")}
              >
                lab · isolated
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={targetMode === "engagement"}
                className={targetMode === "engagement" ? "is-on is-danger" : undefined}
                onClick={() => setTargetMode("engagement")}
              >
                engagement · real target
              </button>
            </div>

            {targetMode === "engagement" ? (
              /* Real-target mode: FULLY OPEN egress (Wall A down). CockpitEngagementMode hosts the
                 enter/exit + a loop/manual toggle — the guided loop may DRAFT here, but every command
                 still needs explicit human approval (the only guard); never hands-off. Recorded runs
                 surface in the same engagement panel below. */
              <>
                <CockpitEngagementMode
                  sessionId={sessionId}
                  goal={path.goal}
                  onRunRecorded={() => setEngToken((t) => t + 1)}
                  onAgentNote={(note) => setNoteSignal({ note, ts: Date.now() })}
                />
                {sessionId && (
                  <>
                    <CockpitState
                      key={`state-${sessionId}`}
                      sessionId={sessionId}
                      refreshToken={engToken}
                    />
                    <CockpitEngagement
                      key={`eng-${sessionId}`}
                      sessionId={sessionId}
                      refreshToken={engToken}
                    />
                  </>
                )}
              </>
            ) : (
              <>
                <div className="hp-cv-execmode" role="tablist" aria-label="Execution mode">
                  <button
                    type="button"
                    role="tab"
                    aria-selected={execMode === "loop"}
                    className={execMode === "loop" ? "is-on" : undefined}
                    onClick={() => setExecMode("loop")}
                  >
                    guided loop
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={execMode === "manual"}
                    className={execMode === "manual" ? "is-on" : undefined}
                    onClick={() => setExecMode("manual")}
                  >
                    manual
                  </button>
                </div>

                {execMode === "loop" ? (
                  sessionId ? (
                    <>
                      <CockpitLoop
                        sessionId={sessionId}
                        goal={path.goal}
                        target={path.target}
                        scopeText={scopeText.trim() || null}
                        onStepActive={setActiveStep}
                        onStepDone={(id) => {
                          if (id) setDoneSteps((s) => new Set(s).add(id));
                          setActiveStep(null);
                        }}
                        onRunRecorded={() => setEngToken((t) => t + 1)}
                        onAgentNote={(note) => setNoteSignal({ note, ts: Date.now() })}
                      />
                      <CockpitState
                        key={`state-${sessionId}`}
                        sessionId={sessionId}
                        refreshToken={engToken}
                      />
                      <CockpitEngagement
                        key={sessionId}
                        sessionId={sessionId}
                        refreshToken={engToken}
                      />
                    </>
                  ) : (
                    <p className="hp-cv-hint">
                      The guided loop needs a saved engagement to record against — it
                      wasn’t created. Re-plot the path, or use manual execution.
                    </p>
                  )
                ) : (
                  <CockpitScreen embedded sessionId={sessionId} />
                )}
              </>
            )}
          </motion.section>
        )}
      </div>

      <LLMSettingsModal
        open={settingsOpen}
        config={config}
        onClose={() => setSettingsOpen(false)}
        onSaved={(c) => setConfig(c)}
      />

      {/* TALK-TO-ME: a chat drawer beside the loop. You can message the agent any time (it
          steers the next proposal), and the loop drops NOTES here on its own as it works. */}
      {sessionId && (
        <EngagementAssistant
          sessionId={sessionId}
          initialHistory={chatHistory}
          noteSignal={noteSignal}
        />
      )}
    </PageShell>
  );
}
