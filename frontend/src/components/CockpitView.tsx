"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { PageShell } from "./PageShell";
import { CockpitAttackMap } from "./CockpitAttackMap";
import { CockpitScreen } from "./CockpitScreen";
import { CockpitLoop } from "./CockpitLoop";
import { CockpitEngagement } from "./CockpitEngagement";
import { LLMSettingsModal } from "./LLMSettingsModal";
import { ModelBadge } from "./ModelBadge";
import { TargetTypeChips } from "./TargetTypeChips";
import {
  ApiError,
  composeAttackPath,
  createSession,
  getLLMConfig,
  type AttackPath,
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
  const [config, setConfig] = useState<LLMConfig | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [execMode, setExecMode] = useState<"loop" | "manual">("loop");
  const [engToken, setEngToken] = useState(0);
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

      composeAttackPath(g, targetType, scopeText.trim() || null, ctrl.signal)
        .then((p) => {
          if (ctrl.signal.aborted) return;
          setPath(p);
          setLoading(false);
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
        });
    },
    [goal, targetType, scopeText, loading]
  );

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

          <ModelBadge
            config={config}
            onOpenSettings={() => setSettingsOpen(true)}
          />

          {error && <p className="hp-cv-error">{error}</p>}

          {!path && !error && (
            <p className="hp-cv-hint">plot a path to begin</p>
          )}

          {path && (
            <motion.div className="hp-cv-map-frame" {...reveal}>
              <CockpitAttackMap path={path} />
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
                    onRunRecorded={() => setEngToken((t) => t + 1)}
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
          </motion.section>
        )}
      </div>

      <LLMSettingsModal
        open={settingsOpen}
        config={config}
        onClose={() => setSettingsOpen(false)}
        onSaved={(c) => setConfig(c)}
      />
    </PageShell>
  );
}
