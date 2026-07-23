"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { PageShell } from "./PageShell";
import { CockpitAttackMap } from "./CockpitAttackMap";
import { CockpitScreen } from "./CockpitScreen";
import { ApiError, composeAttackPath, type AttackPath } from "@/lib/api";

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
  const [path, setPath] = useState<AttackPath | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reduced = useReducedMotion();

  const ctrlRef = useRef<AbortController | null>(null);
  useEffect(() => () => ctrlRef.current?.abort(), []);

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

      composeAttackPath(g, null, null, ctrl.signal)
        .then((p) => {
          if (ctrl.signal.aborted) return;
          setPath(p);
          setLoading(false);
        })
        .catch((err: unknown) => {
          if (ctrl.signal.aborted) return;
          setLoading(false);
          setError(
            err instanceof ApiError ? err.message : "Couldn’t plot an attack path."
          );
        });
    },
    [goal, loading]
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
            <CockpitScreen embedded />
          </motion.section>
        )}
      </div>
    </PageShell>
  );
}
