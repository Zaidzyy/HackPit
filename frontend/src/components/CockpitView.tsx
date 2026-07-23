"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { PageShell } from "./PageShell";
import { CockpitAttackMap } from "./CockpitAttackMap";
import { CockpitScreen } from "./CockpitScreen";
import { COCKPIT_SAMPLE } from "@/lib/cockpitSample";
import { ApiError, composeAttackPath, type AttackPath } from "@/lib/api";

const PLACEHOLDER =
  "Plot a target — e.g. “web app bug bounty”, “HTB Windows AD box”, “Linux host”";

/**
 * The Cockpit command-center view: a composed attack-path rendered as a lit
 * kill-chain map (the "watch it think" centerpiece), above the M1 live-execution
 * panel (approve → sandbox → stream). Until a path is composed, a labelled sample
 * path is shown so the map is never empty.
 */
export function CockpitView() {
  const [goal, setGoal] = useState("");
  const [path, setPath] = useState<AttackPath>(COCKPIT_SAMPLE);
  const [isSample, setIsSample] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
          setIsSample(false);
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

          <div className="hp-cv-map-frame">
            {isSample && (
              <span className="hp-cv-sample-ribbon" title="Composed sample — plot a target above for a live path">
                sample path
              </span>
            )}
            <CockpitAttackMap path={path} />
          </div>
        </section>

        <section className="hp-cv-exec-section">
          <CockpitScreen embedded />
        </section>
      </div>
    </PageShell>
  );
}
