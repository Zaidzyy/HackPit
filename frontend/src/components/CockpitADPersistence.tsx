"use client";

import { useEffect, useState } from "react";
import { ApiError, adPersistenceActions, type ADPersistenceAction } from "@/lib/api";

/**
 * POST-COMPROMISE PERSISTENCE — golden / silver ticket forging.
 *
 * Deliberately a DISTINCT panel, styled unlike the route, because forging a ticket is NOT a hop
 * on the way to Domain Admin: it presupposes the compromise (krbtgt for golden, a service hash
 * for silver) that the route exists to achieve, so it is never part of the path search or the
 * orchestrator frontier. The backend only OFFERS an action once its secret is held, so this panel
 * shows nothing until you have reached DA (golden) or own a service account (silver).
 *
 * Propose-only: the commands are shown for the operator to run through the SAME gated executor
 * every other cockpit command uses (approve-each, red-confirm). This panel adds no execution path.
 */
export function CockpitADPersistence({
  graphId,
  owned,
  traversed,
  engagement = false,
}: {
  graphId: string;
  owned: string[];
  traversed: string[];
  engagement?: boolean;
}) {
  const [actions, setActions] = useState<ADPersistenceAction[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch (and re-fetch as what you hold changes) which forging actions are offered now. Only
  // the async callbacks touch state — never the effect body — so the lint baseline is unchanged.
  useEffect(() => {
    const ctrl = new AbortController();
    adPersistenceActions({ graph_id: graphId, owned, traversed }, ctrl.signal)
      .then((res) => {
        setActions(res.actions);
        setError(null);
        setLoaded(true);
      })
      .catch((err: unknown) => {
        if (ctrl.signal.aborted) return;
        setError(err instanceof ApiError ? err.message : "Couldn’t load persistence actions.");
        setLoaded(true);
      });
    return () => ctrl.abort();
  }, [graphId, owned, traversed]);

  return (
    <section className="hp-adg-persist" aria-label="Post-compromise persistence">
      <header className="hp-adg-persist-head">
        <span className="hp-adg-persist-kicker">⟲ persistence · establish after compromise</span>
        <h3 className="hp-adg-persist-title">Ticket forging</h3>
      </header>
      <p className="hp-adg-persist-sub">
        Golden and silver tickets are <b>post-compromise persistence</b>, not a step on the route —
        the path search never walks them. Each is offered only once you hold the secret it needs,
        and runs only through the gated executor, approve-each.
      </p>

      {error && <p className="hp-tn-error">{error}</p>}

      {loaded && actions.length === 0 && !error && (
        <p className="hp-adg-persist-empty">
          No forging available yet — reach Domain Admin to unlock a <b>golden</b> ticket (krbtgt),
          or own a service account to unlock a <b>silver</b> ticket (its hash).
        </p>
      )}

      <div className="hp-adg-persist-grid">
        {actions.map((a) => {
          const golden = a.kind === "GoldenTicket";
          return (
            <article key={a.kind + a.node_id} className="hp-adg-persist-card">
              <div className="hp-adg-persist-cardhead">
                <span className={`hp-adg-persist-badge is-${golden ? "golden" : "silver"}`}>
                  {golden ? "GOLDEN" : "SILVER"}
                </span>
                <span className="hp-adg-persist-cardtitle">{a.title}</span>
                <span className="hp-adg-persist-on">on {a.node_label}</span>
              </div>
              <p className="hp-adg-persist-summary">{a.summary}</p>
              <p className="hp-adg-persist-requires">requires: {a.requires}</p>
              {a.commands[0]?.cmd && (
                <pre className="hp-adg-persist-cmd">
                  <code>{a.commands[0].cmd}</code>
                </pre>
              )}
              {a.windows_commands[0]?.cmd && (
                <pre className="hp-adg-persist-cmd is-win">
                  <code>{a.windows_commands[0].cmd}</code>
                </pre>
              )}
              <p className="hp-adg-persist-foot">
                Propose-only. Runs only through the gated executor — argv-only,
                {engagement ? " engagement scope-locked" : " isolated lab"}, approve-each, with the
                destructive red-confirm.
              </p>
            </article>
          );
        })}
      </div>
    </section>
  );
}
