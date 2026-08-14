"use client";

import { useCallback, useEffect, useState } from "react";
import { Markdown } from "./Markdown";
import { DetectionDisclosure } from "./DetectionPanel";
import { ModelRetry } from "./ModelRetry";
import {
  ApiError,
  detectionRuns,
  generateReport,
  listCockpitRuns,
  type CockpitRun,
  type DetectionRunsOut,
} from "@/lib/api";

/**
 * The engagement panel inside the cockpit: the runs recorded against the
 * current composed engagement (each approved command is one recorded step) and
 * a "generate report" action that reuses the existing report generator.
 *
 * Rendered with `key={sessionId}` by the parent, so a new engagement gets a
 * fresh instance — no manual state reset. `refreshToken` is bumped by the parent
 * after each run so the list re-pulls; the fetch sets state asynchronously.
 */
export function CockpitEngagement({
  sessionId,
  refreshToken,
}: {
  sessionId: string;
  refreshToken: number;
}) {
  const [runs, setRuns] = useState<CockpitRun[]>([]);
  // Purple-team overlay: the ATT&CK tag for each recorded run + a coverage roll-up. Read-only,
  // and derived server-side from the command each run already stored — the run store is
  // untouched by this. Non-fatal: if it fails the runs still render, just untagged.
  const [tags, setTags] = useState<DetectionRunsOut | null>(null);
  const [reportMd, setReportMd] = useState<string | null>(null);
  const [reportBusy, setReportBusy] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportStatus, setReportStatus] = useState<number | undefined>(undefined);

  useEffect(() => {
    const ctrl = new AbortController();
    listCockpitRuns(sessionId, ctrl.signal)
      .then(setRuns)
      .catch(() => {
        /* listing unavailable — leave the last known runs */
      });
    detectionRuns(sessionId, ctrl.signal)
      .then(setTags)
      .catch(() => {
        /* detection annotation unavailable — runs still render untagged */
      });
    return () => ctrl.abort();
  }, [sessionId, refreshToken]);

  const tagFor = (runId: string) =>
    tags?.runs.find((r) => r.run_id === runId)?.attck ?? null;
  const summary = tags?.summary;

  const makeReport = useCallback(() => {
    if (reportBusy) return;
    setReportBusy(true);
    setReportError(null);
    setReportStatus(undefined);
    generateReport(sessionId)
      .then((r) => setReportMd(r.report_md))
      .catch((err: unknown) => {
        setReportError(
          err instanceof ApiError ? err.message : "Couldn’t generate the report."
        );
        setReportStatus(err instanceof ApiError ? err.status : undefined);
      })
      .finally(() => setReportBusy(false));
  }, [sessionId, reportBusy]);

  return (
    <section className="hp-ck-eng">
      <div className="hp-ck-eng-head">
        <h3 className="hp-ck-eng-title">
          Engagement · recorded steps
          {runs.length > 0 && (
            <span className="hp-ck-eng-count"> {runs.length}</span>
          )}
        </h3>
        <button
          type="button"
          className="hp-ck-report-btn"
          onClick={makeReport}
          disabled={reportBusy || runs.length === 0}
          title={
            runs.length === 0
              ? "Approve a command first — the report is built from recorded runs"
              : "Generate a report from the recorded runs, the path, and the scope"
          }
        >
          {reportBusy ? "generating…" : "generate report"}
        </button>
      </div>

      {runs.length === 0 ? (
        <p className="hp-ck-eng-empty">
          No runs recorded yet — approve a command above and it is recorded here
          as an engagement step.
        </p>
      ) : (
        <>
          {summary && summary.tactics.length > 0 && (
            <div className="hp-det-summary">
              <span className="hp-det-summary-label">detection footprint</span>
              <span>
                {summary.tagged} of {summary.tagged + summary.untagged} runs ATT&amp;CK-tagged
              </span>
              {summary.tactics.map((t) => (
                <span
                  key={t.id}
                  className={`hp-det-summary-tac${
                    t.id === "TA0005" || t.id === "TA0112" ? " is-stealth" : ""
                  }`}
                  title={t.also_known_as ? `${t.id} — formerly “${t.also_known_as}”` : t.id}
                >
                  {t.name}
                </span>
              ))}
              {summary.loudest && <span>loudest: {summary.loudest}</span>}
            </div>
          )}
          <ol className="hp-ck-eng-list">
            {runs.map((r) => (
              <li key={r.run_id} className="hp-ck-eng-item">
                <div className="hp-ck-eng-cmd">
                  <code className="hp-ck-eng-line">
                    {`${r.command} ${r.args.join(" ")}`.trim()}
                  </code>
                  <span
                    className={r.exit_code === 0 ? "hp-ck-exit0" : "hp-ck-exitn"}
                  >
                    {r.exit_code === null ? "…" : `exit ${r.exit_code}`}
                  </span>
                </div>
                {/* what a defender would have seen when this actually ran */}
                <div className="hp-det-row">
                  <DetectionDisclosure
                    tag={tagFor(r.run_id)}
                    source={{ kind: "run", runId: r.run_id }}
                    heading="What a defender would have seen when this ran"
                  />
                </div>
                {(r.stdout || r.stderr) && (
                  <pre className="hp-ck-eng-out">
                    {(r.stdout + (r.stderr ? `\n${r.stderr}` : ""))
                      .trim()
                      .slice(0, 4000)}
                  </pre>
                )}
              </li>
            ))}
          </ol>
        </>
      )}

      {reportError && (
        <ModelRetry
          error={reportError}
          status={reportStatus}
          onRetry={makeReport}
        />
      )}

      {reportMd && (
        <div className="hp-ck-report">
          <Markdown source={reportMd} />
        </div>
      )}
    </section>
  );
}
