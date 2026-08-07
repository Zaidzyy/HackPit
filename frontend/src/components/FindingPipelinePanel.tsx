"use client";

import { useState } from "react";
import {
  getFindingRankers,
  getPipelineSample,
  getPostScripts,
  runFindingPostScript,
  type PipelineFinding,
  type PostScriptMeta,
  type PostScriptResult,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";

const SEV_CLASS: Record<string, string> = {
  critical: "hp-cs-sev-critical",
  high: "hp-cs-sev-high",
  medium: "hp-cs-sev-medium",
  low: "hp-cs-sev-low",
  info: "hp-cs-sev-info",
};

function findingKey(f: PipelineFinding, i: number): string {
  return f.fingerprint || `${i}:${f.title}`;
}

/**
 * The finding-pipeline preview on /engagements. Runs the SYNTHETIC sample pipeline (no
 * engagement, no DB) so the ranker picker, the "merged" badges and the post-scripts panel
 * always have content to render — while the same machinery runs over an engagement's real
 * findings from its own screen. Data operations execute nothing; a command post-script surfaces
 * an approve-each command that the operator fires through the gated executor.
 */
export function FindingPipelinePanel() {
  const rankersQ = useApi(getFindingRankers, []);
  const scriptsQ = useApi(getPostScripts, []);
  const [ranker, setRanker] = useState("bug-bounty-payout");
  const sampleQ = useApi((s) => getPipelineSample(ranker, s), [ranker]);

  const rankers = rankersQ.data?.rankers ?? [];
  const scripts = scriptsQ.data?.postscripts ?? [];
  const active = rankers.find((r) => r.id === ranker);
  const result = sampleQ.data;

  return (
    <section className="hp-fp">
      <header className="hp-fp-head">
        <h2 className="hp-fp-title">Finding pipeline</h2>
        <p className="hp-fp-sub">
          One structured schema for every producer · automatic de-duplication ·
          pluggable severity rankers · post-scripts. Below is a live preview over a
          synthetic finding set — the same pipeline runs over an engagement&apos;s real
          findings.
        </p>
      </header>

      {/* RANKER PICKER */}
      <div className="hp-fp-block">
        <div className="hp-fp-block-label">severity ranker</div>
        <div className="hp-fp-rankers">
          {rankers.map((r) => (
            <button
              key={r.id}
              type="button"
              className={`hp-fp-ranker${r.id === ranker ? " is-on" : ""}`}
              onClick={() => setRanker(r.id)}
              aria-pressed={r.id === ranker}
            >
              {r.label}
            </button>
          ))}
        </div>
        {active && <p className="hp-fp-ranker-desc">{active.description}</p>}
      </div>

      {/* MERGED NOTE + SEVERITY ROLL-UP */}
      {result && (
        <div className="hp-fp-rollup">
          {result.merged > 0 && (
            <span className="hp-fp-merged">▣ {result.merged_note}</span>
          )}
          {(["critical", "high", "medium", "low", "info"] as const).map((s) =>
            result.by_severity[s] ? (
              <span key={s} className={`hp-badge hp-fp-count ${SEV_CLASS[s]}`}>
                {result.by_severity[s]} {s}
              </span>
            ) : null
          )}
          <span className="hp-fp-total">{result.total} findings</span>
        </div>
      )}

      {/* FINDINGS */}
      {sampleQ.loading && <p className="hp-note">running the pipeline…</p>}
      {sampleQ.error && <div className="hp-error-box"><p>{sampleQ.error}</p></div>}
      {result && (
        <ul className="hp-fp-list">
          {result.findings.map((f, i) => (
            <FindingRow
              key={findingKey(f, i)}
              finding={f}
              scripts={scripts}
            />
          ))}
        </ul>
      )}

      <p className="hp-fp-foot">
        Synthetic preview — no real target. Schema, de-dup and ranking execute nothing;
        a <b>command</b> post-script returns an <b>approve-each</b> proposal that runs through
        the gated executor + kali sandbox, never from here.
      </p>
    </section>
  );
}

function FindingRow({
  finding,
  scripts,
}: {
  finding: PipelineFinding;
  scripts: PostScriptMeta[];
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [out, setOut] = useState<{ ps: PostScriptMeta; res: PostScriptResult } | null>(
    null
  );

  const run = (ps: PostScriptMeta) => {
    setBusy(ps.id);
    // "preview" session id — the route takes the inline finding and writes nothing.
    runFindingPostScript("preview", { postscript_id: ps.id, finding })
      .then((r) => setOut({ ps, res: r.result }))
      .catch(() => setOut(null))
      .finally(() => setBusy(null));
  };

  const sev = finding.severity in SEV_CLASS ? finding.severity : "info";

  return (
    <li className="hp-fp-row">
      <div className="hp-fp-row-top">
        <span className={`hp-badge hp-fp-sev ${SEV_CLASS[sev]}`}>{sev}</span>
        {finding.merged_count > 0 && (
          <span
            className="hp-fp-mergebadge"
            title={`${finding.merged_count} duplicate${
              finding.merged_count === 1 ? "" : "s"
            } collapsed into this finding`}
          >
            ▣ merged {finding.merged_count}
          </span>
        )}
        <button
          type="button"
          className="hp-fp-row-title"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
        >
          {finding.title}
        </button>
        {finding.vuln_class && (
          <span className="hp-chip hp-chip-dim">{finding.vuln_class}</span>
        )}
        {finding.tool && <span className="hp-chip hp-chip-tool">{finding.tool}</span>}
      </div>

      <div className="hp-fp-row-meta">
        {finding.target && <span className="hp-fp-target">{finding.target}</span>}
        {finding.cvss && <span className="hp-fp-cvss">{finding.cvss}</span>}
        {finding.source_refs.map((r) => (
          <code key={r} className="hp-fp-ref">
            {r}
          </code>
        ))}
      </div>

      {open && finding.attacker_path && (
        <p className="hp-fp-path">{finding.attacker_path}</p>
      )}

      {/* POST-SCRIPTS */}
      <div className="hp-fp-scripts">
        <span className="hp-fp-scripts-label">post-scripts</span>
        {scripts.map((ps) => (
          <button
            key={ps.id}
            type="button"
            className={`hp-fp-ps${ps.needs_approval ? " is-cmd" : ""}`}
            onClick={() => run(ps)}
            disabled={busy === ps.id}
            title={ps.description}
          >
            {ps.label}
            {ps.needs_approval && <span className="hp-fp-ps-tag">approve-each</span>}
          </button>
        ))}
      </div>

      {out && <PostScriptOutput ps={out.ps} res={out.res} onClose={() => setOut(null)} />}
    </li>
  );
}

function PostScriptOutput({
  ps,
  res,
  onClose,
}: {
  ps: PostScriptMeta;
  res: PostScriptResult;
  onClose: () => void;
}) {
  return (
    <div className={`hp-fp-out${res.mode === "command" ? " is-cmd" : ""}`}>
      <div className="hp-fp-out-head">
        <span className="hp-fp-out-name">{ps.label}</span>
        {res.mode === "command" ? (
          <span className="hp-fp-out-flag">needs approval · not executed</span>
        ) : (
          <span className="hp-fp-out-flag is-data">ran in-process</span>
        )}
        <button type="button" className="hp-fp-out-x" onClick={onClose} aria-label="Dismiss">
          ×
        </button>
      </div>

      {res.summary && <p className="hp-fp-out-summary">{res.summary}</p>}

      {res.mode === "command" && res.command && (
        <pre className="hp-fp-out-cmd">
          <code>{res.command}</code>
        </pre>
      )}

      {res.kind === "validate" && (
        <div className="hp-fp-out-validate">
          <span className={`hp-fp-out-verdict${res.ok ? " is-ok" : " is-warn"}`}>
            {res.ok ? "✓ actionable" : "⚠ needs more evidence"}
          </span>
          {res.problems && res.problems.length > 0 && (
            <ul className="hp-fp-out-problems">
              {res.problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {res.markdown && (
        <pre className="hp-fp-out-md">
          <code>{res.markdown}</code>
        </pre>
      )}
    </div>
  );
}
