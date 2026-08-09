"use client";

import { useState } from "react";
import type { AlternativeResult } from "@/lib/api";

/**
 * On-demand SECOND OPINION for one command. Fetches ONE alternative candidate + a
 * which-is-better verdict when the operator clicks. The primary is rendered by the caller and
 * is never touched here. A grounded alternative links its KB entry and is trusted; an
 * ai_suggested one is badged VERIFY (the model's own, unverified) command.
 *
 * Surface-agnostic: the caller supplies a ``fetcher`` that returns {alternative, verdict}, so the
 * same disclosure serves the attack path, the orchestrator queue, and the graph orchestrators.
 * Self-contained on purpose: it does NOT import a screen's command renderer (that would form an
 * import cycle). Its command block is deliberately simple — a copyable line plus the honesty
 * markers (VERIFY badge, foreign-host note).
 */
export function AlternativeDisclosure({
  fetcher,
}: {
  fetcher: () => Promise<AlternativeResult>;
}) {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [result, setResult] = useState<AlternativeResult | null>(null);

  async function load() {
    setState("loading");
    try {
      const r = await fetcher();
      setResult(r);
      setState("done");
    } catch {
      setState("error");
    }
  }

  if (state === "idle") {
    return (
      <button type="button" className="hp-ap-alt-toggle" onClick={load}>
        ⇄ second opinion
      </button>
    );
  }
  if (state === "loading") return <div className="hp-ap-alt-msg">weighing an alternative…</div>;
  if (state === "error")
    return (
      <div className="hp-ap-alt-msg hp-ap-alt-err">
        couldn’t fetch a second opinion —{" "}
        <button type="button" className="hp-ap-alt-retry" onClick={load}>
          try again
        </button>
      </div>
    );

  const alt = result?.alternative;
  const v = result?.verdict;
  return (
    <div className="hp-ap-alt">
      {alt ? (
        <>
          <div className="hp-ap-alt-head">
            <span className={`hp-ap-alt-badge is-${alt.kind}`}>
              {alt.kind === "grounded"
                ? `GROUNDED · kb:${alt.entry_id}`
                : "AI-SUGGESTED · VERIFY"}
            </span>
            <b className="hp-ap-alt-title">{alt.title}</b>
          </div>
          {alt.commands.map((c, i) => (
            <pre className="hp-ap-alt-cmd" key={i}>
              <code>{c.cmd}</code>
            </pre>
          ))}
          {alt.foreign_refs && alt.foreign_refs.length > 0 && (
            <p className="hp-ap-alt-foreign">
              names a host outside your scope: {alt.foreign_refs.join(", ")} — adjust before running.
            </p>
          )}
        </>
      ) : (
        <div className="hp-ap-alt-msg">
          no better alternative — the primary is the best available move.
        </div>
      )}
      {v?.summary && (
        <p className="hp-ap-alt-verdict">
          <span className="hp-ap-alt-verdict-lead">which &amp; why</span>
          {v.summary}
          {v.factors.length > 0 && (
            <span className="hp-ap-alt-factors"> ({v.factors.join(" · ")})</span>
          )}
        </p>
      )}
    </div>
  );
}
