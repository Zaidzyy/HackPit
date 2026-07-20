"use client";

import Link from "next/link";
import type { CSSProperties } from "react";
import { getScriptsSummary } from "@/lib/api";
import { useApi } from "@/lib/useApi";

const SCRIPTS_COLOR = "#f0776a";

/**
 * Home bento card for the Scripts Arsenal. Links to /scripts and shows the live
 * total (from GET /scripts/summary) with a compact per-type breakdown line.
 */
export function ScriptsCard({ shown }: { shown: boolean }) {
  const summary = useApi(getScriptsSummary, []);
  const total = summary.data?.total;
  const groups = summary.data?.groups ?? [];

  return (
    <Link
      href="/scripts"
      className={`hp-card hp-scriptscard${shown ? " hp-in" : ""}`}
      style={{ "--cc": SCRIPTS_COLOR } as CSSProperties}
    >
      <div className="hp-ic">{"⌘"}</div>
      {total != null && <span className="hp-ct">{total}</span>}
      <h3>
        Scripts arsenal <span className="hp-badge">copy-ready</span>
      </h3>
      <p>
        {groups.length > 0
          ? groups
              .slice(0, 4)
              .map((g) => g.label.toLowerCase())
              .join(" · ")
          : "Reverse shells, payloads, privesc & delivery — deduped from every entry."}
      </p>
    </Link>
  );
}
