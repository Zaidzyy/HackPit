"use client";

import Link from "next/link";
import { useMemo, useState, type CSSProperties } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import { getScripts, type ScriptGroup, type ScriptItem } from "@/lib/api";
import { useApi } from "@/lib/useApi";

/**
 * The Scripts Arsenal: every runnable script/payload extracted + deduped from
 * the KB, grouped by type. Each row is a labelled, copyable code block with the
 * entries it came from as source-link chips. A live filter narrows across every
 * group (matches label + code + type).
 */
export function ScriptsScreen() {
  const arsenal = useApi(getScripts, []);
  const [q, setQ] = useState("");

  const needle = q.trim().toLowerCase();
  const groups = useMemo<ScriptGroup[]>(() => {
    const data = arsenal.data?.groups ?? [];
    if (!needle) return data;
    return data
      .map((g) => ({
        ...g,
        scripts: g.scripts.filter(
          (s) =>
            s.label.toLowerCase().includes(needle) ||
            s.code.toLowerCase().includes(needle) ||
            s.type.includes(needle)
        ),
      }))
      .filter((g) => g.scripts.length > 0);
  }, [arsenal.data, needle]);

  const total = arsenal.data?.total ?? 0;
  const shownCount = groups.reduce((n, g) => n + g.scripts.length, 0);

  return (
    <PageShell crumbs={[{ label: "home", href: "/" }, { label: "Scripts" }]}>
      <div className="hp-scripts">
        <header className="hp-listing-head">
          <span className="hp-listing-ic" style={{ ["--cc" as string]: "#f0776a" }}>
            {"⌘"}
          </span>
          <div>
            <h1 className="hp-listing-title">Scripts Arsenal</h1>
            <p className="hp-listing-sub">
              {arsenal.data
                ? `${total} runnable scripts & payloads, deduped from ${arsenal.data.kb_entries} entries`
                : " "}
            </p>
          </div>
        </header>

        {arsenal.data && total > 0 && (
          <div className="hp-scripts-toolbar">
            <input
              className="hp-scripts-filter"
              type="search"
              placeholder="filter scripts — try 'bash', 'msfvenom', 'ssti', 'suid'…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              aria-label="Filter scripts"
            />
            {needle && (
              <span className="hp-scripts-count">
                {shownCount} match{shownCount === 1 ? "" : "es"}
              </span>
            )}
          </div>
        )}

        {arsenal.loading && <p className="hp-note">loading arsenal…</p>}

        {arsenal.error && (
          <div className="hp-error-box">
            <p>{arsenal.error}</p>
            <Link href="/" className="hp-back-link">
              ← back home
            </Link>
          </div>
        )}

        {arsenal.data && total === 0 && (
          <p className="hp-note">
            No scripts indexed yet — run <code>pipeline/scripts_index.py</code>.
          </p>
        )}

        {needle && groups.length === 0 && (
          <p className="hp-note">No scripts match “{q}”.</p>
        )}

        <div className="hp-scripts-nav">
          {groups.map((g) => (
            <a key={g.type} href={`#grp-${g.type}`} className="hp-scripts-navchip"
               style={{ ["--cc" as string]: g.color }}>
              <span className="hp-scripts-navic">{g.icon}</span>
              {g.label}
              <span className="hp-scripts-navct">{g.scripts.length}</span>
            </a>
          ))}
        </div>

        {groups.map((g) => (
          <ScriptTypeSection key={g.type} group={g} />
        ))}
      </div>
    </PageShell>
  );
}

function ScriptTypeSection({ group }: { group: ScriptGroup }) {
  return (
    <section
      className="hp-scripts-group"
      id={`grp-${group.type}`}
      style={{ ["--cc" as string]: group.color } as CSSProperties}
    >
      <h2 className="hp-scripts-grouphead">
        <span className="hp-scripts-groupic">{group.icon}</span>
        {group.label}
        <span className="hp-scripts-groupct">{group.count}</span>
      </h2>
      <div className="hp-scripts-list">
        {group.scripts.map((s) => (
          <ScriptCard key={s.id} script={s} />
        ))}
      </div>
    </section>
  );
}

function ScriptCard({ script }: { script: ScriptItem }) {
  const extra = script.source_total - script.sources.length;
  return (
    <div className="hp-scriptcard">
      <div className="hp-code hp-scriptcode">
        <div className="hp-code-bar">
          <span className="hp-code-lang">{script.lang || "sh"}</span>
          <span className="hp-script-label">{script.label}</span>
          {script.reuse > 1 && (
            <span className="hp-script-reuse" title={`Seen in ${script.reuse} entries`}>
              ×{script.reuse}
            </span>
          )}
          <CopyButton text={script.code} />
        </div>
        <pre className="hp-code-pre">
          <code>{script.code}</code>
        </pre>
      </div>
      <div className="hp-script-srcs">
        <span className="hp-script-srcs-label">from</span>
        {script.sources.map((src) => (
          <Link
            key={src.id}
            href={`/entry/${encodeURIComponent(src.id)}`}
            className="hp-chip hp-script-srcchip"
            title={src.title}
          >
            {src.title || src.id}
          </Link>
        ))}
        {extra > 0 && <span className="hp-script-srcmore">+{extra} more</span>}
      </div>
    </div>
  );
}
