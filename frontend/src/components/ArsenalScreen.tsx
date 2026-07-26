"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import { getArsenal, getToolReconciliation, type ArsenalTool } from "@/lib/api";
import { useApi } from "@/lib/useApi";

const ARSENAL_COLOR = "#e0c15a";

const CATEGORY_LABEL: Record<string, string> = {
  recon: "Recon & OSINT",
  web: "Web",
  "network-ad": "Network & Active Directory",
  credentials: "Credentials",
  cloud: "Cloud & containers",
  binary: "Binary & RE",
};

/**
 * The tool arsenal — the standard offensive toolbox as a browsable catalog.
 *
 * Every entry is DATA: what the tool is for, well-formed invocation templates to copy,
 * the phases and techniques it serves, and the KB entry documenting it where one exists.
 * Nothing here runs: a template is a string you copy, and it becomes a command only by
 * going through the cockpit executor with an explicit approval, like any other command.
 */
export function ArsenalScreen() {
  const arsenal = useApi(getArsenal, []);
  // What the sandbox actually has (D7). Independent of the catalog load: an unreachable
  // backend or a down Docker leaves this null and the catalog renders exactly as before.
  const recon = useApi(getToolReconciliation, []);
  const [q, setQ] = useState("");
  const [cat, setCat] = useState<string>("all");

  // Only trust a probe that actually ran — an unavailable probe must mark nothing missing.
  const missing = useMemo(
    () => new Set(recon.data?.available ? recon.data.missing : []),
    [recon.data],
  );

  const needle = q.trim().toLowerCase();
  const tools = useMemo<ArsenalTool[]>(() => {
    const all = arsenal.data?.tools ?? [];
    return all.filter((t) => {
      if (cat !== "all" && t.category !== cat) return false;
      if (!needle) return true;
      const hay = [
        t.name,
        ...t.aliases,
        t.purpose,
        ...t.techniques,
        ...t.phases,
        ...t.templates.map((x) => `${x.label} ${x.template}`),
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(needle);
    });
  }, [arsenal.data, cat, needle]);

  const grouped = useMemo(() => {
    const out = new Map<string, ArsenalTool[]>();
    for (const t of tools) {
      const list = out.get(t.category) ?? [];
      list.push(t);
      out.set(t.category, list);
    }
    return [...out.entries()];
  }, [tools]);

  const categories = arsenal.data?.categories ?? [];
  const total = arsenal.data?.total ?? 0;

  return (
    <PageShell crumbs={[{ label: "home", href: "/" }, { label: "Tool arsenal" }]}>
      <div className="hp-ta">
        <header className="hp-listing-head">
          <span className="hp-listing-ic" style={{ ["--cc" as string]: ARSENAL_COLOR }}>
            {"⚒"}
          </span>
          <div>
            <h1 className="hp-listing-title">Tool arsenal</h1>
            <p className="hp-listing-sub">
              {arsenal.data
                ? `${total} tools across ${categories.length} categories, with copy-ready invocations`
                : " "}
            </p>
          </div>
        </header>

        <p className="hp-ta-note">
          <b>A catalog, not an engine.</b> These are invocation <i>templates</i> the
          planner draws on so proposed commands are well-formed. Copying one runs
          nothing — every command still goes through the cockpit executor, approved
          one at a time, exactly as before.
        </p>

        <div className="hp-ta-controls">
          <input
            type="search"
            className="hp-ta-search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="filter by tool, technique or flag — kerberos, subdomain, sqlmap…"
            spellCheck={false}
          />
          <div className="hp-ta-cats">
            <button
              type="button"
              className={`hp-ta-cat${cat === "all" ? " hp-on" : ""}`}
              onClick={() => setCat("all")}
            >
              all
            </button>
            {categories.map((c) => (
              <button
                key={c}
                type="button"
                className={`hp-ta-cat${cat === c ? " hp-on" : ""}`}
                onClick={() => setCat(cat === c ? "all" : c)}
              >
                {CATEGORY_LABEL[c] ?? c}
              </button>
            ))}
          </div>
        </div>

        {/*
          AVAILABILITY (D7). The catalog used to imply every entry was runnable while the
          sandbox shipped a fraction of them. This band reports what the sandbox actually
          answered to `command -v`. When the probe could not run, it says UNKNOWN rather
          than showing a wall of false gaps — absence has to be proven.
        */}
        {recon.data && (
          <p
            className={`hp-ta-note${
              recon.data.available && recon.data.missing.length > 0 ? " hp-ta-warn" : ""
            }`}
          >
            {!recon.data.available ? (
              <>
                <b>Tool availability unknown.</b> {recon.data.detail}
              </>
            ) : (
              <>
                <b>
                  {recon.data.present_count} of{" "}
                  {recon.data.present_count + recon.data.missing.length} catalogued Linux
                  tools are installed
                </b>{" "}
                in <code>{recon.data.container}</code>.
                {recon.data.missing.length > 0 && (
                  <> Not installed: {recon.data.missing.join(", ")}.</>
                )}
                {recon.data.windows_only.length > 0 && (
                  <>
                    {" "}
                    {recon.data.windows_only.length} Windows-only entries (
                    {recon.data.windows_only.join(", ")}) cannot run on a Linux sandbox at
                    all — they stay here for planning and write-ups, and the planner is
                    never offered them.
                  </>
                )}{" "}
                Tools shown as unavailable are excluded from the planner&apos;s prompt, so
                it cannot propose something that is not there.
              </>
            )}
          </p>
        )}

        {arsenal.loading && <p className="hp-ta-empty">Loading the catalog…</p>}
        {arsenal.error && (
          <p className="hp-ta-empty">Could not load the arsenal. Is the backend running?</p>
        )}
        {!arsenal.loading && !arsenal.error && tools.length === 0 && (
          <p className="hp-ta-empty">No tool matches that filter.</p>
        )}

        {grouped.map(([category, list]) => (
          <section key={category} className="hp-ta-group">
            <h2 className="hp-ta-groupname">
              {CATEGORY_LABEL[category] ?? category}
              <span>{list.length}</span>
            </h2>
            {list.map((tool) => (
              <article key={tool.name} className="hp-ta-tool">
                <div className="hp-ta-toolhead">
                  <h3>{tool.name}</h3>
                  {!tool.runs_here ? (
                    <span className="hp-ta-unavail" title="PowerShell/.NET — cannot run on the Linux sandbox. Kept for planning and write-ups; never proposed by the planner.">
                      windows only
                    </span>
                  ) : (
                    missing.has(tool.name) && (
                      <span className="hp-ta-unavail" title="Catalogued but not installed in the sandbox. Excluded from the planner's prompt.">
                        not installed
                      </span>
                    )
                  )}
                  {tool.aliases.length > 0 && (
                    <span className="hp-ta-alias">aka {tool.aliases.join(", ")}</span>
                  )}
                  <span className="hp-ta-phases">{tool.phases.join(" · ")}</span>
                </div>
                <p className="hp-ta-purpose">{tool.purpose}</p>

                <ul className="hp-ta-templates">
                  {tool.templates.map((tpl) => (
                    <li key={tpl.label}>
                      <div className="hp-ta-tplhead">
                        <span className="hp-ta-tpllabel">{tpl.label}</span>
                        <CopyButton text={tpl.template} />
                      </div>
                      <pre className="hp-ta-cmd">
                        <code>{tpl.template}</code>
                      </pre>
                      {tpl.note && <p className="hp-ta-tplnote">{tpl.note}</p>}
                    </li>
                  ))}
                </ul>

                <div className="hp-ta-meta">
                  {tool.techniques.map((t) => (
                    <span key={t} className="hp-ta-tag">
                      {t}
                    </span>
                  ))}
                  {tool.kb_entry_id ? (
                    <Link
                      href={`/entry/${encodeURIComponent(tool.kb_entry_id)}`}
                      className="hp-ta-kb"
                    >
                      technique: {tool.kb_title} →
                    </Link>
                  ) : (
                    tool.docs && (
                      <a
                        href={tool.docs}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hp-ta-kb"
                      >
                        docs →
                      </a>
                    )
                  )}
                </div>

                {tool.flags.length > 0 && (
                  <details className="hp-ta-flags">
                    <summary>common flags</summary>
                    <dl>
                      {tool.flags.map((f) => (
                        <div key={f.flag}>
                          <dt>{f.flag}</dt>
                          <dd>{f.what}</dd>
                        </div>
                      ))}
                    </dl>
                  </details>
                )}
              </article>
            ))}
          </section>
        ))}
      </div>
    </PageShell>
  );
}
