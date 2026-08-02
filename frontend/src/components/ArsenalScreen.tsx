"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import {
  getArsenal,
  getToolReconciliation,
  renderArsenalTool,
  suggestArsenal,
  type ArsenalInvocation,
  type ArsenalTool,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";

const ARSENAL_COLOR = "#e0c15a";

const CATEGORY_LABEL: Record<string, string> = {
  recon: "Recon",
  osint: "OSINT",
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
  // The target every template is rendered against. Empty = show the raw <placeholder> form.
  const [target, setTarget] = useState("");
  // Server-rendered invocations, keyed by tool. Fetched on demand — rendering all ~115
  // tools eagerly would be 115 requests for output you would read one tool of.
  const [rendered, setRendered] = useState<Record<string, ArsenalInvocation[]>>({});
  const [renderBusy, setRenderBusy] = useState<string>("");
  // "What would the planner reach for here" — the /arsenal/suggest selection.
  const [phase, setPhase] = useState<string>("");
  const [suggested, setSuggested] = useState<ArsenalTool[] | null>(null);
  const [suggestBusy, setSuggestBusy] = useState(false);

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

  // Phases come from the catalog itself rather than a hardcoded list, so a phase added to
  // tools.json shows up here without a frontend change.
  const phases = useMemo(() => {
    const seen = new Set<string>();
    for (const t of arsenal.data?.tools ?? []) for (const p of t.phases) seen.add(p);
    return [...seen];
  }, [arsenal.data]);

  // Both handlers set state only from an async callback / event handler — never from an
  // effect body — so the repo's accepted react-hooks lint baseline stays where it is.
  const askSuggest = async (next: string) => {
    if (!next) {
      setPhase("");
      setSuggested(null);
      return;
    }
    setPhase(next);
    setSuggestBusy(true);
    try {
      const res = await suggestArsenal({ phase: next, q: needle || null, limit: 8 });
      setSuggested(res.tools);
    } catch {
      setSuggested(null);
    } finally {
      setSuggestBusy(false);
    }
  };

  const renderFor = async (name: string) => {
    setRenderBusy(name);
    try {
      const res = await renderArsenalTool(name, target.trim() || null);
      setRendered((prev) => ({ ...prev, [name]: res.invocations }));
    } catch {
      setRendered((prev) => ({ ...prev, [name]: [] }));
    } finally {
      setRenderBusy("");
    }
  };

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
          TARGET + PHASE. Two questions the catalog could not answer before: "give me this
          tool's command for THIS host" (server-side render, placeholders that cannot be
          filled stay visible) and "what would the planner reach for in this phase"
          (/arsenal/suggest — the same selection its prompt reference uses).
        */}
        <div className="hp-ta-controls hp-ta-controls2">
          <input
            type="text"
            className="hp-ta-search"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="render templates against a target — 10.10.11.42, example.com…"
            spellCheck={false}
            aria-label="Target to render invocation templates against"
          />
          <div className="hp-ta-cats">
            {phases.map((p) => (
              <button
                key={p}
                type="button"
                className={`hp-ta-cat${phase === p ? " hp-on" : ""}`}
                onClick={() => void askSuggest(phase === p ? "" : p)}
              >
                {p}
              </button>
            ))}
          </div>
        </div>

        {phase && (
          <section className="hp-ta-suggest">
            <h2 className="hp-ta-suggesthead">
              {suggestBusy
                ? `picking tools for ${phase}…`
                : `what to reach for in ${phase}`}
              <span>the planner&apos;s own shortlist</span>
            </h2>
            {suggested && suggested.length > 0 ? (
              <ul className="hp-ta-suggestlist">
                {suggested.map((t) => (
                  <li key={t.name}>
                    <span className="hp-ta-suggestname">{t.name}</span>
                    <span className="hp-ta-suggestwhy">{t.purpose}</span>
                  </li>
                ))}
              </ul>
            ) : (
              !suggestBusy && (
                <p className="hp-ta-empty">
                  No suggestion for that phase{needle ? " with this filter" : ""}.
                </p>
              )
            )}
          </section>
        )}

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
                  {(rendered[tool.name] ?? []).length > 0
                    ? rendered[tool.name].map((inv) => (
                        <li key={inv.label}>
                          <div className="hp-ta-tplhead">
                            <span className="hp-ta-tpllabel">{inv.label}</span>
                            {!inv.ready && (
                              <span
                                className="hp-ta-unfilled"
                                title={`Still unfilled: ${inv.unfilled.join(", ")}. Left visible rather than guessed.`}
                              >
                                {inv.unfilled.length} unfilled
                              </span>
                            )}
                            <CopyButton text={inv.cmd} />
                          </div>
                          <pre className="hp-ta-cmd">
                            <code>{inv.cmd}</code>
                          </pre>
                          {inv.note && <p className="hp-ta-tplnote">{inv.note}</p>}
                        </li>
                      ))
                    : tool.templates.map((tpl) => (
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

                {tool.templates.length > 0 && (
                  <div className="hp-ta-renderrow">
                    <button
                      type="button"
                      className="hp-ta-render"
                      disabled={renderBusy === tool.name}
                      onClick={() => void renderFor(tool.name)}
                    >
                      {renderBusy === tool.name
                        ? "rendering…"
                        : target.trim()
                          ? `fill for ${target.trim()}`
                          : "render invocations"}
                    </button>
                    {rendered[tool.name] && (
                      <button
                        type="button"
                        className="hp-ta-render hp-ta-renderclear"
                        onClick={() =>
                          setRendered((prev) => {
                            const next = { ...prev };
                            delete next[tool.name];
                            return next;
                          })
                        }
                      >
                        show templates
                      </button>
                    )}
                    <span className="hp-ta-rendernote">
                      Rendering produces a <b>string</b>. It reaches a target only through
                      the gated executor, approved.
                    </span>
                  </div>
                )}

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
