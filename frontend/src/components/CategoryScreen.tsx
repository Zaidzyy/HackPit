"use client";

import Link from "next/link";
import { PageShell } from "./PageShell";
import { getCategories, getCategory } from "@/lib/api";
import { useApi } from "@/lib/useApi";

function prettySlug(slug: string) {
  return slug.replace(/-/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

/** Category listing: the entries in one category as a scannable list. */
export function CategoryScreen({ slug }: { slug: string }) {
  const entries = useApi((s) => getCategory(slug, s), [slug]);
  const categories = useApi(getCategories, []);

  const meta = categories.data?.find((c) => c.slug === slug);
  const name = meta?.name ?? prettySlug(slug);
  const color = meta?.color ?? "var(--accent)";

  return (
    <PageShell
      crumbs={[{ label: "home", href: "/" }, { label: name }]}
    >
      <div className="hp-listing">
        <header className="hp-listing-head">
          {meta && (
            <span
              className="hp-listing-ic"
              style={{ ["--cc" as string]: color }}
            >
              {meta.icon}
            </span>
          )}
          <div>
            <h1 className="hp-listing-title">{name}</h1>
            <p className="hp-listing-sub">
              {entries.data
                ? `${entries.data.length} ${
                    entries.data.length === 1 ? "entry" : "entries"
                  }`
                : " "}
            </p>
          </div>
        </header>

        {entries.loading && <p className="hp-note">loading entries…</p>}

        {entries.error && (
          <div className="hp-error-box">
            <p>{entries.error}</p>
            <Link href="/" className="hp-back-link">
              ← back home
            </Link>
          </div>
        )}

        {entries.data && entries.data.length === 0 && (
          <p className="hp-note">No entries in this category yet.</p>
        )}

        {entries.data && entries.data.length > 0 && (
          <ul className="hp-rows">
            {entries.data.map((e) => (
              <li key={e.id}>
                <Link href={`/entry/${encodeURIComponent(e.id)}`} className="hp-row">
                  <div className="hp-row-main">
                    <h3 className="hp-row-title">{e.title}</h3>
                    {e.summary && <p className="hp-row-sum">{e.summary}</p>}
                    {e.tags.length > 0 && (
                      <div className="hp-row-tags">
                        {e.tags.slice(0, 6).map((t) => (
                          <span key={t} className="hp-chip hp-chip-dim">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="hp-row-meta">
                    <span
                      className={`hp-badge-src${e.tier === 1 ? " is-notes" : ""}`}
                    >
                      {e.tier === 1 ? "notes" : e.source}
                    </span>
                    <span className="hp-row-arrow">→</span>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </PageShell>
  );
}
