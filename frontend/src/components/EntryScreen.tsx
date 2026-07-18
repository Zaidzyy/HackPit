"use client";

import Link from "next/link";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import { getCategories, getEntry, type MetaImage, type Step } from "@/lib/api";
import { useApi } from "@/lib/useApi";

function prettySlug(slug: string) {
  return slug.replace(/-/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function basename(path: string) {
  return path.split(/[\\/]/).pop() || path;
}

/** Pull the ingest image metadata (kind, caption) for a given step image path. */
function imageMeta(entryMeta: Record<string, unknown>, path: string): MetaImage | undefined {
  const imgs = entryMeta?.images;
  if (!Array.isArray(imgs)) return undefined;
  return (imgs as MetaImage[]).find((m) => m?.path === path);
}

/** ★ The technique detail view: readable, dense, copy-friendly. */
export function EntryScreen({ id }: { id: string }) {
  const entry = useApi((s) => getEntry(id, s), [id]);
  const categories = useApi(getCategories, []);

  if (entry.loading) {
    return (
      <PageShell crumbs={[{ label: "home", href: "/" }, { label: "…" }]}>
        <div className="hp-entry">
          <p className="hp-note">loading…</p>
        </div>
      </PageShell>
    );
  }

  if (entry.error || !entry.data) {
    return (
      <PageShell crumbs={[{ label: "home", href: "/" }, { label: "not found" }]}>
        <div className="hp-entry">
          <div className="hp-error-box">
            <p>{entry.error ?? "Entry not found."}</p>
            <Link href="/" className="hp-back-link">
              ← back home
            </Link>
          </div>
        </div>
      </PageShell>
    );
  }

  const e = entry.data;
  const catMeta = categories.data?.find((c) => c.slug === e.category);
  const catName = catMeta?.name ?? prettySlug(e.category);

  return (
    <PageShell
      crumbs={[
        { label: "home", href: "/" },
        { label: catName, href: `/category/${e.category}` },
        { label: e.title },
      ]}
    >
      <article className="hp-entry">
        <header className="hp-entry-head">
          <h1 className="hp-entry-title">{e.title}</h1>

          <div className="hp-entry-badges">
            <span className={`hp-badge-src${e.tier === 1 ? " is-notes" : ""}`}>
              {e.source}
            </span>
            <span className="hp-badge-tier">
              tier {e.tier}
              {e.tier === 1 ? " · your notes" : " · curated"}
            </span>
          </div>

          {e.tags.length > 0 && (
            <div className="hp-tagrow">
              {e.tags.map((t) => (
                <span key={t} className="hp-chip hp-chip-dim">
                  {t}
                </span>
              ))}
            </div>
          )}

          {e.tools.length > 0 && (
            <div className="hp-toolrow">
              <span className="hp-toolrow-label">tools</span>
              {e.tools.map((t) => (
                <span key={t} className="hp-chip hp-chip-tool">
                  {t}
                </span>
              ))}
            </div>
          )}

          {e.summary && <p className="hp-entry-summary">{e.summary}</p>}
        </header>

        {e.steps.length > 0 ? (
          <ol className="hp-steps">
            {e.steps.map((s) => (
              <StepBlock key={s.n} step={s} meta={e.meta} />
            ))}
          </ol>
        ) : (
          e.body_md && (
            // No structured steps — fall back to the normalized body so the
            // page isn't empty. (Markdown is shown as-is; not re-rendered.)
            <div className="hp-body">{e.body_md}</div>
          )
        )}

        {e.references.length > 0 && (
          <footer className="hp-refs">
            <h2 className="hp-refs-h">References</h2>
            <ul>
              {e.references.map((r) => (
                <li key={r}>
                  <a href={r} target="_blank" rel="noopener noreferrer">
                    {r}
                  </a>
                </li>
              ))}
            </ul>
          </footer>
        )}
      </article>
    </PageShell>
  );
}

function StepBlock({ step, meta }: { step: Step; meta: Record<string, unknown> }) {
  return (
    <li className="hp-step">
      <div className="hp-step-n">{step.n}</div>
      <div className="hp-step-body">
        {step.text && <div className="hp-step-text">{step.text}</div>}

        {step.code.map((c, i) => (
          <div className="hp-code" key={i}>
            <div className="hp-code-bar">
              <span className="hp-code-lang">{c.lang || "sh"}</span>
              {c.copyable && <CopyButton text={c.cmd} />}
            </div>
            <pre className="hp-code-pre">
              <code>{c.cmd}</code>
            </pre>
          </div>
        ))}

        {step.images.map((path) => (
          <StepImage key={path} path={path} meta={imageMeta(meta, path)} />
        ))}
      </div>
    </li>
  );
}

/**
 * Image reference. The backend doesn't serve the screenshot files, so we show
 * a labelled reference plus — only if present — the machine-generated caption,
 * clearly flagged as unverified rather than presented as fact.
 */
function StepImage({ path, meta }: { path: string; meta?: MetaImage }) {
  const caption = meta?.caption?.trim();
  const ocrLen = meta?.ocr_len ?? meta?.char_count;
  return (
    <figure className="hp-figure">
      <div className="hp-figure-frame">
        <span className="hp-figure-icon">🖼</span>
        <div className="hp-figure-info">
          <span className="hp-figure-name">{basename(path)}</span>
          <span className="hp-figure-tags">
            {meta?.kind && <span className="hp-chip hp-chip-dim">{meta.kind}</span>}
            {typeof ocrLen === "number" && ocrLen > 0 && (
              <span className="hp-figure-ocr">{ocrLen} chars OCR&apos;d</span>
            )}
          </span>
        </div>
      </div>
      {caption && (
        <details className="hp-figure-cap">
          <summary>AI-generated description (unverified — may be inaccurate)</summary>
          <p>{caption}</p>
        </details>
      )}
    </figure>
  );
}
