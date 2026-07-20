"use client";

import Link from "next/link";
import { useState } from "react";
import { PageShell } from "./PageShell";
import { CopyButton } from "./CopyButton";
import { Lightbox } from "./Lightbox";
import { Markdown } from "./Markdown";
import { StepText } from "./StepText";
import {
  getCategories,
  getEntry,
  imageUrl,
  type MetaImage,
  type Step,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { sourceTint } from "@/lib/source";

type OpenImage = (src: string, alt: string) => void;

function prettySlug(slug: string) {
  return slug.replace(/-/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function basename(path: string) {
  return path.split(/[\\/]/).pop() || path;
}

/** Pull the ingest image metadata (kind, caption) for a given step image path. */
function imageMeta(
  entryMeta: Record<string, unknown>,
  path: string
): MetaImage | undefined {
  const imgs = entryMeta?.images;
  if (!Array.isArray(imgs)) return undefined;
  return (imgs as MetaImage[]).find((m) => m?.path === path);
}

/** ★ The technique detail view: readable, dense, copy-friendly. */
export function EntryScreen({ id }: { id: string }) {
  const entry = useApi((s) => getEntry(id, s), [id]);
  const categories = useApi(getCategories, []);
  const [lightbox, setLightbox] = useState<{ src: string; alt: string } | null>(
    null
  );

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
  const openImage: OpenImage = (src, alt) => setLightbox({ src, alt });

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
            <span
              className={`hp-badge-primary${e.from_your_notes ? " is-notes" : ""}`}
              style={{ ["--st" as string]: sourceTint(e.primary_source_label) }}
            >
              {e.primary_source_label}
            </span>
            {e.from_your_notes && (
              <span className="hp-badge-notes" title="Your own tested notes">
                ✦ from your notes
              </span>
            )}
            {e.source_count > 1 && (
              <span className="hp-badge-count">
                {e.source_count} sources
              </span>
            )}
            <span className="hp-badge-tier">
              tier {e.tier}
              {e.tier === 1 ? " · your notes" : " · curated"}
            </span>
          </div>

          {e.source_count > 1 && e.also_covered_in_labels.length > 0 && (
            <div className="hp-alsorow">
              <span className="hp-alsorow-label">also covered in</span>
              {e.also_covered_in_labels.map((label) => (
                <span
                  key={label}
                  className="hp-src-chip"
                  style={{ ["--st" as string]: sourceTint(label) }}
                >
                  {label}
                </span>
              ))}
            </div>
          )}

          {e.variants.length > 0 && (
            <div className="hp-varrow">
              <span className="hp-varrow-label">variants</span>
              {e.variants.map((v) => (
                <span key={v} className="hp-chip hp-chip-dim">
                  {v}
                </span>
              ))}
            </div>
          )}

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
              <StepBlock
                key={s.n}
                step={s}
                meta={e.meta}
                onImage={openImage}
              />
            ))}
          </ol>
        ) : (
          // No structured steps — render the normalized body as themed markdown.
          e.body_md && <Markdown source={e.body_md} />
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

      <Lightbox
        src={lightbox?.src ?? null}
        alt={lightbox?.alt}
        onClose={() => setLightbox(null)}
      />
    </PageShell>
  );
}

function StepBlock({
  step,
  meta,
  onImage,
}: {
  step: Step;
  meta: Record<string, unknown>;
  onImage: OpenImage;
}) {
  return (
    <li className="hp-step">
      <div className="hp-step-n">{step.n}</div>
      <div className="hp-step-body">
        {step.text && <StepText text={step.text} />}

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
          <StepImage
            key={path}
            path={path}
            meta={imageMeta(meta, path)}
            onImage={onImage}
          />
        ))}
      </div>
    </li>
  );
}

/**
 * A real screenshot thumbnail (lazy-loaded) served from the sandboxed backend
 * image route. Click to enlarge. If the file can't be served the component
 * falls back to a labelled reference. The machine (llava) caption stays behind
 * an "unverified" disclosure and is never presented as fact.
 */
function StepImage({
  path,
  meta,
  onImage,
}: {
  path: string;
  meta?: MetaImage;
  onImage: OpenImage;
}) {
  const [failed, setFailed] = useState(false);
  const src = imageUrl(path);
  const name = basename(path);
  const caption = meta?.caption?.trim();
  const ocrLen = meta?.ocr_len ?? meta?.char_count;

  return (
    <figure className="hp-figure">
      {failed ? (
        <div className="hp-figure-frame">
          <span className="hp-figure-icon">🖼</span>
          <div className="hp-figure-info">
            <span className="hp-figure-name">{name}</span>
            <span className="hp-figure-tags">
              {meta?.kind && (
                <span className="hp-chip hp-chip-dim">{meta.kind}</span>
              )}
              <span className="hp-figure-ocr">image unavailable</span>
            </span>
          </div>
        </div>
      ) : (
        <button
          type="button"
          className="hp-thumb"
          onClick={() => onImage(src, name)}
          aria-label={`Enlarge ${name}`}
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            className="hp-thumb-img"
            src={src}
            alt={name}
            loading="lazy"
            onError={() => setFailed(true)}
          />
          <span className="hp-thumb-hint">
            {meta?.kind ? `${meta.kind} · ` : ""}click to enlarge
          </span>
        </button>
      )}

      <figcaption className="hp-figure-meta">
        <span className="hp-figure-name">{name}</span>
        {typeof ocrLen === "number" && ocrLen > 0 && (
          <span className="hp-figure-ocr">{ocrLen} chars OCR&apos;d</span>
        )}
      </figcaption>

      {caption && (
        <details className="hp-figure-cap">
          <summary>
            AI-generated description (unverified — may be inaccurate)
          </summary>
          <p>{caption}</p>
        </details>
      )}
    </figure>
  );
}
