"use client";

import { Markdown } from "./Markdown";
import { sourceTint } from "@/lib/source";

type Segment = { type: "md" | "aside"; content: string };

/**
 * Consolidated steps folded in from another source carry a `[Source · variant]`
 * prefix in their text (written by the merge pipeline). Pull the source label
 * out so it can render as a small provenance chip instead of raw brackets; the
 * variant/heading stays in the prose, so nothing is lost or duplicated.
 */
const SOURCE_PREFIX_RE = /^\[([^\]]+?) · [^\]]*\]\s?/;

function splitSourcePrefix(text: string): { source: string | null; body: string } {
  const m = text.match(SOURCE_PREFIX_RE);
  if (!m) return { source: null, body: text };
  return { source: m[1].trim(), body: text.slice(m[0].length) };
}

/**
 * Split step prose into markdown runs and Notion `<aside>…</aside>` callouts.
 * The aside tags are stripped; their inner content becomes a styled callout.
 */
/**
 * Drop inline image markdown from prose. In note-derived steps these `![](…)`
 * refs duplicate the structured `step.images[]` array, which the entry view
 * already renders as proper thumbnails (with lightbox + OCR/caption) below.
 */
function stripInlineImages(text: string): string {
  return text.replace(/!\[[^\]]*\]\([^)]*\)/g, "");
}

function splitAsides(text: string): Segment[] {
  const re = /<aside>([\s\S]*?)<\/aside>/gi;
  const out: Segment[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const before = text.slice(last, m.index);
    if (before.trim()) out.push({ type: "md", content: before });
    const inner = m[1].trim();
    if (inner) out.push({ type: "aside", content: inner });
    last = re.lastIndex;
  }
  const rest = text.slice(last);
  if (rest.trim()) out.push({ type: "md", content: rest });
  if (out.length === 0) out.push({ type: "md", content: text });
  return out;
}

/**
 * Renders a step's prose as themed markdown (bold, lists, inline code, links),
 * turning Notion callouts into styled callout boxes. The step's structured
 * code[] blocks are rendered separately by the parent and untouched here.
 */
export function StepText({ text }: { text: string }) {
  const { source, body } = splitSourcePrefix(text);
  const segments = splitAsides(stripInlineImages(body));
  return (
    <div className="hp-step-prose">
      {source && (
        <span
          className="hp-src-chip hp-src-chip-step"
          style={{ ["--st" as string]: sourceTint(source) }}
          title={`Folded in from ${source}`}
        >
          {source}
        </span>
      )}
      {segments.map((seg, i) =>
        seg.type === "aside" ? (
          <div className="hp-callout" key={i}>
            <span className="hp-callout-icon" aria-hidden>
              💡
            </span>
            <div className="hp-callout-body">
              {/* drop a duplicate leading 💡 so the icon isn't shown twice */}
              <Markdown source={seg.content.replace(/^\s*💡\s*/, "")} />
            </div>
          </div>
        ) : (
          <Markdown source={seg.content} key={i} />
        )
      )}
    </div>
  );
}
