"use client";

import { Markdown } from "./Markdown";

type Segment = { type: "md" | "aside"; content: string };

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
  const segments = splitAsides(stripInlineImages(text));
  return (
    <div className="hp-step-prose">
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
