/**
 * Per-source tinting for the consolidation UI.
 *
 * A knowledge entry is often stitched from several sources (peh-notes,
 * PayloadsAllTheThings, HackTricks, …). To make that provenance legible we give
 * every source label a STABLE, muted hue — derived from the label string — so
 * the same source wears the same colour wherever it appears on a page: the
 * "also covered in" header chips, the per-step source badges, and the merged
 * body's source dividers. No lookup table to maintain; new labels just work.
 */

/** Deterministic 0–359 hue from a source label (stable across renders). */
export function sourceHue(label: string): number {
  let h = 0;
  for (let i = 0; i < label.length; i += 1) {
    h = (h * 31 + label.charCodeAt(i)) % 360;
  }
  return h;
}

/**
 * A readable, restrained tint for a source label on the dark theme. Callers set
 * it as the `--st` custom property on the element; the stylesheet mixes it into
 * the border/background so chips stay subtle rather than shouting.
 */
export function sourceTint(label: string): string {
  return `hsl(${sourceHue(label)} 52% 66%)`;
}
