"use client";

import { useEffect, useState } from "react";
import { CategoryCard } from "./CategoryCard";
import type { Category } from "@/lib/api";
import { useReducedMotion } from "@/lib/useReducedMotion";

type CategoryGridProps = {
  active: boolean;
  categories: Category[] | null;
  loading: boolean;
  error: string | null;
};

// Near-empty categories we don't surface as a browse card. Their entries stay in
// the KB and remain reachable via search / direct link — this is a display-only
// filter, not a data change (the /categories endpoint is untouched).
const HIDDEN_CATEGORIES = new Set([
  "forensics",
  "ics",
  "supply-chain",
]);

/**
 * The KB category grid — now categories ONLY.
 *
 * It used to also carry five product cards: the two featured surfaces
 * (attack-paths + Cockpit), the scripts arsenal, the tool arsenal and code scan.
 * Every one of those is a tile in the launcher bands above (see
 * `SURFACE_BANDS` in lib/data.ts), so keeping them here would show each surface
 * twice on the same screen. `ScriptsCard`, `FEATURED` and `COCKPIT_FEATURE` are
 * left in the tree unreferenced rather than deleted, so restoring the old layout
 * is a revert of this file alone.
 *
 * Cards stagger in (70ms apart) once revealed and data is present; reduced motion
 * reveals them at once.
 */
export function CategoryGrid({
  active,
  categories,
  loading,
  error,
}: CategoryGridProps) {
  const reduced = useReducedMotion();
  const [shownCount, setShownCount] = useState(0);

  const visibleCategories =
    categories?.filter((cat) => !HIDDEN_CATEGORIES.has(cat.slug)) ?? null;

  // The three-card head start is gone with the product cards — the reveal order
  // is now just the categories themselves.
  const total = visibleCategories?.length ?? 0;

  useEffect(() => {
    if (!active) return;

    if (reduced) {
      setShownCount(total);
      return;
    }

    const timers: ReturnType<typeof setTimeout>[] = [];
    for (let i = 0; i < total; i++) {
      timers.push(
        setTimeout(() => setShownCount((c) => Math.max(c, i + 1)), i * 70)
      );
    }
    return () => timers.forEach(clearTimeout);
  }, [active, reduced, total]);

  return (
    <div className="hp-grid">
      {visibleCategories?.map((cat, i) => (
        <CategoryCard key={cat.slug} category={cat} shown={shownCount > i} />
      ))}

      {loading && !categories && (
        <div className="hp-card-msg">loading categories…</div>
      )}
      {error && !categories && (
        <div className="hp-card-msg hp-note-err">
          couldn&apos;t load categories — {error}
        </div>
      )}
    </div>
  );
}
