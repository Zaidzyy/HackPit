"use client";

import Link from "next/link";
import { useEffect, useState, type CSSProperties } from "react";
import { CategoryCard } from "./CategoryCard";
import { ScriptsCard } from "./ScriptsCard";
import { COCKPIT_FEATURE, FEATURED } from "@/lib/data";
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
  "phishing",
  "supply-chain",
]);

/**
 * The bento grid. The featured card is static; the rest are populated from
 * GET /categories (real counts + colour/icon). Cards stagger in (70ms apart)
 * once revealed and data is present; reduced motion reveals them at once.
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

  // reveal order: attack-paths, cockpit, scripts, then each category
  const total = 3 + (visibleCategories?.length ?? 0);

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
      {/* Two featured surfaces, side-by-side (stack on mobile): the generative
          attack-paths planner and the live Cockpit. */}
      <div className="hp-feat-row">
        {/* Featured — guided attack paths (the first generative feature) */}
        <Link
          href="/attack-path"
          className={`hp-card hp-feat${shownCount > 0 ? " hp-in" : ""}`}
          style={{ "--cc": FEATURED.color } as CSSProperties}
        >
          <div className="hp-ic">{FEATURED.icon}</div>
          <div className="hp-fx">
            <h3>
              {FEATURED.title}{" "}
              <span className="hp-badge">{FEATURED.badge}</span>
            </h3>
            <p>{FEATURED.desc}</p>
          </div>
          <div className="hp-go">{FEATURED.cta}</div>
        </Link>

        {/* Cockpit — plot a path, then run it against the isolated lab */}
        <Link
          href="/cockpit"
          className={`hp-card hp-feat${shownCount > 1 ? " hp-in" : ""}`}
          style={{ "--cc": COCKPIT_FEATURE.color } as CSSProperties}
        >
          <div className="hp-ic">{COCKPIT_FEATURE.icon}</div>
          <div className="hp-fx">
            <h3>
              {COCKPIT_FEATURE.title}{" "}
              <span className="hp-badge">{COCKPIT_FEATURE.badge}</span>
            </h3>
            <p>{COCKPIT_FEATURE.desc}</p>
          </div>
          <div className="hp-go">{COCKPIT_FEATURE.cta}</div>
        </Link>
      </div>

      {/* Scripts arsenal — the copy-ready operator view of the whole KB */}
      <ScriptsCard shown={shownCount > 2} />

      {visibleCategories?.map((cat, i) => (
        <CategoryCard
          key={cat.slug}
          category={cat}
          shown={shownCount > i + 3}
        />
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
