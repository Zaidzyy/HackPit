"use client";

import Link from "next/link";
import { useEffect, useState, type CSSProperties } from "react";
import { CategoryCard } from "./CategoryCard";
import { ScriptsCard } from "./ScriptsCard";
import { FEATURED } from "@/lib/data";
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

  const total = 2 + (visibleCategories?.length ?? 0); // featured + scripts + categories

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
      {/* Featured — guided attack paths (the first generative feature) */}
      <Link
        href="/attack-path"
        className={`hp-card hp-feat${shownCount > 0 ? " hp-in" : ""}`}
        style={{ "--cc": FEATURED.color } as CSSProperties}
      >
        <div className="hp-ic">{FEATURED.icon}</div>
        <div className="hp-fx">
          <h3>
            {FEATURED.title} <span className="hp-badge">{FEATURED.badge}</span>
          </h3>
          <p>{FEATURED.desc}</p>
        </div>
        <div className="hp-go">{FEATURED.cta}</div>
      </Link>

      {/* Scripts arsenal — the copy-ready operator view of the whole KB */}
      <ScriptsCard shown={shownCount > 1} />

      {visibleCategories?.map((cat, i) => (
        <CategoryCard
          key={cat.slug}
          category={cat}
          shown={shownCount > i + 2}
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
