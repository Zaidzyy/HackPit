"use client";

import { useEffect, useState, type CSSProperties } from "react";
import { CategoryCard } from "./CategoryCard";
import { CATEGORIES, FEATURED } from "@/lib/data";
import { useReducedMotion } from "@/lib/useReducedMotion";

/** Total cards = 1 featured + N categories. */
const TOTAL = CATEGORIES.length + 1;

/**
 * The bento grid. Cards stagger in (70ms apart) once `active` becomes true,
 * matching the mock. Reduced motion reveals them all at once.
 */
export function CategoryGrid({ active }: { active: boolean }) {
  const reduced = useReducedMotion();
  const [shownCount, setShownCount] = useState(0);

  useEffect(() => {
    if (!active) return;

    if (reduced) {
      setShownCount(TOTAL);
      return;
    }

    const timers: ReturnType<typeof setTimeout>[] = [];
    for (let i = 0; i < TOTAL; i++) {
      timers.push(setTimeout(() => setShownCount((c) => Math.max(c, i + 1)), i * 70));
    }
    return () => timers.forEach(clearTimeout);
  }, [active, reduced]);

  return (
    <div className="hp-grid">
      {/* Featured — guided attack paths */}
      <div
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
      </div>

      {CATEGORIES.map((cat, i) => (
        <CategoryCard key={cat.title} {...cat} shown={shownCount > i + 1} />
      ))}
    </div>
  );
}
