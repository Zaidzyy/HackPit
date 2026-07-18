import type { CSSProperties } from "react";

type CategoryCardProps = {
  icon: string;
  /** Per-category restrained accent, applied via the `--cc` var. */
  color: string;
  title: string;
  desc: string;
  count?: number;
  /** Adds the card to the reveal (stagger-in) once true. */
  shown: boolean;
};

/**
 * A bento-grid category card: per-category color, hover lift, and the
 * top-border draw-on. Entrance is driven by the `shown` flag (staggered
 * by the parent grid).
 */
export function CategoryCard({
  icon,
  color,
  title,
  desc,
  count,
  shown,
}: CategoryCardProps) {
  return (
    <div
      className={`hp-card${shown ? " hp-in" : ""}`}
      style={{ "--cc": color } as CSSProperties}
    >
      <div className="hp-ic">{icon}</div>
      {count !== undefined && <span className="hp-ct">{count}</span>}
      <h3>{title}</h3>
      <p>{desc}</p>
    </div>
  );
}
