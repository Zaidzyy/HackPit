import Link from "next/link";
import type { CSSProperties } from "react";
import type { Category } from "@/lib/api";
import { categoryBlurb } from "@/lib/data";

type CategoryCardProps = {
  category: Category;
  /** Adds the card to the reveal (stagger-in) once true. */
  shown: boolean;
};

/**
 * A bento-grid category card: per-category colour, hover lift, top-border
 * draw-on. Links to the category listing. Entrance driven by `shown`.
 */
export function CategoryCard({ category, shown }: CategoryCardProps) {
  const { slug, name, count, color, icon } = category;
  return (
    <Link
      href={`/category/${slug}`}
      className={`hp-card${shown ? " hp-in" : ""}`}
      style={{ "--cc": color } as CSSProperties}
    >
      <div className="hp-ic">{icon}</div>
      <span className="hp-ct">{count}</span>
      <h3>{name}</h3>
      <p>{categoryBlurb(slug, count)}</p>
    </Link>
  );
}
