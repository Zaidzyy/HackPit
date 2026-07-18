import Link from "next/link";
import { Fragment } from "react";

export type Crumb = {
  label: string;
  href?: string;
};

/** Compact breadcrumb trail; the last crumb renders as the current (amber) page. */
export function Breadcrumb({ crumbs }: { crumbs: Crumb[] }) {
  return (
    <nav className="hp-crumb" aria-label="breadcrumb">
      {crumbs.map((c, i) => {
        const last = i === crumbs.length - 1;
        return (
          <Fragment key={i}>
            {c.href && !last ? (
              <Link href={c.href}>{c.label}</Link>
            ) : (
              <span className={last ? "hp-crumb-cur" : undefined}>{c.label}</span>
            )}
            {!last && <span className="hp-crumb-sep">/</span>}
          </Fragment>
        );
      })}
    </nav>
  );
}
