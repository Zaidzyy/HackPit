"use client";

import Link from "next/link";
import { WaveGrid } from "./WaveGrid";
import { Wordmark } from "./Wordmark";
import { Breadcrumb, type Crumb } from "./Breadcrumb";

/**
 * Chrome for the working views (category listing, entry detail): the living
 * wave-grid behind everything, a light header with the wordmark linking home
 * and a breadcrumb, then a constrained content column.
 */
export function PageShell({
  crumbs,
  children,
}: {
  crumbs: Crumb[];
  children: React.ReactNode;
}) {
  return (
    <main>
      <WaveGrid />
      <div className="hp-veil" />

      <div className="hp-page">
        <header className="hp-subhead">
          <Link href="/" className="hp-wm-link" aria-label="HackPit home">
            <Wordmark />
          </Link>
          <Breadcrumb crumbs={crumbs} />
        </header>

        {children}
      </div>
    </main>
  );
}
