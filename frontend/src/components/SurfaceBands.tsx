"use client";

import Link from "next/link";
import type { CSSProperties } from "react";
import { SURFACE_BANDS } from "@/lib/data";
import type { HomeRail } from "@/lib/api";

/**
 * The launcher grid — every surface the app has, grouped by what it does.
 *
 * REVEAL IS CSS-ONLY (`animation-delay` computed per tile). CategoryGrid staggers
 * with a setState-per-tile effect, which is one of the accepted
 * `react-hooks/set-state-in-effect` baseline errors; there was no reason to add
 * four more, so this one animates without touching React state at all.
 */
export function SurfaceBands({
  surfaces,
  rail,
}: {
  /** Surface id -> count. Empty until /home-summary lands; tiles render without badges. */
  surfaces: Record<string, number> | null;
  rail: HomeRail | null;
}) {
  // Unknown (null) is not "down" — don't grey a tile out over a probe we never got.
  const stackDown = rail ? rail.sandbox_up === false : false;

  let tileIndex = 0;

  return (
    <>
      {SURFACE_BANDS.map((band) => (
        <section key={band.key} aria-labelledby={`band-${band.key}`}>
          <div className="hp-sec">
            <h2 id={`band-${band.key}`}>{band.title}</h2>
            <div className="hp-rule" />
            <span className="hp-hint">{band.hint}</span>
          </div>

          <div className="hp-grid hp-grid-4">
            {band.surfaces.map((s) => {
              const count =
                s.countKey && surfaces ? surfaces[s.countKey] : undefined;
              const blocked = !!s.needsStack && stackDown;
              const delay = `${(tileIndex++ * 0.03).toFixed(2)}s`;

              return (
                <Link
                  key={s.key}
                  href={s.href}
                  className={`hp-card hp-surface${blocked ? " hp-card-dim" : ""}`}
                  style={
                    {
                      "--cc": band.color,
                      animationDelay: delay,
                    } as CSSProperties
                  }
                >
                  <div className="hp-ic" aria-hidden>
                    {s.icon}
                  </div>
                  {typeof count === "number" ? (
                    <span className="hp-ct">{count.toLocaleString()}</span>
                  ) : null}
                  <h3>{s.label}</h3>
                  <p>{s.desc}</p>
                  {s.needsStack ? (
                    <span className={`hp-req${blocked ? " hp-req-off" : ""}`}>
                      <i aria-hidden />
                      {blocked ? "stack down" : "needs the stack"}
                    </span>
                  ) : null}
                </Link>
              );
            })}
          </div>
        </section>
      ))}
    </>
  );
}
