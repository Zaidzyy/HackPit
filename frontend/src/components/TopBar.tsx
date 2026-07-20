"use client";

import Link from "next/link";
import { Wordmark } from "./Wordmark";
import { ACCENTS, ENTRY_COUNT, NAV } from "@/lib/data";
import { openPalette } from "@/lib/paletteBus";
import { getStats } from "@/lib/api";
import { useApi } from "@/lib/useApi";

/**
 * Swaps the single signature accent at runtime by rewriting the three
 * `--accent*` vars on :root. The wave-grid reads `--accent` live, so the
 * whole app (including the moving glow) reskins instantly.
 */
function setAccent(hex: string) {
  const h = hex.replace("#", "");
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  const rs = document.documentElement.style;
  rs.setProperty("--accent", hex);
  rs.setProperty("--accent-soft", `rgba(${r},${g},${b},.14)`);
  rs.setProperty("--accent-line", `rgba(${r},${g},${b},.4)`);
}

/** Top bar: wordmark · mono nav · ⌘K affordance (visual only) · accent swatches. */
export function TopBar() {
  // Real KB size from the backend; ENTRY_COUNT is just the pre-load fallback so
  // the affordance never flashes an obviously-stale hardcoded number.
  const stats = useApi(getStats, []);
  const entryCount = stats.data?.total_entries ?? ENTRY_COUNT;

  return (
    <div className="hp-topbar">
      <Wordmark />

      <nav className="hp-nav">
        {NAV.map((item) => (
          <span key={item.key} className={item.active ? "hp-on" : undefined}>
            {item.label}
          </span>
        ))}
        <Link href="/engagements" className="hp-nav-eng">
          :engagements
        </Link>
      </nav>

      <button
        type="button"
        className="hp-cmdk"
        onClick={openPalette}
        aria-label="Open search"
      >
        search {entryCount} entries <kbd>⌘</kbd>
        <kbd>K</kbd>
      </button>

      <div className="hp-swatches">
        {ACCENTS.map((sw) => (
          <button
            key={sw.hex}
            type="button"
            className="hp-sw"
            title={sw.title}
            aria-label={`accent: ${sw.title}`}
            style={{ background: sw.hex }}
            onClick={() => setAccent(sw.hex)}
          />
        ))}
      </div>
    </div>
  );
}
