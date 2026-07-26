"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Wordmark } from "./Wordmark";
import { ENTRY_COUNT, NAV } from "@/lib/data";
import { openPalette } from "@/lib/paletteBus";
import { getStats } from "@/lib/api";
import { useApi } from "@/lib/useApi";

/** Top bar: wordmark · mono nav (centred) · ⌘K search affordance. */
export function TopBar() {
  // Real KB size from the backend; ENTRY_COUNT is just the pre-load fallback so
  // the affordance never flashes an obviously-stale hardcoded number.
  const stats = useApi(getStats, []);
  const entryCount = stats.data?.total_entries ?? ENTRY_COUNT;
  const pathname = usePathname();

  return (
    <div className="hp-topbar">
      <Wordmark />

      <nav className="hp-nav">
        {NAV.map((item) => {
          const active =
            item.href === "/"
              ? pathname === "/"
              : pathname === item.href || pathname.startsWith(`${item.href}/`);
          return (
            <Link
              key={item.key}
              href={item.href}
              className={active ? "hp-on" : undefined}
              aria-current={active ? "page" : undefined}
            >
              {item.label}
            </Link>
          );
        })}
      </nav>

      <button
        type="button"
        className="hp-cmdk"
        onClick={openPalette}
        aria-label="Open search"
      >
        <span>search {entryCount} entries</span>
        <span className="hp-cmdk-keys">
          <kbd>⌘</kbd>
          <kbd>K</kbd>
        </span>
      </button>
    </div>
  );
}
