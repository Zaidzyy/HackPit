"use client";

import { motion } from "framer-motion";
import { TopBar } from "./TopBar";
import { StatCounter } from "./StatCounter";
import { CategoryGrid } from "./CategoryGrid";
import { STAT_FIELDS } from "@/lib/data";
import { getCategories, getStats } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useReducedMotion } from "@/lib/useReducedMotion";

/**
 * The app shell revealed after the intro: top bar, hero with live stat
 * counters, and the bento grid populated from the API. `active` gates the
 * reveal + count-up + stagger; data is fetched on mount regardless.
 */
export function Home({ active }: { active: boolean }) {
  const reduced = useReducedMotion();
  const stats = useApi(getStats, []);
  const categories = useApi(getCategories, []);

  // Counters only start once revealed AND real numbers are in hand.
  const countersActive = active && !!stats.data;

  return (
    <motion.div
      className="hp-home"
      initial={{ opacity: 0 }}
      animate={{ opacity: active ? 1 : 0 }}
      transition={{ duration: reduced ? 0 : 1, delay: reduced ? 0 : 0.1 }}
      aria-hidden={!active}
    >
      <TopBar />

      <div className="hp-hero">
        <div className="hp-kicker">crack the box · pass the cert · win the bounty</div>
        <div className="hp-htitle">
          Every technique you know,
          <br />
          <b>one keystroke away.</b>
        </div>
        <div className="hp-stats">
          {STAT_FIELDS.map((f) => (
            <StatCounter
              key={f.key}
              to={stats.data ? stats.data[f.key] : null}
              label={f.label}
              active={countersActive}
            />
          ))}
        </div>
        {stats.error && (
          <div className="hp-note hp-note-err">
            couldn&apos;t load stats — {stats.error}
          </div>
        )}
      </div>

      <CategoryGrid
        active={active}
        categories={categories.data}
        loading={categories.loading}
        error={categories.error}
      />
    </motion.div>
  );
}
