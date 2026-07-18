"use client";

import { motion } from "framer-motion";
import { TopBar } from "./TopBar";
import { StatCounter } from "./StatCounter";
import { CategoryGrid } from "./CategoryGrid";
import { STATS } from "@/lib/data";
import { useReducedMotion } from "@/lib/useReducedMotion";

/**
 * The app shell revealed after the intro: top bar, hero with animated stat
 * counters, and the bento grid. `active` gates the reveal + count-up + stagger.
 */
export function Home({ active }: { active: boolean }) {
  const reduced = useReducedMotion();

  return (
    <motion.div
      className="hp-home"
      initial={{ opacity: 0 }}
      animate={{ opacity: active ? 1 : 0 }}
      transition={{ duration: reduced ? 0 : 1, delay: reduced ? 0 : 0.1 }}
      // Keep it out of the tab order / off-screen readers until revealed.
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
          {STATS.map((s) => (
            <StatCounter key={s.label} to={s.to} label={s.label} active={active} />
          ))}
        </div>
      </div>

      <CategoryGrid active={active} />
    </motion.div>
  );
}
