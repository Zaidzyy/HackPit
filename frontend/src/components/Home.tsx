"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { TopBar } from "./TopBar";
import { StatCounter } from "./StatCounter";
import { CategoryGrid } from "./CategoryGrid";
import { StatusRail } from "./StatusRail";
import { SurfaceBands } from "./SurfaceBands";
import { LLMSettingsModal } from "./LLMSettingsModal";
import { STAT_FIELDS } from "@/lib/data";
import { getCategories, getHomeSummary, getLLMConfig, getStats } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useReducedMotion } from "@/lib/useReducedMotion";

/**
 * The app shell revealed after the intro: top bar, hero with live stat counters,
 * the launcher (status rail + surface bands), then the KB category grid.
 *
 * WHY THE LAUNCHER IS HERE rather than on its own route: about a dozen surfaces
 * were reachable only by typing the URL. A page you have to navigate to fixes
 * that only if you remember to navigate to it, so the index lives on the screen
 * you already land on. The hero and the category grid are unchanged.
 *
 * THREE INDEPENDENT FETCHES on purpose. /home-summary runs docker probes, so
 * folding it into /stats would gate the hero's counters behind a container
 * inspect; each section renders as its own data arrives.
 */
export function Home({ active }: { active: boolean }) {
  const reduced = useReducedMotion();
  // Bumped after an inline model switch or a settings save, to refetch the rail + config.
  const [refreshKey, setRefreshKey] = useState(0);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const stats = useApi(getStats, []);
  const categories = useApi(getCategories, []);
  const summary = useApi(getHomeSummary, [refreshKey]);
  const llm = useApi(getLLMConfig, [refreshKey]);

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

      <StatusRail
        rail={summary.data?.rail ?? null}
        loading={summary.loading}
        error={summary.error}
        onOpenSettings={() => setSettingsOpen(true)}
        onModelChanged={() => setRefreshKey((k) => k + 1)}
      />

      <LLMSettingsModal
        open={settingsOpen}
        config={llm.data}
        onClose={() => setSettingsOpen(false)}
        onSaved={() => {
          setSettingsOpen(false);
          setRefreshKey((k) => k + 1);
        }}
      />

      <SurfaceBands
        surfaces={summary.data?.surfaces ?? null}
        rail={summary.data?.rail ?? null}
      />

      <div className="hp-sec hp-sec-major">
        <h2 id="band-library">browse the library</h2>
        <div className="hp-rule" />
        <span className="hp-hint">
          {stats.data
            ? `${stats.data.categories} categories · ${stats.data.total_entries.toLocaleString()} entries`
            : "the knowledge base"}
        </span>
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
