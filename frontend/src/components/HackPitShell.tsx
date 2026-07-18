"use client";

import { AnimatePresence } from "framer-motion";
import { useCallback, useEffect, useState } from "react";
import { WaveGrid } from "./WaveGrid";
import { Intro } from "./Intro";
import { Home } from "./Home";

const SESSION_KEY = "hackpit_intro_seen";

/**
 * Top-level client orchestrator. Owns the intro → home reveal flow:
 *
 *  - living wave-grid background (always on)
 *  - intro plays once per session; returning within the session skips it
 *  - "enter ↵" / Enter dissolves the intro and reveals the app
 *  - a replay control re-runs the intro on demand
 */
export function HackPitShell() {
  const [entered, setEntered] = useState(false);
  const [ready, setReady] = useState(false);

  // Decide on the client whether the intro has already been seen this session.
  useEffect(() => {
    if (sessionStorage.getItem(SESSION_KEY)) setEntered(true);
    setReady(true);
  }, []);

  const handleEnter = useCallback(() => {
    sessionStorage.setItem(SESSION_KEY, "1");
    setEntered(true);
  }, []);

  const replay = useCallback(() => {
    sessionStorage.removeItem(SESSION_KEY);
    setEntered(false);
  }, []);

  return (
    <main>
      <WaveGrid />
      <div className="hp-veil" />

      <Home active={ready && entered} />

      <AnimatePresence>
        {ready && !entered && <Intro key="intro" onEnter={handleEnter} />}
      </AnimatePresence>

      <button type="button" className="hp-replay" onClick={replay}>
        ↻ replay intro
      </button>
    </main>
  );
}
