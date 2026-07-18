"use client";

import { motion } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "@/lib/useReducedMotion";

const WORD = "hackpit_";

type IntroProps = {
  /** Called on click of "enter ↵" or pressing Enter. */
  onEnter: () => void;
};

/**
 * The cinematic intro: `hackpit_` types itself out char-by-char, an amber
 * cursor blinks, the tagline fades in, then an "enter ↵" affordance appears.
 * It never auto-advances — it proceeds only on click or the Enter key.
 * The dissolve on exit is handled by the parent's <AnimatePresence>.
 */
export function Intro({ onEnter }: IntroProps) {
  const reduced = useReducedMotion();
  const [typed, setTyped] = useState("");
  const [showTag, setShowTag] = useState(false);
  const [showEnter, setShowEnter] = useState(false);

  // typing sequence
  useEffect(() => {
    if (reduced) {
      setTyped(WORD);
      setShowTag(true);
      setShowEnter(true);
      return;
    }

    const timers: ReturnType<typeof setTimeout>[] = [];
    [...WORD].forEach((ch, k) => {
      timers.push(
        setTimeout(() => setTyped((prev) => prev + ch), 260 + k * 130)
      );
    });
    const base = 260 + WORD.length * 130;
    timers.push(setTimeout(() => setShowTag(true), base + 250));
    timers.push(setTimeout(() => setShowEnter(true), base + 900));

    return () => timers.forEach(clearTimeout);
  }, [reduced]);

  // Enter key advances
  const onEnterRef = useRef(onEnter);
  onEnterRef.current = onEnter;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Enter") onEnterRef.current();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <motion.div
      className="hp-intro"
      initial={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: reduced ? 0 : 0.9, ease: "easeInOut" }}
    >
      <div className="hp-type">
        <span>{typed}</span>
        <span className="hp-cursor" />
      </div>

      <motion.div
        className="hp-tag"
        animate={{ opacity: showTag ? 1 : 0 }}
        transition={{ duration: reduced ? 0 : 1, delay: reduced ? 0 : 0.3 }}
      >
        offensive security companion
      </motion.div>

      <motion.button
        type="button"
        className="hp-enter"
        onClick={onEnter}
        animate={{ opacity: showEnter ? 1 : 0 }}
        transition={{ duration: reduced ? 0 : 0.3 }}
        style={{ pointerEvents: showEnter ? "auto" : "none" }}
      >
        enter ↵
      </motion.button>
    </motion.div>
  );
}
