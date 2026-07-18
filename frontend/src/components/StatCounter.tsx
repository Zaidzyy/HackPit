"use client";

import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "@/lib/useReducedMotion";

type StatCounterProps = {
  /** Target value; `null` means "not loaded yet / unavailable". */
  to: number | null;
  label: string;
  /** When true, the count-up animation runs (once real data is present). */
  active: boolean;
};

/**
 * A single stat with an eased count-up. Matches the mock: ~1.1s, easeOutCubic.
 * Jumps straight to the final value when reduced motion is preferred, and
 * shows an em-dash placeholder until a real value arrives.
 */
export function StatCounter({ to, label, active }: StatCounterProps) {
  const [value, setValue] = useState(0);
  const started = useRef(false);
  const reduced = useReducedMotion();

  useEffect(() => {
    if (!active || to === null || started.current) return;
    started.current = true;

    if (reduced) {
      setValue(to);
      return;
    }

    let raf = 0;
    let start: number | null = null;
    const step = (ts: number) => {
      if (start === null) start = ts;
      const p = Math.min((ts - start) / 1100, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      setValue(Math.round(to * eased));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [active, to, reduced]);

  return (
    <div className="hp-stat">
      <div className="hp-n">{to === null ? "—" : value}</div>
      <div className="hp-l">{label}</div>
    </div>
  );
}
