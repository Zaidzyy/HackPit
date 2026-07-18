"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { useReducedMotion } from "@/lib/useReducedMotion";

const PHASES = [
  "reading the knowledge base",
  "retrieving recon techniques",
  "chaining enumeration → exploitation",
  "ordering privesc & post-ex",
  "grounding every step in your notes",
];

/**
 * On-theme "composing your attack path…" state. Composition on the local model
 * can take a minute+, so the wait cycles through the pipeline stages to make
 * the latency legible rather than dead. Reduced motion shows a static line.
 */
export function ComposingLoader({ model }: { model?: string }) {
  const reduced = useReducedMotion();
  const [i, setI] = useState(0);

  useEffect(() => {
    if (reduced) return;
    const t = setInterval(() => setI((n) => (n + 1) % PHASES.length), 1800);
    return () => clearInterval(t);
  }, [reduced]);

  return (
    <div className="hp-ap-loading" role="status" aria-live="polite">
      <div className="hp-ap-scan" aria-hidden>
        <span className="hp-ap-scanline" />
      </div>
      <div className="hp-ap-loading-title">composing your attack path…</div>

      <div className="hp-ap-loading-stage" aria-hidden>
        {reduced ? (
          <span>{PHASES[0]}</span>
        ) : (
          <motion.span
            key={i}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.4 }}
          >
            {PHASES[i]}
          </motion.span>
        )}
      </div>

      <div className="hp-ap-loading-dots" aria-hidden>
        {PHASES.map((_, n) => (
          <span
            key={n}
            className={`hp-ap-loading-dot${n <= i ? " is-on" : ""}`}
          />
        ))}
      </div>

      <div className="hp-ap-loading-note">
        {model ? (
          <>
            running <b>{model}</b> locally — this can take a minute on the first
            call.
          </>
        ) : (
          <>this can take a minute on a local model.</>
        )}
      </div>
    </div>
  );
}
