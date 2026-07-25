"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import type { LLMConfig } from "@/lib/api";
import { useReducedMotion } from "@/lib/useReducedMotion";

/**
 * The stages a composition actually goes through, in order. Defined ONCE here so
 * the Companion's composer and the cockpit's plot-path read identically — they
 * call the same backend and pass through the same phases, so a second copy of
 * this list could only ever drift out of sync with the first.
 */
const PHASES = [
  "reading the knowledge base",
  "retrieving recon techniques",
  "chaining enumeration → exploitation",
  "ordering privesc & post-ex",
  "grounding every step in your notes",
];

/**
 * On-theme "composing your attack path…" state, SHARED by the Companion's
 * attack-path composer and the cockpit's plot-path. Composition can take a
 * minute+, so the wait cycles through the pipeline stages to make the latency
 * legible rather than dead. Reduced motion shows a static line.
 *
 * The closing note names the ACTIVE model and distinguishes frontier from local
 * the same way `ModelBadge` does (`provider === "ollama"` is the local one) —
 * "running <model> locally" is simply false when the composer is pointed at a
 * frontier provider, and both surfaces read the same `/llm-config`.
 */
export function ComposingLoader({ config }: { config?: LLMConfig | null }) {
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
          /* No `exit` transition here on purpose. An exit only runs under an
             AnimatePresence wrapper, and there isn't one — the phase line is swapped by
             remounting on `key`. The prop was dead code; adding the wrapper instead would
             introduce a real exit animation and change how the line reads. */
          <motion.span
            key={i}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
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
        {config ? (
          config.provider === "ollama" ? (
            <>
              running <b>{config.model}</b> locally — this can take a minute on
              the first call.
            </>
          ) : (
            <>
              running <b>{config.model}</b>
              <span className="hp-ap-local"> · {config.provider}</span> — this
              can take a minute.
            </>
          )
        ) : (
          <>this can take a minute on a local model.</>
        )}
      </div>
    </div>
  );
}
