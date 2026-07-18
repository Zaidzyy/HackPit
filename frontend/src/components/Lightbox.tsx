"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useEffect } from "react";
import { useReducedMotion } from "@/lib/useReducedMotion";

type LightboxProps = {
  src: string | null;
  alt?: string;
  onClose: () => void;
};

/** Simple image lightbox: click backdrop or press Esc to close. */
export function Lightbox({ src, alt, onClose }: LightboxProps) {
  const reduced = useReducedMotion();

  useEffect(() => {
    if (!src) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", onKey);
    };
  }, [src, onClose]);

  return (
    <AnimatePresence>
      {src && (
        <motion.div
          className="hp-lb-overlay"
          role="dialog"
          aria-modal="true"
          aria-label="Enlarged screenshot"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: reduced ? 0 : 0.15 }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) onClose();
          }}
        >
          <button
            type="button"
            className="hp-lb-close"
            onClick={onClose}
            aria-label="Close"
          >
            esc ✕
          </button>
          <motion.img
            className="hp-lb-img"
            src={src}
            alt={alt ?? "screenshot"}
            initial={{ scale: reduced ? 1 : 0.97, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: reduced ? 1 : 0.97, opacity: 0 }}
            transition={{ duration: reduced ? 0 : 0.18, ease: "easeOut" }}
          />
        </motion.div>
      )}
    </AnimatePresence>
  );
}
