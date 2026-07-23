"use client";

import { useEffect, useRef, useState } from "react";
import { useReducedMotion } from "@/lib/useReducedMotion";

/**
 * A decorative video backdrop. Everything about it is defensive:
 *
 * - **lazy**: the <video> is only mounted once the wrapper nears the viewport
 *   (IntersectionObserver) and never rendered on the server.
 * - **poster / fallback**: the wrapper carries a CSS-gradient background (styled
 *   per `variant`), so before the video loads — and if the file is missing or
 *   errors — that gradient is what shows. Nothing ever breaks.
 * - **reduced-motion**: the video is not mounted at all; the gradient stands in.
 * - **readable**: a scrim sits above the video so overlaid text keeps contrast.
 *
 * It is purely ambient (aria-hidden, pointer-events: none).
 */
export function VideoBackdrop({
  src,
  variant,
  className = "",
}: {
  src: string;
  variant: "hero" | "map" | "waveform";
  className?: string;
}) {
  const reduced = useReducedMotion();
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const [inView, setInView] = useState(false);
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el || typeof IntersectionObserver === "undefined") {
      setInView(true);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setInView(true);
          io.disconnect();
        }
      },
      { rootMargin: "200px" }
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  const show = inView && !reduced && !failed;

  return (
    <div
      ref={wrapRef}
      className={`hp-vbd is-${variant} ${className}`.trim()}
      aria-hidden="true"
    >
      {show && (
        <video
          className={`hp-vbd-video${ready ? " is-ready" : ""}`}
          src={src}
          muted
          loop
          playsInline
          autoPlay
          preload="none"
          onCanPlay={() => setReady(true)}
          onError={() => setFailed(true)}
        />
      )}
      <div className="hp-vbd-scrim" />
    </div>
  );
}
