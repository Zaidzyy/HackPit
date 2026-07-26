"use client";

import { useEffect, useRef } from "react";

/** Reads the current `--accent` CSS var as [r,g,b]. */
function accentRGB(): [number, number, number] {
  const s = getComputedStyle(document.documentElement)
    .getPropertyValue("--accent")
    .trim();
  const h = s.replace("#", "");
  return [
    parseInt(h.slice(0, 2), 16),
    parseInt(h.slice(2, 4), 16),
    parseInt(h.slice(4, 6), 16),
  ];
}

/**
 * Living wave-grid background — a field of dots rippling on layered sine waves
 * with a soft accent glow drifting across it. Ported from the design mock.
 *
 * Performance: DPR capped at 2, rAF paused when the tab is hidden, and a single
 * static frame is drawn (no loop) when the user prefers reduced motion.
 */
export function WaveGrid() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;
    const cx = cv.getContext("2d");
    if (!cx) return;

    let W = 0;
    let H = 0;
    let DPR = 1;
    let t = 0;
    let raf = 0;

    const prefersReduced = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;

    // ACCENT IS CACHED, not read per frame. accentRGB() calls getComputedStyle on the root
    // element, which forces a style recalculation; it was being called TWICE inside frame(),
    // so a page sitting idle did ~120 forced recalcs a second for a value that changes only
    // when the operator picks a new accent.
    //
    // --accent is the CSS default (amber) now that the runtime accent picker is gone, so it
    // does not change in normal use. The MutationObserver is kept as a cheap safety net: if
    // anything ever sets --accent as an inline style on <html>, the reskin is still instant.
    // Steady-state cost is zero.
    let accent = accentRGB();
    const accentObserver = new MutationObserver(() => {
      accent = accentRGB();
    });
    accentObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["style", "class"],
    });

    function resize() {
      DPR = Math.min(window.devicePixelRatio || 1, 2);
      W = cv!.width = window.innerWidth * DPR;
      H = cv!.height = window.innerHeight * DPR;
      cv!.style.width = window.innerWidth + "px";
      cv!.style.height = window.innerHeight + "px";
    }

    function frame() {
      cx!.clearRect(0, 0, W, H);
      const gap = 42 * DPR;
      const cols = Math.ceil(W / gap) + 2;
      const rows = Math.ceil(H / gap) + 2;
      const [ar, ag, ab] = accent;

      for (let j = 0; j < rows; j++) {
        for (let i = 0; i < cols; i++) {
          const x = i * gap;
          const y0 = j * gap;
          const w =
            Math.sin(i * 0.35 + t * 2) +
            Math.cos(j * 0.4 + t * 1.6) +
            Math.sin((i + j) * 0.2 + t);
          const y = y0 + w * 7 * DPR;
          const cy = j / rows;
          const glow = Math.max(0, w) / 3;
          cx!.beginPath();
          cx!.arc(x, y, 1.15 * DPR, 0, 6.28);
          cx!.fillStyle = `rgba(${120 + glow * ar * 0.4},${
            128 + glow * ag * 0.4
          },${122 + glow * ab * 0.4},${0.05 + glow * 0.18 + cy * 0.04})`;
          cx!.fill();
        }
      }

      // soft moving accent glow
      const gx = W * (0.5 + 0.28 * Math.sin(t * 0.6));
      const gy = H * (0.35 + 0.2 * Math.cos(t * 0.5));
      const [r, g, b] = accent;
      const rad = cx!.createRadialGradient(gx, gy, 0, gx, gy, 420 * DPR);
      rad.addColorStop(0, `rgba(${r},${g},${b},0.05)`);
      rad.addColorStop(1, "rgba(0,0,0,0)");
      cx!.fillStyle = rad;
      cx!.fillRect(0, 0, W, H);
    }

    function loop() {
      t += 0.006;
      frame();
      raf = requestAnimationFrame(loop);
    }

    function onVisibility() {
      if (document.hidden) {
        cancelAnimationFrame(raf);
        raf = 0;
      } else if (!raf && !prefersReduced) {
        raf = requestAnimationFrame(loop);
      }
    }

    resize();
    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", onVisibility);

    if (prefersReduced) {
      frame(); // one static frame, no animation
    } else {
      raf = requestAnimationFrame(loop);
    }

    return () => {
      cancelAnimationFrame(raf);
      accentObserver.disconnect();
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden
      className="fixed inset-0 z-0 block"
    />
  );
}
