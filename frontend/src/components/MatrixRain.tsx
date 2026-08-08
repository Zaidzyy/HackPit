"use client";

import { useEffect, useRef } from "react";

/** Reads the current `--accent` CSS var as an "r,g,b" string for rgba(). */
function accentRGB(): string {
  const s = getComputedStyle(document.documentElement)
    .getPropertyValue("--accent")
    .trim();
  const h = s.replace("#", "");
  return [
    parseInt(h.slice(0, 2), 16),
    parseInt(h.slice(2, 4), 16),
    parseInt(h.slice(4, 6), 16),
  ].join(",");
}

// Half-width katakana + a few glyphs — the classic rain alphabet.
const GLYPHS =
  "アイウエオカキクケコサシスセソタチツテトナニヌネノ0123456789<>=/\\[]{}$#*";
const FONT_PX = 16; // coarse grid — cheap
const MAX_COLS = 64; // capped column count regardless of viewport width
const TAIL = 8; // glyphs drawn per column (head + fading trail)
const STEP_MS = 70; // ~14 fps — low per-frame cost, classic step cadence
const HEAD_ALPHA = 0.11; // brightest glyph opacity — ambient (~8–12% target)

/** Deterministic glyph for a (column, row) cell — stable, no per-frame RNG. */
function glyphAt(col: number, row: number): string {
  const i = ((col * 92821 + row * 68389) >>> 0) % GLYPHS.length;
  return GLYPHS[i];
}

/**
 * Ambient matrix-rain background — falling glyph columns drawn in the current
 * accent at low opacity. It layers *behind* the WaveGrid (both live at z-0) and
 * exists purely as texture, so it is kept deliberately cheap:
 *
 *  - DPR capped at 2, a coarse grid, and at most MAX_COLS columns
 *  - the draw is throttled to ~14 fps via STEP_MS (rAF only checks a timestamp
 *    at 60 Hz, which is free), so it does not double WaveGrid's per-frame cost
 *  - each frame clearRect()s to full transparency (never a black fade), so the
 *    WaveGrid and veil below show through untouched
 *  - the loop is paused when the tab is hidden (CPU while backgrounded)
 *
 * The rain always animates: prefers-reduced-motion is intentionally NOT honoured
 * here (Zaid's call — he wants motion regardless of the OS setting).
 */
export function MatrixRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;
    const cx = cv.getContext("2d");
    if (!cx) return;

    let W = 0;
    let H = 0;
    let DPR = 1;
    let cell = 0; // glyph box in device px
    let colStep = 0; // horizontal spacing between columns
    let cols = 0;
    let heads: number[] = []; // head row index per column
    let raf = 0;
    let last = 0;

    // Accent is cached and refreshed only when --accent actually changes (same
    // approach as WaveGrid): getComputedStyle forces a style recalc, so it must
    // never run per frame.
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
      cell = FONT_PX * DPR;
      // Cap the column count; if the viewport is wider than the cap, spread the
      // columns evenly rather than leaving the right edge bare.
      cols = Math.min(MAX_COLS, Math.max(1, Math.ceil(W / cell)));
      colStep = W / cols;
      // Stagger the starting heads so columns don't fall in lockstep.
      heads = Array.from({ length: cols }, () =>
        Math.floor((Math.random() * H) / cell)
      );
      // Canvas font does NOT resolve CSS custom properties — use a literal
      // family so the glyphs render at the intended cell size, not the 10px
      // sans-serif default.
      cx!.font = `${cell}px ui-monospace, SFMono-Regular, Menlo, monospace`;
      cx!.textBaseline = "top";
    }

    function draw() {
      cx!.clearRect(0, 0, W, H); // fully transparent — WaveGrid shows through
      const rowsOnScreen = Math.ceil(H / cell);
      for (let i = 0; i < cols; i++) {
        const x = i * colStep;
        const head = heads[i];
        for (let k = 0; k < TAIL; k++) {
          const row = head - k;
          if (row < 0 || row > rowsOnScreen) continue;
          // head brightest, trail fades to nothing
          const a = (1 - k / TAIL) * HEAD_ALPHA;
          cx!.fillStyle = `rgba(${accent},${a.toFixed(3)})`;
          cx!.fillText(glyphAt(i, row), x, row * cell);
        }
      }
    }

    function step() {
      for (let i = 0; i < cols; i++) {
        heads[i] += 1;
        // reset to the top once well past the bottom, with a little jitter so
        // columns re-seed at different times
        if (heads[i] * cell > H && Math.random() > 0.975) heads[i] = 0;
      }
      draw();
    }

    function loop(now: number) {
      raf = requestAnimationFrame(loop);
      if (now - last < STEP_MS) return; // throttle the actual draw to ~14 fps
      last = now;
      step();
    }

    function onVisibility() {
      if (document.hidden) {
        cancelAnimationFrame(raf);
        raf = 0;
      } else if (!raf) {
        raf = requestAnimationFrame(loop);
      }
    }

    resize();
    window.addEventListener("resize", resize);
    document.addEventListener("visibilitychange", onVisibility);

    raf = requestAnimationFrame(loop); // always animate

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
      className="pointer-events-none fixed inset-0 z-0 block"
    />
  );
}
