"use client";

import { useEffect, useRef, useState } from "react";

/**
 * Copies the given text verbatim (placeholders like <TARGET>/<USER> preserved)
 * to the clipboard and shows a brief "copied" confirmation. Falls back to a
 * hidden-textarea copy where the async Clipboard API is unavailable.
 */
export function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<"idle" | "copied" | "error">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  async function copy() {
    let ok = false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        ok = true;
      } else {
        ok = legacyCopy(text);
      }
    } catch {
      ok = legacyCopy(text);
    }
    setState(ok ? "copied" : "error");
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"), 1500);
  }

  return (
    <button
      type="button"
      className={`hp-copy${state !== "idle" ? " is-active" : ""}`}
      onClick={copy}
      aria-label="Copy command"
    >
      {state === "copied" ? "✓ copied" : state === "error" ? "copy failed" : "copy"}
    </button>
  );
}

function legacyCopy(text: string): boolean {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
