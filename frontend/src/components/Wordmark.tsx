/**
 * The `hackpit_` wordmark with a blinking amber underscore.
 * Reusable across the intro, top bar, and future views.
 */
export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={`hp-wm ${className ?? ""}`.trim()}>
      hackpit<span className="hp-c">_</span>
    </span>
  );
}
