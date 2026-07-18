/**
 * Tiny decoupled bus so any component (e.g. the TopBar ⌘K affordance) can open
 * the globally-mounted command palette without prop drilling or context.
 */
export const OPEN_PALETTE_EVENT = "hackpit:open-palette";

export function openPalette() {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(OPEN_PALETTE_EVENT));
  }
}
