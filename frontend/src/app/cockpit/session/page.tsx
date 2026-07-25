import { CockpitSession } from "@/components/CockpitSession";

/**
 * The live session panel — catch a shell and drive it by hand. Standalone so the
 * existing cockpit exec flow is untouched. Starting a session is a gated command; a
 * live session's stdin is human-only (see docs/C2-SESSION-PANEL.md).
 */
export default function CockpitSessionPage() {
  return <CockpitSession />;
}
