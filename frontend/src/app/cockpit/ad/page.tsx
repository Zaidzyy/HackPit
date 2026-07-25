import Link from "next/link";
import { CockpitADGraph } from "@/components/CockpitADGraph";

/**
 * The AD attack-path graph page — the route from an owned low-priv user to Domain Admin,
 * rendered in the cockpit's kill-chain style. Standalone so the existing cockpit exec flow is
 * untouched. Loading the sample needs no AD lab; a live collection wires in through the gated
 * executor when a real domain is in an engagement scope (see docs/AD-GRAPH.md).
 */
export default function CockpitADPage() {
  return (
    <main className="hp-adg-page">
      <div className="hp-adg-page-bar">
        <Link href="/cockpit" className="hp-adg-back">
          ← cockpit
        </Link>
        <h1 className="hp-adg-page-title">AD attack-path graph</h1>
        <span className="hp-adg-page-tag">BloodHound → route to Domain Admin</span>
      </div>
      <CockpitADGraph />
    </main>
  );
}
