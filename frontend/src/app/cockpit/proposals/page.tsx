import { ProposalsQueue } from "@/components/ProposalsQueue";
import { PageShell } from "@/components/PageShell";

/**
 * The approval queue — agent-proposed commands (via the MCP server) waiting for a human.
 * Reviewing records a decision; it never runs anything. Each row shows the gate verdict it would
 * meet and offers a ⇄ second opinion (one AI-curated alternative for the proposed command).
 */
export default function CockpitProposalsPage() {
  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "proposals" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">the approval queue · proposes · never executes</div>
          <h1 className="hp-tn-title">:proposals</h1>
          <p className="hp-tn-sub">
            Commands an agent proposed for your attention — each with the gate verdict it would
            meet and a ⇄ second opinion. Approving or rejecting records a review decision;{" "}
            <b>it does not run anything</b>. To execute a command, send it to the executor yourself
            with your own approval flags.
          </p>
        </header>
        <ProposalsQueue />
      </div>
    </PageShell>
  );
}
