import { CockpitCloudGraph } from "@/components/CockpitCloudGraph";
import { PageShell } from "@/components/PageShell";

/**
 * The cloud IAM privilege-escalation graph page — the route from an owned principal to an
 * admin/owner-equivalent identity, rendered in the cockpit's kill-chain style. The cloud parallel
 * to /cockpit/ad. Loading the sample needs no cloud credentials; a live enumeration
 * (ScoutSuite / Prowler / pacu / cloudfox) wires in as a gated job when a real account is in an
 * engagement scope (see the README).
 *
 * Like the AD page, this sits in PageShell (wave grid, wordmark, breadcrumb) under the kicker /
 * :title / sub header block, and reuses the graph component's own hp-adg-* canvas primitives —
 * nodes, edges, hop drawers — which have no hp-tn-* equivalent.
 */
export default function CockpitCloudPage() {
  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "cloud-graph" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">
            scoutsuite · prowler · pacu · cloudfox · IAM privesc edges · route to admin · every abuse gated
          </div>
          <h1 className="hp-tn-title">:cloud-graph</h1>
          <p className="hp-tn-sub">
            Maps the route from an owned cloud principal to an admin/owner-equivalent identity across
            AWS, Azure and GCP. The agent picks an EDGE, never authors a command — each edge&apos;s
            IAM abuse is grounded in the KB and runs only through the gated executor, so you approve
            every command individually.
          </p>
        </header>
        <CockpitCloudGraph />
      </div>
    </PageShell>
  );
}
