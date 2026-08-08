import { CockpitKillchain } from "@/components/CockpitKillchain";
import { PageShell } from "@/components/PageShell";

/**
 * The cross-domain kill-chain page — the capstone that stitches the web foothold, cloud IAM and
 * on-prem AD graphs into ONE routed kill chain, rendered as three swim-lanes with the stitched path
 * lit across them. The cloud/AD parallel, one level up: instead of a route inside a single lane, it
 * routes a foothold in one lane to a high-value target in another, across the cross-domain seams.
 *
 * Read-and-stitch overlay: it reads each graph's public output and executes nothing. The agent picks
 * an EDGE, never a command — a seam crossing runs only through the gated executor, a within-lane hop
 * in its own :cloud / :ad-graph view. `?demo=1` loads a synthetic web→cloud→on-prem chain.
 */
export default function CockpitKillchainPage() {
  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "kill-chain" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">
            web foothold · cloud IAM · on-prem AD · cross-domain seams · route to Domain Admin · every hop gated
          </div>
          <h1 className="hp-tn-title">:killchain</h1>
          <p className="hp-tn-sub">
            Stitches the three attack-path graphs — a web foothold, the cloud IAM graph, and the
            on-prem Active Directory graph — into one routed kill chain, joined by the cross-domain
            seams (SSRF→cloud metadata, cloud secret→AD credential, web RCE→host). The agent picks an
            EDGE, never authors a command: a seam crossing is grounded in the KB and runs only through
            the gated executor, a within-lane hop is approved in its own view — so you approve every
            step individually, and nothing runs on its own.
          </p>
        </header>
        <CockpitKillchain />
      </div>
    </PageShell>
  );
}
