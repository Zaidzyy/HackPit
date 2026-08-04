import { CockpitADGraph } from "@/components/CockpitADGraph";
import { PageShell } from "@/components/PageShell";

/**
 * The AD attack-path graph page — the route from an owned low-priv user to Domain Admin,
 * rendered in the cockpit's kill-chain style. Standalone so the existing cockpit exec flow is
 * untouched. Loading the sample needs no AD lab; a live collection wires in through the gated
 * executor when a real domain is in an engagement scope (see docs/AD-GRAPH.md).
 *
 * D9 RESTYLE. This page used to be a bare `<main>` with its own back-link bar and title, which
 * is why it read as a different product: every other surface sits in `PageShell` (wave grid,
 * wordmark, breadcrumb) under the kicker / `:title` / sub header block. It now does too.
 *
 * The graph component's own `hp-adg-*` vocabulary is deliberately LEFT ALONE. Unlike
 * `:evasion`, which was raw Tailwind utilities, those classes are a purpose-built set of
 * primitives for a graph — nodes, edges, hop drawers — with no equivalent in `hp-tn-*`.
 * Replacing them would be a rewrite of a working canvas rather than a restyle, and D9 is
 * explicitly cosmetic: no behaviour, no gates, no endpoints.
 */
export default function CockpitADPage() {
  return (
    <PageShell crumbs={[{ label: "cockpit", href: "/cockpit" }, { label: "ad-graph" }]}>
      <div className="hp-tn">
        <header className="hp-tn-head">
          <div className="hp-ap-kicker">
            bloodhound · edges · route to domain admin · every abuse gated
          </div>
          <h1 className="hp-tn-title">:ad-graph</h1>
          <p className="hp-tn-sub">
            Maps the route from an owned low-privilege user to Domain Admin. The agent picks an
            EDGE, never authors a command — each edge&apos;s abuse is grounded in the KB and runs
            only through the gated executor, so you approve every command individually.
          </p>
        </header>
        <CockpitADGraph />
      </div>
    </PageShell>
  );
}
