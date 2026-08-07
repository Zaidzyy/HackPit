"use client";

import { useState } from "react";
import { PageShell } from "./PageShell";
import { TokenPanel } from "./TokenPanel";

/**
 * :tokens — the token workbench as a dedicated surface (it also mounts inside :proxy).
 *
 * *** THE ANALYSIS/TAMPER CORE IS PURE. *** Decode / analyze / tamper a JWT, OAuth/OIDC flow or
 * SAML assertion, flag the classic misconfigs, and hand the mutated token to the repeater to send
 * (approve-each, scope-checked on the wire). Nothing on this screen sends. The one thing that runs
 * — the weak-secret crack — is one gated job, gated by the same four gates as every other command.
 */
export function TokensScreen() {
  const [engagementId, setEngagementId] = useState("");

  return (
    <PageShell crumbs={[{ label: "tokens" }]}>
      <div className="hp-tn">
        <div className="hp-tn-head">
          <h1 className="hp-tn-title">:tokens</h1>
          <p className="hp-tn-sub">
            JWT / OAuth / OIDC / SAML — decode, analyze, tamper. A mutated token goes to a real
            endpoint only through the human-approved repeater.
          </p>
        </div>

        <div className="hp-tn-card">
          <div className="hp-tn-cardsub">
            Optional: the engagement id the weak-secret crack runs under (a crack needs an active
            engagement — the lab sandbox has no loot mount). Leave blank for analysis/tamper only.
          </div>
          <div className="hp-tn-form">
            <input
              value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)}
              placeholder="engagement id (for the crack)"
            />
          </div>
        </div>

        <TokenPanel
          engagementId={engagementId.trim() || null}
          sessionId={engagementId.trim() || null}
        />
      </div>
    </PageShell>
  );
}
