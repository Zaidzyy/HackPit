"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  cloudImdsCatalog,
  type CloudProvider,
  type CloudSeedResult,
  type ImdsCatalogEntry,
} from "@/lib/api";

/**
 * "Seed from SSRF / IMDS" — the web↔cloud seam. A captured instance-metadata (IMDS) response,
 * pasted here (or pulled from a repeater exchange / an OOB callback body), is parsed into an OWNED
 * cloud principal and seeded into the :cloud graph, so the IAM privesc walk begins from the identity
 * you just stole through SSRF/RCE.
 *
 * IT RUNS NOTHING. The request that actually touched 169.254.169.254 already went through the
 * human-approved repeater / nuclei / executor (or arrived out-of-band). This panel only submits the
 * captured body for parsing + seeding; the secret it extracts is stored in the engagement vault /
 * loot and is never shown here or written into the finding.
 *
 * The `onSeed` callback (owned by the graph) posts to /cockpit/cloud/seed-imds and refreshes the
 * graph so the new owned node lights up. This component holds the input + shows the parsed result.
 */

const PROVIDERS: { id: CloudProvider; label: string }[] = [
  { id: "aws", label: "AWS" },
  { id: "azure", label: "Azure" },
  { id: "gcp", label: "GCP" },
];

// SYNTHETIC example bodies — fake account ids / ARNs / tenants / tokens, never a real credential.
// The AWS one matches the synthetic sample account's `ci-deployer` role, so seeding it merges onto
// that enumerated node and the route to admin lights up.
const SYNTH_BODY: Record<CloudProvider, string> = {
  aws: JSON.stringify(
    {
      Code: "Success",
      LastUpdated: "2026-08-07T00:00:00Z",
      Type: "AWS-HMAC",
      AccessKeyId: "ASIAEXAMPLE0SYNTHETIC",
      SecretAccessKey: "wSyntheticSecretKeyMaterialDoNotUseFAKE1234567890",
      Token: "SyntheticSessionTokenAAAABBBBCCCCDDDDEEEEFFFF==",
      Expiration: "2026-08-07T06:00:00Z",
    },
    null,
    2
  ),
  azure: JSON.stringify(
    {
      access_token:
        "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.eyJvaWQiOiAiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDBkZWFkIiwgImFwcGlkIjogIjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsICJ0aWQiOiAiOTk5OTk5OTktODg4OC03Nzc3LTY2NjYtNTU1NTU1NTU1NTU1IiwgImV4cCI6IDE5MDAwMDAwMDB9.c3ludGhldGljLXNpZ25hdHVyZQ",
      expires_on: "1900000000",
      resource: "https://management.azure.com/",
      token_type: "Bearer",
    },
    null,
    2
  ),
  gcp: JSON.stringify(
    { access_token: "ya29.SYNTHETICgcpAccessTokenDoNotUseFAKE", expires_in: 3599, token_type: "Bearer" },
    null,
    2
  ),
};

// The role/identity hint that matches each synthetic example onto its enumerated node.
const SYNTH_HINT: Record<CloudProvider, string> = {
  aws: "ci-deployer",
  azure: "",
  gcp: "svc-deploy@synthetic-project.iam.gserviceaccount.com",
};

type Source = "repeater" | "oob" | "paste";

export function CockpitCloudSeed({
  onSeed,
  disabled = false,
  engagement = false,
  autoSeed = false,
}: {
  onSeed: (
    provider: CloudProvider,
    body: string,
    source: Source,
    roleHint: string
  ) => Promise<CloudSeedResult>;
  disabled?: boolean;
  engagement?: boolean;
  /** When true (the ?seed screenshot deep-link), auto-fills + seeds the synthetic AWS example on
   *  mount so the panel renders a real parsed result without a click. */
  autoSeed?: boolean;
}) {
  const [provider, setProvider] = useState<CloudProvider>("aws");
  const [body, setBody] = useState("");
  const [roleHint, setRoleHint] = useState("");
  const [source, setSource] = useState<Source>("paste");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CloudSeedResult | null>(null);
  const [catalog, setCatalog] = useState<ImdsCatalogEntry[]>([]);
  const [showCatalog, setShowCatalog] = useState(false);
  const catalogAbort = useRef<AbortController | null>(null);

  // Load the per-provider IMDS request cheat-set whenever the provider changes.
  useEffect(() => {
    catalogAbort.current?.abort();
    const ctrl = new AbortController();
    catalogAbort.current = ctrl;
    cloudImdsCatalog(provider, ctrl.signal)
      .then((r) => setCatalog(r.requests))
      .catch(() => {
        if (!ctrl.signal.aborted) setCatalog([]);
      });
    return () => ctrl.abort();
  }, [provider]);

  const loadExample = useCallback(() => {
    setBody(SYNTH_BODY[provider]);
    setRoleHint(SYNTH_HINT[provider]);
    setSource("oob");
    setError(null);
  }, [provider]);

  const seedWith = useCallback(
    async (prov: CloudProvider, bodyStr: string, src: Source, hint: string) => {
      if (!bodyStr.trim()) return;
      setBusy(true);
      setError(null);
      try {
        const res = await onSeed(prov, bodyStr, src, hint.trim());
        setResult(res);
      } catch (err: unknown) {
        setResult(null);
        setError(err instanceof Error ? err.message : "Could not seed the identity.");
      } finally {
        setBusy(false);
      }
    },
    [onSeed]
  );

  const seed = useCallback(() => {
    if (busy) return;
    void seedWith(provider, body, source, roleHint);
  }, [busy, seedWith, provider, body, source, roleHint]);

  // ?seed deep-link: fill the AWS synthetic example and seed it once, so the headless screenshot
  // shows the panel's parsed result. The setState lives in seedWith's async body (lint baseline).
  const didAuto = useRef(false);
  useEffect(() => {
    if (!autoSeed || didAuto.current) return;
    didAuto.current = true;
    setProvider("aws");
    setBody(SYNTH_BODY.aws);
    setRoleHint(SYNTH_HINT.aws);
    setSource("oob");
    void seedWith("aws", SYNTH_BODY.aws, "oob", SYNTH_HINT.aws);
  }, [autoSeed, seedWith]);

  return (
    <section className="hp-tn-card">
      <div className="hp-tn-cardhead">seed from SSRF / IMDS</div>
      <div className="hp-tn-cardsub">
        Turn a web-side SSRF/RCE into cloud credentials. Paste a captured instance-metadata (IMDS)
        response — from the repeater, a nuclei hit, or an OOB callback body — and the identity behind
        it is seeded as an <b>owned</b> principal, so the privesc walk starts from what you just
        stole. This panel runs nothing; the request that hit <code>169.254.169.254</code> went
        through the gated executor. The secret is stored in the vault{engagement ? " / loot" : ""} —
        never shown here, never in the finding.
      </div>

      <div className="hp-adg-providers" role="tablist" aria-label="captured cloud provider">
        {PROVIDERS.map((pr) => (
          <button
            key={pr.id}
            type="button"
            role="tab"
            aria-selected={provider === pr.id}
            className={`hp-tn-chip${provider === pr.id ? " is-on" : ""}`}
            onClick={() => setProvider(pr.id)}
          >
            {pr.label}
          </button>
        ))}
      </div>

      <div className="hp-tn-form">
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          rows={6}
          spellCheck={false}
          placeholder={
            provider === "aws"
              ? "Paste the IMDS response, e.g. GET …/iam/security-credentials/<role> → {\"AccessKeyId\":…}"
              : provider === "azure"
                ? "Paste the managed-identity token JSON → {\"access_token\":\"<JWT>\", …}"
                : "Paste the SA token JSON → {\"access_token\":\"ya29.…\", …} (or the SA email)"
          }
          style={{ flexBasis: "100%", width: "100%", fontFamily: "var(--mono, monospace)" }}
        />
      </div>

      <div className="hp-tn-form">
        {provider !== "azure" && (
          <input
            type="text"
            value={roleHint}
            onChange={(e) => setRoleHint(e.target.value)}
            placeholder={provider === "aws" ? "role name (the <role> in the URL)" : "service-account email"}
            aria-label="identity hint"
          />
        )}
        <select value={source} onChange={(e) => setSource(e.target.value as Source)} aria-label="captured via">
          <option value="paste">source: paste</option>
          <option value="repeater">source: repeater</option>
          <option value="oob">source: OOB callback</option>
        </select>
        <button type="button" className="hp-tn-chip" onClick={loadExample} disabled={busy}>
          load synthetic example
        </button>
      </div>

      {error && <div className="hp-tn-error">{error}</div>}

      <div className="hp-tn-actions">
        <span className="hp-tn-actions-label">act</span>
        <button
          type="button"
          className="hp-tn-start"
          onClick={seed}
          disabled={disabled || busy || !body.trim()}
          title="Parse the captured IMDS body and seed the owned identity into the graph"
        >
          {busy ? "seeding…" : "seed identity"}
        </button>
      </div>

      {result && result.node && (
        <div className="hp-tn-row">
          <div className="hp-tn-rowtop">
            <span className="hp-adg-tag">owned</span>
            <b>{result.identity || result.node_id}</b>
            <span className="hp-adg-badge is-grounded">via ssrf-imds</span>
            <span className="hp-adg-badge">{result.imds_version}</span>
            {result.matched_existing ? (
              <span className="hp-adg-badge is-grounded">matched an enumerated node</span>
            ) : (
              <span className="hp-adg-badge is-ai">new node</span>
            )}
          </div>
          <div className="hp-tn-cardsub">
            {result.provider.toUpperCase()}
            {result.account ? (
              <>
                {" "}
                · account/tenant <b>{result.account}</b>
              </>
            ) : null}
            {result.expiration ? (
              <>
                {" "}
                · token expires <b>{result.expiration}</b>
              </>
            ) : null}{" "}
            · secret → <b>{result.secret_stored}</b>
            {result.finding_recorded ? " · finding recorded (high)" : ""}
          </div>
          {result.warnings.length > 0 && (
            <ul className="hp-tn-bullets">
              {result.warnings.map((w, i) => (
                <li key={i}>⚠ {w}</li>
              ))}
            </ul>
          )}
          <p className="hp-tn-note">
            Next: <b>{result.next_step.action}</b> — {result.next_step.note}
          </p>
        </div>
      )}

      <div className="hp-tn-actions">
        <span className="hp-tn-actions-label">reach it</span>
        <button
          type="button"
          className="hp-tn-chip"
          onClick={() => setShowCatalog((v) => !v)}
          aria-expanded={showCatalog}
        >
          {showCatalog ? "hide" : "show"} IMDS request cheat-set
        </button>
      </div>
      {showCatalog && (
        <div className="hp-tn-row">
          <div className="hp-tn-cardsub">
            Copy one into the repeater and approve-and-send it — the bridge never fires these. AWS
            IMDSv2 is a two-step (PUT for a token, then GET with the header); GCP needs the
            <code> Metadata-Flavor: Google</code> header; Azure needs <code>Metadata: true</code>.
          </div>
          {catalog.map((c, i) => (
            <div key={i}>
              <div className="hp-tn-note">{c.label}</div>
              <pre className="hp-adg-cmd">{c.cmd}</pre>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
