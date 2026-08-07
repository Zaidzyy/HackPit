"use client";

import { useCallback, useEffect, useState } from "react";
import { CopyButton } from "./CopyButton";
import {
  ApiError,
  buildOAuthAttack,
  buildSAMLAttack,
  decodeToken,
  parseOAuth,
  parseSAML,
  tamperJWT,
  type DecodedToken,
  type OAuthBuild,
  type OAuthRequest,
  type SAMLAnalysis,
  type SAMLBuild,
  type TamperResult,
  type TokenVerdict,
} from "@/lib/api";
import { TokenCrackPanel } from "./TokenCrackPanel";

/**
 * TOKEN WORKBENCH — JWT / OAuth / OIDC / SAML, the web-core surface.
 *
 * *** THE ANALYSIS/TAMPER CORE IS PURE AND NEVER SENDS. *** A tamper returns a NEW token STRING;
 * you copy it into the repeater and send it there (approve-each, scope-checked on the wire). This
 * panel is modelled on GraphQLPanel — recognise by shape, hand values back only where the operator
 * typed them, and send through the one human-approved path.
 *
 * The pasted token is the operator's OWN value (the box they typed, exactly like the repeater
 * body), so decode shows it in full. A token HackPit spots in captured traffic is name/claim-only.
 */

/** A SYNTHETIC, self-signed demo JWT — never a real user's token. Loaded by `/tokens?demo=1`
 *  so a first-run screen (and the README screenshot) shows a decoded token, not an empty box. */
const DEMO_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhhY2twaXQtZGVtby1rZXkifQ" +
  ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8gVXNlciIsInJvbGUiOiJ1c2VyIiwiaXNzIjoiaGFja3BpdC1k" +
  "ZW1vIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5OTk5OTk5OTl9" +
  ".KcVCN2a0YRpJ-gMZfOoU0KfECQ5fzF3JtZygSZFPdoI";

const SEV_CLASS: Record<string, string> = {
  high: "is-bad",
  medium: "is-disabled",
  low: "is-disabled",
  info: "is-ok",
};

function Verdicts({ verdicts }: { verdicts: TokenVerdict[] }) {
  if (!verdicts.length) return null;
  return (
    <div className="hp-gql-fields">
      {verdicts.map((v) => (
        <div key={v.id} className="hp-gql-field">
          <span className={`hp-gql-status ${SEV_CLASS[v.severity] ?? ""}`}>{v.severity}</span>
          <span className="hp-gql-fieldname">{v.id}</span>
          <span className="hp-tn-note">{v.detail}</span>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ JWT --- */
function JWTWorkbench({
  engagementId,
  sessionId,
}: {
  engagementId?: string | null;
  sessionId?: string | null;
}) {
  // A lazy initializer (runs during the hydration render, not only in an effect) so `/tokens?demo=1`
  // shows the synthetic token immediately — the effect below then decodes it.
  const [token, setToken] = useState(() =>
    typeof window !== "undefined" &&
    new URLSearchParams(window.location.search).has("demo")
      ? DEMO_TOKEN
      : ""
  );
  const [decoded, setDecoded] = useState<DecodedToken | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<TamperResult | null>(null);

  // tamper inputs
  const [variant, setVariant] = useState("none");
  const [pem, setPem] = useState("");
  const [kidPayload, setKidPayload] = useState("../../dev/null");
  const [headerField, setHeaderField] = useState("jku");
  const [headerValue, setHeaderValue] = useState("");
  const [secret, setSecret] = useState("");
  const [claimsEdit, setClaimsEdit] = useState("");

  const runDecode = useCallback(async () => {
    if (!token.trim()) return;
    setError(null);
    setResult(null);
    try {
      const d = await decodeToken(token.trim());
      setDecoded(d);
      setClaimsEdit(JSON.stringify(d.claims, null, 2));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setDecoded(null);
    }
  }, [token]);

  // `/tokens?demo=1` loads the synthetic token and decodes it, so a first-run screen shows the
  // workbench populated. The setState runs inside an async callback (not the effect body) to
  // stay off the accepted set-state-in-effect lint baseline.
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (!new URLSearchParams(window.location.search).has("demo")) return;
    void (async () => {
      setToken(DEMO_TOKEN);
      try {
        const d = await decodeToken(DEMO_TOKEN);
        setDecoded(d);
        setClaimsEdit(JSON.stringify(d.claims, null, 2));
      } catch {
        /* the operator can still paste one by hand */
      }
    })();
  }, []);

  const tamper = useCallback(
    async (kind: string, extra: Record<string, string> = {}) => {
      if (!token.trim()) return;
      setError(null);
      try {
        setResult(await tamperJWT({ token: token.trim(), kind, ...extra }));
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
        setResult(null);
      }
    },
    [token]
  );

  return (
    <div className="hp-tk">
      <div className="hp-tn-cardsub">
        Paste a JWT. It is <strong>your</strong> token in a box you typed — decoded in full — while
        a token HackPit spots in captured traffic is name/claim-only. Decode does not verify: it
        surfaces <code>alg</code>, <code>kid</code>, <code>jku</code>/<code>x5u</code>/
        <code>jwk</code>, the timing claims and every claim so you can pick a tamper.
      </div>
      <div className="hp-tn-form">
        <textarea
          className="hp-rp-body"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.…"
          rows={3}
        />
      </div>
      <div className="hp-tn-form">
        <button type="button" className="hp-tn-start" onClick={runDecode} disabled={!token.trim()}>
          decode &amp; analyze
        </button>
      </div>
      {error ? <p className="hp-tn-error">{error}</p> : null}

      {decoded ? (
        <>
          {decoded.note ? <p className="hp-tn-note-warn">{decoded.note}</p> : null}
          <div className="hp-tn-cardsub">header</div>
          <div className="hp-gql-args">
            {Object.entries(decoded.header).map(([k, v]) => (
              <span key={k} className="hp-gql-arg">
                {k}: {typeof v === "object" ? JSON.stringify(v) : String(v)}
              </span>
            ))}
          </div>
          <div className="hp-tn-cardsub">claims</div>
          <div className="hp-gql-fields">
            {Object.entries(decoded.claims).map(([k, v]) => (
              <div key={k} className="hp-gql-field">
                <span className="hp-gql-fieldname">{k}</span>
                <span className="hp-gql-fieldtype">
                  {typeof v === "object" ? JSON.stringify(v) : String(v)}
                </span>
              </div>
            ))}
          </div>
          <p className="hp-tn-note">
            signature: <code>{decoded.signature ? decoded.signature.slice(0, 24) + "…" : "(none)"}</code>
          </p>
          <Verdicts verdicts={decoded.verdicts} />

          {/* ---- tamper primitives ------------------------------------------------ */}
          <div className="hp-tn-cardsub">tamper — each produces a token you send via the repeater</div>

          <div className="hp-tn-form">
            <select value={variant} onChange={(e) => setVariant(e.target.value)}>
              <option value="none">none</option>
              <option value="None">None</option>
              <option value="nOnE">nOnE</option>
              <option value="NONE">NONE</option>
            </select>
            <button type="button" onClick={() => tamper("alg-none", { variant })}>
              alg = none (strip signature)
            </button>
          </div>

          <div className="hp-tn-form">
            <textarea
              className="hp-rp-body"
              value={pem}
              onChange={(e) => setPem(e.target.value)}
              placeholder="-----BEGIN PUBLIC KEY----- … (server's public key → the HMAC secret)"
              rows={2}
            />
            <button type="button" onClick={() => tamper("alg-confusion", { public_key_pem: pem })}>
              RS256 → HS256 confusion
            </button>
          </div>

          <div className="hp-tn-form">
            <input
              value={kidPayload}
              onChange={(e) => setKidPayload(e.target.value)}
              placeholder="kid payload — ../../dev/null, ' OR '1'='1, |id"
            />
            <input
              className="hp-tn-port"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder="sign key (blank = empty)"
            />
            <button type="button" onClick={() => tamper("kid", { kid_payload: kidPayload, secret })}>
              kid injection
            </button>
          </div>

          <div className="hp-tn-form">
            <select value={headerField} onChange={(e) => setHeaderField(e.target.value)}>
              <option value="jku">jku</option>
              <option value="jwk">jwk</option>
              <option value="x5u">x5u</option>
            </select>
            <input
              value={headerValue}
              onChange={(e) => setHeaderValue(e.target.value)}
              placeholder="attacker URL (jku/x5u) or JSON key (jwk)"
            />
            <button
              type="button"
              onClick={() => tamper("header", { header_field: headerField, header_value: headerValue, secret })}
            >
              {headerField} header injection
            </button>
          </div>

          <div className="hp-tn-form">
            <textarea
              className="hp-rp-body"
              value={claimsEdit}
              onChange={(e) => setClaimsEdit(e.target.value)}
              rows={4}
            />
          </div>
          <div className="hp-tn-form">
            <input
              className="hp-tn-port"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder="HMAC secret"
            />
            <button
              type="button"
              onClick={() => tamper("edit", { claims_json: claimsEdit, secret })}
            >
              edit claims &amp; re-sign
            </button>
          </div>
        </>
      ) : null}

      {result ? (
        <div className="hp-tk-out">
          <div className="hp-tn-form">
            <span className={`hp-gql-status ${result.ok ? "is-ok" : "is-bad"}`}>{result.kind}</span>
            {result.ok ? <CopyButton text={result.token} /> : null}
          </div>
          <p className="hp-tn-note">{result.note}</p>
          {result.ok ? (
            <>
              <pre className="hp-tn-pre">{result.token}</pre>
              <p className="hp-tn-note">
                Copy this and send it in the <strong>repeater</strong> (approve-each, scope-checked).
                Nothing here sends — the mutated token is handed back to you.
              </p>
            </>
          ) : null}
        </div>
      ) : null}

      <TokenCrackPanel token={token} engagementId={engagementId} sessionId={sessionId} />
    </div>
  );
}

/* ---------------------------------------------------------------- OAuth --- */
function OAuthWorkbench() {
  const [url, setUrl] = useState("");
  const [parsed, setParsed] = useState<OAuthRequest | null>(null);
  const [built, setBuilt] = useState<OAuthBuild | null>(null);
  const [evil, setEvil] = useState("evil.example");
  const [error, setError] = useState<string | null>(null);

  const runParse = useCallback(async () => {
    if (!url.trim()) return;
    setError(null);
    setBuilt(null);
    try {
      setParsed(await parseOAuth(url.trim()));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setParsed(null);
    }
  }, [url]);

  const build = useCallback(
    async (attack: string, response_mode = "form_post") => {
      if (!url.trim()) return;
      setError(null);
      try {
        setBuilt(await buildOAuthAttack({ url: url.trim(), attack, evil_host: evil, response_mode }));
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
        setBuilt(null);
      }
    },
    [url, evil]
  );

  return (
    <div className="hp-tk">
      <div className="hp-tn-cardsub">
        Paste an authorization request URL (or a callback). Each attack builder emits a mutated URL
        for the repeater: <code>redirect_uri</code> bypasses (reusing the open-redirect table),
        <code> state</code> removal, PKCE downgrade, forced <code>response_mode</code>, implicit
        leak.
      </div>
      <div className="hp-tn-form">
        <textarea
          className="hp-rp-body"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://idp/authorize?client_id=…&redirect_uri=…&response_type=code&state=…"
          rows={3}
        />
      </div>
      <div className="hp-tn-form">
        <button type="button" className="hp-tn-start" onClick={runParse} disabled={!url.trim()}>
          parse flow
        </button>
      </div>
      {error ? <p className="hp-tn-error">{error}</p> : null}

      {parsed ? (
        <>
          {parsed.note ? <p className="hp-tn-note-warn">{parsed.note}</p> : null}
          <div className="hp-gql-fields">
            {(
              [
                ["client_id", parsed.client_id],
                ["redirect_uri", parsed.redirect_uri],
                ["response_type", parsed.response_type],
                ["response_mode", parsed.response_mode],
                ["scope", parsed.scope],
                ["state", parsed.state],
                ["nonce", parsed.nonce],
                ["PKCE", parsed.has_pkce ? `${parsed.code_challenge_method || "?"} challenge` : "none"],
              ] as [string, string][]
            )
              .filter(([, v]) => v)
              .map(([k, v]) => (
                <div key={k} className="hp-gql-field">
                  <span className="hp-gql-fieldname">{k}</span>
                  <span className="hp-gql-fieldtype">{v}</span>
                </div>
              ))}
          </div>
          {parsed.is_callback ? (
            <p className="hp-tn-note-warn">
              This is a callback — it carries {parsed.callback_params.join(", ")} (by name; the
              value is a live credential and is not shown).
            </p>
          ) : null}
          <Verdicts verdicts={parsed.verdicts} />

          <div className="hp-tn-cardsub">attack builders</div>
          <div className="hp-tn-form">
            <input
              className="hp-tn-port"
              value={evil}
              onChange={(e) => setEvil(e.target.value)}
              placeholder="attacker host"
            />
            <button type="button" onClick={() => build("redirect_uri")}>
              redirect_uri bypasses
            </button>
            <button type="button" onClick={() => build("drop_state")}>
              drop state (CSRF)
            </button>
            <button type="button" onClick={() => build("pkce_downgrade")}>
              PKCE downgrade
            </button>
            <button type="button" onClick={() => build("implicit_leak")}>
              implicit leak
            </button>
            <button type="button" onClick={() => build("response_mode", "form_post")}>
              response_mode=form_post
            </button>
          </div>
        </>
      ) : null}

      {built ? (
        <div className="hp-tk-out">
          <div className="hp-tn-form">
            <span className={`hp-gql-status ${built.ok ? "is-ok" : "is-bad"}`}>{built.attack}</span>
            {built.ok ? <CopyButton text={built.url} /> : null}
          </div>
          <p className="hp-tn-note">{built.note}</p>
          {built.ok ? <pre className="hp-tn-pre">{built.url}</pre> : null}
        </div>
      ) : null}
    </div>
  );
}

/* ----------------------------------------------------------------- SAML --- */
function SAMLWorkbench() {
  const [blob, setBlob] = useState("");
  const [parsed, setParsed] = useState<SAMLAnalysis | null>(null);
  const [built, setBuilt] = useState<SAMLBuild | null>(null);
  const [nameId, setNameId] = useState("admin@target");
  const [error, setError] = useState<string | null>(null);

  const runParse = useCallback(async () => {
    if (!blob.trim()) return;
    setError(null);
    setBuilt(null);
    try {
      setParsed(await parseSAML(blob.trim()));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setParsed(null);
    }
  }, [blob]);

  const build = useCallback(
    async (attack: string) => {
      if (!blob.trim()) return;
      setError(null);
      try {
        setBuilt(await buildSAMLAttack({ blob: blob.trim(), attack, new_name_id: nameId }));
      } catch (e) {
        setError(e instanceof ApiError ? e.message : String(e));
        setBuilt(null);
      }
    },
    [blob, nameId]
  );

  const XSW = ["xsw1", "xsw2", "xsw3", "xsw4", "xsw5", "xsw6", "xsw7", "xsw8"];

  return (
    <div className="hp-tk">
      <div className="hp-tn-cardsub">
        Paste a SAML Response (base64, or base64+deflate for the redirect binding, or raw XML). The
        builders emit a mutated <code>SAMLResponse</code> for the repeater: XML Signature Wrapping
        (XSW1–8), signature stripping, comment-injection, an unsigned assertion.
      </div>
      <div className="hp-tn-form">
        <textarea
          className="hp-rp-body"
          value={blob}
          onChange={(e) => setBlob(e.target.value)}
          placeholder="PHNhbWxwOlJlc3BvbnNl…  (base64 SAMLResponse) or <samlp:Response …>"
          rows={3}
        />
      </div>
      <div className="hp-tn-form">
        <button type="button" className="hp-tn-start" onClick={runParse} disabled={!blob.trim()}>
          parse assertion
        </button>
      </div>
      {error ? <p className="hp-tn-error">{error}</p> : null}

      {parsed ? (
        <>
          {parsed.note ? <p className="hp-tn-note-warn">{parsed.note}</p> : null}
          <div className="hp-gql-fields">
            {(
              [
                ["issuer", parsed.issuer],
                ["NameID", parsed.subject_name_id],
                ["destination", parsed.destination],
                ["audience", parsed.audience],
                ["NotOnOrAfter", parsed.not_on_or_after],
                ["assertions", String(parsed.assertion_count)],
              ] as [string, string][]
            )
              .filter(([, v]) => v)
              .map(([k, v]) => (
                <div key={k} className="hp-gql-field">
                  <span className="hp-gql-fieldname">{k}</span>
                  <span className="hp-gql-fieldtype">{v}</span>
                </div>
              ))}
          </div>
          <div className="hp-tn-form">
            <span className={`hp-gql-status ${parsed.response_signed ? "is-ok" : "is-disabled"}`}>
              response {parsed.response_signed ? "signed" : "unsigned"}
            </span>
            <span className={`hp-gql-status ${parsed.assertion_signed ? "is-ok" : "is-disabled"}`}>
              assertion {parsed.assertion_signed ? "signed" : "unsigned"}
            </span>
            {parsed.was_deflated ? <span className="hp-gql-status is-disabled">deflated</span> : null}
          </div>
          <Verdicts verdicts={parsed.verdicts} />

          <div className="hp-tn-cardsub">attack builders</div>
          <div className="hp-tn-form">
            <input
              value={nameId}
              onChange={(e) => setNameId(e.target.value)}
              placeholder="forged NameID"
            />
            <button type="button" onClick={() => build("strip")}>
              strip signature
            </button>
            <button type="button" onClick={() => build("unsigned")}>
              unsigned assertion
            </button>
            <button type="button" onClick={() => build("comment")}>
              comment injection
            </button>
          </div>
          <div className="hp-tn-form">
            {XSW.map((x) => (
              <button key={x} type="button" onClick={() => build(x)}>
                {x}
              </button>
            ))}
          </div>
        </>
      ) : null}

      {built ? (
        <div className="hp-tk-out">
          <div className="hp-tn-form">
            <span className={`hp-gql-status ${built.ok ? "is-ok" : "is-bad"}`}>{built.attack}</span>
            {built.ok ? <CopyButton text={built.saml} /> : null}
          </div>
          <p className="hp-tn-note">{built.note}</p>
          {built.ok ? <pre className="hp-tn-pre">{built.saml}</pre> : null}
        </div>
      ) : null}
    </div>
  );
}

/* --------------------------------------------------------------- shell --- */
export function TokenPanel({
  engagementId,
  sessionId,
}: {
  engagementId?: string | null;
  sessionId?: string | null;
}) {
  const [tab, setTab] = useState<"jwt" | "oauth" | "saml">("jwt");
  return (
    <section className="hp-tn-card">
      <div className="hp-tn-cardhead">Token workbench — JWT · OAuth/OIDC · SAML</div>
      <div className="hp-tn-cardsub">
        Decode, analyze and tamper a token, then hand the mutated one to the repeater to send.{" "}
        <strong>The core is pure and sends nothing</strong> — a real tampered token goes to a real
        endpoint, but only through the human-approved, scope-checked repeater. The weak-secret crack
        is one gated job.
      </div>
      <div className="hp-tk-tabs">
        {(["jwt", "oauth", "saml"] as const).map((t) => (
          <button
            key={t}
            type="button"
            className={`hp-tk-tab${tab === t ? " is-active" : ""}`}
            onClick={() => setTab(t)}
          >
            {t.toUpperCase()}
          </button>
        ))}
      </div>
      {tab === "jwt" ? (
        <JWTWorkbench engagementId={engagementId} sessionId={sessionId} />
      ) : tab === "oauth" ? (
        <OAuthWorkbench />
      ) : (
        <SAMLWorkbench />
      )}
    </section>
  );
}
