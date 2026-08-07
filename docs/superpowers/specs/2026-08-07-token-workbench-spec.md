# Build spec — Token workbench: JWT / OAuth / OIDC / SAML (web core)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** make token attacks a **first-class surface** the way GraphQL is — decode / analyze / tamper a JWT, OAuth/OIDC flow, or SAML assertion, flag the classic misconfigs, and hand the mutated token to the repeater to send. Today this is only `jwt_tool` in the arsenal + KB + skills; there is no workflow.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. Keep it **maximally open / offensive**: real tampered tokens go to real endpoints — but they go through the **repeater / executor** (approve-each, scope-checked on the wire), never fired by this module. The **analysis/tamper core is PURE** (no I/O, spawns nothing, reaches no daemon) — mirror `cockpit/graphql.py` exactly, so the hermetic suite covers every claim against fixtures. Secret-cracking (weak HMAC key) is **one gated job** (like the intruder), not an autonomous loop.

## 1. Read-first (this is the GraphQL core, applied to tokens)

- `backend/cockpit/graphql.py` — **the template.** A PURE module: detection *by shape not path*, parsing into named structures, and the operator round-trip via the repeater. Read its three tenets and apply them: **recognised by structure, not path**; **the operator's repeater body is where values live** (the workbench *does* let the operator edit their own token value — that's the one place values belong, exactly like the repeater body — but auto-detected tokens in proxy history are modeled **names/claims, not secret values** where they travel to run records/screen).
- `backend/cockpit/graphql_enum.py` / `graphql_zap.py` — the scan/enrich side (optional analogue for an OAuth-endpoint discovery helper).
- `frontend/src/components/GraphQLPanel.tsx` mounted in `ProxyScreen.tsx` — clone this mounting pattern for a `TokenPanel` (in the proxy/repeater surface) **and/or** a dedicated `/tokens` page.
- `backend/cockpit/repeater.py` — the send path (approve-each, hardcoded container). The workbench builds a request; the repeater sends it.
- `backend/cockpit/router.py` — where cockpit routes register; add `/tokens/*` here.
- `backend/arsenal/tools.json` — `jwt_tool` is present; add nothing heavy (hashcat/john already present for the crack).
- Memory: **attack-step schema lives in 3 files**; **cockpit/arsenal decoupling**; GraphQL tests `test_graphql.py` + `test_graphql_safety.py` are the test template.

## 2. What to build — `backend/cockpit/tokens.py` (PURE) + a scan/crack side

### 2a. JWT
- **Decode/analyze** (no verify): split header/payload/signature, surface `alg`, `kid`, `jku`, `jwk`, `x5u`, `typ`, expiry/nbf, and every claim by **name** (auto-detected tokens: names + non-secret claim values; the operator's pasted token: full value, editable).
- **Tamper primitives** (produce a new token string the operator sends via repeater):
  - `alg=none` / `None` / `nOnE` (strip signature).
  - **alg confusion** RS256→HS256: sign with the server's *public* key as the HMAC secret (operator pastes the PEM).
  - **`kid` injection**: path traversal (`../../dev/null`), SQLi, command — for key-file lookups.
  - **`jwk` / `jku` / `x5u` header injection**: embed/point at an attacker key (pairs with the OOB/canary surface for `jku` fetch).
  - **weak-secret crack** — **ONE gated job**: `jwt_tool`/`hashcat -m 16500` against a wordlist; recovered secret → loot (mirror `:credentials` secrets→loot), then re-sign.
- **Verdicts**: flag accept-none, missing-exp, weak-secret-crackable, kid/jku injectable.

### 2b. OAuth / OIDC
- **Parse an authorization request / callback**: `client_id`, `redirect_uri`, `response_type`, `response_mode`, `scope`, `state`, `nonce`, `code_challenge`/`method` (PKCE).
- **Attack builders** (each produces the mutated URL/request for the repeater): `redirect_uri` manipulation (subdomain, path append, `@`-confusion, open-redirect chain — reuse the open-redirect bypass table), missing/echoed `state` (CSRF), **PKCE downgrade** (drop `code_challenge`), implicit-flow token-in-fragment leak, `response_mode=form_post`/`web_message` tricks, `id_token` alg/aud confusion (reuse the JWT core).
- **Discovery helper**: fetch `/.well-known/openid-configuration` + JWKS **via the repeater** (approve-each), parse endpoints/keys.

### 2c. SAML
- **Parse** a SAML Response/Assertion (base64+inflate), surface issuer, conditions, signature location, whether the assertion vs response is signed.
- **Attack builders**: **XML Signature Wrapping (XSW1–8)** templates, signature stripping, comment-injection (`admin<!---->@`), unsigned-assertion acceptance, `xmlns` confusion. Each emits the mutated SAMLResponse for the repeater.

### 2d. Frontend — `TokenPanel` + `/tokens`
Clone `GraphQLPanel`'s mounting into the proxy/repeater surface, plus a dedicated `/tokens` page: paste a token/flow → decoded view → pick a tamper → "send to repeater". `hp-tn-*` classes; **look at the screen**.

## 3. Tests
- `backend/test_tokens.py` — JWT decode + each tamper against fixtures (alg-none produces a valid unsigned token; RS→HS confusion signs with a fixture pubkey; kid/jku injection lands in the header); OAuth request parse + redirect_uri/PKCE builders; SAML XSW templates produce well-formed XML. Assert **auto-detected** tokens carry names/claims, **not** secret values, in serialized models.
- `backend/test_tokens_safety.py` — mirror `test_graphql_safety.py`: `tokens.py` is **PURE** (AST: no `subprocess`/`socket`/`urllib`/`requests`); the crack path is a **gated job** using the same four gates, no new gate; stop ungated. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Operator pastes a JWT → sees decoded claims → picks `alg=none` / RS→HS / kid-injection → gets a mutated token → sends via repeater (approve-each). OAuth + SAML builders likewise emit mutated requests to the repeater.
- Weak-secret crack runs as one gated job; recovered secret → loot, re-sign available.
- Analysis core executes nothing; sends go through the human-approved repeater; findings land in engagement state.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Ship **JWT end-to-end first**, then OAuth, then SAML, if one session can't do all three — say so in the PR (JWT is the highest-value).
- The workbench edits the operator's pasted token value (like the repeater body); only auto-detected tokens are name/claim-only.
- No new heavy tool — `jwt_tool` + hashcat/john are present.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/tokens`** (and the proxy panel).
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic** token only (a self-signed demo JWT — never a real user's token):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/tokens"
  ```
  **View it** — decoded token + tamper controls render (not blank/error).
- Add screenshot to `assets/screenshots/` (next free number); README feature section + "at a glance" row (token workbench).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf (`python docs/build-assessment.py`) same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
