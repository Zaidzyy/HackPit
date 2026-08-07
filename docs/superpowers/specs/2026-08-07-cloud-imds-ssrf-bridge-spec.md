# Build spec — Metadata-SSRF → creds bridge (`:cloud` seam)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** turn a web-side SSRF/RCE primitive into cloud credentials — hit the instance metadata service (IMDS), extract the temporary role/identity token, and **seed it as an *owned* starting principal in the `:cloud` IAM graph** so the privesc walk begins from the identity you just stole. This is the missing seam between the web/cockpit half and `cloudgraph/`.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** The only bound is the executor's **per-command human approval**, same as everything else. Keep it **maximally open** (Wall A down: the sandbox already reaches internet + LAN + host + **cloud metadata** on purpose — that is what makes this work). The bridge module itself **executes nothing**: the SSRF/RCE request that actually touches `169.254.169.254` runs through the **repeater / nuclei / executor** where a human approves it (or arrives as an **OOB callback body**); the bridge only **parses a captured response** and **seeds the graph**. Nothing here is propose-and-fire. Mirror the cloudgraph/adgraph safety posture: no autonomy, no auto-harvest of host creds without an operator action.

## 1. Read-first

- `backend/cloudgraph/` — the target of the seed. Specifically:
  - `schema.py` — `Node(owned=…, high_value=…)`; a seeded IMDS identity is an **`owned` principal**.
  - `enumerate.py` — the gated enumeration job; after seeding creds we can (optionally, gated) enumerate **as** the stolen identity.
  - `store.py` — where a session's graph lives; the seed merges into it (`add_node`).
  - `router.py` — the `/cloud/*` routes; add the seed route here or wire cross-cutting glue in `main.py`.
- `backend/cockpit/repeater.py` — how a captured HTTP exchange (request+response) is represented; the operator can point the bridge at a repeater exchange that already fetched IMDS.
- `backend/oob/` — blind SSRF often returns **out-of-band**; an IMDS token can land in an OOB canary/interact.sh callback body. The bridge must accept a pasted/blob body from any of these sources.
- `backend/state/store.py` (`upsert_findings`) — record "cloud credentials captured via SSRF/IMDS" as a `Finding`.
- Memory: **cockpit/arsenal decoupling** — cockpit must not import cloudgraph and vice-versa; the bridge is **cross-cutting**, so its endpoint + wiring live in `main.py` (call a small pure `cloudgraph.imds` parser from there). Memory: **cloud KB grounding degrades commands** — IMDS requests are fixed URLs; keep them **catalog-first**, cite the KB only when it matches.

## 2. What to build

### 2a. IMDS parser + cred extractor — `backend/cloudgraph/imds.py` (pure, executes nothing)
A stateless module that takes a **captured response body** (string/JSON the operator pasted, or pulled from a repeater exchange / OOB callback) plus the provider hint, and returns extracted credentials + a seed `Node`. Cover all three clouds:

- **AWS (IMDSv1)** — `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → JSON with `AccessKeyId` / `SecretAccessKey` / `Token` / `Expiration`. Also parse `.../iam/security-credentials/` (the role-name listing) and `.../dynamic/instance-identity/document` (account id, region).
- **AWS (IMDSv2)** — two-step: `PUT http://169.254.169.254/latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds: 21600` → token; then the GET above with `X-aws-ec2-metadata-token: <token>`. The parser should recognize both the token PUT response and the creds GET. (SSRF that can't send a PUT/custom header only reaches IMDSv1 — say so in the finding.)
- **Azure** — `GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` with header `Metadata: true` → JSON with `access_token` (a JWT). Decode the JWT payload (no verify) to pull `oid` / `appid` / tenant for the node id/label.
- **GCP** — `GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` with header `Metadata-Flavor: Google` → `access_token`. Also `.../default/email` for the SA identity, and `.../default/identity?audience=…` for an ID token. **Note the `X-Forwarded-For`-free / header requirement** in the finding (GCP requires the `Metadata-Flavor` header, which blind SSRF may not set).

Return a normalized `{provider, account, identity, creds:{...}, expiration, imds_version}` and a `Node(type=role|serviceaccount, owned=True, provider=…, props={via:"ssrf-imds", token_expiry:…})`.

### 2b. Seed route — `POST /cloud/seed-imds` (wired in `main.py`, cross-cutting)
Body: `{session_id, provider, response_body, source:"repeater|oob|paste", role_hint?}`. It:
1. calls `cloudgraph.imds.parse(...)`,
2. `add_node` the **owned** identity into that session's graph (create the graph if none yet),
3. `upsert_findings` a "cloud creds captured via SSRF→IMDS" Finding (severity high; include provider + identity + expiry, **never** the secret material in the finding text — store the secret only in the engagement vault/loot, mirror how `:credentials` handles secrets → loot files),
4. return the seeded node id + a **suggested next step**: "enumerate as this identity" → the existing gated `POST /cloud/enumerate`, now runnable with the stolen creds. Do **not** auto-run it.

### 2c. The "how to reach IMDS" helper (catalog, not execution)
Add an **IMDS request catalog** the operator can copy into the repeater (a curl/gopher/redirect cheat-set per provider + IMDSv2 two-step), surfaced in the UI next to the seed box. These are **templates to approve-and-send via the repeater/executor**, never fired by the bridge. Ground against the `hacktricks-cloud` KB where a real entry matches; otherwise use the catalog (KB-grounding-degrades trap).

### 2d. Frontend — extend `/cockpit/cloud`
A small **"Seed from SSRF/IMDS"** panel above the graph: provider tabs (AWS/Azure/GCP), a paste box for the captured body (or a picker for a repeater exchange / OOB callback), a "Seed identity" button → calls `/cloud/seed-imds`, then the new **owned** node appears in the graph and the orchestrator can route from it. `hp-tn-*` classes only; **look at the screen**.

## 3. Tests
- `backend/test_cloud_imds.py` — parse fixtures for **all three** providers (AWS v1 + v2, Azure JWT, GCP), including malformed/partial bodies (blind-SSRF truncation) → graceful `warnings`, no crash. Assert the seeded node is `owned=True`, provider set, secret **not** present in the returned finding text.
- Extend `backend/test_cloudgraph_safety.py` — assert `cloudgraph/imds.py` **executes nothing** (AST scan: no `subprocess`/`os.system`/`requests`/`urllib` network calls — it only parses strings). Add to `run_safety_tests.sh`.
- **Trap:** `test_state.py` bans `urllib` in `state/parsers.py`; if you touch a parser there, hand-parse. The imds module lives in `cloudgraph/`, but keep it network-free regardless.

## 4. Acceptance criteria
- Operator captures an IMDS response (via repeater/nuclei SSRF or an OOB callback), pastes it (or points at the exchange), clicks **Seed identity** → an **owned** cloud principal appears in the `:cloud` graph, tagged `via ssrf-imds`, with a Finding recorded and the secret in loot (not in the finding text).
- The `:cloud` orchestrator can immediately propose an edge **from** that seeded identity toward a high-value principal (the whole point: SSRF → foothold identity → IAM privesc walk).
- Bridge executes nothing; the actual IMDS fetch went through the human-approved repeater/executor.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Build **all three providers'** parsers; if one session can't finish GCP/Azure, ship AWS (v1+v2) end-to-end and stub the other two — say so in the PR.
- The bridge is **parse+seed only** by design. If you later want a one-click "fetch IMDS through this repeater request" it must still be an **approve-each** executor call, never a bridge-internal fetch.
- Secrets → loot/vault, never the finding body — mirror `:credentials`.

---

## 6. README + screenshot + assessment (do this exactly like prior sessions)

**Not done until the README + a real screenshot ship with it.** Screen route: **`/cockpit/cloud`** (the new seed panel).

- **Capture a real lab-state screenshot** with headless Edge (`headless-edge-screenshots` method), app running, using a **synthetic** IMDS body fixture (fake account id / ARN / token — never a real account, ARN, tenant, or live token):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/cockpit/cloud"
  ```
  **View it** to confirm the seed panel + a seeded owned node rendered (not blank/error).
- **Add the screenshot** to `assets/screenshots/` with the next free number; commit it.
- **Add a concise README feature section** (existing voice) + a row in the "What you get, at a glance" table: web SSRF → cloud creds → privesc walk.
- **Update `docs/ASSESSMENT-2026-07-26.md`** + regenerate html/pdf (`python docs/build-assessment.py`) in the **same commit** (`keep-assessment-current`). You cannot grep the PDF — verify against the html.
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card` (renders invisible).
