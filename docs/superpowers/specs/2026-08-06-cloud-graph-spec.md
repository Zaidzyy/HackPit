# Build spec — Cloud attack surface & IAM privesc graph (`:cloud`)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-06.
**One line:** the cloud parallel to the AD graph — creds → enumerate → a typed **IAM privilege-escalation graph** routed to a high-value principal, walked the same edge-index way the BloodHound orchestrator already works.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Enumeration and every exploit step run through the executor's **per-command human approval** and nothing else. The graph **proposes an edge to abuse (an index), never a raw command** — copy the AD orchestrator's safety design exactly (`adgraph/orchestrator.py`: the model picks an edge index; a pick outside the list is refused, not repaired; it never authors a command). No autonomy. Keep it maximally open otherwise (real cloud creds reach real cloud APIs — that is the point).

## 1. Read-first (this is a near-clone of `adgraph/`)

Study the entire `backend/adgraph/` package — it IS the template:
- `schema.py` — `Graph`, `Node`, `Edge` (copy the shapes).
- `parser.py` — BloodHound → graph (you will write the cloud-enum → graph equivalent).
- `paths.py` — BFS over abusable edges, shortest path, k-alternatives (reuse the algorithm).
- `orchestrator.py` — `AdState`, `advance`, `frontier`, `propose_next`, `proposal_for_edge`, edge-index model (copy wholesale).
- `techniques.py` — per-edge abuse commands, KB-grounded with catalog fallback (you write the cloud technique catalog).
- `store.py`, `router.py`, `sample_data.py`, `collector.py`.
- Frontend: `frontend/src/components/CockpitADGraph.tsx` + `CockpitADOrchestrator.tsx` + `frontend/src/app/cockpit/ad/page.tsx` — clone these for `/cockpit/cloud`.
- `backend/state/models.py` + `store.py` (`upsert_findings`) — privesc findings go here.
- KB: 534 cloud entries exist (`hacktricks-cloud`); the technique catalog should be KB-grounded via the same mechanism `adgraph/techniques.py` uses.

## 2. What to build — `backend/cloudgraph/` (new package, mirrors `adgraph/`)

### Enumeration → graph
- **Credential ingest**: read cloud creds from env/`~/.aws`/`~/.azure`/`~/.config/gcloud` or operator-pasted keys (operator input, not auto-harvested from the host without a click).
- **Enumerate** with tools already catalogued: `scoutsuite`, `prowler` (present in `tools.json`); run them as gated jobs (`cockpit/jobs.py`) and parse their JSON output into a typed IAM graph. **`pacu` and `cloudfox` are NOT catalogued or in the image — add them in THIS build, up front:** add both to `arsenal/tools.json` **and** `docker/Dockerfile.sandbox` and **rebuild the sandbox image** (respect the `kali-sandbox-image-traps` memory: verify the actual installed binary name, watch setcap / no-new-privileges, add a `docker/proof/` install check that the launcher accepts the invocations the catalog templates hardcode — the `zap_install_proof` lesson). The image rebuild is part of the definition of done, not a follow-up.
- **Graph model** (`cloudgraph/schema.py`): nodes = principals (users, roles, service accounts, groups), resources (buckets, functions, secrets, KMS keys); edges = abusable IAM relationships — `iam:PassRole`, `sts:AssumeRole`, `lambda:UpdateFunctionCode`, `iam:CreatePolicyVersion`, Azure `Owner-on-self`/AAD app cred add, GCP `serviceAccountTokenCreator`/`actAs`. Each edge carries an abuse command (KB-grounded) exactly like `adgraph/techniques.py`.

### Routing + orchestrator (`cloudgraph/orchestrator.py`)
Copy the AD orchestrator: BFS to a goal principal (default: an Admin/Owner-equivalent), `frontier`, `propose_next` returns an **edge index**, `advance` requires an approved, exit-0 run (`run_id` verified server-side — copy the `advance` endpoint's evidence check). Multi-cloud: keep provider on the node so one engine serves AWS/Azure/GCP.

### Routes (`backend/cloudgraph/router.py`, included from `main.py`)
`POST /cloud/enumerate` (gated job), `GET /cloud/graph`, `POST /cloud/propose`, `POST /cloud/advance` — 1:1 with the AD routes. Respect **cockpit/arsenal decoupling**: cross-cutting wiring in `main.py`.

### Frontend — `/cockpit/cloud` (clone `/cockpit/ad`)
Graph view + orchestrator panel (propose edge → approve command → advance). Provider tabs (AWS/Azure/GCP). `hp-tn-*` classes; **look at the screen** before done.

## 3. Tests
- `backend/test_cloudgraph.py` — parser (scoutsuite/prowler JSON → graph), BFS routing, orchestrator edge-index proposal, `advance` requires approved+exit0.
- `backend/test_cloudgraph_safety.py` — mirror `test_adorch_safety.py`: **the orchestrator picks an index, never authors a command**; a pick outside the frontier is refused; the module executes nothing (AST). Add both to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Given cloud creds, `:cloud` enumerates (as an approved job) and renders a typed IAM graph; the orchestrator proposes an edge index to a high-value principal; approving the command runs it via the executor; `advance` moves the walk only on an approved exit-0 run.
- Privesc steps and misconfigs land as `Finding`s in engagement state.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Providers: build **AWS + Azure + GCP** node/edge model, but it's fine to ship AWS end-to-end first and stub the other two providers' enumerators if one session can't do all three — say so in the PR.
- `pacu`/`cloudfox` **are added to the arsenal + image up front** (the sandbox image rebuild is included in this build, not deferred). Sequence the *graph/orchestrator* work AWS-first (enumeration + privesc edges on scoutsuite/prowler/pacu/cloudfox), then extend the same engine to Azure + GCP — but the tooling additions land in this build regardless.
- Goal principal defaults to Admin/Owner-equivalent; operator can pick a different target node.

---

## 6. README + screenshot — do this exactly like the 2026-08-06 README session

**Not done until the README and a real screenshot ship with it.** New screen route: **`/cockpit/cloud`**.

- **Capture a real lab-state screenshot** with headless Edge (the `headless-edge-screenshots` method). With the app running:
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/cockpit/cloud"
  ```
  **View it** to confirm it rendered (use synthetic/sample cloud data — mirror `adgraph/sample_data.py` so the graph renders without live cloud creds), not a blank/error page.
- **Never a real target/account in a public screenshot.** Synthetic IAM data only — no real account ids, ARNs, or tenant names.
- **Add the screenshot** to `assets/screenshots/` with the next free number and commit it.
- **Add a concise README feature section** in the existing voice + a row in the "What you get, at a glance" table.
- **Update `docs/ASSESSMENT-2026-07-26.md`** + regenerate html/pdf in the **same commit** (`keep-assessment-current`).
- **Look at the screen** (`frontend-class-vocabulary`): use `hp-tn-*`, never a bare `hp-card` (renders invisible).
