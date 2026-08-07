# Build spec — Cross-domain kill-chain graph (capstone)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** one view that stitches the existing **web foothold → cloud → on-prem AD** graphs into a single routed kill chain — the capstone over `adgraph/` + `cloudgraph/` + web findings, using the cross-domain seams (SSRF→IMDS, node→cloud, cloud-creds→on-prem) as edges the same edge-index orchestrator can walk end to end.

**Best built AFTER** the SSRF→IMDS bridge (`2026-08-07-cloud-imds-ssrf-bridge-spec.md`) and the K8s graph (`2026-08-07-k8s-attack-graph-spec.md`) — they create two of the cross-domain seams this overlay consumes. It renders with whatever exists, but is richest after those.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. Keep it **maximally open / offensive**: a chain that crosses web→cloud→on-prem is real lateral movement, each hop through the executor (approve-each). The overlay **proposes an edge index, never authors a command** — copy `adgraph/orchestrator.py` / `cloudgraph/orchestrator.py` exactly (pick outside frontier refused; executes nothing by AST). It is a **read-and-stitch overlay**, not a new engine.

## 1. Read-first

- `backend/adgraph/` and `backend/cloudgraph/` — the two graphs. Read their `schema.py` `to_dict()` and `store.py` (how a session's graph is stored/retrieved). The overlay consumes each graph's **public dict output** — it does NOT reach into internals (keeps the two graph packages decoupled).
- `backend/adgraph/orchestrator.py` / `cloudgraph/orchestrator.py` + `paths.py` — the edge-index proposal + BFS you reuse over the merged node/edge set.
- `backend/state/` — web findings (SSRF, RCE, leaked creds) live here; they are the **web lane's** nodes/edges.
- The two cross-domain seams that already exist / are being built:
  - **web SSRF → IMDS → cloud principal** — `cloudgraph/imds.py` + `/cloud/seed-imds` (the SSRF-bridge spec). A web SSRF Finding → an owned cloud node.
  - **node → cloud** (`NodeToCloud`) and **cloud → cluster** (EKS/GKE/AKS) — the K8s spec.
- Memory: **cockpit/arsenal decoupling** — the overlay is cross-cutting; wire it in `main.py`, reading each graph's public output. Do NOT make adgraph import cloudgraph or vice-versa.

## 2. What to build — `backend/killchain/` (a read-and-stitch overlay package)

### 2a. Merge
Build a merged graph from three lanes, each node tagged with its `domain` (`web` | `cloud` | `onprem`):
- **web lane**: from engagement `state` — a foothold (SSRF/RCE/leaked-cred Finding) is a node; its capability is the outgoing edge.
- **cloud lane**: `cloudgraph`'s nodes/edges (incl. K8s) via its public dict.
- **on-prem lane**: `adgraph`'s nodes/edges via its public dict.

### 2b. Cross-domain edges (`killchain/bridges.py`) — the new, small catalog
Synthesize the seams that connect the lanes (each an abusable edge with a KB-grounded technique, catalog fallback):
- `SsrfToImds` — web SSRF Finding → cloud principal (the bridge already extracts the identity; this makes it a graph edge).
- `NodeToCloud` — K8s/compute node → cloud principal (node's instance role via IMDS).
- `CloudToOnprem` — cloud → on-prem AD, via the realistic hybrid paths: **password/secret reuse** (a secret read from cloud = an AD cred), **Entra/AD Connect sync account** compromise, **cloud-hosted DC / hybrid-joined VM**, **RunCommand on a domain-joined VM** → AD foothold.
- `OnpremToCloud` — on-prem → cloud, via **AD-synced identity**, a **service principal cert on a domain box**, or **cloud creds in SYSVOL/GPP/loot**.
- `WebToHost` — web RCE Finding → a host node (→ then AD via existing adgraph edges).

Each carries `domain_from`/`domain_to` in `props` so the UI can draw the lane crossing.

### 2c. Orchestrator + routes
Reuse the edge-index orchestrator over the merged graph: BFS from an owned web/cloud foothold to a high-value target in **any** lane (Domain Admin, cloud Owner/root, cluster-admin). `propose_next` returns an edge index; `advance` on an approved exit-0 run. Routes in `main.py` (cross-cutting): `GET /killchain/graph`, `POST /killchain/propose`, `POST /killchain/advance`. A synthetic three-lane sample so it renders without live data.

### 2d. Frontend — `/cockpit/killchain`
Three swim-lanes (web / cloud / on-prem) with the stitched path lit across them; the orchestrator panel proposes the next edge index; per-hop drawer shows the technique. `?demo=1` loads the synthetic chain (mirror `:cloud`). `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_killchain.py` — merge of three synthetic lane dicts → one graph with `domain` tags; the bridge catalog synthesizes the cross-domain edges; BFS routes **web foothold → cloud → on-prem DA** across lanes; orchestrator proposes an index; `advance` requires approved+exit0.
- `backend/test_killchain_safety.py` — mirror `test_adorch_safety`/`test_cloudgraph_safety`: **picks an index, never authors a command**; a pick outside the frontier is refused; the overlay **executes nothing** and **does not import graph internals** (only public dicts). Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- `/cockpit/killchain` renders three lanes from the (synthetic) web/cloud/on-prem graphs; the orchestrator proposes an edge index routing a foothold in one lane to a high-value target in another; approving each hop's command runs via the executor; `advance` only on approved exit-0.
- Cross-domain edges (SsrfToImds / NodeToCloud / CloudToOnprem / OnpremToCloud / WebToHost) are modeled with techniques.
- Overlay executes nothing, imports no graph internals (decoupling preserved); steps land as `Finding`s.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- The overlay **reads each graph's public dict** and stitches — it does not re-implement or deep-import either graph (keeps `adgraph`/`cloudgraph` decoupled). If a cleaner seam than "public dict" exists, use it but preserve decoupling.
- Cross-domain edges are a small catalog like the per-graph technique catalogs; ship the SSRF→IMDS and NodeToCloud seams first (they pair with the two prior specs), then the hybrid AD↔cloud seams.
- Renders on synthetic data; live data arrives from the three underlying surfaces.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/cockpit/killchain`**.
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic** three-lane chain (`?demo=1`) — no real hosts/accounts/domains:
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/cockpit/killchain?demo=1"
  ```
  **View it** — three lanes + the stitched path render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (cross-domain kill-chain graph).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
