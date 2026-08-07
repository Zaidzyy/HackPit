# Build queue — 2026-08-07 offensive gap-closure (4 specs)

Four self-contained builds that close the missing pieces in AD CS / Kerberos delegation and — the big one — **cloud/Kubernetes active exploitation**. Run **one per session**, in its own terminal, sequentially (each is its own commit that updates README + a screenshot + the assessment + regenerated PDF). They have **no hard dependency** on each other, so any order works — but the recommended order below minimizes context switching and builds the cloud story in the natural chain order.

**Shared rules (baked into every spec's §0):** no new gate — **per-command human approval is the only bound**; maximally open (Wall A down: internet + LAN + host + cloud metadata); maximally offensive (real creds/APIs/coercion/escape); **propose-only** (the graph picks an edge index, never authors a command; a pick outside the frontier is refused, not repaired); the executing modules run nothing by AST. Single-branch repo (`main`). Each build: tests green + wired into `run_safety_tests.sh`, `next build` exit 0, **look at the screen**, README + screenshot + `docs/ASSESSMENT-2026-07-26.md` + regenerated html/pdf **in the same commit**.

---

## Recommended order

| # | Spec file | What it adds | Touches |
|---|-----------|--------------|---------|
| 1 | `2026-08-07-cloud-imds-ssrf-bridge-spec.md` | Web SSRF/RCE → IMDS → **seed an owned cloud principal** (the missing web↔cloud seam) | `cloudgraph/` + `main.py` |
| 2 | `2026-08-07-k8s-attack-graph-spec.md` | **Kubernetes attack chain + container escape** — cloud→cluster→pod→SA token→secrets/RBAC→privileged pod→escape→node→IMDS→cloud loop; EKS/GKE/AKS foothold edges | `cloudgraph/` + arsenal + image |
| 3 | `2026-08-07-adcs-esc-graph-spec.md` | **AD CS ESC1–8** as routable graph edges (certipy `find` → cert nodes → composite ESC edges) | `adgraph/` |
| 4 | `2026-08-07-kerberos-unconstrained-tickets-spec.md` | **Unconstrained delegation** edge + **golden/silver ticket** forging (persistence) | `adgraph/` |

Cloud first (1→2) because #2 reuses #1's IMDS reader to close the node→cloud loop (works standalone too, just with a little duplication). AD after (3→4) since both touch `adgraph/` and are lower-risk near-clones of existing patterns.

---

## What to say to each session

Open a fresh session in the repo and paste the matching line. Each spec is self-describing (§0 constraints, §1 read-first, §2 build, §3 tests, §4 acceptance, §5 assumptions, §6 README/assessment).

**Session 1 — Cloud SSRF→IMDS bridge:**
> Read `docs/superpowers/specs/2026-08-07-cloud-imds-ssrf-bridge-spec.md` and build it end to end. Follow §0 exactly (no new gate, human-approval-each is the only bound, propose-only, bridge executes nothing). Tests green + added to `run_safety_tests.sh`, `next build` exit 0, real screenshot of `/cockpit/cloud` (synthetic data), README + assessment updated and PDF regenerated in the same commit, look at the screen. Ask me anything blocking first.

**Session 2 — Kubernetes attack graph + container escape:**
> Read `docs/superpowers/specs/2026-08-07-k8s-attack-graph-spec.md` and build it end to end. It extends `backend/cloudgraph/` — mirror the existing edge-index orchestrator's safety design (picks an index, never a command; executes nothing by AST). Follow §0 exactly. Add peirates/kubeletctl to arsenal + Dockerfile + a `docker/proof/` check (flag the image rebuild for me to run). Tests green + safety suite green, `next build` exit 0, screenshot of `/cockpit/cloud` with the synthetic cluster, README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 3 — AD CS ESC1–8 graph edges:**
> Read `docs/superpowers/specs/2026-08-07-adcs-esc-graph-spec.md` and build it end to end. It's a near-clone of how DCSync/shadow-creds are already synthesized in `backend/adgraph/` — mirror that exactly (composite edges from a predicate; module executes nothing). Follow §0. Tests green + safety suite green, `next build` exit 0, screenshot of `/cockpit/ad` showing an ESC route (synthetic CA), README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 4 — Unconstrained delegation + ticket forging:**
> Read `docs/superpowers/specs/2026-08-07-kerberos-unconstrained-tickets-spec.md` and build it end to end. Mirror the existing RBCD/S4U delegation edges in `backend/adgraph/`. Unconstrained delegation is a routable edge; golden/silver tickets are propose-only persistence techniques that BFS must NOT traverse. Follow §0. Tests green + safety suite green, `next build` exit 0, screenshot of `/cockpit/ad`, README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

---

## After each session
- Confirm `run_safety_tests.sh` is green (the one known Windows-host exception is `test_redirector.py` — a UDP-port env limitation, not the build; it passes on CI/Linux).
- Commit lands on `main` with README + screenshot + assessment + regenerated PDF together.
- The sandbox **image rebuild** for #2 (peirates/kubeletctl) is your manual step — the spec adds the catalog + Dockerfile + proof; you run `docker build`.
