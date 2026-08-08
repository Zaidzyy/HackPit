# Build spec — Kubernetes RBAC privilege-escalation map (`:cloud` extension, safe subset)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** model Kubernetes **RBAC relationships** as a typed graph in `cloudgraph/` — cloud principal → cluster → pod → service-account → secrets → RBAC-escalation to cluster-admin — so the existing edge-index orchestrator maps "which identity can reach cluster-admin," exactly the way `adgraph/` maps Active Directory. This is the **safe, high-value subset** of the deferred `2026-08-07-k8s-attack-graph-spec.md`: it deliberately omits the container-escape and node→cloud-metadata edges (build those later from the full spec if wanted).

---

## Context (read first — this is access-control analysis tooling)

This extends **HackPit**, an authorized, operator-owned security-assessment platform. The work is **modeling only** — a typed graph of Kubernetes **RBAC (role-based access control) relationships**, the defensive equivalent of a BloodHound access-control map. The code **executes nothing** (AST-proven by `test_cloudgraph_safety.py`), the graph **proposes an edge index, never a command**, and any command is human-approved at runtime and supplied by the KB grounder from data — never authored in code. Think "audit which service accounts are over-privileged," not "run attacks."

## 0. Guiding constraint (do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. The graph proposes an **edge index, never a raw command** — copy `cloudgraph/orchestrator.py` / `adgraph/orchestrator.py` exactly (a pick outside the frontier is refused, not repaired; the module executes nothing by AST). Commands come from the KB grounder (`hacktricks-cloud`), catalog fallback; **no raw payloads in this spec or in code prose**. No autonomy.

## 1. Read-first (rides on the existing `:cloud` engine)

- `backend/cloudgraph/schema.py` — `NODE_TYPES`, `PRINCIPAL_TYPES`, `ABUSABLE_EDGES`, `STRUCTURAL_EDGES`, `Node`, `Edge`, `Graph.add_edge`. You add K8s node + edge types here.
- `backend/cloudgraph/techniques.py` — the `AbuseSpec` catalog + `technique_for_edge` (KB-grounded, catalog fallback). One entry per new edge, **tool name + technique name + `kb_seeds` only**.
- `backend/cloudgraph/parser.py` — tool-output → graph. You add the RBAC ingest.
- `backend/cloudgraph/paths.py` + `orchestrator.py` — unchanged; BFS routes the new edges once they exist.
- `backend/cloudgraph/sample_data.py` — add a synthetic cluster so `/cockpit/cloud` renders without a live cluster.
- `backend/arsenal/tools.json` — `kube-hunter` is already catalogued (enumeration); wire its JSON into the parser. (This safe subset needs **no new offensive tooling** — kubectl + kube-hunter suffice.)
- Memory: **cockpit/arsenal decoupling**; keep any container-liveness helper LOCAL (the `_container_running` lesson from the `:cloud` build).

## 2. What to build

### 2a. Schema — new K8s node + edge types (`cloudgraph/schema.py`)
Add to `NODE_TYPES`: `"cluster"`, `"node"`, `"pod"`, `"k8s_sa"`, `"k8s_secret"`, `"k8s_role"`. Add `"k8s_sa"` to `PRINCIPAL_TYPES`. Provider-tagged (an EKS cluster is `provider="aws"`), so one engine still serves everything.

Add to `ABUSABLE_EDGES` (each gets an `AbuseSpec`):

**Cloud → cluster foothold** (cloud principal → cluster; standard "get cluster credentials" ops):
- `EKSAdminCreds` — `aws eks get-token` / `update-kubeconfig` → API access as the caller's mapped RBAC.
- `GKEAdminCreds` — `gcloud container clusters get-credentials` → kubeconfig.
- `AKSAdminCreds` — **already exists**; keep it; make EKS/GKE mirror its shape.

**In-cluster RBAC relationships** (the privesc chain — pure access-control modeling):
- `MountsSAToken` — pod → k8s_sa : the pod mounts the SA token; controlling the pod = acting as the SA.
- `K8sSecretAccess` — k8s_sa → k8s_secret : RBAC `get/list secrets` → read secrets (often other creds/tokens).
- `K8sImpersonate` — k8s_sa → k8s_sa : RBAC `impersonate` verb → act as another SA/user.
- `CanEscalateRBAC` — k8s_sa → k8s_role : `bind` / `escalate` verbs or create/patch (cluster)rolebindings → grant self cluster-admin.
- `ExecPod` — k8s_sa → pod : RBAC `pods/exec` → run in a pod and read its mounted SA token.

**Structural (context, not traversed):** `RunsOn` (pod → node), `InCluster` (node/pod → cluster).

> **Explicitly OUT of this subset** (defer to the full `k8s-attack-graph-spec` if ever wanted): `CreatePrivilegedPod`, `ContainerEscape`, `NodeToCloud`. Do not add them here.

### 2b. Techniques (`cloudgraph/techniques.py`)
One `AbuseSpec` per new edge, copying the existing entries' shape: **tool name + technique name + `kb_seeds`** into `hacktricks-cloud`; the grounder supplies the command (catalog fallback; respect the KB-grounding-degrades trap). No raw payloads here. Examples (names only):
- `EKSAdminCreds` — tool `aws eks`/`kubectl`, "map cluster kubeconfig + enumerate RBAC (`auth can-i --list`)".
- `K8sSecretAccess` — tool `kubectl`, "read cluster secrets via RBAC get/list".
- `CanEscalateRBAC` — tool `kubectl`, "self-grant cluster-admin via a rolebinding when holding bind/escalate".

### 2c. Parser (`cloudgraph/parser.py`)
Build the in-cluster subgraph from a **kubeconfig + `kubectl auth can-i --list`** dump, a **kube-hunter `--report json`**, or a plain RBAC dump (`kubectl get clusterrolebindings,rolebindings,roles,clusterroles -o json`). Map RBAC verbs → edge kinds (get/list secrets → `K8sSecretAccess`; bind/escalate → `CanEscalateRBAC`; impersonate → `K8sImpersonate`; pods/exec → `ExecPod`; SA mount → `MountsSAToken`). Attach the parsed cluster so a cloud principal with `EKS/GKE/AKSAdminCreds` links into it.

### 2d. Enumeration (gated job) — `cloudgraph/enumerate.py`
Add a K8s path to the existing gated enumerate job: given a kubeconfig / token, run the RBAC / kube-hunter dump as an **approved job** (recon-shape, `executor.validate_request` before spawn, ungated stop — mirror the existing cloud enumerate + `:recon`/crack-worker shape), parse → graph. No new gate.

### 2e. Frontend — `/cockpit/cloud`
The K8s nodes/edges render in the same graph; add styling for `cluster/node/pod/k8s_sa/k8s_secret/k8s_role` (`hp-tn-*`) and show the cloud→cluster→SA→cluster-admin route in the orchestrator panel. **Look at the screen** with the synthetic cluster.

## 3. Tests
- `backend/test_k8s_rbac.py` — parser (RBAC / kube-hunter JSON → edges); routing: a synthetic graph where **cloud principal → EKS → pod → SA token → secret → CanEscalateRBAC → cluster-admin** produces a full BFS path; each new edge has a technique with tool + kb_seeds.
- Extend `backend/test_cloudgraph_safety.py` — orchestrator still **picks an index, never authors a command**; a pick outside the frontier is refused; parser/techniques/orchestrator **execute nothing** (AST); enumeration adds **no gate**. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- With a synthetic cluster loaded, `/cockpit/cloud` renders cluster/node/pod/SA/secret/role nodes; the orchestrator proposes an **edge index** routing cloud → cluster → SA → secrets → RBAC-escalation → cluster-admin, each approved-and-run via the executor, `advance` only on an approved exit-0 run.
- Over-privileged RBAC paths land as `Finding`s in engagement state.
- No container-escape / node-pivot edges in this build; no new gate; module executes nothing.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Safe subset by design: cloud→cluster + in-cluster RBAC privesc only. The escape/pivot edges live in the deferred full spec.
- No new offensive tooling needed (kubectl + kube-hunter). If you want peirates/kubeletctl later, they belong to the full spec, not this one.
- In-cluster enumeration accepts an operator-provided kubeconfig/token — no auto-harvest.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/cockpit/cloud`** (K8s RBAC map).
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic** cluster only (no real cluster names / tokens):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/cockpit/cloud"
  ```
  **View it** — cluster/pod/SA/secret nodes + the RBAC route render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (Kubernetes RBAC privesc map).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf (`python docs/build-assessment.py`) same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
