# Build spec — Kubernetes attack graph + container escape (`:cloud` extension)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** extend the `:cloud` graph *into the cluster* — model the **cloud → cluster → pod → service-account-token → secrets/RBAC-escalation → privileged pod → container escape → node → node's IMDS → back to cloud** chain as real typed edges, so the same edge-index orchestrator that routes AWS IAM privesc now routes a full Kubernetes compromise loop. This is the biggest genuinely-absent capability: today `cloudgraph`'s `serviceaccount` is *cloud IAM*, there is **no pod/node/cluster model at all**, and only Azure has a single cluster-foothold edge (`AKSAdminCreds`).

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. Keep it **maximally open / maximally offensive**: real kubeconfig → real API server, real `kubectl exec`, real privileged-pod scheduling, real container breakout to the node, real node-IMDS pivot back to cloud — all reachable, all through **approve-each**. The graph **proposes an edge index, never authors a command** — copy `cloudgraph/orchestrator.py` / `adgraph/orchestrator.py` exactly (a pick outside the frontier is refused, not repaired; the module executes nothing by AST). No autonomy.

## 1. Read-first (this rides on the existing `:cloud` engine)

- `backend/cloudgraph/schema.py` — `NODE_TYPES`, `PRINCIPAL_TYPES`, `ABUSABLE_EDGES`, `STRUCTURAL_EDGES`, `Node`, `Edge`, `Graph.add_edge` (abusable set is computed there). You will **add K8s node + edge types here**.
- `backend/cloudgraph/techniques.py` — `AbuseSpec` catalog (`title/summary/tool/kb_seeds/template/destructive/no_command`) + `technique_for_edge` (KB-grounded, catalog fallback). You add K8s techniques.
- `backend/cloudgraph/parser.py` — tool-JSON → graph. You add a K8s parser (kubeconfig / `kubectl auth can-i --list` / kube-hunter JSON / peirates → graph).
- `backend/cloudgraph/paths.py` + `orchestrator.py` — **unchanged**: BFS already walks any abusable edge, so once the K8s edges exist the cloud↔cluster↔node loop routes for free. Verify a same-length tie-break rank is set for the new edges (`ABUSABLE_EDGES` order = directness rank).
- `backend/cloudgraph/sample_data.py` (or `collector.py`) — add a **synthetic K8s cluster** so `/cockpit/cloud` renders the chain without a live cluster (for the screenshot).
- `backend/arsenal/tools.json` — `kube-hunter` is already present (enumeration). You add **active** K8s tooling.
- Memory: **cockpit/arsenal decoupling**; **kali-sandbox-image-traps** (verify installed binary names, setcap/no-new-privileges, add a `docker/proof/` install check); **cloud KB grounding degrades commands** (catalog-first). Importing `cockpit.repeater` from outside cockpit trips `test_repeater` — keep any container-liveness helper **local** (the `_container_running` lesson from the `:cloud` build).

## 2. What to build

### 2a. Schema — new K8s node + edge types (`cloudgraph/schema.py`)
Add to `NODE_TYPES`: `"cluster"`, `"node"`, `"pod"`, `"k8s_sa"`, `"k8s_secret"`, `"k8s_role"`. Add `"k8s_sa"` to `PRINCIPAL_TYPES` (a pod-mounted SA token is a principal you can act as). Keep them provider-tagged (an EKS cluster is `provider="aws"`, etc.) so one engine still serves everything.

Add to `ABUSABLE_EDGES` (each gets an `AbuseSpec`):

**Cloud → cluster foothold** (cloud principal → cluster node):
- `EKSAdminCreds` — `eks:AccessKubernetesApi` / `aws eks get-token` → API access as the caller's mapped RBAC.
- `GKEAdminCreds` — `container.clusters.get` + `gcloud container clusters get-credentials` → kubeconfig.
- `AKSAdminCreds` — **already exists**; keep it, and make sure EKS/GKE mirror its shape.

**In-cluster movement** (k8s_sa / pod → …):
- `MountsSAToken` — pod → k8s_sa : the pod auto-mounts `/var/run/secrets/kubernetes.io/serviceaccount/token`; owning the pod = acting as the SA.
- `K8sSecretAccess` — k8s_sa → k8s_secret : RBAC `get/list secrets` → read every secret (often cloud creds, registry creds, other SA tokens).
- `K8sImpersonate` — k8s_sa → k8s_sa : RBAC `impersonate` verb → act as any user/SA.
- `CanEscalateRBAC` — k8s_sa → k8s_role : `bind` / `escalate` verbs, or create/patch (cluster)rolebindings → grant yourself cluster-admin.
- `CreatePrivilegedPod` — k8s_sa → node : `pods create` with `privileged:true` / `hostPID` / `hostPath:/` → schedule a pod that owns the node (this is also the escape vector).
- `ExecPod` — k8s_sa → pod : `pods/exec` → shell into a running (possibly higher-priv) pod and steal its SA token.

**Container escape** (pod → node) — first-class, also valid for non-K8s Docker:
- `ContainerEscape` — pod/container → node/host : breakout via **privileged container**, **hostPath `/` mount**, **`/var/run/docker.sock`**, **hostPID + `nsenter`**, **`CAP_SYS_ADMIN` + cgroup `release_agent`**, or **kubelet API `RunInPod`** (kubeletctl). `destructive` where it plants a payload; carry the specific vector in `edge.props`.

**Node → cloud pivot (the loop-closer, the seam to the SSRF/IMDS work):**
- `NodeToCloud` — node → cloud principal : from a compromised node, read **the node's instance role via IMDS** (`169.254.169.254`) → assume the node's cloud identity → re-enter the cloud IAM graph *with higher privilege*. This connects directly to `cloudgraph/imds.py` if the IMDS-bridge spec is also built; if not, ship a self-contained IMDS read here and note the overlap.

Structural (context, not traversed): `RunsOn` (pod → node), `InCluster` (node/pod → cluster).

### 2b. Techniques (`cloudgraph/techniques.py`)
One `AbuseSpec` per new edge, KB-seeded into `hacktricks-cloud`, catalog fallback (KB-grounding-degrades trap — adopt KB command only when the CLI action matches). Concrete templates, e.g.:
- `EKSAdminCreds`: `aws eks update-kubeconfig --name {cluster} --region {region} && kubectl auth can-i --list`
- `K8sSecretAccess`: `kubectl get secrets -A -o json | jq '.items[] | {name:.metadata.name, data:.data}'`
- `CreatePrivilegedPod`: a `kubectl apply -f -` heredoc for a `hostPath:/` + `nodeName` pod, then `kubectl exec … -- chroot /host`
- `ContainerEscape` (docker.sock): `curl --unix-socket /var/run/docker.sock -X POST 'http://localhost/containers/create' -d '{…hostPath / …}'`
- `ContainerEscape` (kubelet): `kubeletctl -i --server {node} exec "id" -p {pod} -c {container}`
- `NodeToCloud`: `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/` (then the role) — reuse `cloudgraph.imds` if present.

Give each a `win_template` only where a Windows-node variant makes sense (mostly N/A for K8s — leave blank).

### 2c. Parser (`cloudgraph/parser.py`)
Add a K8s ingest that builds the in-cluster subgraph from any of: a **kubeconfig + `kubectl auth can-i --list`** dump, **kube-hunter `--report json`**, **peirates** output, or a plain RBAC dump (`kubectl get clusterrolebindings,rolebindings,roles,clusterroles -o json`). Map RBAC verbs → the edge kinds above (get/list secrets → `K8sSecretAccess`; bind/escalate → `CanEscalateRBAC`; pods/exec → `ExecPod`; pods create + securityContext → `CreatePrivilegedPod`). Attach the parsed cluster to the cloud graph so a cloud principal with `EKS/GKE/AKSAdminCreds` links into it.

### 2d. Enumeration (gated job) — `cloudgraph/enumerate.py`
Add a K8s enumeration path to the existing gated enumerate job: given a kubeconfig / in-cluster token, run the RBAC/kube-hunter dump as an **approved job** (recon-shape, `executor.validate_request` before spawn, ungated stop — mirror the existing cloud enumerate + the `:recon`/crack-worker shape), parse → graph.

### 2e. Arsenal + image
Add to `backend/arsenal/tools.json` (and `docker/Dockerfile.sandbox`, with a `docker/proof/k8s_install_proof.sh` install check): **`peirates`** (in-cluster escalation/pivot), **`kubeletctl`** (kubelet API abuse), **`kubectl`** (if not already in the image). `kube-hunter` is already catalogued — wire its JSON into the parser. Respect `kali-sandbox-image-traps` (real binary names, setcap/no-new-privileges). **The `docker build` rebuild is the operator's step** (as with `:cloud`) — add the tooling + proof and flag the rebuild in the PR.

### 2f. Frontend — `/cockpit/cloud`
The K8s nodes/edges render in the **same** graph (they're cloudgraph nodes). Add node styling for `cluster/node/pod/k8s_sa/k8s_secret/k8s_role` (`hp-tn-*` classes) and make sure the orchestrator panel shows the full cloud→cluster→node→cloud route. A small legend/filter for "Kubernetes" nodes is nice-to-have. **Look at the screen** with the synthetic cluster loaded.

## 3. Tests
- `backend/test_k8s_graph.py` — parser (RBAC/kube-hunter JSON → K8s edges); routing: a synthetic graph where **cloud principal → EKS → pod → SA token → secret (other cloud creds) → node (escape) → NodeToCloud → higher cloud principal** produces a full BFS path; each new edge has a technique with a runnable template.
- Extend `backend/test_cloudgraph_safety.py` — the orchestrator still **picks an index, never authors a command**; a pick outside the frontier is refused; the parser/techniques/orchestrator **execute nothing** (AST). Enumeration adds **no gate** (mirror the "enumeration adds no gate" assertion from `:cloud`). Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- With a synthetic K8s cluster loaded, `/cockpit/cloud` renders cluster/node/pod/SA/secret nodes; the orchestrator proposes an **edge index** stepping cloud → cluster → in-cluster escalation → container escape → node → back to cloud, each approved-and-run via the executor, `advance` only on an approved exit-0 run.
- Container escape is a first-class edge with vector-specific techniques (privileged / hostPath / docker.sock / hostPID / kubelet).
- Compromises/misconfigs land as `Finding`s in engagement state.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit). `peirates`/`kubeletctl` added to arsenal + Dockerfile + proof (rebuild flagged for the operator).

## 5. Assumptions (flip any)
- All three managed-cluster foothold edges (EKS/GKE/AKS). If a session can't finish all three, ship EKS + the full in-cluster/escape/loop model and stub GKE/AKS foothold — say so in the PR (AKS foothold already exists, so GKE is the only genuinely-new one to risk deferring).
- In-cluster enumeration accepts a kubeconfig/token the operator provides (or a captured one) — no auto-harvest without a click.
- Container escape modeled as `pod → node`; the same edge kind covers a non-K8s Docker breakout (container → host) so it's reusable.

---

## 6. README + screenshot + assessment (do this exactly like prior sessions)

**Not done until the README + a real screenshot ship with it.** Screen route: **`/cockpit/cloud`** (now showing the K8s chain).

- **Capture a real lab-state screenshot** with headless Edge (`headless-edge-screenshots`), app running, **synthetic cluster** only (no real cluster names, node IPs, tokens, or account ids):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/cockpit/cloud"
  ```
  **View it** — confirm cluster/pod/node nodes and the routed chain render (not blank/error). If you need a deep-link to force the K8s sample to load for the shot, add one like `:recon`'s `?session=` / `:cloud`'s `?demo=1` pattern.
- **Add the screenshot** to `assets/screenshots/` (next free number); commit it.
- **Add a concise README feature section** (existing voice) + a "What you get, at a glance" row: full Kubernetes attack chain incl. container escape.
- **Update `docs/ASSESSMENT-2026-07-26.md`** + regenerate html/pdf (`python docs/build-assessment.py`) in the **same commit** (`keep-assessment-current`; verify against the html, not the pdf).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
