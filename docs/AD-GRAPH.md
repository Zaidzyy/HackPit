# AD attack-path graph

**Branch:** `ad-graph` (off `engagement-wall-a-down`) · **Status:** supervised, local-only, not
pushed. Built against **synthetic BloodHound data** — no VM, no GOAD, no live AD lab. Live
collection + abuse execution are wired and ready, pending a lab (see [§8](#8-deferred)).

The headliner: parse a BloodHound collection → an internal typed graph → the animated
route-to-Domain-Admin in the cockpit, where each edge's abuse technique is grounded in the KB
and runnable **only** through the existing gated executor.

This is the GRAPH + walk-the-path experience. An agent reasoning over the graph (AD
orchestration) is a **separate later phase** and is deliberately not built here.

---

## 1. The safety model (unchanged — nothing weakened)

The AD graph adds **no new way to run a command**. It is a visualization + a path engine; every
AD command — the collector and every abuse step — is an ordinary `ExecRequest` through the same
gated executor as the rest of the cockpit:

- **human-approve-each** — the collector and every abuse step need an individual approval
  (`approved=true`); there is no batch, no approve-all, no auto-run. AD abuse (DCSync, password
  resets, DACL edits, add-to-DA) is destructive on a real domain, so approve-each is load-bearing
  here, not ceremony. The UI marks destructive edges and requires an extra explicit confirm.
- **engagement scope-lock** — collection + abuse run in engagement mode against a real domain the
  operator scoped (hosts / domain apex / CIDR via `cockpit/scope.py`). A host outside the scope is
  refused at the `target` gate before anything runs — proven for both the collector and abuse steps.
- **argv-only** — no shell; the DC / domain / abuse target are inspectable argv tokens.
- **zero `:kali` path** — no `adgraph` module references the `:kali` open shell, and none execute
  anything themselves (no `subprocess`/`Popen`/`docker`, no call into the executor run path).
- **lab mode byte-for-byte unchanged** — the lab target-lock wording + gate order are untouched;
  regression-locked.

All of this is enforced in `test_adgraph_safety.py` (6 checks) and re-uses the existing gate code
in `cockpit/executor.py` — the AD graph did not fork or reimplement any gate.

---

## 2. The pipeline (G1–G5)

```
 bloodhound-python  ──▶  BloodHound JSON  ──▶  parser  ──▶  Graph  ──▶  path engine  ──▶  route to DA
   (gated exec)          (captured/ingest)    schema.py    (typed)     paths.py         + KB-grounded
        G1                     G1/G2            parser.py               G3               techniques  G4
                                                                                            │
                                                                        walk a hop ─────────┘  G5
                                                                        (gated exec, approve-each)
```

---

## 3. The collector (G1) — `adgraph/collector.py`

`bloodhound-python` is read-only LDAP/SMB enumeration, but on a real domain it is still a command
against a real host, so it runs like everything else:

- `build_collector_request(params, engagement_id)` builds an **argv-only, UNAPPROVED**
  `ExecRequest` (`bloodhound-python -u <user> -d <domain> -dc <DC> -c All [--hashes :NT | -p pw]
  [-ns <DC-IP>] --zip`). It **requires an active engagement** — collection can't run outside a
  scoped engagement. The DC / domain / nameserver are argv tokens the scope-lock checks.
- The human approves it at `POST /cockpit/exec`; the executor's engagement gates
  (`engagement → target → approval → danger`) apply unchanged. An out-of-scope DC is refused.
- `classify_failure(exit, stdout, stderr)` turns bad-creds / lockout / expired / clock-skew /
  DNS / unreachable into a clean, actionable message.
- `ingest_collection(source, session_id, engagement_id)` parses a captured collection (zip / dir /
  json / bytes / decoded mapping) and persists the parsed graph (`adgraph/store.py`, `ad_graphs`
  table in `sessions.db`).

The collector module **executes nothing** — it builds the request the human approves and ingests
captured output. On this branch it is unit-tested against captured/sample output but **not run
live** (no AD lab).

> **Scope note (surfaced by the tests):** an AD engagement scope must list the **domain apex**
> explicitly (`sevenkingdoms.local`), because a `*.wildcard` covers subdomains only and
> `bloodhound-python -d sevenkingdoms.local` puts the apex on the argv. A good AD scope is e.g.
> `sevenkingdoms.local, *.sevenkingdoms.local, 10.10.10.0/24`.

---

## 4. The parser + graph model (G2) — `adgraph/parser.py`, `adgraph/schema.py`

`parser.py` is the **only** module that knows BloodHound's on-disk shape (v4 / v5 / CE). It
accepts the per-type files (`*_users.json`, `_groups`, `_computers`, `_domains`, `_gpos`, `_ous`,
`_containers`), a combined mapping, a list of files, a directory, or a `.zip`, and produces the
stable schema in `schema.py`:

- **Nodes** — `user | group | computer | domain | ou | gpo | container`, keyed by BloodHound
  ObjectIdentifier, with high-value detection (Domain Admins RID 512, Enterprise Admins 519, DCs
  516, BUILTIN\Administrators, etc.).
- **Edges** — a directed `source → target` of a `kind`, split into **structural** (`Contains`,
  `GpLink`, `TrustedBy`) and **abusable**:
  - ACEs → `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `Owns`, `AddMember`, `AddSelf`,
    `ForceChangePassword`, `AllExtendedRights`, `ReadLAPSPassword`, `ReadGMSAPassword`,
    `AddKeyCredentialLink`, `AddAllowedToAct` (right-name mapping reconciles v4/v5/CE);
  - group `Members` → `MemberOf`; computer `LocalAdmins`/`RDP`/`PSRemote`/`DCOM`/`Sessions` →
    `AdminTo`/`CanRDP`/`CanPSRemote`/`ExecuteDCOM`/`HasSession`; delegation + SID history;
  - **DCSync** synthesized from `GetChanges` + `GetChangesAll` on the same target (or CE's direct
    `DCSync` right).

Partial collections (missing methods) **warn** instead of crashing; an empty collection raises
`ParseError`. All input shapes parse to the same graph (proven).

---

## 5. The path engine (G3) — `adgraph/paths.py`

Given a **start** (the owned low-priv principal) and a **high-value target** (a node, or auto-pick
Domain Admins RID 512), a breadth-first shortest path over the **abusable edges only**
(structural edges are inert). Equal-length ties break toward the **cheaper/quieter** abuse.
Returns the best route plus up to N distinct alternatives, and reports no-path cleanly
(`found=False` + reason) rather than raising.

On the sample domain the engine resolves the exact 5-hop route:

```
tywin --ForceChangePassword--> jaime --GenericWrite--> joffrey --WriteDacl--> tyrion
      --AddSelf--> [Small Council] --GenericAll--> [Domain Admins]
```

---

## 6. KB-grounded edge techniques (G4) — `adgraph/techniques.py`

For each abusable edge, `technique_for_edge` returns the abuse title, a one-line summary, the
tool, whether it's **destructive**, and a concrete command — with the **same grounded/
ai_suggested treatment as the kill-chain map**:

- a static catalog gives every edge kind a correct fallback command template with the concrete
  endpoints (source/target sam-names, domain, DC) substituted in;
- the command is **grounded** in the KB via an injected grounder (`main._ad_kb_grounder`,
  restricted to `active-directory` / `windows` KB categories so a network-scan/web entry can never
  mis-ground an ACL/DCSync abuse). `grounded=True` cites the `entry_id`; otherwise the template is
  used `ai_suggested`.
- `GenericAll`/`GenericWrite` specialize by target type (on a group → `AddMember`, on the domain →
  `DCSync`).

Endpoints for the API live under `/cockpit/ad` (`adgraph/router.py`), all **read-only**: `ingest`,
`graph/{id}`, `latest`, `path` (with per-hop techniques), `technique`, and `collect/preview`
(builds the unapproved collector request + a **redacted** argv for the UI to hand to
`/cockpit/exec`). None of these execute anything.

---

## 7. Walk the path (G5) — `frontend/src/components/CockpitADGraph.tsx`

The route renders in the cockpit's kill-chain cinematic style at **`/cockpit/ad`**: typed nodes
(user/group/computer icons) ignite in sequence, each abuse edge is labeled, the owned start is
green and Domain Admins is red. Clicking an edge opens a drawer with the KB-grounded technique,
the concrete command, the grounded/ai-suggested badge + KB citation, and a destructive flag.

**Walk the path:** from the drawer the human sends the edge's abuse command to the **same gated
executor** every cockpit command uses (`execCockpitStream` → `/cockpit/exec`): approve-each,
argv-only, engagement scope-locked, heuristic red-confirm; destructive edges need an extra
explicit confirm. Running a step marks the edge **traversed** and lights the next hop. In
engagement-loop mode the agent may propose the next edge, but the human still approves each. The
graph **never runs anything on its own**.

The wiring + the visual advance are built and verified in-browser against the sample. Actual
**live execution** of abuse steps defers with the live e2e ([§8](#8-deferred)).

---

## 8. Deferred

- **Live collection.** `bloodhound-python` against a real DC is wired (`build_collector_request`)
  and unit-tested against captured output, but not run — there is no AD lab on this branch. When a
  domain is in an engagement scope, the operator approves the collector at `/cockpit/exec` and the
  scope-lock covers the DC.
- **Live abuse execution.** The walk-the-path command → gated executor path is built and the graph
  advances visually; running an abuse step against a real domain defers to a human-present session
  (GOAD or another authorized domain), approving each step.
- **G7 live e2e** (collect → graph → walk a real path to DA → report) is intentionally skipped
  here. It is ready to run together.

---

## 9. Tests + verification

Wired into `sh backend/run_safety_tests.sh` (all hermetic, green):

| Suite | Covers |
|---|---|
| `test_adgraph.py` (11) | parser typing/high-value, ACE direction, membership/computer edges, DCSync synthesis, partial/empty, input-shape agreement; the exact route to DA, no-path, only-abusable traversal, tie-breaking |
| `test_adgraph_collector.py` (7) | collector argv, never-pre-approved + needs-engagement, **scope-lock covers the collector** (in-scope DC passes / out-of-scope refused), never-auto-run, failure classification, ingest+persist, collector has no exec / no :kali |
| `test_adgraph_safety.py` (6) | no execution in any adgraph module, zero :kali path, collector gated, **abuse step gated (never-auto-run + scope-lock)**, lab mode byte-for-byte unchanged, technique returns data not execution |

Plus the full pre-existing safety suite (cockpit / :kali / loop / engagement / engagement-mode /
scope / engagement-scope) — all still green; lab isolation + engagement-open proofs unaffected.
Frontend: `tsc` clean, `eslint` at the accepted baseline (10 err / 1 warn), `next build` exit 0
with `/cockpit/ad`. Verified live in-browser (Ollama): sample loads → the 5-hop route renders and
animates → the ForceChangePassword drawer shows the grounded KB technique + command + the gated
walk button.

**Ollama** was used for automated LLM checks; restore the frontier `llm_config.json` after review.
**Not pushed** — Zaid reviews the graph + that every AD command still routes through the gated
executor first.
