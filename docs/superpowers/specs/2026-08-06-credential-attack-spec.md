# Build spec — Credential-attack surface (`:credentials`)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-06.
**One line:** wire the credential loop that already has all its pieces — spray captured/OSINT creds, crack captured hashes, and feed results back into engagement state so the AD graph and authenticated rescans light up.

---

## 0. Guiding constraint (read first, do not weaken)

This feature adds **NO new gate.** It rides the existing executor's single load-bearing gate: **per-command human approval.** Follow the project's standing philosophy (`docs/ASSESSMENT-2026-07-26.md` §1.2, and the `engagement-mode` posture): the human approves every command; nothing runs hands-off; there is no batch/risk-tiered auto-run; the proposer never executes.

**Bulk operations (a spray, a crack) are one gated job, not thousands of gated attempts.** Mirror `cockpit/jobs.py` exactly: one human approval starts the whole job, it streams progress, and the **stop button is NOT gated** (the panic switch, like `stop_scan`). This is the "one approval buys many requests" model the intruder already uses (`cockpit/router.py` ~line 788, ~919) — reuse it, don't reinvent it.

Everything else stays maximally open (engagement mode = no isolation floor, reaches the internet/LAN as today). Keep the source-scan locks: the new module must be human-driven and must not become an execution path the orchestrator/agent can reach.

## 1. Read-first (study before writing code)

- `backend/cockpit/jobs.py` + `backend/cockpit/router.py` (the long-running-tool-as-one-approval job engine + stop button + the intruder, which is the closest existing analogue).
- `backend/cockpit/executor.py` — `ExecRequest`, `validate_request`, `iter_run`, `danger_reasons_for_mode` (all commands go through this).
- `backend/state/models.py` — `Credential(kind, principal, secret, domain, note, ...)`, `Finding`, `Host`, `Service`.
- `backend/state/store.py` — `upsert_credentials`, `upsert_findings`, `load_state`, `severity_rank`.
- `backend/state/credvault.py` — `fill(command, cred)`, `best_matches(command, creds)`, `credential_placeholders(command)`.
- `backend/state/parsers.py` + `backend/state/ingest.py` — how tool output becomes state rows (you will add parsers for the crackers/sprayers).
- `backend/arsenal/tools.json` — `hashcat`, `john`, `hydra`, `kerbrute`, `netexec` are already catalogued (note: `crackmapexec` is NOT — use `netexec`).
- `backend/adgraph/store.py` + `orchestrator.py` — so a newly cracked/sprayed credential can mark AD nodes owned.
- Frontend: `frontend/src/components/CockpitState.tsx` (where creds/findings render), `IntruderScreen.tsx` (a job-driven screen to mirror), and the `frontend-class-vocabulary` memory rule (`hp-tn-*`, never bare `hp-card`).

## 2. What to build

### Backend — `backend/cockpit/credattack.py` (new)
A pure, execution-free planner + result-parser module (like `graphql_enum.py` / `intruder.py` build their commands but the *executor* runs them). It:

1. **Builds spray commands** from state, as argv (never a shell string): given a target service (SMB/WinRM/LDAP/SSH/HTTP-form/Kerberos) and a set of `Credential`s + a userlist, emit `netexec <proto> <target> -u users -p passwords`, `kerbrute passwordspray`, `hydra`, etc. Use `credvault.fill` for placeholders. **Spray safety knobs are operator-set inputs, not gates:** a delay and a "stop on N lockouts" threshold are *parameters the operator chooses* (surface them, default them sanely), not a refusal path.
2. **Builds crack commands**: given captured `Credential`s of `kind in (ntlm, hash, ticket)`, emit `hashcat -m <mode> hashes wordlist` / `john`. Include hash-mode detection (map the hash shape → hashcat `-m`). The hashes come from state; write them to a job-scoped file under the sandbox's loot dir (see `cockpit/loot.py`), never echoed on the argv.
3. **Parses results** back into state: a spray hit → `upsert_credentials` (a *validated* credential, `note="sprayed OK on <target>"`), a crack hit → update the existing `Credential.secret` (kind stays, now with plaintext) + a `Finding(severity="high", tool="hashcat", title="cracked <principal>")`. Add parsers to `state/parsers.py` for hashcat `--show`/potfile output and netexec's `[+]` success lines.

### Backend — routes (in `backend/cockpit/router.py`, the cockpit router)
- `POST /cockpit/credentials/spray` → validate via `executor.validate_request` (approval gate), then launch as a **job** (`jobs.py`) streaming progress; results ingested on completion.
- `POST /cockpit/credentials/crack` → same, as a job.
- `GET /cockpit/credentials/plan?session_id=...` → dry preview of the commands that WOULD run (so the operator sees the exact argv before approving). Executes nothing.
- Reuse the existing job **stop** route (the ungated panic button) — do not add a new one.

Respect **cockpit/arsenal decoupling** (memory): the credattack module lives in `cockpit/`; anything cross-cutting between `state` and `cockpit` is wired in `main.py`, not by cross-imports.

### Backend — "light up the graph" hook
After a spray/crack ingests a working credential, if an AD graph exists for the session, mark the matching principal **owned** in `adgraph/store.py` (there is already an owned-node concept in `orchestrator.AdState`). This is the payoff: a cracked cred → new frontier edges in `:ad-graph`.

### Frontend — `frontend/src/app/credentials/page.tsx` + `CredentialAttackScreen.tsx` (new)
Mirror `IntruderScreen.tsx` (job-driven: launch → live progress → results). Sections: **Spray** (pick target + service + which state creds/userlist, show the exact argv preview, one Approve button, live hits), **Crack** (pick captured hashes from state, detected mode, wordlist, Approve, live cracked count), **Results feed** (new creds/findings, with a link back to `:ad-graph`). Add a nav entry (`:credentials`) alongside the other cockpit surfaces. Use `hp-tn-*` classes and **look at the screen** before calling it done (memory: a frontend change is not verified until it has been looked at; capture a headless screenshot).

## 3. Tests (mirror the existing pattern)
- `backend/test_credattack.py` — command building from state, hash-mode detection, result parsing → state upserts, credvault fill correctness.
- `backend/test_credattack_safety.py` — **the module executes nothing** (AST-assert, like `test_state.py`/`test_mcp_safety.py` do): `credattack.py` builds argv and parses text; only `executor`/`jobs` run anything. Assert the spray/crack routes go through `validate_request` (approval gate). Assert secrets never land on an argv (hashes go to a loot file). Add both to `backend/run_safety_tests.sh`.

## 4. Acceptance criteria
- Spray and crack each run as ONE approved job with a working ungated stop button; no per-attempt approval.
- A successful spray/crack writes a `Credential` and a `Finding` into engagement state, visible in `CockpitState.tsx`, and marks the AD node owned when a graph exists.
- `run_safety_tests.sh` stays green (add the two new files); frontend `next build` exits 0; the screen has been looked at.
- Update `docs/ASSESSMENT-2026-07-26.md` (+ regenerate html/pdf, same commit) per the `keep-assessment-current` rule, and add a README feature blurb + screenshot.

## 5. Assumptions (flip any before starting)
- Spray/crack = one approval + stop button (per the guiding constraint). If you want per-attempt approval instead, that contradicts the "no extra gates" intent — confirm first.
- Cracking uses the sandbox's local wordlists (rockyou etc. in the Kali image); a custom wordlist is an operator input.
- `netexec` is the spray driver (crackmapexec is not catalogued).

---

## 6. README + screenshot — do this exactly like the 2026-08-06 README session

**Not done until the README and a real screenshot ship with it** (same workflow every feature this project got). New screen route: **`/credentials`**.

- **Capture a real lab-state screenshot** with headless Edge (no Chrome extension needed — the method in the `headless-edge-screenshots` memory). With the app running (`cd backend && uv run uvicorn main:app` + `cd frontend && npm run dev`):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/credentials"
  ```
  Then **view it** (or a Pillow contact sheet) to confirm it rendered — not a blank page or a Next dev-error overlay.
- **Never a real target in a public screenshot.** Lab/synthetic only. The engagement list holds real bug-bounty targets (e.g. Majid Al Futtaim, crateandbarrel.me) — keep them out of frame; use lab hosts / OWASP Juice Shop / example.com.
- **Add the screenshot** to `assets/screenshots/` with the next free number (they run 01–30 today) and commit it.
- **Add a concise README feature section** in the existing voice — one or two plain sentences + the screenshot + a one-line caption — and a row in the "What you get, at a glance" table.
- **Update `docs/ASSESSMENT-2026-07-26.md`** and regenerate its html/pdf in the **same commit** (`keep-assessment-current`).
- **Look at the screen, don't trust the build** (`frontend-class-vocabulary`): `tsc`/`next build`/eslint can't see a missing CSS class or a dead animation; a bare `hp-card` renders invisible — use `hp-tn-*`.
