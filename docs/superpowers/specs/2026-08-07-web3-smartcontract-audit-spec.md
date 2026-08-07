# Build spec — Web3 / smart-contract audit depth

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** give HackPit real smart-contract audit capability — add the **missing web3 static-analysis tooling** (slither/mythril/echidna/foundry/semgrep — HackPit has NONE today), ship **built-in code-audit playbooks** for Solidity / Rust-Anchor / Cosmos-Go (ported from open·kritt's proven `external-flow-analysis` + `Cosmos ABCI Panic Halt Review`), and deepen the **KB** with smart-contract methodology (loss-of-funds, consensus halt, reentrancy, oracle, access control). open·kritt's Blockian team earned $1.5M in bug bounties with exactly these patterns — the operator owns them.

**Best built AFTER** `2026-08-07-ai-codeaudit-fanout-spec.md` — the built-in playbooks run on that engine.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** A smart-contract audit run is ONE approved job (the code-audit-fanout justification). Keep it **maximally aggressive** in what it hunts (loss-of-funds, consensus halt, reentrancy, oracle manipulation, unchecked math, access-control) — real exploitable findings with an attacker path, not style nits. Tool runs (slither/mythril/echidna) go through the gated executor + kali sandbox (approve-each); PoC/fuzzing is approve-each. The analysis/reasoning is unbounded; execution is gated. **Do not adopt open·kritt's autonomous-root model.**

## 1. Read-first

**HackPit (the host):**
- `2026-08-07-ai-codeaudit-fanout-spec.md` — the engine these playbooks run on (entrypoint-map-once → per-flow agent → concrete-or-stub). Read it first.
- `backend/codescan/` — the audit surface + `rules/` (semgrep rule dir — add web3 rulesets).
- `backend/arsenal/tools.json` + `docker/Dockerfile.sandbox` — where new tools land (respect `kali-sandbox-image-traps`).
- The **KB ingest workflow** (`kb-source-ingest-workflow`, `kb-consolidation-engine`, `kb-pipeline-build-order`) — how methodology content becomes KB entries. **Trap:** `test_corpora` flakes after an ingest — re-run first; Defender can quarantine `entries.jsonl` (verify after every ingester run).
- The `web3-audit` / `token-scan` / `meme-coin-audit` skills already present — align, don't duplicate.

**open·kritt (port from, operator owns — steal freely):**
- `docs-site/workflows/built-in-workflows.mdx` — the two playbooks (`external-flow-analysis`, `Cosmos ABCI Panic Halt Review`) with their exact step decomposition (enumerate ABCI methods → fan out four panic classes: explicit panic / arithmetic / nil-pointer / bounds-type).
- `backend/src/lib/defaultWorkflows.js` + `defaultWorkflowSeeds.json` — the seeded workflow definitions/prompts to port as HackPit built-ins.

## 2. What to build

### 2a. Web3 tooling (arsenal + image)
Add to `backend/arsenal/tools.json` + `docker/Dockerfile.sandbox` + `docker/proof/web3_install_proof.sh`:
- **`slither`** (Solidity static analysis), **`mythril`** (symbolic execution), **`echidna`** (property fuzzing), **`foundry`/`forge`+`cast`** (build/test/PoC), **`semgrep`** with smart-contract rulesets, and (Rust/Anchor) **`cargo`/`anchor`** + clippy lints, (Cosmos-Go) the Go toolchain for ABCI review. Respect `kali-sandbox-image-traps` (real binary names, setcap/no-new-privs). Image rebuild is the operator's step — flag it.

### 2b. Built-in audit playbooks (on the code-audit-fanout engine)
Port as HackPit built-in workflows:
- **`evm-external-flow`** — Solidity: enumerate external/public entrypoints → trace flows (value transfers, state changes, external calls, delegatecall, oracle reads) → per-flow agent returns concrete loss-of-funds / reentrancy / access-control / oracle-manipulation vuln-or-stub.
- **`cosmos-abci-halt`** — Go/Cosmos: enumerate wired ABCI methods + phase handlers → fan out four panic classes (explicit panic, arithmetic, nil-pointer, bounds/type) → return only maliciously-triggerable production-reachable halt paths.
- **`anchor-solana`** — Rust/Anchor: enumerate instructions → trace account validation / signer checks / CPI / arithmetic → per-flow agent returns missing-owner-check / signer-spoof / integer-overflow / CPI-confusion vuln-or-stub.
Each grounds in the KB (2c) and can chain a **tool pass** (slither/mythril/echidna) whose run is approve-each.

### 2c. KB methodology ingest
Author/ingest smart-contract methodology entries (via the KB ingest pipeline): the vuln taxonomy the `web3-audit` skill covers (accounting desync, access control, incomplete path, off-by-one, oracle, ERC4626, reentrancy, flash-loan oracle manip, signature replay, proxy/upgrade) + chain-specific (Cosmos halt, Solana account model) — so the fan-out agents are KB-grounded. Follow `kb-pipeline-build-order` (re-running one ingester alone reverts downstream enrichment); verify `entries.jsonl` after (Defender trap).

### 2d. Frontend — `/code-scan`
The web3 playbooks appear as selectable built-ins in the AI-audit mode; a "run tool pass" (slither/mythril) offers an approve-each executor run; findings carry chain + contract + function refs. `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_web3_audit.py` — the three playbooks parse/run on a **fixture** contract set (a deliberately-vulnerable Solidity + a Cosmos ABCI Go snippet + an Anchor program) and their fan-out returns the expected concrete findings-or-stubs; a slither/mythril fixture output parses into findings; KB grounding cites web3 entries.
- KB: `test_corpora` green after ingest (re-run once if it flakes); `entries.jsonl` present after the ingester (Defender check).
- Safety: tool runs are approve-each; the analysis executes nothing; no new gate. Add to `run_safety_tests.sh`.

## 4. Acceptance criteria
- `/code-scan` AI mode offers the three web3 playbooks; pointing one at a (fixture) contract produces concrete, KB-grounded, attacker-path-backed findings deduped + ranked; a tool pass (slither/mythril/echidna) is available approve-each.
- Web3 tooling added to arsenal + Dockerfile + proof (rebuild flagged); KB deepened with smart-contract methodology.
- Analysis executes nothing; tool/PoC runs gated; no new gate.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Ship **Solidity/EVM end-to-end first** (biggest audience), then Cosmos-Go, then Anchor/Solana — say so in the PR if only some land.
- Depends on the code-audit-fanout engine; if that isn't built yet, this spec can ship the **tooling + KB** standalone and stub the playbooks until the engine exists — note it.
- Align with the existing `web3-audit`/`token-scan` skills; the KB entries make those skills' methodology retrievable, not duplicated.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/code-scan`** (web3 playbook selected).
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, on a **fixture** vulnerable contract (never a real client's contract):
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/code-scan"
  ```
  **View it** — web3 playbook + contract findings render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (web3 / smart-contract audit).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
