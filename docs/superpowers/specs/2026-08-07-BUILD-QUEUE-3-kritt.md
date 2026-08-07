# Build queue #3 — Kritt-derived code-audit capabilities (4 specs)

Four builds that port the good parts of **open·kritt** (the operator's own tool — license is a non-issue, code can be lifted freely) into HackPit, adapted to HackPit's **approve-every-command** model. Run **one per session**, own terminal, sequentially — each is its own commit (README + screenshot + assessment + regenerated PDF together). **Run these AFTER the 11 specs in BUILD-QUEUE + BUILD-QUEUE-2.**

**The one non-negotiable adaptation:** open·kritt runs agents **autonomously as root in disposable containers with direct internet**. HackPit does the **opposite** — agents **read source and PROPOSE**; any PoC/tool/confirmation command is **approve-each** through the existing executor + kali sandbox. Every spec's §0 states this. Adopt open·kritt's *decomposition, dedup, ranking, schema, and playbooks* — never its autonomy.

**Shared rules (every §0):** no new gate — a scan/workflow run is ONE approved job (the ZAP-scanner/nuclei/intruder justification: one approval buys many analysis tasks); analysis executes nothing; commands are approve-each; maximally aggressive in what it hunts (real exploitable, attacker-path-backed findings); KB-grounded (HackPit's edge over open·kritt). Single-branch repo (`main`). Each build: tests + `run_safety_tests.sh` green, `next build` exit 0, **look at the screen**, README + screenshot + `docs/ASSESSMENT-2026-07-26.md` + regen PDF **same commit**.

---

## Recommended order (dependencies matter here)

| # | Spec file | What it adds | Depends on |
|---|-----------|--------------|------------|
| 1 | `2026-08-07-ai-codeaudit-fanout-spec.md` | **AI code-audit fan-out** on `codescan` (map entrypoints once → per-flow agent → concrete-vuln-or-stub → dedup+rank), reusing `reasoning/` specialists | — (flagship, build first) |
| 2 | `2026-08-07-finding-pipeline-upgrade-spec.md` | **Dynamic finding schema + auto-dedup + pluggable severity rankers + post-scripts** (cross-cutting, all surfaces) | independent (pairs with #1) |
| 3 | `2026-08-07-web3-smartcontract-audit-spec.md` | **Smart-contract audit**: slither/mythril/echidna/foundry/semgrep tooling (HackPit has none) + Solidity/Cosmos/Anchor playbooks + KB depth | #1 (playbooks run on its engine) |
| 4 | `2026-08-07-workflow-builder-spec.md` | **Reusable prompt-workflow builder** (variables/batches/depth-siblings/import-export) — the authoring UI | #1 (+ #2's schema); optional/polish |

Order rationale: **#1 is the engine** everything else uses — build it first. **#2** is independent and broadly useful (upgrades findings everywhere), good second. **#3** (web3) is the highest-value *new capability* (real tooling gap + $1.5M-proven playbooks) and needs #1. **#4** (builder UI) is the most product-polish — optional; #1 ships usable built-ins without it.

---

## What to say to each session

**Session 1 — AI code-audit fan-out:**
> Read `docs/superpowers/specs/2026-08-07-ai-codeaudit-fanout-spec.md` and build it end to end. Port open·kritt's map-entrypoints-once → per-flow-agent → concrete-or-stub decomposition onto HackPit's `backend/reasoning/` specialists + `codescan`. Human-gated — agents read source and PROPOSE; PoC is approve-each; do NOT adopt open·kritt's autonomous-root model. Follow §0. Tests + safety green, `next build` exit 0, screenshot of `/code-scan` (AI mode, sample repo), README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 2 — Finding pipeline upgrade:**
> Read `docs/superpowers/specs/2026-08-07-finding-pipeline-upgrade-spec.md` and build it end to end. Port open·kritt's `schema.py` (dynamic finding schema), `post_processing.py` (dedup + IMPACT_LEVELS rank), `severityRankers.js` (pluggable rankers), `postScripts.js` (post-finding hook). Data ops execute nothing; command post-scripts are approve-each. Respect the 3-schema-places rule. Follow §0. Tests + safety green, `next build` exit 0, screenshot of `/engagements`, README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 3 — Web3 / smart-contract audit:**
> Read `docs/superpowers/specs/2026-08-07-web3-smartcontract-audit-spec.md` and build it end to end. Add slither/mythril/echidna/foundry/semgrep to arsenal + Dockerfile + proof (flag the image rebuild for me); port open·kritt's external-flow + Cosmos-ABCI-halt playbooks (+ an Anchor one) onto the code-audit-fanout engine; deepen the KB with smart-contract methodology (watch the test_corpora flake + Defender/entries.jsonl trap). Follow §0. Tests + safety green, `next build` exit 0, screenshot of `/code-scan` (web3 playbook, fixture contract), README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

**Session 4 — Reusable workflow builder:**
> Read `docs/superpowers/specs/2026-08-07-workflow-builder-spec.md` and build it end to end. Port open·kritt's workflows/steps/batches/depth-siblings/variables/import-export (`workflows.js`, `steps.js`, `prompting.py` render_prompt/resolve_ref, `defaultWorkflows.js`) as an authoring UI over the code-audit-fanout engine. Authoring executes nothing; runs are one gated job; imports inspect-before-run. Follow §0. Tests + safety green, `next build` exit 0, screenshot of `/workflows`, README + assessment + PDF same commit, look at the screen. Ask me anything blocking first.

---

## After each session
- `run_safety_tests.sh` green (known Windows-host exception: `test_redirector.py`, a UDP-port env limit — passes on CI/Linux).
- Commit on `main` with README + screenshot + assessment + regenerated PDF together.
- Image rebuild (#3 web3 toolchain) is your manual `docker build` step — the spec adds catalog + Dockerfile + proof.
- The open·kritt clone to port from lives at `scratchpad/open-kritt` (this session) — re-clone `https://github.com/Kritt-ai/open-kritt` if a future session needs it.
