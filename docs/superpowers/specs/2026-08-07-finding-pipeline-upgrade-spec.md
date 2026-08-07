# Build spec — Finding pipeline upgrade: dynamic schema + dedup + pluggable rankers + post-scripts

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** port open·kritt's finding-processing machinery (which the operator owns) to strengthen HackPit findings **across every surface**: a **dynamic/structured finding schema**, **automatic de-duplication**, **pluggable severity rankers**, and **post-scripts** (a gated hook that validates a finding / builds a PoC / produces a report after it lands). HackPit has findings + validation gates + report-writer; this adds dedup, pluggable ranking, and a post-finding automation hook that benefits recon/nuclei/credentials/AD/cloud/code-audit alike.

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate.** Per-command human approval is the only bound. A **post-script that runs a command is an approve-each executor run** (never auto-fired); a post-script that only reshapes/validates data in-process runs freely (executes nothing). Keep it **maximally open / offensive** — post-scripts can build real PoCs and real reports — but any command goes through the gated executor + kali sandbox. Ranking/dedup/schema are pure data operations (execute nothing).

## 1. Read-first

**HackPit (the host):**
- `backend/state/` (`models.py`, `store.py`, `upsert_findings`) — the engagement finding store. This is what gets richer.
- `backend/codescan/findings.py` + `backend/report.py` + the report route — existing finding + report machinery.
- The validation gates + `report-writer` — the post-script hook composes with these, doesn't replace them.
- Memory: **attack-step schema lives in 3 files** (a new finding field needs the model + the main.py Pydantic + the frontend, or `response_model` strips it) — respect it when adding schema fields.

**open·kritt (port from, operator owns — steal freely):**
- `engine/open_kritt_engine/schema.py` — **dynamic finding output schema**: `normalize_output_format`, `output_schema`, `validate_payload`, `FIELD_TYPE_MAP`, the `_kritt_extractor_helper` pattern. A configurable, jsonschema-validated finding shape.
- `engine/open_kritt_engine/post_processing.py` — **dedup + severity ranking** (`IMPACT_LEVELS`, `BATCH_SIZE`, the merge/extract logic).
- `backend/src/routes/severityRankers.js` + `backend/src/lib/defaultSeverityRankers.js` — **pluggable severity rankers** (custom, per-engagement ranking logic) + sensible defaults.
- `backend/src/routes/postScripts.js` + `postScriptLocks.js` — **post-scripts**: a hook that runs after a finding to validate / PoC / report.
- `backend/src/routes/vulnerabilities.js` — the finding CRUD/serialize shape.

## 2. What to build

### 2a. Dynamic / structured finding schema (port `schema.py`)
Let a finding carry a **configurable field set** (title, severity, attacker-path, source-refs, CVSS, plus engagement-defined custom fields), validated against a generated jsonschema so every producer (recon/nuclei/AD/cloud/code-audit/manual) emits a consistent, machine-checkable finding. Wire the new fields through all 3 schema places (model + main.py Pydantic + frontend).

### 2b. Automatic de-duplication (port `post_processing.py`)
When findings arrive (especially from fan-out producers like the AI code-audit or a multi-host recon), **collapse duplicates** by a stable key (normalized title + location + type). Idempotent — re-ingesting the same finding must not multiply it. Surface a "merged N duplicates" note.

### 2c. Pluggable severity rankers (port `severityRankers.js` + defaults)
A **ranker** is a small, per-engagement-selectable rule set that (re)scores findings into `critical/high/medium/low/informational` — e.g. weight loss-of-funds/RCE up, informational down; a bug-bounty-payout ranker vs a compliance ranker. Ship sensible defaults (port `defaultSeverityRankers.js`); operator can pick/customize per engagement.

### 2d. Post-scripts (port `postScripts.js`)
A **post-script** is an operator-authored step that runs **after a finding lands**, to do one of: **validate** (re-check the finding is real — composes with the existing validation gates), **build a PoC** (an approve-each executor run in the kali sandbox), or **produce a report** (feed `report-writer`). Data-only post-scripts run in-process; command post-scripts are **approve-each**. Locks (port `postScriptLocks.js`) prevent concurrent double-runs.

### 2e. Frontend
Extend the engagement/findings surface: the dedup "merged" badges, a ranker picker per engagement, and a post-scripts panel (author/select + run, with the approve-each surfaced for command post-scripts). `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_finding_pipeline.py` — dynamic schema validates a finding + rejects a malformed one; dedup is idempotent (same finding twice → one, "merged 1"); a ranker rescored a fixture finding set into the right order; a data-only post-script runs in-process; a command post-script is **approve-each** (never auto-fires).
- Safety: schema/dedup/rank execute nothing; command post-scripts route through the executor; no new gate. Add to `run_safety_tests.sh`. Respect the 3-schema-places rule (a round-trip test that the new fields survive `response_model`).

## 4. Acceptance criteria
- Findings from any surface carry the structured schema; duplicates auto-merge idempotently; a selected ranker rescored them; post-scripts validate / build-PoC (approve-each) / report after a finding lands.
- Ranking/dedup/schema execute nothing; command post-scripts are gated; no new gate class.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- This is cross-cutting (improves all surfaces), independent of the AI code-audit spec — but they pair well (the fan-out is the heaviest dedup/rank consumer).
- Post-scripts compose with the existing validation gates + report-writer, they do not replace them.
- Ship the schema + dedup + rankers first; post-scripts second if a session runs short — say so in the PR.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: the engagement/findings surface.
- Headless-Edge screenshot (`headless-edge-screenshots`), app running, **synthetic** findings only:
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/engagements"
  ```
  **View it** — ranker picker + merged badges + post-scripts panel render (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (finding pipeline: schema/dedup/rankers/post-scripts).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
