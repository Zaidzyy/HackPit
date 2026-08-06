# Build spec — Nuclei template-scan surface (`:nuclei`)

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-06.
**One line:** a first-class gated nuclei surface — scoped target(s) → templates → results mapped to engagement `Finding`s — the bug-bounty staple, mirroring the existing ZAP-active-scan job. **Lowest-effort of the four; the plumbing already exists.**

---

## 0. Guiding constraint (read first)

Adds **NO new gate.** A nuclei run is **one approved job** (`cockpit/jobs.py`) with the existing **ungated stop button** — exactly how ffuf / the ZAP active scanner already work (`cockpit/router.py` ~line 788 names nuclei as one of these single-command jobs). One human approval starts the whole scan; it streams progress; stop halts it. No per-template approval, no autonomy.

## 1. Read-first
- `backend/cockpit/jobs.py` — the job engine (nuclei is already anticipated here; check whether a nuclei runner exists and extend it rather than duplicating).
- `backend/cockpit/router.py` — the ZAP active-scan and ffuf job routes + the stop route (copy the shape).
- `backend/cockpit/graphql_zap.py` — how a scanner's alerts become structured results, and `backend/state/ingest.py` (`store.upsert_findings`) — how results become `Finding`s. This is the mapping to copy.
- `backend/state/models.py` — `Finding(title, severity[info|low|medium|high|critical], target, evidence, tool, reference)`. Nuclei severity maps 1:1; `reference` = the template id.
- `backend/cockpit/scope.py` — `parse_scope`, `ResolvedScope.in_scope` (targets must be in the engagement scope in engagement mode, as an inherited handrail — do NOT add a stronger gate).
- `backend/arsenal/tools.json` — `nuclei` is catalogued; confirm it's in `docker/Dockerfile.sandbox`.
- Frontend: `frontend/src/components/CodeScanScreen.tsx` and `ProxyScreen.tsx` (findings-list screens to mirror), `CockpitState.tsx` (where findings render).

## 2. What to build

### Backend — `backend/cockpit/nuclei.py` (new, or extend `jobs.py` if a stub exists)
1. **Build the argv** (never a shell): `nuclei -u <target> -jsonl -severity <...> -tags <...> -t <template dirs>`, targets from the engagement's in-scope hosts/URLs (pull from `state` endpoints/hosts or an operator list). Output JSONL to a job loot file.
2. **Run as a job** via `jobs.py` behind `executor.validate_request` (approval gate) — reuse the ZAP-active-scan job path.
3. **Parse nuclei JSONL → `Finding`s** and `upsert_findings`: `info.name`→title, `info.severity`→severity, `matched-at`→target, `template-id`→reference, curl/matcher output→evidence, `tool="nuclei"`. Dedupe by (template-id, matched-at).
4. **Template management (read-only)**: expose the installed template catalogue (`nuclei -tl` / the templates dir) so the operator can pick tags/severities. A "update templates" action, if included, is itself a gated job.

### Backend — routes (`cockpit/router.py`)
`POST /cockpit/nuclei/scan` (gated job → findings), `GET /cockpit/nuclei/templates` (list, executes nothing), reuse the existing job **stop** route.

### Frontend — `/nuclei` + `NucleiScreen.tsx`
Mirror `CodeScanScreen.tsx`: pick targets (default = in-scope endpoints from state) + severity/tags, show the exact argv, one Approve, live finding count, results table (severity-ranked) linking into `CockpitState.tsx` findings. `hp-tn-*`; look at the screen before done.

## 3. Tests
- `backend/test_nuclei.py` — argv building from scope/state, nuclei JSONL → `Finding` mapping (feed a captured sample JSONL fixture, like the ZAP scan tests feed a chosen alert string), dedupe.
- `backend/test_nuclei_safety.py` — module builds argv + parses JSON only; the scan goes through `validate_request`; scope handrail applies in engagement mode. Add both to `run_safety_tests.sh`.
- Note the `zap_install_proof`-style lesson: a hermetic test feeds the parser a string it chose, so it can't prove the image's `nuclei` accepts the flags. If practical, add a tiny image proof (`docker/proof/nuclei_proof.sh`) that runs `nuclei -version`/a no-op template; otherwise state it as NOT-RUN honestly (mirror the CI "Report what could not run here" discipline).

## 4. Acceptance criteria
- A nuclei scan runs as ONE approved job with a working ungated stop; results appear as severity-ranked `Finding`s in engagement state and the report.
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Default target set = in-scope endpoints/hosts already in engagement state; operator can paste an explicit list.
- Findings go into the same engagement `Finding` store the report already renders (no separate store).
- Template updates are an explicit gated job, not automatic.

---

## 6. README + screenshot — do this exactly like the 2026-08-06 README session

**Not done until the README and a real screenshot ship with it.** New screen route: **`/nuclei`**.

- **Capture a real lab-state screenshot** with headless Edge (the `headless-edge-screenshots` method). With the app running:
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/nuclei"
  ```
  **View it** to confirm it rendered (a findings table against a lab target reads best), not a blank/error page.
- **Never a real target in a public screenshot.** Lab / OWASP Juice Shop / example.com only.
- **Add the screenshot** to `assets/screenshots/` with the next free number and commit it.
- **Add a concise README feature section** in the existing voice + a row in the "What you get, at a glance" table.
- **Update `docs/ASSESSMENT-2026-07-26.md`** + regenerate html/pdf in the **same commit** (`keep-assessment-current`).
- **Look at the screen** (`frontend-class-vocabulary`): use `hp-tn-*`, never a bare `hp-card`.
