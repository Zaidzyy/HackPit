# HackPit — full-project end-to-end audit (overnight brief)

**Written 2026-08-04 by the session that finished build #14 part 3.** Zaid is asleep. He
authorised this run explicitly; his answers are in §1. Read this whole file before doing anything.

The question he actually wants answered is not "do the tests pass". It is:

> **Can HackPit run a real bug bounty / a real engagement end to end today — and if not, exactly
> what is missing, what is limited, and what is being blocked by a gate rather than by reality?**

Everything below serves that question.

---

## 1. Authority — what Zaid decided before sleeping

| Decision | Answer |
|---|---|
| Real target | **He is naming one.** See `[[TARGET]]` below. |
| Latitude | **Fix + commit + push.** Fix what you find, run the suite, update the assessment, push to `main`. He wants to wake to green CI and a report. |
| Windows/AD VM | **UP and reachable** — `192.168.13.140:5985`, `Administrator@CORP`, secret set, connection tested. Drive the live WinRM / AD path as build #9 did. |
| LLM | **Ollama is running.** Use it, never the Agent SDK. |
| Classifier | **Work around it.** Do everything you can directly; for anything the real-time cyber classifier refuses, write a **self-verifying `.sh`** and leave it for him to run in a plain shell. Do not stall waiting for permission. |
| Scope | **The entire HackPit project** — every surface, not just build #14. |

### The targets — CONFIRMED AVAILABLE

**Windows / AD — full latitude.** `192.168.13.140:5985`, WinRM, `Administrator@CORP`, password
auth, secret already stored, connection tested and reaching. Zaid's own VM. Drive the entire
Windows/AD path against it as build #9 did — collection, graph, the gated abuse edges, DCSync,
the detection describe-side. Nothing is off limits here.

**Lab — full latitude.** `hackpit-lab-target` (Juice Shop) in the isolated sandbox. All
intrusive testing belongs here.

**LLM — Ollama is running.** Use it (never the Agent SDK).

**Real bug bounty program — Majid Al Futtaim Lifestyle (Bugcrowd), RetailSafe safe harbor,
ongoing since 2019.** In scope:

```
www.crateandbarrel.me            Cloudflare CDN, MySQL
https://api-prod.thatconceptstore.com/     API testing
https://thatconceptstore.com     API + website testing
https://www.cb2.ae/en            Akamai CDN
https://www.allsaints.me/        Akamai CDN
www.lululemon.me                 Akamai CDN
lapi.yellowblocks.me             Akamai CDN
https://www.shiseido.me/         Akamai CDN
lego.me
psychobunny.me                   Akamai CDN, Algolia
fashion4less.me
THAT Concept Store iOS / Android  (mobile app testing)
```

### 1.1 RULES OF ENGAGEMENT for the bug bounty targets — read twice

These are production retail sites belonging to a third party. In-scope testing is authorised by
the program; **an unattended overnight scanner is not what that authorisation contemplates**, and
it is also bad practice — it breaches the automation clauses most programs carry, gets the source
IP banned, and produces submissions that get rejected. It is additionally at odds with HackPit's
own central design: **every command is human-approved**, and Zaid is asleep.

So the split is deliberate, and it is not a limitation of the audit — it is the audit:

**DO, freely — this is where the real answer lives:**
- Scope modelling: load this program into an engagement. Wildcards? Out-of-scope lists? Mobile
  targets? Does the scope model even *fit* a real program? **This is hypothesis #6 and the most
  valuable thing you can test tonight.**
- Passive recon and OSINT: subdomain enumeration, DNS, certificate transparency, `httpx`
  fingerprinting, `waybackurls` / `gau`, JS endpoint mining, technology detection.
- Surface mapping into engagement state, then a rendered report.
- Everything that reads rather than attacks.

**DO NOT, under any circumstance:**
- Unattended active scanning. No `zaproxy -quickurl`, no `sqlmap`, no `ffuf`/`feroxbuster`
  brute-forcing, no `nuclei` with intrusive templates against these hosts.
- Anything that could degrade service, lock an account, or write data.
- Volume. If you probe at all, single requests at human pace.
- Chasing the CDN. Most of these sit behind **Akamai or Cloudflare** — naive scanning hits the
  edge, not the origin, and teaches you nothing except that a WAF exists.
- Continuing after any sign of blocking (403 wall, captcha, rate-limit). Stop and record it.
- Submitting anything anywhere. Findings are drafted for Zaid, never filed.

**Any active testing you believe is genuinely warranted goes into a `.sh` for Zaid to run and
approve in the morning** — which is exactly the workflow HackPit is built around, so exercising
that path *is* a valid test of the product.

If a target is unreachable, geo-blocked or otherwise not cooperating, do not fight it: note it,
move on, and use the lab and the DC. Zaid's words: *"if this target is not happening or smth let
claude do whatever it wants but do everything."*

---

## 2. Non-negotiables

These are project standing rules. Breaking one is worse than finding nothing.

1. **One branch: `main`.** Never create or push another.
2. **The assessment is not optional.** Every substantive change lands in
   `docs/ASSESSMENT-2026-07-26.md` **plus** regenerated html/pdf
   (`backend/.venv/Scripts/python.exe docs/build-assessment.py`) in the **same commit**.
   **You cannot grep the PDF** (Edge subsets fonts to glyph IDs) — verify against the **HTML**.
3. **Gate every verification on a captured exit code.** `cmd > log 2>&1; echo "EXIT=$?"`.
   `cmd | tail && git commit` does **not** gate — this has shipped broken work three times.
4. **Never widen a safety allow-list so new code fits.** Fix the *predicate*, never narrow the
   file set. (Build #5.)
5. **Do not re-ingest the KB.** `data/kb/entries.jsonl` is **gitignored** — there is no commit to
   fall back on. Last night a `PATH`-stripped test run silently dropped an entry. If
   `test_corpora.py` or `test_kb_fixture.py` fails, **re-run it first** (it flakes right after an
   ingest), and check `wc -l data/kb/entries.jsonl` is **2743** before assuming damage.
6. **Windows Defender deletes `entries.jsonl`** on some writes. Verify it exists after anything
   that touches it.
7. **Never simulate CI by stripping `PATH`** — it also removes `git`, and the ingester's recovery
   path needs it. Simulate by running the *specific* test files.
8. If the classifier blocks a command, write the `.sh` and move on — do not stall.

---

## 3. Where things are

```
backend/          FastAPI + the cockpit package (gates, executor, all surfaces)
backend/run_safety_tests.sh     71 hermetic files; the safety spine
docker/proof/     live proofs (need the stack up)
frontend/         Next 16 app, 18 surfaces
docs/ASSESSMENT-2026-07-26.md   the running record — READ THE LAST ~400 LINES FIRST
docs/superpowers/specs/         design specs per build
pipeline/, data/kb/             the knowledge base (DO NOT re-ingest)
```

Bring the stack up: `docker compose -f docker/docker-compose.yml up -d`
Suite: `sh backend/run_safety_tests.sh` → expect **71 files, 0 failures**
Proofs: `sh docker/proof/zap_scan_proof.sh` (8/0), `zap_proxy_proof.sh` (7/0),
`zap_install_proof.sh` (9/0), `isolation_proof.sh`, `engage_open_proof.sh`
Frontend: `cd frontend && npm run dev` → localhost:3000 (backend: `uvicorn main:app --port 8000`)
LLM: **Ollama, not the Agent SDK** (Zaid's rule) — `ollama serve` first; it was NOT running.

---

## 4. What to test — every surface, end to end

Do not trust a green suite. Build #7 and #9 both found defects a green suite could not see,
because the tests asserted structure that nothing had ever executed. **Execute everything.**

### 4.1 The 18 surfaces (drive each in the BROWSER, not just via curl)
`:cockpit` `:terminal` `:kali` `:repeater` `:proxy` · `:c2` `:tunnels` `:windows` `:evasion`
`:oob` `:exposure` · `:attack-paths` `:engagements` `:ad-graph` `:code-scan` · `:exploits`
`:arsenal` `:scripts` `:detection`

For each: does it render, does every control work, does every button reach a real endpoint, does
it show *observed* state rather than assumed, and does its error path say something useful?

⚠ **A frontend change is not verified until it has been LOOKED AT.** `tsc` + `next build` +
`eslint` all pass on a screen that renders nothing — the `:proxy` screen was invisible for two
builds with everything green (bare `.hp-card` is `opacity:0`; six of its classes did not exist).
See the `frontend-class-vocabulary` memory before touching any screen.

### 4.2 The safety spine — prove each gate FIRES, and prove it can fail
allowlist → target-lock/scope → approval → danger red-confirm → isolation. For each: a refusal
**and** a positive control in the same check. The 2026-07-27 gate audit probed 24 guards and
found **seven that existed and never fired**. Assume there is an eighth.

### 4.3 The execution modes
lab (isolated sandbox) · engagement (fully open, Wall A down) · Windows/WinRM · `:kali` open box
· PTY terminal. Drive a real command through each.

### 4.4 The data path
run → parse → state (hosts/services/creds/findings/endpoints) → report. Feed each parser real
tool output and confirm the finding reaches a rendered report **with secrets redacted**.

---

## 5. The questions Zaid actually asked — answer each explicitly

Give a direct verdict per item, with evidence. "Probably fine" is not an answer.

1. **Can it run a full bug bounty today?** Walk the **real Majid Al Futtaim program** end to end
   within the §1.1 rules: load the scope → recon → surface discovery → map into state → draft a
   report. For the intrusive half, walk the same workflow against the **lab** and reason honestly
   about what would differ against production. Where does it stop being usable?
   Answer these specifically:
   - Can you even **express** this program's scope? 11 web/API targets, several wildcarded in
     practice, **two mobile apps**, a CDN in front of most of them.
   - HackPit has **no mobile execution surface** — iOS/Android are 2 of 4 scope categories here.
     Is that a gap worth closing, or correctly out of scope for this product?
   - Does anything model **known issues** / duplicate suppression, which every mature program has?
   - Is the report output shaped for **Bugcrowd/H1 (VRT, P1–P4, CVSS)**, or only for exams?
2. **What is limited *by the lab* rather than by design?** Zaid's explicit instruction: *if a
   feature is only limited because of the lab, we can skip the lab case and implement it for
   engagements only.* Name every such case.
3. **Is any gate restricting something legitimate?** A gate that blocks real work trains the
   operator to click through — that is its own safety failure. Name each one and propose the
   narrowest fix.
4. **What is missing for real-world engagements?** Features, not polish.
5. **Is the build done?** A straight yes/no with the list that makes it true.

### Hypotheses to verify — DO NOT TRUST THIS LIST, test each
These come from project memory and last night's work. Several may be wrong; some may be worse
than stated.

- **The app has ZERO route auth.** Anything that can reach the backend can drive it, and
  `/cockpit/terminal/ws` is an unauthenticated PTY. Fine on localhost; blocking for anything
  hosted. Is this still true?
- **Browser interception is blocked** — ZAP's `api.key` was MEASURED to enforce nothing, and its
  proxy and API share one listener, so publishing the port for a browser also publishes an
  unauthenticated scan trigger. Three candidate fixes exist, **none verified**.
- **No authenticated scanning** — no ZAP contexts/sessions, so anything behind a login is
  unreachable by the active scanner.
- **Approve-every-command** is by design and correct — but is it *workable* for a bug bounty
  sweep of hundreds of endpoints? Is there any batching/queue, and should there be?
- **Bug bounty reporting** — exam/OSCP templates exist. Is there an H1/Bugcrowd-shaped report?
  CVSS? A dedupe against known-issue lists?
- **Scope handling** — do engagements support wildcard scopes (`*.example.com`) and explicit
  out-of-scope lists, which every real program has?
- **Rate limiting / program rules** — most programs forbid unthrottled automation. Is there any
  throttle at all?
- **Concurrency** — one engagement at a time? One proxy per container (ZAP locks its home dir).
  What else is accidentally single-tenant?
- **Coverage gaps** — mobile, wireless, cloud exec, source-to-exploit. KB content exists; does
  *execution* exist?
- **4 offensive proofs are NOT-RUN by choice** in the proof harness. Should they still be?

---

## 6. Deliverables

1. **`docs/AUDIT-2026-08-04.md`** — the report. Verdict per §5 question, evidence per claim,
   and an explicit **NOT-RUN** list. Never let an untested thing read as passing.
2. **A punch list**, severity-ordered, separating *bug* / *missing feature* / *over-tight gate* /
   *lab-only limitation*.
3. **Fixes committed and pushed** for everything you can safely fix, suite green, assessment
   updated in the same commit.
4. **`.sh` scripts** for anything the classifier blocked, with a one-line "run this" for Zaid.
5. **Memory updates** — new traps and decisions, index line in `MEMORY.md` (keep it under 17KB).

---

## 7. Traps that will cost you hours if you skip them

- **The container is NOT the image.** `compose up -d` does not recreate a running container after
  a rebuild. Use `up -d --force-recreate <svc>`; compare image IDs.
- **MSYS rewrites container paths** — `MSYS_NO_PATHCONV=1` on any `/tmp/...` you hand Docker.
- **bash `/tmp` ≠ Windows-Python `/tmp`.** Pipe into python; never stage through a host file.
- **An exit code is not a result.** ZAP exits non-zero for both success and failure.
- **`pkill -f` matches its own command line** — write `[z]aproxy`.
- **The spawned argv is not the running argv** — wrappers exec the JVM.
- **ZAP locks its HOME DIR, not its port** — one daemon per container, whatever the port.
- **AST, not substring**, when scanning source for calls — docstrings will fool a grep.
- **`main.app.routes` shows no `/cockpit` routes even though they serve fine.** Use
  `TestClient(main.app).get(...)` — it is decisive; the route list is not.
- **Browser automation:** clicks on an enabled button did not always dispatch to React last
  night. If a click seems ignored, verify against the backend log before concluding the UI is
  broken — and stop after 2–3 attempts rather than burning the night on it.

---

## 8. Definition of done for the night

- Every surface in §4.1 driven in a browser, with a verdict.
- Every gate in §4.2 proven to fire **and** proven able to fail.
- Each §5 question answered with evidence.
- `sh backend/run_safety_tests.sh` green; all live proofs green or explicitly NOT-RUN with a reason.
- Report + punch list written; fixes pushed; CI green.
- `data/kb/entries.jsonl` still **2743** entries.
- **Nothing was submitted anywhere, and no unattended active scan touched a third-party host.**
  If §1.1 was breached in any way, say so at the top of the report in plain words.
