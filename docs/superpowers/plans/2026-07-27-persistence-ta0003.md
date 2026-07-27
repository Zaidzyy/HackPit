# Persistence / backdoors (TA0003) enrich — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the knowledge / reference / describe layer for MITRE TA0003 (Persistence) to HackPit — a KB methodology pair, four arsenal catalog entries, and a per-mechanism detection-footprint layer — without adding any execution capability.

**Architecture:** Three additive, independently-testable slices mirroring the reconFTW pass: (1) a KB ingester cloned from `ingest_recon_methodology.py`; (2) four `tools.json` catalog entries (CRLF-preserving splice); (3) new `attck.py` technique rows + `catalog.py` `FootprintSpec`s (blue/describe side only). All existing gates, guards, and the execution path are untouched.

**Tech Stack:** Python 3 (backend `.venv/Scripts/python.exe`, has `markdown` 3.10.2), Pydantic `Entry` schema, python-markdown, Edge headless for PDF. Tests are plain scripts run from `backend/`.

## Global Constraints

- **No new execution capability, no persistence engine/autorunner.** Knowledge/catalog/describe only. The gated-executor path for persistence commands is left exactly as is.
- **No image rebuild.** If any item seems to require an install, STOP and ask.
- **Frameworks reference-only:** Sliver, Empire, weevely reference-only (not installed); SharPersist `platform:windows`. Reconcile suppresses not-installed tools from the planner — intended.
- **`attck.py` edits are purely additive** — new technique rows only; do not perturb any existing row or mapping. `pipeline/detection_sources.py --verify` must confirm.
- **Detection = `FootprintSpec` (blue/describe) only.** No `OpsecNote`s (that channel is build #4). Honesty ("quiet = defender coverage gap, not operator advantage; X still records it") lives in each spec's `why_rating`. `assert_opsec_is_separate` and `assert_describes_not_prescribes` stay untouched.
- **`tools.json` is CRLF; `.py` is LF.** Preserve CRLF on any edit; verify `git diff --cached --stat` is clean-additive, not a line-ending flip. `executes_nothing` stays `true`.
- **KB ingester marker** `persistence_methodology` (distinct from `corpus_ingest`, `recon_methodology`); `no_merge: true`; corpus block segregated to tail; byte-preserving; idempotent; post-write count assert.
- **No strikethrough** (`~~…~~`) in the assessment doc — python-markdown core doesn't support it.
- **Interpreter:** `backend/.venv/Scripts/python.exe`. Tests run from `backend/` as plain scripts. Full suite: `sh backend/run_safety_tests.sh`.
- Commit message ends with: `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`. Branch: `sandbox-kali-image`.

---

### Task 1: KB persistence-methodology ingester + two entries

**Files:**
- Create: `pipeline/ingest_persistence_methodology.py`
- Reference (clone from): `pipeline/ingest_recon_methodology.py`
- Data touched (gitignored, not committed): `data/kb/entries.jsonl`
- Verify with: `backend/test_corpora.py`

**Interfaces:**
- Produces: a script with `--dry-run`, and `main()` writing two `Entry` rows with ids `persistence-methodology-windows`, `persistence-methodology-linux`, each carrying `meta["persistence_methodology"] = True`, `meta["no_merge"] = True`.
- Consumes: `pipeline/schema.py::Entry` (same import shim as the recon ingester).

- [ ] **Step 1: Clone the ingester structure.** Copy `pipeline/ingest_recon_methodology.py` to `pipeline/ingest_persistence_methodology.py`. Change `MARK = "persistence_methodology"`, `SOURCE = "hackpit-methodology"`, `SOURCE_LABEL = "HackPit persistence methodology (TA0003 mechanism map)"`. Keep the `merge()` function **verbatim** — the `[head, added, corpus_tail]` fixed-point order and `CORPUS_MARK` handling are exactly what keeps `test_corpora` byte-identical. Keep the atomic write and the post-write count assert.

- [ ] **Step 2: Author the two entries** in `_entries()`. Each is a `checklist` entry, `category="persistence"`, `tier=2`, `source=SOURCE`, `meta=_meta("checklist")`. Use only commands that already appear in the corpus. Structure each `steps=[{n, text, code:[{lang, cmd}]}]` with one command per TA0003 mechanism, and a `body_md` mechanism map that names, per mechanism, the ATT&CK id **and** a one-line "what the defender sees → see the detection footprint" pointer. Advisory ordering; not an auto-chain.

  Entry 1 — `persistence-methodology-windows`, title *"Windows host persistence — the mechanism map (TA0003)"*. Mechanisms + representative command (illustrative — keep commands corpus-faithful):
  - Registry Run/RunOnce keys (T1547.001): `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v <name> /t REG_SZ /d "<payload>" /f`
  - Startup folder / shortcut (T1547.001): drop a `.lnk`/script into `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
  - Scheduled task (T1053.005): `schtasks /create /sc onlogon /tn <name> /tr "<payload>" /rl highest`
  - Service (T1543.003): `sc create <name> binPath= "<payload>" start= auto`
  - WMI event subscription (T1546.003): `wmic /namespace:\\root\subscription PATH __EventFilter CREATE ...` (permanent filter→consumer binding)
  - Accessibility / IFEO (T1546.008): sethc/utilman replacement or `Image File Execution Options` debugger key
  - Backdoor account + privileged group (T1136.001 / T1098): `net user <u> <p> /add` then `net localgroup administrators <u> /add`
  - Web shell (T1505.003): drop a script into the web root

  Entry 2 — `persistence-methodology-linux`, title *"Linux host persistence — the mechanism map (TA0003)"*. Mechanisms:
  - Cron / `/etc/cron.d` (T1053.003): `(crontab -l; echo "@reboot <payload>") | crontab -`
  - systemd unit + timer (T1543.002 / T1053.006): a `.service` (+ optional `.timer`) under `/etc/systemd/system/` then `systemctl enable`
  - SSH `authorized_keys` (T1098.004): append a public key to `~/.ssh/authorized_keys`
  - Shell-init profile (T1546.004): append to `~/.bashrc` / `/etc/profile.d/<x>.sh`
  - Backdoor account / `/etc/passwd` (T1136.001): `useradd`, or an appended `/etc/passwd` line with a known hash
  - KB-only note: rootkits/bootkits are knowledge here, never tooling.

  Both entries cite `references=["https://attack.mitre.org/tactics/TA0003/"]`.

- [ ] **Step 3: Dry-run.** Run and confirm it reports two ids and would replace 0 existing marker lines:
  ```
  backend/.venv/Scripts/python.exe pipeline/ingest_persistence_methodology.py --dry-run
  ```
  Expected: `would write 2 entries: ['persistence-methodology-windows', 'persistence-methodology-linux']` and `existing persistence_methodology lines that would be replaced: 0`.

- [ ] **Step 4: Real run + Defender-quarantine check.** Run without `--dry-run`. Expected: prints the merge report, post-write count assert passes, KB line count grows by exactly 2. Then confirm the file still exists and is readable (`wc -l data/kb/entries.jsonl`) — the [[defender-quarantines-kb-file]] trap.

- [ ] **Step 5: Idempotent byte-identical re-run.** Snapshot, re-run, diff:
  ```bash
  cp data/kb/entries.jsonl /tmp/kb_before.jsonl
  backend/.venv/Scripts/python.exe pipeline/ingest_persistence_methodology.py
  cmp /tmp/kb_before.jsonl data/kb/entries.jsonl && echo "BYTE-IDENTICAL"
  ```
  Expected: `BYTE-IDENTICAL` (report shows `own_lines_replaced: 2`, `own_lines_written: 2`).

- [ ] **Step 6: `test_corpora` stays byte-identical.** From `backend/`:
  ```
  cd backend && .venv/Scripts/python.exe test_corpora.py
  ```
  Expected: PASS (the corpus-ingest block was preserved at the tail; no drift).

- [ ] **Step 7: Commit** (code only — `entries.jsonl` is gitignored):
  ```bash
  git add pipeline/ingest_persistence_methodology.py
  git commit -m "kb: add TA0003 persistence methodology ingester (Windows + Linux mechanism maps)"
  ```

---

### Task 2: Arsenal — persistence category + four catalog entries

**Files:**
- Modify: `backend/arsenal/tools.json` (CRLF-preserving splice)
- Verify with: `backend/test_arsenal.py`, `backend/test_arsenal_safety.py`

**Interfaces:**
- Produces: four new objects in the `tools` array with `category: "persistence"` — `SharPersist`, `Sliver`, `Empire`, `weevely`. Tool count 101 → 105.

- [ ] **Step 1: Confirm the CRLF baseline.** `file backend/arsenal/tools.json` or `python -c "print(open('backend/arsenal/tools.json','rb').read().count(b'\r\n'))"` — note the count; the final diff must add only new lines, not flip existing ones.

- [ ] **Step 2: Add the four entries** to the end of the `tools` array, following the exact per-tool shape (`name/category/purpose/phases/techniques/docs/templates/flags`, plus `platform`/`aliases` where relevant). Perform the edit as a **textual splice that preserves CRLF** on every line (or write the whole file back with `newline="\r\n"`). Content:

  - **SharPersist** — `platform: "windows"`, `aliases: ["SharPersist.exe"]`, `category: "persistence"`, `phases: ["post-exploitation"]`, `techniques: ["scheduled task","registry autorun","startup folder","service","persistence"]`, `docs: "https://github.com/mandiant/SharPersist"`. `templates`: a KeePass/scheduled-task/registry example using the established placeholder convention, e.g. `SharPersist -t schtask -c "<payload>" -n "<taskname>" -m add`, `SharPersist -t reg -c "<payload>" -a "<value>" -k "hkcurun" -m add`, `SharPersist -t startupfolder -c "<payload>" -f "<name>" -m add`. `flags`: `-t` (technique), `-m` (add/remove), `-c` (command), `-k` (registry key location).
  - **Sliver** — reference-only. `category: "persistence"`, `phases: ["command-and-control","post-exploitation"]`, `techniques: ["C2","implant persistence","beaconing"]`, `docs: "https://github.com/BishopFox/sliver"`, `purpose` names it as a C2 framework whose install + wiring is **deferred to build #4**; `templates: []` (no invocation templates — not installed).
  - **Empire** — reference-only. `category: "persistence"`, `phases: ["command-and-control","post-exploitation"]`, `techniques: ["C2","PowerShell/Python agents","persistence modules"]`, `docs: "https://github.com/BC-SECURITY/Empire"`, `purpose` notes install deferred to #4; `templates: []`.
  - **weevely** — reference-only. `category: "persistence"`, `aliases: ["weevely3"]`, `phases: ["post-exploitation"]`, `techniques: ["web shell","T1505.003"]`, `docs: "https://github.com/epinna/weevely3"`, `purpose` = obfuscated PHP web-shell generator/manager (not installed). One shape-only template: `weevely generate <password> <output.php>` / `weevely <url> <password>`.

- [ ] **Step 3: Validate JSON + count + CRLF.**
  ```bash
  python -c "import json;d=json.load(open('backend/arsenal/tools.json'));print(len(d['tools']));import collections;print(collections.Counter(t['category'] for t in d['tools'])['persistence'])"
  git add backend/arsenal/tools.json && git diff --cached --stat
  ```
  Expected: `105`, persistence `4`, and the `--stat` shows a small additive line delta (not ~3800 lines changed). If the stat shows a whole-file churn, the CRLF was flipped — revert and redo the splice.

- [ ] **Step 4: Arsenal tests.**
  ```
  cd backend && .venv/Scripts/python.exe test_arsenal.py && .venv/Scripts/python.exe test_arsenal_safety.py
  ```
  Expected: both PASS at 105 tools; `executes_nothing` still true, no gate bypassed. If `test_arsenal.py` hard-codes a tool count, update that constant as part of this task.

- [ ] **Step 5: Commit.**
  ```bash
  git commit -m "arsenal: add persistence category (SharPersist, Sliver, Empire, weevely — reference-only)"
  ```

---

### Task 3: `attck.py` — additive persistence technique rows

**Files:**
- Modify: `backend/detection/attck.py` (append rows to the `TECHNIQUES` list only)
- Verify with: `pipeline/detection_sources.py --verify`

**Interfaces:**
- Produces: `TECHNIQUES` entries for `T1547.001`, `T1543.003`, `T1543.002`, `T1053.003`, `T1053.006`, `T1546.003`, `T1546.004`, `T1546.008`, `T1136.001`, `T1505.003`, `T1098.004`. (`T1053.005`, `T1098` already exist — **reuse, do not duplicate or edit**.)
- Consumed by: Task 4's `FootprintSpec`s (their `techniques` tuples resolve through `attck.get`).

- [ ] **Step 1: Append rows** using the existing `_t(id, name, tactics, components, logs, det="")` helper, inside the `TECHNIQUES` list, after the last existing row — **touching no existing line**. Each `tactics` string must include `TA0003`. `components` (`;`-separated) and `logs` (`;`-separated) must be **transcribed from ATT&CK v19.1's own detection strategy** for that technique and kept to the Windows/Linux/network subset (macOS/cloud/ESXi entries dropped — `log_sources` must be a SUBSET of upstream, never a superset). Worked example (verify the exact strings against `--verify` output):
  ```python
  _t("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
     "TA0003 TA0004",
     "Windows Registry Key Creation; Windows Registry Key Modification; File Creation; "
     "Command Execution",
     "WinEventLog:Security EventCode=4657; WinEventLog:Microsoft-Windows-Sysmon/Operational "
     "EventCode=13; WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11"),
  _t("T1543.003", "Create or Modify System Process: Windows Service", "TA0003 TA0004",
     "Service Creation; Service Modification; Command Execution; Windows Registry Key Modification",
     "WinEventLog:System EventCode=7045; WinEventLog:Security EventCode=4697"),
  ```
  Add the remaining nine the same way (Linux ones cite `auditd`/`journald`/`Linux:` log sources).

- [ ] **Step 2: Internal check (offline).**
  ```
  backend/.venv/Scripts/python.exe pipeline/detection_sources.py   # no --verify: runs check_internal only
  ```
  Expected: no internal errors (every technique id referenced elsewhere resolves; no malformed rows).

- [ ] **Step 3: Live `--verify`** (needs network — ATT&CK + SigmaHQ):
  ```
  backend/.venv/Scripts/python.exe pipeline/detection_sources.py --verify
  ```
  Expected: every new technique id/name/tactic/log-source confirmed present upstream and a subset. **Trim any `log_sources` line `--verify` flags as not-upstream** — never invent to satisfy a spec. Existing rows must still pass unchanged (proves additivity).

- [ ] **Step 4: Commit.**
  ```bash
  git add backend/detection/attck.py
  git commit -m "detection(attck): add TA0003 persistence technique rows (additive, ATT&CK v19.1)"
  ```

---

### Task 4: `catalog.py` — persistence FootprintSpecs, aliases, Sigma (describe side only)

**Files:**
- Modify: `backend/detection/catalog.py` (append to `SPECS`, `ALIASES`, and `SIGMA` — no edits to `OPSEC`, no `OpsecNote`s)
- Verify with: `backend/test_detection.py`, `backend/test_detection_safety.py`, `pipeline/detection_sources.py --verify`

**Interfaces:**
- Consumes: Task 3's technique ids.
- Produces: 13 `FootprintSpec`s keyed `persist_registry_run`, `persist_startup_folder`, `persist_scheduled_task`, `persist_service`, `persist_wmi_event`, `persist_accessibility`, `persist_account_windows`, `persist_webshell`, `persist_cron`, `persist_systemd`, `persist_ssh_authkeys`, `persist_shell_profile`, `persist_account_linux`; matching `ALIASES` for unambiguous binaries.

- [ ] **Step 1: Add Sigma rules (verified only).** For mechanisms with a real SigmaHQ rule, add a `SIGMA[...]` entry with the true UUID/title/path/level (e.g. Run-key, new-service `7045`, scheduled-task creation, WMI persistence, new-local-user rules). Do not add a Sigma key you cannot cite exactly — `--verify` (Step 5) will reject invented UUIDs. Leave a spec's `sigma` empty where no rule is confidently known (allowed — `dns_enum` ships empty).

- [ ] **Step 2: Add the 13 `FootprintSpec`s** to `SPECS` via the existing `_f(key, label, techniques, sigma, telemetry, loudness, blue_view, why_rating)` helper. `telemetry` is `;`-separated concrete observations; `loudness` ∈ {quiet, moderate, notable, loud}; `why_rating` carries the honesty marker. Two fully-worked examples pinning the voice (author the other 11 to the §3.3 table in the spec, same voice):
  ```python
  _f("persist_registry_run", "Persistence via Registry Run/RunOnce key", "T1547.001", "",
     "Sysmon EID 13: a value written under a ...\\CurrentVersion\\Run key; "
     "Security 4657 (registry value modified) where registry auditing is on; "
     "reg.exe / powershell in the 4688 process-creation record; "
     "Autoruns / EDR autostart baseline enumerates the new value on the next sweep",
     "quiet",
     "A new value under a Run key — invisible in real time unless registry auditing is on, but "
     "sitting in plain view of any autostart baseline.",
     "Quiet: Run-key writes are rarely audited live, so detection leans on autostart baselining "
     "(Autoruns/EDR). That reliance is the defender's coverage gap to close, not an operator "
     "advantage — the value is durable on disk and enumerable at any time."),
  _f("persist_account_windows", "Persistence via backdoor account / privileged group",
     "T1136.001 T1098", "",
     "Security 4720 (user account created); "
     "Security 4722 (account enabled); "
     "Security 4732/4728 (added to a privileged local/global group), naming who added whom; "
     "net.exe / net1.exe in the 4688 process-creation record",
     "loud",
     "A new account appearing and being added to a privileged group — among the most closely "
     "watched events in any directory or host log.",
     "Loud: 4720/4732 are collected almost everywhere and usually sit on a watchlist; the events "
     "name the actor, so this is durable evidence as well as a live alert."),
  ```

- [ ] **Step 3: Add `ALIASES`** for unambiguous persistence binaries only — do NOT blanket-alias multi-purpose binaries (`reg`, `sc`, `net`, `systemctl`, `ssh-keygen`):
  ```python
  "schtasks": "persist_scheduled_task",
  "crontab": "persist_cron",
  "useradd": "persist_account_linux", "adduser": "persist_account_linux",
  "sharpersist": "persist_scheduled_task", "sharpersist.exe": "persist_scheduled_task",
  "weevely": "persist_webshell",
  ```

- [ ] **Step 4: Detection tests.**
  ```
  cd backend && .venv/Scripts/python.exe test_detection.py && .venv/Scripts/python.exe test_detection_safety.py
  ```
  Expected: both PASS. `test_detection_safety` proves `assert_describes_not_prescribes` still holds over the new blue lines and `assert_opsec_is_separate` is unaffected (no opsec notes added). If a `why_rating`/`blue_view` string trips the never-prescribe guard, rephrase it as description ("X still records this") — never as advice.

- [ ] **Step 5: Live `--verify` (full).**
  ```
  backend/.venv/Scripts/python.exe pipeline/detection_sources.py --verify
  ```
  Expected: every new technique id AND every newly-cited Sigma UUID/title/path confirmed against live ATT&CK v19.1 + SigmaHQ. Drop anything flagged.

- [ ] **Step 6: Commit.**
  ```bash
  git add backend/detection/catalog.py
  git commit -m "detection(catalog): add TA0003 persistence footprints + aliases (describe-side only)"
  ```

---

### Task 5: Assessment doc + HTML + PDF

**Files:**
- Modify: `docs/ASSESSMENT-2026-07-26.md` (new PART III subsection; short PART II ledger line)
- Regenerate: `docs/ASSESSMENT-2026-07-26.html`, `docs/ASSESSMENT-2026-07-26.pdf`

- [ ] **Step 1: Write the PART III subsection** *"Persistence (TA0003) enrich"* — what was audited (the cloud-vs-host correction; mechanisms present at command level, methodology absent), what was added across KB / arsenal / detection, the reference-only framework decision (Sliver/Empire/weevely install deferred to #4), and "no new execution capability." Add one line to the PART II gaps ledger if it fits. Match the doc's voice; **no strikethrough**.

- [ ] **Step 2: Regenerate the HTML.** Split the current `.html` on the literal marker `<div class="toc"><span class="toctitle">Contents</span>`, reuse everything before it verbatim (head/style/cover), then append that marker + a **fresh** ToC (the Markdown instance's `.toc`) + `</div></div>` + the converted body + `</body></html>`. Convert the `.md` with python-markdown extensions `[tables, fenced_code, toc, sane_lists, attr_list]` via `backend/.venv/Scripts/python.exe`.

- [ ] **Step 3: Regenerate the PDF** with Edge headless:
  ```
  "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu --no-pdf-header-footer --print-to-pdf="C:\Users\zaid_\Downloads\HackPit\docs\ASSESSMENT-2026-07-26.pdf" "file:///C:/Users/zaid_/Downloads/HackPit/docs/ASSESSMENT-2026-07-26.html"
  ```

- [ ] **Step 4: Verify outputs.** The `.html` still carries the reused `<style>` + cover and a fresh ToC that now includes the persistence section; the `.pdf` starts with `%PDF` and is multi-page:
  ```bash
  head -c 5 docs/ASSESSMENT-2026-07-26.pdf; echo
  grep -c 'persistence\|Persistence' docs/ASSESSMENT-2026-07-26.html
  ```

- [ ] **Step 5: Stage** (commit happens in Task 6 with the full suite green):
  ```bash
  git add docs/ASSESSMENT-2026-07-26.md docs/ASSESSMENT-2026-07-26.html docs/ASSESSMENT-2026-07-26.pdf docs/superpowers/
  ```

---

### Task 6: Full safety suite + push

**Files:** none new — validation + delivery.

- [ ] **Step 1: Run the full safety suite.**
  ```
  sh backend/run_safety_tests.sh
  ```
  Expected: all checks PASS — including `test_detection`, `test_detection_safety`, `test_arsenal`, `test_arsenal_safety`, `test_corpora`.

- [ ] **Step 2: Final diff review.** `git status` and `git diff --cached --stat` — confirm: only the intended files staged; `entries.jsonl` is NOT staged (gitignored); `tools.json` shows an additive delta, not a CRLF flip; no changes to `resolver.py`, `OPSEC`, the executor, or the Dockerfile.

- [ ] **Step 3: Commit the assessment + any remaining staged docs.**
  ```bash
  git commit -m "assessment: fold in the Persistence (TA0003) enrich; regen .html/.pdf"
  ```

- [ ] **Step 4: Push.**
  ```bash
  git push origin sandbox-kali-image
  ```

- [ ] **Step 5: Update memory.** Add/refresh a memory noting: the cloud-vs-host audit correction, the FootprintSpec-only detection decision, the four reference-only arsenal tools, and that Sliver/Empire/weevely install is deferred to build #4.

---

## Self-Review

**Spec coverage:** §3.1 KB → Task 1; §3.2 arsenal → Task 2; §3.3a attck.py → Task 3; §3.3b–d catalog/aliases/Sigma → Task 4; §4 verification → folded into each task + Task 6; §5 assessment/PDF → Task 5; §6 commit/push → Tasks 1–6. All covered.

**Placeholder scan:** code steps carry real commands and worked code; the 11 un-worked FootprintSpecs are pinned by two full examples + the spec's §3.3 data table + the never-prescribe guard as the gate (data authoring, not hand-waved structure). No TBD/TODO.

**Type consistency:** `_t(id,name,tactics,components,logs,det="")`, `_f(key,label,techniques,sigma,telemetry,loudness,blue_view,why_rating)`, `Entry(...)` with `meta["persistence_methodology"]` — all match the real signatures confirmed in `attck.py`, `catalog.py`, and `ingest_recon_methodology.py`. Spec keys in Task 4's Interfaces match the `_f(...)` keys and the `ALIASES` targets.
