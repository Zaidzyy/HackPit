# Persistence / backdoors (TA0003) enrich — design spec

**Date:** 2026-07-27
**Branch:** `sandbox-kali-image`
**Build:** #3 (enrich, not a new capability)
**Pattern:** mirrors the reconFTW incorporation pass (mine the *knowledge*, never add an auto-runner).

## 1. Intent and boundaries

HackPit already **executes** persistence on scoped targets through the one gated executor
(engagement mode + WinRM + `:kali`), and `msfconsole` is installed. This build adds **only the
knowledge / reference / describe layer** — no new execution capability, no persistence engine,
no autorunner. The gated-executor path for `schtasks`/`reg`/`sc`, `cron`/`systemd`/`useradd`/
`ssh-keygen`, and msf modules is left exactly as is.

Fixed boundaries (from the build brief):

- **No new execution capability / no persistence autorunner.** Additive knowledge only.
- **Reference-only for Sliver, Empire, and weevely; SharPersist is `platform:windows`.** None are
  installed. Reconcile correctly reports them not-installed, so the planner won't propose them
  (same as `subwiz` today). That is intended — their install + C2 wiring is deferred to build #4.
- **No image rebuild.** `msfconsole` is present and OS built-ins cover every mechanism. If any
  item turns out to genuinely require an install, STOP and ask before rebuilding.
- **Rootkits / bootkits: KB knowledge only, never tooling.**
- **Evasion / guard rewrite is build #4, not here.** The describe-not-prescribe guard stays intact.

## 2. Audit — covered vs missing (done before adding anything)

Ran an analysis pass over `data/kb/entries.jsonl` (2,619 entries) and `backend/detection/attck.py`.

**KB.** The earlier "~60 persistence entries" figure conflated **cloud** persistence with host
persistence:

- Only **2** entries are `category=="persistence"` (both Linux: SSH-key persist, `/etc/passwd`
  persist).
- **72** entries are persistence-relevant, but **52 of those are cloud** (IAM / AAD / GCP
  backdoors). AD / Windows / post-ex account for the remainder.
- The TA0003 *mechanisms* are present at the **command level, scattered** across HackTricks/OSCP
  writeups — corpus hits: scheduled-task/cron 64, services 59, backdoor accounts 70, web shells
  46, SSH authorized_keys 22, Run keys 20. What is **missing is the organized, per-mechanism
  TA0003 methodology** that ties them together (exactly the reconFTW situation: the raw material
  existed, the *methodology map* did not). Genuinely thin as knowledge: WMI event subscription
  (3 hits), accessibility/sticky-keys (0 dedicated).

**Detection.** `attck.py` carries **49 techniques**; most persistence technique IDs are **absent**
— missing: `T1547.001`, `T1543.003`, `T1543.002`, `T1546.003`, `T1546.004`, `T1546.008`,
`T1136.001`, `T1505.003`, `T1098.004`, `T1053.003`, `T1053.006`, `T1037`. Present: `T1053.005`,
`T1098`. So the detection layer needs both new `FootprintSpec`s **and** new technique metadata in
`attck.py`.

**Arsenal.** 101 tools; no `persistence` category. Windows reference tools (`rubeus`, `powerview`)
already exist as `platform:windows` reference entries with templates — SharPersist mirrors them.

**Conclusion:** add a compact methodology layer to the KB, four catalog entries to the arsenal,
and a per-mechanism describe-side footprint layer. Do not duplicate the scattered command-level
coverage that already exists.

## 3. What gets built

### 3.1 KB — `pipeline/ingest_persistence_methodology.py`

A near-clone of `pipeline/ingest_recon_methodology.py`. Discipline is identical:

- **Own meta marker** `persistence_methodology` (distinct from `corpus_ingest` and
  `recon_methodology`), so the three ingesters never touch each other's lines.
- **`no_merge: true`** on every entry — a mechanism map is a sequence; consolidate must not fold it.
- **Additive + byte-preserving** — existing lines copied through as raw bytes, never JSON
  round-tripped.
- **Fixed-point order** `[other lines, our methodology lines, corpus block last]` — the corpus
  block is re-segregated to the tail so `test_corpora`'s byte-identity assertion stays green.
- **Idempotent** — a re-run drops exactly this ingester's own lines and regenerates them, yielding
  a byte-identical file. Atomic tmp + `os.replace`. Post-write count assert (Defender-quarantine
  trap from `defender-quarantines-kb-file`).
- Embeddings are **not** rebuilt here (new ids are BM25-retrievable immediately; `pipeline/embed.py`
  is an optional follow-up).

**Two entries** (mirroring reconFTW's 2-entry shape):

1. `persistence-methodology-windows` — *Windows host persistence — the mechanism map (TA0003)*,
   `category: persistence`. A checklist over the Windows TA0003 mechanisms: Registry Run/RunOnce
   keys (T1547.001), Startup folder / shortcut (T1547.001), scheduled tasks (T1053.005), services
   (T1543.003), WMI event subscription (T1546.003), accessibility features / IFEO (T1546.008),
   backdoor account + privileged-group add (T1136.001 / T1098), web shell (T1505.003). Each step:
   one **vetted command already present in the corpus** + a one-line "what the defender sees"
   pointer into the detection layer. Advisory ordering, gated one command at a time — not an
   auto-chain.
2. `persistence-methodology-linux` — *Linux host persistence — the mechanism map (TA0003)*,
   `category: persistence`. Same shape over: cron / `/etc/cron.d` (T1053.003), systemd unit +
   timer (T1543.002 / T1053.006), SSH `authorized_keys` (T1098.004), shell-init profiles
   (T1546.004), backdoor account / `/etc/passwd` (T1136.001), plus a KB-only note on rootkits
   (knowledge, never tooling).

Both cite MITRE ATT&CK and carry `source: hackpit-methodology`, `tier: 2`.

### 3.2 Arsenal — `backend/arsenal/tools.json` (101 → 105)

New `category: persistence`. Four entries, schema `name/category/purpose/phases/techniques/docs/
templates/flags` (+ `platform`/`aliases` where relevant):

- **SharPersist** — `platform: windows`, reference with templates (mirrors `rubeus`). A Windows
  persistence toolkit (scheduled task, registry, startup, service, etc.). Templates use the
  established placeholder convention; `executes_nothing` unaffected.
- **Sliver** — reference-only (`docs` + `purpose`, no templates). C2 framework with persistence;
  not installed, install/wiring deferred to #4.
- **Empire** — reference-only. PowerShell/Python post-exploitation + persistence framework; not
  installed, deferred to #4.
- **weevely** — reference-only (a template or two for shape). Web-shell generator/manager
  (T1505.003); not installed.

**CRLF trap:** `tools.json` is CRLF while `.py`/`.tsx` are LF. The edit is done by **textual
splice preserving CRLF** (or re-emit with `newline="\r\n"`), then `git diff --cached --stat` is
checked to prove a clean-additive diff, **not** a whole-file line-ending flip. `executes_nothing`
stays `true`. `test_arsenal.py` + `test_arsenal_safety.py` must pass at the new count (105).

### 3.3 Detection footprint — `backend/detection/` (describe side only)

**Decision (confirmed): `FootprintSpec` entries only — the blue/describe side.** No `OpsecNote`s
are added; the `quieter`-tradecraft channel is build #4. The honesty invariant ("quiet = a
defender **coverage gap**, not an operator advantage; Autoruns / auditd / EDR baseline still
records it") is carried in each spec's **`why_rating`**, exactly as the existing quiet specs
(`dns_enum`, `passive_recon`) do. This leaves `assert_opsec_is_separate` **wholly untouched**.

**a. `attck.py`** — add the missing persistence technique metadata (tactic TA0003 "Persistence",
data components, concrete log channels) for the IDs the specs reference: `T1547.001`, `T1053.005`
(present — reuse), `T1543.003`, `T1543.002`, `T1053.003`, `T1053.006`, `T1546.003`, `T1546.004`,
`T1546.008`, `T1136.001`, `T1505.003`, `T1098.004` (`T1098` present — reuse). Every ID is
re-checked by `pipeline/detection_sources.py --verify` against live ATT&CK v19.1.

**b. `catalog.py` — new `FootprintSpec`s** (one per mechanism), each with concrete telemetry
(Windows Event IDs / Sysmon / Autoruns / EDR; Linux auditd / journald / file artifacts), a
`loudness`, a `blue_view`, and a `why_rating` that carries the honesty marker:

| key | technique(s) | primary telemetry | loudness |
|---|---|---|---|
| `persist_registry_run` | T1547.001 | Sysmon 13 (reg value set), `reg.exe` 4688, Autoruns | quiet |
| `persist_startup_folder` | T1547.001 | Sysmon 11 file-create in Startup, Autoruns | quiet |
| `persist_scheduled_task` | T1053.005 | Security 4698/4702, TaskScheduler/Operational 106 | notable |
| `persist_service` | T1543.003 | System 7045, Security 4697, Autoruns services | notable |
| `persist_wmi_event` | T1546.003 | WMI-Activity/Operational 5859/5861, Sysmon 19/20/21 | quiet |
| `persist_accessibility` | T1546.008 | Sysmon 11 / registry 13 (IFEO Debugger), 4688 sethc→cmd | notable |
| `persist_account_windows` | T1136.001 / T1098 | Security 4720/4722/4732/4728 | loud |
| `persist_webshell` | T1505.003 | web-server process → cmd/sh child, Sysmon 11 in webroot, access log | notable |
| `persist_cron` | T1053.003 | auditd watch on `/etc/cron*`, cron syslog, file-create | quiet |
| `persist_systemd` | T1543.002 / T1053.006 | auditd on `/etc/systemd`, journald, `systemctl` execve | quiet |
| `persist_ssh_authkeys` | T1098.004 | auditd file-watch on `authorized_keys`, sshd accepted-key login | quiet |
| `persist_shell_profile` | T1546.004 | auditd file-watch on `.bashrc`/`.profile`/`profile.d` | quiet |
| `persist_account_linux` | T1136.001 | auditd on `/etc/passwd`+`/etc/shadow`, `auth.log` useradd, wtmp | moderate |

**c. Sigma** — cite a curated subset of **real SigmaHQ rules** where confident (e.g. Run-key,
scheduled-task, service-install, WMI-subscription, new-user rules); leave `sigma` **empty** for
the rest (allowed — `dns_enum`/`passive_recon` already ship empty). Every cited UUID/title/path is
verified by `detection_sources.py --verify` during build; any that don't verify are dropped, never
invented.

**d. `ALIASES`** — add only **unambiguous** persistence binaries: `schtasks`→`persist_scheduled_task`,
`crontab`→`persist_cron`, `useradd`/`adduser`→`persist_account_linux`, `sharpersist`→a persistence
spec, `weevely`→`persist_webshell`. Multi-purpose binaries (`reg`, `sc`, `net`, `systemctl`,
`ssh-keygen`) are **not** blanket-aliased — they resolve via the existing argv/LLM path so a
`reg query` isn't mislabelled persistence. Final minimal alias set decided during build.

**Guards, untouched:** `assert_describes_not_prescribes` (runs over the blue lines) and
`assert_opsec_is_separate` (no opsec notes added) stay exactly as they are. `test_detection.py` +
`test_detection_safety.py` must stay green.

## 4. Verification

- `python backend/detection/test_detection.py`, `test_detection_safety.py` — green.
- `python backend/arsenal/test_arsenal.py`, `test_arsenal_safety.py` — green at 105 tools;
  `executes_nothing` still true.
- `python pipeline/detection_sources.py --verify` — every new technique id/tactic/log-source and
  every cited Sigma UUID/title/path re-checked against live ATT&CK v19.1 + SigmaHQ.
- KB ingester: prove `--dry-run`, a real run, an **idempotent byte-identical re-run**, and that
  `test_corpora.py` stays byte-identical.
- Full suite: `sh backend/run_safety_tests.sh` — green.
- `tools.json`: `git diff --cached --stat` shows a clean-additive diff (no CRLF→LF flip).

## 5. Assessment doc + PDF

- Fold a concise **"Persistence (TA0003) enrich"** subsection into **PART III** of
  `docs/ASSESSMENT-2026-07-26.md` (what was audited; what was added across KB / arsenal /
  detection; the reference-only framework decision with Sliver/Empire/weevely install deferred to
  #4; "no new execution capability"). Add a short line to the PART II gaps ledger if it fits.
  Match the doc's voice; no strikethrough (`~~…~~`) — python-markdown core doesn't support it.
- Regenerate `docs/ASSESSMENT-2026-07-26.html`: split the current `.html` on the literal marker
  `<div class="toc"><span class="toctitle">Contents</span>`, reuse everything before it verbatim
  (head/style/cover), then append the marker + a **fresh** ToC + `</div></div>` + the converted
  body + `</body></html>`. Convert the `.md` with python-markdown extensions
  `[tables, fenced_code, toc, sane_lists, attr_list]` via `backend/.venv/Scripts/python.exe`.
- Regenerate the PDF with Edge headless (`--no-pdf-header-footer --print-to-pdf`), verify it
  starts with `%PDF` and is multi-page, and that the fresh ToC includes the persistence section.

## 6. Commit + push

One commit on `sandbox-kali-image` with the code (ingester, arsenal, detection) + the regenerated
assessment `.md`/`.html`/`.pdf`. `entries.jsonl` is gitignored (`data/`) and is **not** committed —
the ingester code is what ships. Match the repo commit style; end the message with:

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

Push to origin.

## 7. Reused traps (carried forward)

- `tools.json` CRLF vs LF — preserve CRLF, verify clean-additive diff.
- Two-ingester fixed-point order — corpus block last; own marker.
- `entries.jsonl` can be Defender-quarantined on rewrite — post-write count assert.
- Arsenal reconcile keys on tool name and `is_present` — reference-only tools stay suppressed.
