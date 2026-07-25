# Detection footprint — the purple-team panel

> **The line this feature holds.** It **describes detection from the defender's side**. It does
> **not** perform, recommend, or teach **evasion**.
>
> *"This action is loud / here's the event it throws / here's the rule that catches it"* — yes,
> that is the entire product.
> *"Here's how to make it quieter / evade that rule / blind that sensor"* — no. That is an evasion
> engine, it is out of scope, and it does not exist here.
>
> The loud-vs-quiet rating is an **awareness** indicator, and read from the blue side a
> **coverage** indicator: *quiet* means the defender probably cannot see this yet — a gap for them
> to close, never a lane for the operator to drive through. The whole value is showing the
> footprint, not erasing it. This is enforced in code, not just in review (see
> [The line, in code](#the-line-in-code)).

Everywhere else, HackPit's surface is the operator's: what to run, what it gets you. This panel
is the flip. For the same command it answers *what would a defender see?* — the MITRE ATT&CK
technique and tactic, the telemetry it generates, the public detection rule that would fire, and
how loud it is. The UI uses a deliberately cool hue rather than the amber operator accent:
**amber = what you can do, blue = what they can see.**

---

## 1. Where the knowledge comes from

Two public, defensive sources. Nothing is invented, and that claim is machine-checked.

### MITRE ATT&CK Enterprise — `backend/detection/attck.py`

49 techniques transcribed from **Enterprise ATT&CK v19.1**
(`mitre-attack/attack-stix-data`). Each row carries:

| field | ATT&CK source |
| --- | --- |
| `name`, `tactics` | the technique's `kill_chain_phases` |
| `data_components` | the `x-mitre-data-component` objects its detection strategy references — ATT&CK's own "what kind of telemetry shows this?" taxonomy |
| `log_sources` | the concrete channels named by ATT&CK's detection **analytics** (`x_mitre_analytic_refs → x_mitre_log_source_references`), e.g. `WinEventLog:Security EventCode=4662` |

`log_sources` keeps the Windows / Linux / network entries (the platforms HackPit touches) and
drops macOS / ESXi / cloud / container. It is therefore always a **subset** of upstream, never a
superset — and the verifier enforces exactly that.

> © 2015–2026 The MITRE Corporation. Reproduced and distributed with permission.
> <https://attack.mitre.org/>

**A note on TA0005.** In ATT&CK v19 the tactic historically called **Defense Evasion** is named
**Stealth** (TA0005), and a new **Defense Impairment** (TA0112) tactic carries the "turn the
defenses off" techniques. The panel surfaces both, and `TACTIC_ALIASES` keeps the old name
visible (`Stealth · aka Defense Evasion`) so the mapping is obvious to anyone who learned the
old matrix.

### SigmaHQ — `backend/detection/catalog.py`

49 real rules from the **SigmaHQ** open ruleset (<https://github.com/SigmaHQ/sigma>, Detection
Rule License 1.1), each cited by its upstream **UUID**, title, repo path and severity, and linked
to the public rule.

### The curated mapping

33 activity **specs** (`portscan`, `dcsync`, `kerberoast`, `psexec`, `relay_poison`, …), each
holding:

```
key · label · ATT&CK technique ids · Sigma rule keys · telemetry · loudness · blue_view · why_rating
```

plus a matcher (aliases, protocol subcommands like `nxc smb`, verbs like `net rpc password`,
interpreter-run scripts like `python3 targetedKerberoast.py`) and 8 **argument signals**.

### Verification — nothing here is invented

```bash
python pipeline/detection_sources.py            # offline: internal consistency + the KB lock
python pipeline/detection_sources.py --verify    # + fetch ATT&CK + SigmaHQ and diff every fact
```

`--verify` re-checks, against the live upstream sources: the ATT&CK version, every tactic name,
every technique id / name / tactic set / data component / log source, every Sigma UUID / title /
path / level, **and** every ATT&CK id and Sigma rule cited in prose by the defensive KB pages.
Exit code is non-zero on any drift, so it can be wired into CI.

This is not decorative — the verifier caught **six real errors** in the first draft of the
catalog (three wrong repo paths and three log-source strings that did not match upstream).

---

## 2. Grounded vs `ai_suggested`

The same split the kill-chain map and the AD abuse resolver use, and it is styled the same way in
the UI.

| | **grounded** | **ai_suggested** |
| --- | --- | --- |
| when | the curated map covers the command | it does not (the cockpit lets a human run anything) |
| source | ATT&CK + SigmaHQ, via the catalog | the LLM's own reading |
| badge | `grounded · ATT&CK + SigmaHQ` | `ai-suggested · verify` |
| Sigma rules | real, cited by UUID + link | **none, ever** |

An `ai_suggested` answer is **re-grounded before it is returned**:

* an ATT&CK id the model produced is kept only if it resolves in `detection/attck.py`; anything
  else is dropped **and disclosed** in the provenance line;
* the model can **never** introduce a Sigma rule — only the curated table cites rules;
* the curated **argument signals still apply**, so an uncatalogued command can still carry a
  *grounded* stealth or escalation annotation.

If there is no map hit *and* no model reading, the footprint is an explicit **unknown** — never a
silent "nothing here". The same honesty runs through the UI (`detection: not mapped`) and the
report (*"no footprint is asserted for this command. Unmapped is not the same as untraceable."*).

---

## 3. The read-only guarantee

The detection package is a **pure annotation layer**. It executes nothing, changes no gate, and
adds no new capability. Structurally it is the same lock the AD graph has.

**Source-scanned invariants** (`backend/test_detection_safety.py`, in the safety suite):

1. **No execution.** No module in `backend/detection/` contains `subprocess`, `Popen`,
   `os.system`, `os.popen`, `docker exec`, `pty.spawn` or `os.exec`.
2. **No executor run path.** No module calls `iter_run(`, `run_command(`, `.Popen(` — or even
   constructs an `ExecRequest(`.
3. **Zero `:kali` path.** No reference to `run_kali`, `KALI_OPEN`, `cockpit.kali` or
   `/cockpit/kali`.
4. **Read-only routes.** All 8 routes are reads; the router contains no `approved=True`,
   `save_run`, `write_stdin`, `start_session` or `engagement.enter`.
5. **The cockpit package is untouched.** No module in `backend/cockpit/` references `detection`
   at all — the execution layer does not know this feature exists, so it cannot be changed by it.
   `git diff` over `backend/cockpit/` and every pre-existing test file is empty.
6. **A footprint carries no runnable command.** Unlike the AD technique resolver — which
   deliberately returns a command for the human to approve — a footprint has no runnable surface
   at all: no `commands`, no `request`, no `approved`.
7. **The gates are unchanged.** After importing and exercising the whole package, the lab
   target-lock wording and gate order, and engagement's never-auto-run + scope-lock, are
   byte-for-byte what they were.

Run-record tags are **derived, not stored**: a run already persists its command and argv, and the
tag is a pure function of those, so `GET /detection/runs` computes it at read time. No schema
migration, and no execution path writes anything new.

---

## 4. The line, in code

The rule is not left to review. `detection/resolver.py` carries
`_evasion_prescription()`, a guard that scans every line the panel is about to return for
**prescriptive** evasion phrasing — *"to avoid detection…"*, *"evade the rule"*, *"so the rule
will not fire"*, *"quieter alternative"*, *"stay under the radar"*, *"disable the sensor first"*.

* A **generated** footprint that trips it is **discarded** — the caller gets the honest-unknown
  footprint instead.
* A **curated** string that trips it **raises**. That would be a data bug, and it fails the build
  rather than shipping.

The guard is written to catch advice while *permitting* description, because the descriptive
forms are the entire point of the panel. Both directions are asserted:

| must be caught | must be allowed |
| --- | --- |
| "To avoid detection, use a slower scan." | "This is loud: the scan shape is what NSM tooling is built to spot." |
| "Use `--tamper` instead to evade the WAF rule." | "ATT&CK classifies source spoofing as Masquerading (Stealth, TA0005)." |
| "Disable the sensor first so the rule will not fire." | "Detection rules match the encoding itself, so this is often a *stronger* signal." |
| "This is a quieter alternative to secretsdump." | "Quiet: ATT&CK lists no target-side detection strategy, which is a defender gap." |
| "Make it stealthier by encoding the command." | "Clearing a log announces that a log was cleared." |

241 curated strings and all 33 grounded footprints pass. The report's system prompt carries the
same instruction: the model may never suggest how the tester could have been quieter, and may
only frame detectability **for the defender** — what they should have seen, and whether they
would have.

### Stealth-shaped arguments are *surfaced*, never advised

Eight argument signals annotate what the flags change. Some are escalations (`-just-dc` turns a
credential dump into a replication request). Others are **stealth-shaped** — decoy/spoofed-source
scanning, fragmented probes, `--tamper`, `-enc`, log clearing. For those the panel names the
ATT&CK Stealth / Defense-Impairment technique **and the telemetry that still records them**:

> *ATT&CK classifies source spoofing as Masquerading (Stealth, TA0005). It is itself a tracked
> technique: NSM tooling fingerprints decoy patterns, so this typically produces MORE alertable
> traffic, not less.*

> *ATT&CK calls this Command Obfuscation (Stealth, TA0005). Detection rules match the ENCODING
> ITSELF, so an encoded command line is frequently a stronger signal than the plain one would
> have been.*

That is the purple-team framing at its sharpest: the thing you might think hides you is itself a
catalogued, detected technique.

---

## 5. ATT&CK tagging

Every **planned step** and every **executed run** carries a compact tag: technique ids, names,
tactics, and the loudness rating.

Tagging is **deterministic and LLM-free** — it runs over every step of every path and every run
of every report, so it must be instant and offline. It uses the curated catalog only. A command
the catalog does not cover gets `attck: null` rather than a guess; the drawer can still fetch the
`ai_suggested` footprint for that one command on demand.

* **Steps** — `attack_path.compose()` tags phases on both return paths (writeup-first and
  KB-first), *after* scope filtering, so the tag reflects the steps actually kept.
  `main.AttackStep` carries the `attck` field — without it FastAPI's `response_model` silently
  strips the tag on the way out.
* **Runs** — `GET /detection/runs?session_id=` returns a tag per run plus a coverage summary.

### The loud-vs-quiet scale

| level | score | meaning |
| --- | --- | --- |
| `quiet` | 1 | Little or no telemetry on the target by default — a defender only sees this if the relevant logging (LDAP/NSM/auditd) is switched on and retained. |
| `moderate` | 2 | Logged, but the events look like ordinary administration until correlated with volume, source or timing. |
| `notable` | 3 | Throws distinctive events that mature detection stacks alert on directly. |
| `loud` | 4 | High-volume and/or high-fidelity — public detection rules match this shape, and a monitored environment should raise it. |

An argument signal marked `louder` bumps the rating one step.

---

## 6. Where it shows up

**API** (all read-only, all under `/detection`):

| route | what it returns |
| --- | --- |
| `GET /detection/sources` | provenance, counts, the loudness scale, and the line — for the About box |
| `POST /detection/footprint` | the full footprint for one command (`allow_llm: false` for grounded-only) |
| `POST /detection/footprint/step` | the footprint for an attack-path step (its first real command) |
| `GET /detection/footprint/run/{run_id}` | what blue saw when a recorded run actually ran |
| `POST /detection/tag` | the compact tag for one command |
| `GET /detection/runs?session_id=` | tags for every run on an engagement + a coverage roll-up |
| `GET /detection/technique/{id}` | one ATT&CK technique as the panel renders it |
| `GET /detection/catalog` | the whole curated map, for a browsable reference view |

**UI** — a chip that expands into the drawer, on:

* the cockpit **kill-chain map** step drawer,
* the **attack-path** step cards,
* each **recorded run** in the engagement panel (plus the coverage roll-up above the list),
* each **hop** in the AD attack-path graph drawer.

The drawer shows: the activity in defender language, a one-line *what appears on their screen*,
the 4-segment loudness meter with its rationale, the ATT&CK tactic pills and technique rows
(linked to `attack.mitre.org`, Stealth tinted and labelled with its old name), the telemetry, the
SigmaHQ rules (severity chip + UUID + link), and what the arguments changed.

**Report** — the engagement report becomes a purple-team artefact:

* a **Detection footprint (purple team)** roll-up ahead of Evidence — runs tagged, tactics
  exercised, loudest action, and a technique table;
* a **Detection footprint** block under each recorded run in Evidence.

Both are built **programmatically and grounded-only** (`allow_llm=False`). Like the Evidence
section itself, they never pass through the model, so they cannot be embellished or
mistranscribed. The roll-up closes with the line that makes it actionable for blue:

> *A defender who sees none of the above for this window has a monitoring gap worth closing; the
> telemetry named per run is where to start.*

---

## 7. The defensive KB pages

Eight Companion-KB reference pages cover the evasion taxonomy — **obfuscation, in-memory
execution, process injection, AMSI/ETW tampering, LOLBins, behavioural/sandbox evasion, traffic
obfuscation, persistence** — written for **understanding and detection**, not as recipes.

Every page follows the same shape: what it is → why it works → **why it usually fails** → what a
defender should collect → the public SigmaHQ detections to start from → what removes the gap.
Each opens by stating plainly that it is a defender's reference and will not tell you how to
evade anything. The bulk of every page is detection and hardening.

**The structural lock:** every page carries **zero command blocks**. `attack_path.entry_commands()`
lifts commands out of step code blocks, so a page with none can never be surfaced as a runnable
attack-path step — it is browsable and searchable only. `category: reference` also ranks them
below focused techniques and makes them excludable via `pipeline/exclude.json` like any other
reference doc. Both the no-commands lock and the prose citations are asserted by the test suite
and by `detection_sources.py`.

They live in `pipeline/authored/authored_entries.jsonl` (source `hackpit-authored`). To merge:

```bash
python pipeline/ingest_authored.py    # replaces the authored rows, preserves every other source
python pipeline/embed.py              # incremental — only vectorises the new rows
```

> ⚠️ **Heads-up for this machine.** Rewriting `data/kb/entries.jsonl` can trip Windows Defender:
> the KB legitimately contains web-shell examples, and a 15 MB rewrite triggers a full rescan that
> has matched `Backdoor:PHP/Perhetshell.B!dha`. If the file disappears after an ingest run, it is
> in quarantine — restore it with an elevated `MpCmdRun.exe -Restore`, and consider a Defender
> exclusion for `HackPit\data` before running the pipeline again.

---

## 8. Verifying it yourself

```bash
# the knowledge is real and matches upstream (network)
python pipeline/detection_sources.py --verify

# the functional + safety suites (hermetic — no LLM, no Docker, no network)
python backend/test_detection.py
python backend/test_detection_safety.py

# everything, including the pre-existing gates
sh backend/run_safety_tests.sh          # 14 suites, 134 checks
```

**Status at the time of writing:** `--verify` → 0 problems across ATT&CK v19.1, SigmaHQ and the
KB citations. Safety suite → 14 suites, 134 checks, exit 0. Frontend → `tsc` clean, `next build`
exit 0, `npm run lint` at its documented pre-existing baseline (11 problems), unchanged.

---

## 9. Scope

This layer is **purely additive**. It executes nothing, changes no gate, and adds no capability.
It describes detection from the defender's side, and it never teaches evasion — in the data, in
the code, in the copy, and in the report.
