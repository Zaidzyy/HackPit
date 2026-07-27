# Build #4 — AV/EDR evasion + traffic obfuscation (TA0005 / TA0011)

**Date:** 2026-07-27
**Branch:** `sandbox-kali-image`
**Status:** design — awaiting approval before implementation
**Prereq:** build #3 (persistence, TA0003) is committed **and** pushed (commits `90ff27d` `171639d` `39b9e0f` `ead27b7`; 0 ahead / 0 behind origin, clean tree). Verified.

This is the most sensitive build in the project. It adds a live C2 surface + a bespoke evasion
engine **and** deliberately rewrites a safety guardrail, on a public repo. It is
authorized-pentest / CRTP tradecraft — the same dual-use class HackPit already carries (C2
session panel, AD abuse, exploit-dev). The change is explicit, tested, and recorded as a
decision; nothing here happens silently.

---

## 1. Non-negotiable invariants (unchanged by this build)

These are load-bearing and are **not** touched. Only the OPSEC describe-not-prescribe guard
changes (§5.D).

1. **Human-gated.** Every C2/evasion action is reachable only by a human. No orchestrator /
   agent / executor code path to any of it — AST/source-scan asserted, exactly like `state/`,
   `repeater.py`, `tunnels.py`, `session.py`.
2. **Scope-locked.** Implant deployment and payload/artifact targeting are checked against the
   active engagement scope (`cockpit/scope.py`). Out-of-scope target ⇒ refused, nothing produced.
3. **Audited.** Every start / stop / generate is written to the run store (`runstore.save_run`).
4. **No autonomy.** The orchestrator never auto-proposes or auto-runs evasion or C2. The
   `<listener>` placeholder is operator-side and is never target-substituted.

The gate, scope model, and audit trail all remain. The **only** deliberate change is the
describe-not-prescribe posture of the OPSEC/evasion guard (§5.D), taken as an explicit decision.

---

## 2. Two design decisions (confirmed with the user)

**D-gate — Split gating.**
- **Lifecycle actions** (Sliver server start/stop; dnscat2 / iodine listener start/stop) are
  **human-only**: source-scan locked (no agent/executor path), audited, "clicking Start *is*
  the approval" — mirrors `tunnels.py`. No separate red-confirm on infra.
- **Generative / targeted actions** (Sliver implant generation; evasion-artifact generation;
  implant deployment) are **red-confirm gated** through the existing executor danger gate,
  **scope-checked** when they name a scoped host, and audited — mirrors `session.py`'s gated
  start.

**D-guard — Lift the sensor-tamper ban entirely.**
The current OPSEC guard (`_opsec_has_tamper`) rejects in-process sensor-blinding
("patch AMSI", "disable Sysmon", "wevtutil cl"). The evasion engine *emits* AMSI-patch and
ETW-blind stubs, so its own honest notes would trip that guard. The ban is **removed**. The
sole surviving invariants on the OPSEC/evasion channel are: (a) every note carries a non-empty
`still_recorded` honesty marker, and (b) the blue-view footprint is **always** produced
alongside and is never suppressible. This is the biggest public-repo posture shift in the
project and is recorded as an explicit assessment decision (§8).

---

## 3. What already exists (the correction to the brief's mental model)

The guard is **not** a single wall. It is two layers plus a live OPSEC channel shipped by D10:

- **Blue-side guard** — `detection/resolver.py::assert_describes_not_prescribes` /
  `_evasion_prescription`, run over detection fields (`blue_view`, `telemetry`, `why_rating`,
  signals, loudness). Forbids all prescriptive evasion phrasing on the defender view.
- **OPSEC channel** — `catalog.OPSEC` notes (opt-in `include_opsec=True`), each an `OpsecNote`
  (`loud_because`, `quieter`, `still_recorded`, `tradeoff`), guarded by
  `assert_opsec_is_separate` + `_opsec_has_tamper`. Already allows *quieter* tradecraft; already
  mandates `still_recorded`; currently **rejects sensor-blinding**.
- `test_blue_view_is_byte_identical_with_and_without_opsec` locks the blue view against the
  offensive half.

Existing surfaces to mirror:
- `cockpit/tunnels.py` — human-only listener lifecycle (start/stop), pure route/rewrite fns,
  source-scan locked, audited.
- `cockpit/session.py` — **gated** start + human-only stdin, mode-bound, recorded.
- `cockpit/repeater.py` — argv-only in `config.KALI_OPEN_CONTAINER`, scope-checked, audited,
  AST-locked no-agent-path.
- `cockpit/loot.py` + `state/ingest.py` — per-run loot dir is mounted; new loot files are
  auto-ingested and surfaced by the loot panel (`cockpit_loot.describe()`).
- `cockpit/executor.py::validate_request` + `allowlist.py::dangerous_reasons` — the red-confirm
  danger gate (`dangerous_ack`).
- `arsenal/tools.json` — `{schema_version, note, placeholders, tools[]}`, **CRLF**, 105 tools,
  categories incl. `persistence` (Sliver already cataloged reference-only by #3).
- #3 persistence footprint specs already in `catalog.py`: `persist_registry_run`,
  `persist_startup_folder`, `persist_scheduled_task`, `persist_service`, `persist_wmi_event`,
  `persist_accessibility`, `persist_account_windows`, `persist_webshell`, `persist_cron`,
  `persist_systemd`, `persist_ssh_authkeys`, `persist_shell_profile`, `persist_account_linux`.

---

## 4. Components

### A. Sliver C2 — human-only lifecycle surface

**Module:** `backend/cockpit/sliver.py` + a frontend panel. Wired into `main.py` (cross-cutting
route lives in `main.py`, not inside `cockpit` — the cockpit/arsenal decoupling rule).

- **Server lifecycle** (`start_server` / `stop_server`): starts/stops `sliver-server` as a
  tracked process **inside the engage sandbox**, listener config (mTLS / HTTP / DNS, host, port,
  jitter). **Human-only**, source-scan locked, audited. No red-confirm (infra).
- **Implant generation** (`generate_implant`): builds an implant via the Sliver client
  (`generate --os windows --arch amd64 --mtls <listener> ...`), emits it to the **loot dir**.
  **Red-confirm gated + scope-checked** (the implant's callback/target host must be in scope
  when a named engagement is active) + audited. `<listener>` is operator-side, never
  target-substituted.
- **Implant registry** (`list_implants` / `describe`): tracks generated implants (id, os/arch,
  listener, path, run_id). In-memory + reflected from the loot dir.
- **Deferred:** live beacon catch / interactive session over the C2 channel — same posture as
  `tunnels.py` ("connect-back deferred to a real engagement"). Built: server lifecycle + implant
  generation + tracked registry. Not built: driving a live beacon.

**Containment:** `start_server` / `stop_server` / `generate_implant` are HUMAN-ONLY — the
orchestrator/agent/executor have zero path (regression-locked by a source scan). Pure helpers
(argv construction, registry views) may be called from the proposal/UI path; they execute
nothing.

### B. Traffic obfuscation — DNS tunneling lifecycle + C2 profile config

**Same module family as A / mirrors `tunnels.py`.** dnscat2 + iodine listener lifecycle
(start/stop server, hand back the operator-side one-liner to run on the compromised host),
human-only, source-scan locked, audited.

- **Sliver C2 profiles + jitter / low-and-slow beacon config** are *configuration on top of A*
  (listener/implant options), not a separate surface.
- **Domain fronting: describe-only.** Largely dead; not built. Its network footprint is
  described in the detection catalog (§E).
- Each technique's network footprint is added to the detection footprint (§E) so the blue view
  covers it.

### C. Bespoke evasion engine

**New package `backend/evasion/`** (top-level, like `detection/` and `state/` — not inside
`cockpit`, preserving the decoupling rule). Human-invoked via an endpoint in `main.py` + a
panel.

- **Input:** a payload / shellcode / exe path (from the loot dir) + options: target OS, and a
  set of techniques — `donut-pack`, `amsi-patch`, `etw-blind`, `string/encoding obfuscation`.
- **Output:** an obfuscated / evasive artifact written **into the loot dir** (auto-surfaced by
  the loot panel + state ingest). **It GENERATES ONLY** — it never runs or deploys the payload.
  Deployment is a separate gated command elsewhere.
- **Backends:** installed generators where sensible — **Donut** and **ScareCrow** (Linux tools
  that emit Windows payloads), run **inside the sandbox container via `docker exec`, argv-only**
  (mirrors `repeater.py`; hardcoded container constant, never a request field, no shell). Plus
  the engine's own **AMSI-patch / ETW-blind stub templates** (text templates in
  `evasion/templates/`).
- **Gating:** **red-confirm gated + scope-checked** (when the artifact targets a scoped host) +
  audited. **No orchestrator/agent path — AST-asserted.**
- **Mandatory honesty (D-guard, §5.D):** every generation *also* emits the honest-footprint note
  — the blue-view detection footprint for the artifact's technique(s) **plus** an OPSEC/evasion
  note carrying `still_recorded` ("evades X, still recorded by Y"). The footprint is **never
  suppressed**. A generation that cannot produce both is a bug and fails — asserted by
  `test_evasion_safety.py`.

**Containment:** `generate` runs only from the HTTP route (human), argv-only in the hardcoded
open container, no shell, no agent path. The package imports nothing from the executor's run
entrypoints.

### D. Guard rewrite + persistence OpsecNote backfill

**Rewrite (in `detection/resolver.py` + `catalog.py`):**

- `assert_describes_not_prescribes` / `_evasion_prescription` (**blue-side**): **UNCHANGED.**
  The blue view stays purely descriptive and always-on; prescription never enters the detection
  channel. Structural separation is preserved. `test_blue_view_is_byte_identical...` stays green.
- `assert_opsec_is_separate` (**OPSEC/evasion-side**): **rewritten.** Remove the
  `_opsec_has_tamper` rejection. The remaining invariants: `still_recorded` is non-empty
  (mandatory), and OPSEC content lives only under the `opsec` key (never merges into blue
  fields). `_opsec_has_tamper` / `_SENSOR_TAMPER` are removed.
- The ai_suggested OPSEC path (`_opsec_from_llm`): a model note is now **kept** when it carries
  `still_recorded` (prescriptive evasion, incl. AMSI-patch/ETW-blind, is allowed); dropped only
  if it lacks the honesty marker.

**Tests — rewritten to assert the NEW contract (not deleted):**
- `test_opsec_guard_catches_sensor_tampering` → `test_opsec_guard_allows_prescriptive_evasion`:
  AMSI-patch / ETW-blind / log-clearing phrasings now **pass** the guard *when* `still_recorded`
  is present; a note missing `still_recorded` is **rejected**; the blue footprint is present.
- `test_model_opsec_tampering_is_discarded` → `test_model_opsec_kept_with_honesty_marker`: an
  ai_suggested evasion note is kept iff it carries `still_recorded`.
- `test_every_curated_opsec_note_carries_the_honesty_marker`: extended to the backfilled
  persistence notes.
- `report.py`'s honest footprint roll-up is kept.

**Backfill — per-mechanism OpsecNotes for #3's persistence specs (TA0003).** Add an `OpsecNote`
to `catalog.OPSEC` for each of the 13 persistence specs listed in §3, each with `loud_because`,
`quieter`, a **mandatory** `still_recorded`, and `tradeoff`. This closes the #3→#4 seam: #3
deliberately deferred the `quieter` persistence tradecraft to #4; it lands here.

### E. Detection footprint extension (describe side, additive)

Additive specs in `catalog.py` for the C2/obfuscation techniques, each mapped to the correct
TA0011 ATT&CK id (verified against `detection/attck.py` — extend `attck.py` if an id is missing):

- **DNS tunneling** (dnscat2 / iodine) — T1071.004 / T1572. What NDR/IDS/DNS-analytics see:
  high TXT/NULL query volume, long/high-entropy labels, one resolver dominating.
- **Malleable / custom C2 profiles** — T1071.001 / T1001. What proxy/NDR see: JA3/JA3S + header
  fingerprints, beacon periodicity.
- **Jitter / low-and-slow beacon** — T1029 / T1071. Why it's quieter and what still catches it
  (long-baseline beacon analytics, cumulative volume).
- **Domain fronting** — T1090.004 — describe-only: SNI≠Host mismatch at the TLS-terminating
  proxy; largely dead because CDNs blocked it.

Each carries `loud_because` / `still_recorded` via a paired OpsecNote (the always-on blue view
from D-guard). These are the always-on defender view; they are never suppressed by the offensive
half.

### F. Arsenal + image

**`arsenal/tools.json` (CRLF — preserve on any programmatic edit: re-emit `newline="\r\n"` or
splice textually; verify a clean additive diff):**
- **Add:** dnscat2, iodine (category `evasion`); Donut, ScareCrow (category `evasion`);
  Invoke-Obfuscation (category `evasion`, `platform: windows` — reference-only).
- **Sliver:** recategorize `persistence` → `c2` and enrich (it is a C2 framework). Verify
  `test_arsenal.py` still passes (category counts / schema).
- **Shellter:** reference-only unless it builds cleanly under wine.
- The `executes_nothing` catalog invariant (`test_arsenal_safety.py`) must stay true — the
  catalog is data, not an executor.

**`docker/Dockerfile.sandbox` — install robustly + smoke-test EACH new binary** (reconFTW
lesson: watch the Go-toolchain trap — pin a working Go or use release-binary installers; a tool
needing Go≥1.25 breaks a Go-1.23 layer):
- **Sliver** — official **release binaries** (`sliver-server`, `sliver-client`), not `go install`.
- **dnscat2** — apt (Kali) / git; **iodine** — apt.
- **Donut** — release binary or `pip install donut-shellcode`; **ScareCrow** — release binary.
- **Invoke-Obfuscation** — Windows PowerShell module; **not installed in the Linux image**
  (catalog reference-only).
- Smoke tests (new RUN layer): `sliver-server version`, dnscat2 present, `iodine --version`,
  `donut -h` (or import), `ScareCrow -h`. Report per-tool pass/fail when the ~9 GB background
  rebuild finishes.

---

## 5. Data flow

```
operator (browser panel)
  │  start Sliver server / dnscat2 / iodine listener   ── human-only ──► sliver.py.start_*  ─► docker exec in engage sandbox ─► runstore.save_run
  │  generate implant (os/arch/listener, target host)  ── red-confirm + scope ─► sliver.py.generate_implant ─► loot dir ─► runstore + registry
  │  generate evasion artifact (payload + techniques)  ── red-confirm + scope ─► evasion.generate ─► docker exec donut/scarecrow (argv) ─► loot dir
  │                                                                                 └─► detection.footprint(technique) + OPSEC note (still_recorded)  [always]
  └─ loot panel / state ingest auto-surface the artifact (existing)
```
No path from orchestrator/agent/executor into any `start_* / generate_*` (AST-asserted). Pure
helpers (argv build, registry/footprint views) are execute-nothing and callable from the UI path.

---

## 6. Testing plan

- **Existing green:** `test_arsenal.py`, `test_arsenal_safety.py` (`executes_nothing` holds).
- **New — Sliver:** `test_sliver.py` (server lifecycle argv, implant argv, registry, records
  mode) + `test_sliver_safety.py` (AST no-agent-path, lifecycle human-only, generation gated +
  scope-checked, `<listener>` never substituted, audited).
- **New — evasion:** `test_evasion.py` (donut/scarecrow argv, stub-template emission, artifact
  lands in loot dir) + `test_evasion_safety.py` (generates-only / never-runs, AST no-agent-path,
  red-confirm, scope-checked, **every artifact carries a blue footprint + a still_recorded
  note**).
- **New — obfuscation:** dnscat2 / iodine lifecycle covered in the Sliver module family tests
  (or a small `test_obfuscation.py`).
- **Rewritten detection tests:** the new D-guard contract (prescribe allowed + honesty/footprint
  always present); `test_blue_view_is_byte_identical...` stays green.
- **Runner:** add the new safety tests to `backend/run_safety_tests.sh`; `sh
  backend/run_safety_tests.sh` green **including** the rewritten detection tests.
- **Image:** fresh build succeeds; every new tool resolves in the smoke test.

---

## 7. Assessment + PDF (same recipe)

- Fold #4 into `docs/ASSESSMENT-2026-07-26.md` as a **PART III subsection** ("AV/EDR evasion +
  traffic obfuscation"): Sliver (option A), traffic obfuscation, the bespoke evasion engine, the
  guard rewrite (what changed, why, and that gate/scope/audit/no-autonomy are untouched), and
  the persistence OpsecNote backfill. Be honest about the public-repo posture shift. **No
  strikethrough (`~~`).**
- **Record the guard change as an explicit decision** — amend **D10** and/or add a new **D-entry**.
- Regenerate `.html` by splitting the current `.html` on the literal marker
  `<div class="toc"><span class="toctitle">Contents</span>` to reuse head/style/cover verbatim,
  then append that marker + a fresh ToC + `</div></div>` + converted body + `</body></html>`.
  Convert via `backend/.venv/Scripts/python.exe` with python-markdown extensions
  `[tables, fenced_code, toc, sane_lists, attr_list]`.
- Regenerate the PDF with Edge headless (`--headless --disable-gpu --no-pdf-header-footer
  --print-to-pdf=...`).
- Verify: `.html` has reused `<style>` + cover + a fresh ToC including the #4 section; `.pdf`
  starts with `%PDF` and is multi-page.

---

## 8. Commit + push

Branch `sandbox-kali-image`. Commit the code (evasion pkg, Sliver/obfuscation wiring, detection
+ rewritten guard/tests, arsenal, Dockerfile) and the regenerated `.md`/`.html`/`.pdf`. Match
repo commit style; end each commit with:

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

Push to origin.

---

## 9. Out of scope / deferred

- Live Sliver beacon catch + interactive C2 loop (deferred to a real engagement, as tunnels).
- Domain fronting *implementation* (describe-only; technique is dead).
- Invoke-Obfuscation execution in the Linux image (reference-only, `platform: windows`).
- Shellter if it does not build cleanly under wine (reference-only fallback).
- Any orchestrator/agent path to C2 or evasion (forbidden by invariant, AST-asserted).

---

## 10. Risks & traps (from memory)

- **tools.json CRLF vs LF** — the file is CRLF while `.py`/`.tsx`/Dockerfile are LF. Re-emit
  `newline="\r\n"` or splice textually; verify an additive-only diff.
- **Go toolchain trap** — a tool needing Go≥1.25 breaks a Go-1.23 layer; prefer release binaries
  (Sliver, ScareCrow).
- **Defender quarantine** — rewriting `data/kb/entries.jsonl` (or emitting web-shell-signature
  artifacts) can get files deleted by Windows Defender; the evasion artifacts land in the loot
  dir *inside the container*, not the repo — verify no repo file trips Defender.
- **Attack-step schema in 3 places** — not expected here (no new per-step field), but if a
  footprint field is surfaced per-step, it must be added in `attack_path.py` + `main.py`
  `AttackStep` + frontend or FastAPI strips it.
- **cockpit/arsenal decoupling** — `evasion/` is top-level; cross-cutting routes live in
  `main.py`, never a cockpit↔arsenal reference in either direction.
- **detection catalog atomicity** — a new spec + its ATT&CK row must land together or
  `test_knowledge_is_internally_consistent` fails.
