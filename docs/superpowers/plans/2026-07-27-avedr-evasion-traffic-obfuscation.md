# AV/EDR Evasion + Traffic Obfuscation (Build #4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a human-gated Sliver C2 surface, DNS-tunnel obfuscation lifecycle, and a bespoke generate-only evasion engine to HackPit, and deliberately relax the OPSEC guard so prescriptive evasion is allowed — with the honesty marker and always-on blue-view footprint as the surviving invariants.

**Architecture:** New surfaces mirror existing containment patterns exactly — Sliver/obfuscation lifecycle mirrors `cockpit/tunnels.py` (human-only, source-scan-locked, audited); gated generation mirrors `cockpit/session.py` (`validate_start` → `executor.validate_request`, red-confirm via `dangerous_ack`); the evasion engine mirrors `cockpit/repeater.py` (argv-only `docker exec` in a hardcoded container). The guard rewrite touches only `detection/resolver.py` + `detection/catalog.py`; the blue-side describe-not-prescribe guard is left untouched so the defender view stays byte-identical.

**Tech Stack:** Python 3.13 (backend, `backend/.venv/Scripts/python.exe`), Pydantic v2 models, pytest-free plain-script tests (`python test_*.py`), Docker (Kali sandbox image), Next.js/React frontend (TSX), python-markdown + Edge headless for docs.

## Global Constraints

- **Interpreter:** `backend/.venv/Scripts/python.exe`. Tests run as plain scripts: `python test_x.py` (they `print(... PASS)` and assert; no pytest).
- **Safety invariants (never weakened):** human-gated (no orchestrator/agent/executor path — AST/source-scan asserted), scope-locked (target checked against `cockpit/scope.py`), audited (`runstore.save_run`), no autonomy. Only the OPSEC describe-not-prescribe guard changes.
- **`<listener>` placeholder is operator-side — NEVER target-substituted.**
- **`tools.json` is CRLF** while `.py`/`.tsx`/Dockerfile are LF. Any programmatic edit MUST preserve CRLF (`newline="\r\n"`) or be a textual splice; verify an additive-only diff.
- **Go-toolchain trap:** a tool needing Go ≥ 1.25 breaks the image's Go layer — prefer release binaries (Sliver, ScareCrow).
- **cockpit/arsenal decoupling:** `backend/evasion/` is a top-level package (like `detection/`, `state/`); cross-cutting HTTP routes live in `backend/main.py`, never a cockpit↔arsenal reference in either direction.
- **detection catalog atomicity:** a new footprint spec + its ATT&CK id row must land together or `test_knowledge_is_internally_consistent` fails.
- **No strikethrough (`~~`) in the assessment.**
- **Commit trailer (every commit):** `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`. Commits may be blocked by the auto-mode classifier — if so, hand the exact `git commit` line to the operator to run via `!`.
- **Container constants:** `config.ENGAGE_SANDBOX_CONTAINER` (`hackpit-engage-sandbox`), `config.KALI_OPEN_CONTAINER` (`hackpit-kali-open`), `config.SANDBOX_CONTAINER` (lab). Loot: `loot.host_dir(engagement_id)` (host path), `loot.container_path(name)` → `/loot/<name>`.

---

## Existing interfaces this plan consumes (verbatim)

```python
# detection/catalog.py
@dataclass(frozen=True)
class OpsecNote:
    key: str; loud_because: str; quieter: tuple[str, ...]; still_recorded: str; tradeoff: str
def _o(key, loud_because, quieter, still_recorded, tradeoff): ...   # quieter is ';'-split into a tuple
OPSEC: dict[str, OpsecNote]                                          # keyed by .key
def opsec_for(key: str) -> OpsecNote | None: ...
def _f(key, label, techniques, sigma, telemetry, loudness, blue_view, why_rating): ...  # -> FootprintSpec

# detection/resolver.py
def _evasion_prescription(text: str) -> str | None: ...             # BLUE-SIDE — unchanged
def assert_describes_not_prescribes(strings, where) -> None: ...     # BLUE-SIDE — unchanged
def assert_opsec_is_separate(opsec: dict, where: str) -> None: ...   # REWRITE target
def footprint(command, args=None, *, context="", allow_llm=True, cfg=None, include_opsec=False) -> dict: ...

# cockpit/session.py  (the GATED-generation pattern to mirror)
def _gate_request(req) -> ExecRequest: ...      # builds ExecRequest(command,args,approved,dangerous_ack,engagement_id,session_id,step_id)
def validate_start(req) -> ExecRejected | None: # returns executor.validate_request(_gate_request(req))
# cockpit/executor.py
def validate_request(request: ExecRequest) -> ExecRejected | None: ...
def resolve_mode(request: ExecRequest) -> <resolved with .container>: ...
# cockpit/tunnels.py  (the HUMAN-ONLY lifecycle pattern to mirror)
def start_tunnel(req: TunnelStartRequest) -> Tunnel: ...
def stop_tunnel(tid: str) -> Tunnel: ...
def _container_running(name: str) -> bool: ...
# cockpit/scope.py
def parse_scope(spec: str, resolve: bool = True) -> ResolvedScope: ...
class ResolvedScope: def in_scope(self, token: str) -> bool: ...
# cockpit/runstore.py + models.py
def save_run(rec: RunRecord) -> None: ...       # RunRecord(run_id, command, args, target, mode, exit_code, stdout, stderr, started_at, ...)
# cockpit/loot.py
def host_dir(engagement_id: str) -> Path: ...
def container_path(name: str) -> str: ...        # -> "/loot/<name>"
```

---

## PHASE 0 — Guard rewrite + persistence backfill (do FIRST)

Everything downstream (the evasion engine's honest note, the detection extension's OpsecNotes) depends on the NEW contract, so the guard changes land first.

### Task 1: Rewrite `assert_opsec_is_separate` — lift the tamper ban, keep the honesty marker

**Files:**
- Modify: `backend/detection/resolver.py:405-497` (remove `_SENSOR_TAMPER`, `_opsec_has_tamper`; rewrite `assert_opsec_is_separate`; simplify `_opsec_from_llm`'s discard rule)
- Modify: `backend/test_detection.py` (rewrite the two tamper tests to the new contract)
- Modify: `backend/test_detection_safety.py` (invariant #5 comment: blue side still describes-not-prescribes; opsec side now allows prescription with mandatory honesty)

**Interfaces:**
- Consumes: `catalog.opsec_for`, `assert_describes_not_prescribes` (unchanged).
- Produces: `assert_opsec_is_separate(opsec: dict, where: str) -> None` — raises `ValueError` iff `still_recorded` is empty. `_opsec_has_tamper` / `_SENSOR_TAMPER` no longer exist.

- [ ] **Step 1: Rewrite the failing test in `test_detection.py`** — replace `test_opsec_guard_catches_sensor_tampering` with:

```python
def test_opsec_guard_allows_prescriptive_evasion_with_honesty() -> None:
    """New contract (build #4, D-guard): prescriptive evasion — including in-process
    sensor-blinding — is ALLOWED as long as every note names what still records it."""
    # These were REJECTED before #4; they are now allowed WHEN still_recorded is present.
    now_allowed = [
        {"loud_because": "AMSI scans the script as it loads.",
         "quieter": ["Patch AMSI in-process before loading the script."],
         "still_recorded": "The patch itself is a known-bad memory write Sysmon/EDR image-load "
                           "and AMSI-bypass rules flag; the process still starts.",
         "tradeoff": "Fragile across patch levels; a failed patch is louder than none."},
        {"loud_because": "ETW feeds the EDR's script/telemetry pipeline.",
         "quieter": ["Blind ETW for the current process."],
         "still_recorded": "ETW-tampering has its own detections; the parent process, its image "
                           "load and network are still recorded.",
         "tradeoff": "Process-scoped only; does not stop kernel callbacks."},
    ]
    for op in now_allowed:
        R.assert_opsec_is_separate(op, "test")   # must NOT raise

    # The ONE surviving invariant: a note with no honesty marker is rejected.
    try:
        R.assert_opsec_is_separate(
            {"loud_because": "x", "quieter": ["patch amsi"], "still_recorded": "  ", "tradeoff": ""},
            "test",
        )
        assert False, "a note missing still_recorded must be rejected"
    except ValueError:
        pass
    print("  OPSEC guard allows prescriptive evasion; still_recorded stays mandatory: PASS")
```

Also replace `test_model_opsec_tampering_is_discarded` with `test_model_opsec_kept_with_honesty_marker` (a `_FakeLLM` returning an AMSI-patch note WITH `still_recorded` is kept; the same note WITHOUT it is dropped). Update the `__main__` block to call the two renamed tests.

- [ ] **Step 2: Run to verify it fails**

Run: `backend/.venv/Scripts/python.exe backend/test_detection.py`
Expected: FAIL — the old guard raises on "patch amsi".

- [ ] **Step 3: Rewrite the guard in `resolver.py`** — delete lines 407-426 (`_SENSOR_TAMPER` + `_opsec_has_tamper`) and replace `assert_opsec_is_separate` (429-447) with:

```python
def assert_opsec_is_separate(opsec: dict[str, Any], where: str) -> None:
    """The OPSEC/evasion channel's guard (build #4, D-guard).

    History: this channel once refused any sensor-blinding phrasing. Build #4 lifts that
    ban as an explicit, documented decision (assessment D10 amendment) — the bespoke evasion
    engine EMITS AMSI-patch / ETW-blind artifacts, so its own honest note must be able to say
    so. The surviving invariant is the honesty marker: a quieter path that named nothing that
    still logs it would be an evasion how-to, which this is not. The blue-view footprint is
    ALWAYS produced alongside (never suppressible) — enforced by the callers, not here.
    """
    if not opsec:
        return
    if not str(opsec.get("still_recorded") or "").strip():
        raise ValueError(f"{where}: an OPSEC/evasion note must name what still records the activity")
```

Then in `_opsec_from_llm` (467-497), the `try/except ValueError -> return None` around `assert_opsec_is_separate` stays as-is (a model note missing the honesty marker is still discarded) — no change needed beyond the guard body it calls.

- [ ] **Step 4: Run detection tests to verify pass**

Run: `backend/.venv/Scripts/python.exe backend/test_detection.py`
Expected: PASS (all, incl. the two rewritten tests).

- [ ] **Step 5: Run the safety test to confirm the blue side is intact**

Run: `backend/.venv/Scripts/python.exe backend/test_detection_safety.py`
Expected: PASS — `test_blue_view_is_byte_identical_with_and_without_opsec` and the blue-side describe-not-prescribe checks are unchanged.

- [ ] **Step 6: Commit**

```bash
git add backend/detection/resolver.py backend/test_detection.py backend/test_detection_safety.py
git commit -m "detection: lift OPSEC sensor-tamper ban; honesty marker is the sole invariant"
```

### Task 2: Persistence OpsecNote backfill (#3 → #4 seam)

**Files:**
- Modify: `backend/detection/catalog.py` (add `_o(...)` entries to the `OPSEC` list, one per #3 persistence spec)
- Modify: `backend/test_detection.py` (`test_every_curated_opsec_note_carries_the_honesty_marker` already iterates `C.OPSEC` — it will now cover the new notes; add an assertion that every `persist_*` spec HAS an OPSEC note)

**Interfaces:**
- Consumes: the #3 persistence spec keys (confirm the exact set by grepping `catalog.py` for `_f("persist_`): expected `persist_registry_run`, `persist_startup_folder`, `persist_scheduled_task`, `persist_service`, `persist_wmi_event`, `persist_accessibility`, `persist_account_windows`, `persist_webshell`, `persist_cron`, `persist_systemd`, `persist_ssh_authkeys`, `persist_shell_profile`, `persist_account_linux`).
- Produces: an `OpsecNote` in `OPSEC` for every `persist_*` spec key.

- [ ] **Step 1: Add the failing assertion in `test_detection.py`** — inside `test_every_curated_opsec_note_carries_the_honesty_marker`, after the existing loop, add:

```python
    persist_specs = [k for k in C.SPECS if k.startswith("persist_")]
    assert persist_specs, "expected #3 persistence specs"
    missing = [k for k in persist_specs if k not in C.OPSEC]
    assert not missing, f"persistence specs with no OPSEC note (backfill incomplete): {missing}"
    print(f"  all {len(persist_specs)} persistence specs carry an OPSEC note: PASS")
```

- [ ] **Step 2: Run to verify it fails**

Run: `backend/.venv/Scripts/python.exe backend/test_detection.py`
Expected: FAIL — `missing` lists all 13 persist keys.

- [ ] **Step 3: Add the 13 OpsecNotes to `catalog.py`** — append `_o(...)` entries to the `OPSEC` list. Each: `key` = the spec key, `loud_because` = the specific signal source, `quieter` = concrete `;`-split knobs, `still_recorded` = MANDATORY, `tradeoff`. Two worked examples (write all 13 in this shape, grounded in the mechanism):

```python
    _o("persist_scheduled_task",
       "Task creation writes Security 4698 (author named) and a Task Scheduler operational-log "
       "entry; the on-disk task XML in C:\\Windows\\System32\\Tasks is a file-create event.",
       "Prefer an existing task's action over creating a new one; name it to blend with vendor "
       "tasks; trigger on a common event rather than a fixed clock time",
       "4698/4702 fire whenever scheduled-task auditing is on (mature stacks enable it), and the "
       "Tasks-folder file write is recorded regardless of the audit policy.",
       "Editing an existing task risks breaking it; blending takes recon time and is site-specific."),
    _o("persist_ssh_authkeys",
       "A publickey login from a new key later stands out, and the write to "
       "~/.ssh/authorized_keys is a file event auditd can watch.",
       "Match the key comment to an existing key; place it on an account that already logs in by "
       "key; avoid changing the file's mtime pattern",
       "If auditd watches authorized_keys the write is logged, and the first login with the key "
       "is a publickey auth event in the SSH/auth logs.",
       "Quiet only until first use; picking a plausible account needs prior enumeration."),
    # ... 11 more: persist_registry_run, persist_startup_folder, persist_service, persist_wmi_event,
    #     persist_accessibility, persist_account_windows, persist_webshell, persist_cron,
    #     persist_systemd, persist_shell_profile, persist_account_linux
```

- [ ] **Step 4: Run to verify pass**

Run: `backend/.venv/Scripts/python.exe backend/test_detection.py`
Expected: PASS.

- [ ] **Step 5: Verify the KB file was not quarantined** (Defender trap) — confirm `data/kb/entries.jsonl` still exists and the catalog imports cleanly:

Run: `backend/.venv/Scripts/python.exe -c "import sys; sys.path.insert(0,'backend'); from detection import catalog; print(len(catalog.OPSEC),'opsec notes')"`
Expected: prints a count ≥ (baseline + 13).

- [ ] **Step 6: Commit**

```bash
git add backend/detection/catalog.py backend/test_detection.py
git commit -m "detection: backfill per-mechanism OPSEC notes for TA0003 persistence"
```

---

## PHASE 1 — Detection footprint extension (C2 / obfuscation)

### Task 3: Add C2/obfuscation footprint specs + ATT&CK rows + paired OpsecNotes

**Files:**
- Modify: `backend/detection/catalog.py` (new `_f(...)` specs; new `SIGMA` rows if a rule is cited; new alias entries; new `_o(...)` OpsecNotes)
- Modify: `backend/detection/attck.py` (add any TA0011 technique id not already present)
- Modify: `backend/test_detection.py` (`test_knowledge_is_internally_consistent` already validates every referenced id resolves — it will cover the new rows)

**Interfaces:**
- Consumes: `_f`, `_o`, `attck.TECHNIQUES`.
- Produces: footprint specs `c2_dns_tunnel`, `c2_malleable_profile`, `c2_jitter_beacon`, `c2_domain_fronting`, each with a paired `OpsecNote` (except domain-fronting, which is describe-only — still gets an OpsecNote naming what betrays it).

- [ ] **Step 1: Add a failing test** — in `test_detection.py` add:

```python
def test_c2_obfuscation_specs_present_and_grounded() -> None:
    for key in ("c2_dns_tunnel", "c2_malleable_profile", "c2_jitter_beacon", "c2_domain_fronting"):
        assert key in C.SPECS, f"missing C2/obfuscation spec {key!r}"
        R._grounded("x", [], C.Match(spec=C.SPECS[key], signals=(), matched_on="tool"))
    # every id these specs cite must resolve (also covered by the consistency test)
    print("  C2/obfuscation footprints present, grounded, describe-only: PASS")
```
Add it to `__main__`.

- [ ] **Step 2: Run to verify it fails**

Run: `backend/.venv/Scripts/python.exe backend/test_detection.py`
Expected: FAIL — KeyError / missing spec.

- [ ] **Step 3: Add the specs + ATT&CK rows + OpsecNotes.** First confirm which ids exist: grep `attck.py` for `T1071`, `T1572`, `T1001`, `T1029`, `T1090`. Add any missing to `attck.TECHNIQUES` (id, name, tactic `TA0011 Command and Control`, telemetry). Then add specs, e.g.:

```python
    # --- C2 / traffic obfuscation (TA0011) — describe side only -------------------------- #
    _f("c2_dns_tunnel", "Command & control over a DNS tunnel", "T1071.004 T1572", "",
       "DNS resolver query logs; NSM DNS analytics; passive DNS",
       "loud",
       "A defender watching DNS sees an abnormal share of TXT/NULL/CNAME queries, unusually long "
       "and high-entropy labels, and one internal resolver path dominating volume.",
       "DNS is ubiquitous so the CHANNEL blends, but the query SHAPE (entropy, record types, "
       "volume) is exactly what DNS-tunnel detections score."),
    _f("c2_malleable_profile", "C2 with a custom/malleable transport profile", "T1071.001 T1001", "",
       "TLS/HTTP proxy logs; JA3/JA3S; NDR beacon analytics",
       "moderate",
       "Shaping traffic to look like normal web still leaves a client TLS fingerprint (JA3) and "
       "server response fingerprint, plus beacon periodicity a proxy can profile.",
       "A good profile defeats naive signatures; fingerprint + periodicity analytics still apply."),
    _f("c2_jitter_beacon", "Low-and-slow beaconing with jitter", "T1029 T1071", "",
       "NDR long-baseline beacon analytics; netflow",
       "quiet",
       "Jitter and long sleeps break fixed-interval detection, but cumulative connections to one "
       "destination over a long baseline still form a beacon pattern NDR can surface.",
       "Quieter per-interval; slows the operator and raises cumulative-volume risk over time."),
    _f("c2_domain_fronting", "Domain fronting (describe-only; largely dead)", "T1090.004", "",
       "TLS-terminating proxy logs (SNI vs Host)",
       "moderate",
       "At a TLS-terminating proxy the SNI (the fronting domain) and the inner HTTP Host header "
       "disagree — the mismatch is the tell; most CDNs now block the technique outright.",
       "Historically hid the true endpoint; now unreliable because providers disabled it."),
```

Add a paired `_o(...)` for `c2_dns_tunnel`, `c2_malleable_profile`, `c2_jitter_beacon`, and `c2_domain_fronting` (each with mandatory `still_recorded`). Add aliases if a tool name maps cleanly (`dnscat2` → `c2_dns_tunnel`, `iodine` → `c2_dns_tunnel`).

- [ ] **Step 4: Run detection + consistency tests**

Run: `backend/.venv/Scripts/python.exe backend/test_detection.py`
Expected: PASS (incl. `test_knowledge_is_internally_consistent`).

- [ ] **Step 5: Commit**

```bash
git add backend/detection/catalog.py backend/detection/attck.py backend/test_detection.py
git commit -m "detection: add C2/DNS-tunnel/jitter/domain-fronting footprints (TA0011)"
```

---

## PHASE 2 — Arsenal catalog (data only)

### Task 4: Catalog the new tools in `tools.json` (CRLF-preserving)

**Files:**
- Modify: `backend/arsenal/tools.json` (add 5 tools; recategorize Sliver; new categories `c2`, `evasion`)
- Modify: `backend/test_arsenal.py` if it hard-codes category counts (update to the new totals)

**Interfaces:**
- Consumes: the tools.json schema `{schema_version, note, placeholders, tools[]}`; each tool `{name, category, purpose, phases[], techniques[], docs, templates[{label, template, note}], platform?}`.
- Produces: entries for `dnscat2`, `iodine`, `donut`, `scarecrow`, `invoke-obfuscation` (`platform: "windows"`); Sliver moved to category `c2`.

- [ ] **Step 1: Write a failing test** — add to `test_arsenal.py`:

```python
def test_c2_and_evasion_tools_catalogued() -> None:
    names = {t["name"].lower() for t in TOOLS}
    for n in ("dnscat2", "iodine", "donut", "scarecrow", "invoke-obfuscation"):
        assert n in names, f"missing arsenal entry {n!r}"
    cats = {t["category"] for t in TOOLS}
    assert {"c2", "evasion"} <= cats, f"expected c2+evasion categories, got {cats}"
    sliver = next(t for t in TOOLS if t["name"].lower() == "sliver")
    assert sliver["category"] == "c2", "Sliver should be recategorized to c2"
    print("  C2 + evasion tools catalogued; Sliver in c2: PASS")
```
(`TOOLS` = the loaded `tools` list — mirror how the file's other tests load it.)

- [ ] **Step 2: Run to verify it fails**

Run: `backend/.venv/Scripts/python.exe backend/test_arsenal.py`
Expected: FAIL.

- [ ] **Step 3: Edit tools.json PRESERVING CRLF.** Use a script (do NOT hand-edit and risk LF): read with `open(..., newline="")` to keep line endings, or load/dump then re-emit with `newline="\r\n"`. Minimal script:

```python
# backend/arsenal/_add_build4_tools.py  (one-shot; delete after)
import json, io
p = "backend/arsenal/tools.json"
with io.open(p, encoding="utf-8") as f:
    d = json.load(f)
tools = d["tools"]
for t in tools:
    if t["name"].lower() == "sliver":
        t["category"] = "c2"
        t["purpose"] = ("Cross-platform adversary-emulation C2 framework (mTLS/HTTP(S)/DNS "
                        "listeners, per-OS implants). Human-driven in HackPit; see cockpit Sliver panel.")
add = [
  {"name": "dnscat2", "category": "evasion", "purpose": "DNS-tunnelled C2/exfil channel...",
   "phases": ["c2","exfiltration"], "techniques": ["DNS tunneling","covert channel"],
   "docs": "https://github.com/iagox86/dnscat2", "templates": [
     {"label": "Server (operator side)", "template": "dnscat2-server <domain>",
      "note": "Run on an authoritative resolver you control; deliver the client one-liner by hand."}]},
  {"name": "iodine", "category": "evasion", "purpose": "IP-over-DNS tunnel...",
   "phases": ["c2","pivoting"], "techniques": ["DNS tunneling","IP over DNS"],
   "docs": "https://github.com/yarrick/iodine", "templates": [
     {"label": "Server", "template": "iodined -f -c -P <password> <tun-ip> <domain>",
      "note": "Operator-side; the client half runs on the compromised host."}]},
  {"name": "donut", "category": "evasion", "purpose": "Shellcode-from-PE/.NET generator...",
   "phases": ["evasion","payload"], "techniques": ["shellcode generation","in-memory execution"],
   "docs": "https://github.com/TheWover/donut", "templates": [
     {"label": "PE -> shellcode", "template": "donut -i <input.exe> -o <output.bin>",
      "note": "Generates position-independent shellcode; deployment is a separate gated step."}]},
  {"name": "scarecrow", "category": "evasion", "purpose": "Loader/packer emitting EDR-evasive Windows payloads from Linux...",
   "phases": ["evasion","payload"], "techniques": ["loader generation","syscall/unhook stubs"],
   "docs": "https://github.com/optiv/ScareCrow", "templates": [
     {"label": "Loader from shellcode", "template": "ScareCrow -I <input.bin> -Loader <binary|dll>",
      "note": "Emits a Windows artifact; HackPit generates only, never deploys."}]},
  {"name": "invoke-obfuscation", "category": "evasion", "platform": "windows",
   "purpose": "PowerShell obfuscation framework (reference-only; Windows/PowerShell host).",
   "phases": ["evasion"], "techniques": ["PowerShell obfuscation"],
   "docs": "https://github.com/danielbohannon/Invoke-Obfuscation", "templates": [
     {"label": "Obfuscate a script", "template": "Invoke-Obfuscation -ScriptPath <script.ps1>",
      "note": "Runs on a Windows PowerShell host; catalogued for reference, not baked in the Linux image."}]},
]
names = {t["name"].lower() for t in tools}
for t in add:
    if t["name"].lower() not in names:
        tools.append(t)
with io.open(p, "w", encoding="utf-8", newline="\r\n") as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
    f.write("\n")
```
Run it, then `git diff --stat` and eyeball `git diff backend/arsenal/tools.json` to confirm CRLF preserved and additive-only. Delete the one-shot script.

- [ ] **Step 4: Run arsenal tests**

Run: `backend/.venv/Scripts/python.exe backend/test_arsenal.py && backend/.venv/Scripts/python.exe backend/test_arsenal_safety.py`
Expected: PASS both (`executes_nothing` still true — the catalog is data).

- [ ] **Step 5: Verify CRLF** — `python -c "print(open('backend/arsenal/tools.json','rb').read().count(b'\r\n'), 'CRLF lines')"` shows a nonzero count and no bare `\n`.

- [ ] **Step 6: Commit**

```bash
git add backend/arsenal/tools.json backend/test_arsenal.py
git commit -m "arsenal: add c2 + evasion tools (dnscat2/iodine/donut/scarecrow/invoke-obfuscation); Sliver -> c2"
```

---

## PHASE 3 — Sliver C2 + DNS-tunnel obfuscation lifecycle

### Task 5: `cockpit/sliver.py` — human-only server lifecycle + gated implant generation + registry

**Files:**
- Create: `backend/cockpit/sliver.py`
- Test: `backend/test_sliver.py`

**Interfaces:**
- Consumes: `config.ENGAGE_SANDBOX_CONTAINER`, `tunnels._container_running` pattern, `executor.validate_request` + `resolve_mode` (gated implant gen), `scope`/engagement lookup, `loot.host_dir`/`container_path`, `runstore.save_run`, `models.ExecRequest`/`RunRecord`.
- Produces:
  - `start_server(req: SliverServerRequest) -> SliverServer` (HUMAN-ONLY)
  - `stop_server(sid: str) -> SliverServer` (HUMAN-ONLY)
  - `list_servers() -> list[SliverServer]`
  - `generate_implant(req: ImplantRequest) -> Implant` (GATED + scope-checked)
  - `list_implants() -> list[Implant]`, `get_implant(iid) -> Implant | None`
  - `SliverServerRequest`, `SliverServer`, `ImplantRequest`, `Implant` (Pydantic), `SliverRefused(RuntimeError)`
  - `_implant_argv(req) -> list[str]` (PURE — safe for UI/proposal path), `_gate_request(req) -> ExecRequest`, `validate_generate(req) -> ExecRejected | None`

- [ ] **Step 1: Write failing tests** in `test_sliver.py` (mirror `test_tunnels.py` + `test_session.py` structure; monkeypatch `subprocess`/`docker` so nothing runs):

```python
"""Functional tests for the Sliver C2 surface. Hermetic: docker/subprocess monkeypatched."""
import sys; sys.path.insert(0, "backend")
from cockpit import sliver as S

def test_implant_argv_is_pure_and_never_substitutes_listener():
    req = S.ImplantRequest(os="windows", arch="amd64", listener="<listener>", target="10.0.0.5",
                           fmt="exe", approved=True, dangerous_ack=True)
    argv = S._implant_argv(req)               # PURE: no execution
    assert "generate" in argv
    assert "<listener>" in argv, "operator-side listener placeholder must pass through verbatim"

def test_generate_is_gated_and_scope_checked(monkeypatch):
    # An out-of-scope target under an active engagement is refused; nothing generated.
    # (mirror test_session.py's gate assertions using a fake engagement + executor.validate_request)
    ...

def test_server_lifecycle_records_a_run(monkeypatch):
    # start_server -> save_run called with command="sliver-server", mode recorded
    ...

if __name__ == "__main__":
    test_implant_argv_is_pure_and_never_substitutes_listener()
    print("ALL sliver functional tests pass")
```

- [ ] **Step 2: Run to verify it fails** — `backend/.venv/Scripts/python.exe backend/test_sliver.py` → FAIL (module missing).

- [ ] **Step 3: Implement `sliver.py`.** Mirror `tunnels.py` for the human-only lifecycle and `session.py` for the gated path. Key load-bearing code:

```python
"""Sliver C2 — human-only lifecycle + GATED implant generation (build #4, item A).

CONTAINMENT (mirrors tunnels.py + session.py):
* start_server / stop_server / generate_implant are HUMAN-ONLY: the orchestrator / agent /
  executor have ZERO code path here (source-scan locked, like tunnels/repeater/session).
* Server lifecycle is "clicking Start is the approval" (no red-confirm) — operator infra.
* generate_implant is a GATED command: it builds an ExecRequest and runs the SAME gates a
  one-shot run does (validate_request → approval + scope + danger red-confirm), scope-checking
  the implant's target host. Deployment is a SEPARATE gated command; this only GENERATES.
* Every start / stop / generate is recorded via runstore.save_run.
* <listener> is operator-side and is NEVER target-substituted.
Live beacon catch / interactive session is DEFERRED (same posture as tunnels' connect-back).
"""
from __future__ import annotations
import subprocess, uuid
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from . import config, executor, loot, runstore
from .models import ExecRequest, ExecRejected, RunRecord

class ImplantRequest(BaseModel):
    os: str = "windows"; arch: str = "amd64"; fmt: str = "exe"
    listener: str = "<listener>"          # operator-side; NEVER substituted
    target: str = ""                       # scope-checked when an engagement is active
    engagement_id: str | None = None; session_id: str | None = None; step_id: str | None = None
    approved: bool = False
    dangerous_ack: bool = Field(default=False)

def _implant_argv(req: ImplantRequest) -> list[str]:
    # PURE argv construction — no execution. Safe for the UI/proposal path.
    return ["sliver-client", "generate", "--os", req.os, "--arch", req.arch,
            "--format", req.fmt, "--mtls", req.listener]

def _gate_request(req: ImplantRequest) -> ExecRequest:
    # Gate the superset (argv + declared target) — at-least-as-strict as gating argv alone.
    return ExecRequest(command="sliver-client", args=[*_implant_argv(req)[1:], req.target],
                       approved=req.approved, dangerous_ack=req.dangerous_ack,
                       engagement_id=req.engagement_id, session_id=req.session_id, step_id=req.step_id)

def validate_generate(req: ImplantRequest) -> ExecRejected | None:
    return executor.validate_request(_gate_request(req))

def generate_implant(req: ImplantRequest) -> "Implant":
    rejected = validate_generate(req)
    if rejected is not None:
        raise SliverRefused(rejected.reason, gate=rejected.gate)
    resolved = executor.resolve_mode(_gate_request(req))   # container from the mode, never the request
    run_id = uuid.uuid4().hex[:12]
    out_name = f"implant-{run_id}.{req.fmt}"
    argv = ["docker", "exec", resolved.container, *_implant_argv(req),
            "--save", loot.container_path(out_name)]        # artifact lands in the loot dir
    # ... subprocess.run(argv), capture, then:
    runstore.save_run(RunRecord(run_id=run_id, command="sliver-generate",
                                args=[req.os, req.arch, req.fmt], target=req.target,
                                mode=resolved.mode, exit_code=..., stdout=..., stderr=...,
                                started_at=...))
    # register + return Implant(...)
```
Server lifecycle (`start_server`/`stop_server`) mirrors `tunnels.start_tunnel`/`stop_tunnel` verbatim in structure: track a `_LiveServer`, `docker exec`/`Popen` `sliver-server` inside `config.ENGAGE_SANDBOX_CONTAINER`, `save_run(command="sliver-server", ...)`, no gate. Add `SliverRefused(RuntimeError)` with a `gate` attr like `SessionRefused`.

- [ ] **Step 4: Run to verify pass** — `backend/.venv/Scripts/python.exe backend/test_sliver.py` → PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/cockpit/sliver.py backend/test_sliver.py
git commit -m "cockpit: add Sliver C2 (human-only server lifecycle + gated implant generation)"
```

### Task 6: DNS-tunnel obfuscation lifecycle (dnscat2 / iodine)

**Files:**
- Create: `backend/cockpit/obfuscation.py` (or extend `sliver.py` — keep it separate: DNS tunneling is its own surface)
- Test: `backend/test_obfuscation.py`

**Interfaces:**
- Consumes: same as tunnels (`config.ENGAGE_SANDBOX_CONTAINER`, `runstore.save_run`).
- Produces: `start_listener(req: ObfuscationRequest) -> ObfuscationListener` (HUMAN-ONLY), `stop_listener(lid)`, `list_listeners()`, `operator_oneliner(listener) -> str` (the client half to run BY HAND on the compromised host — never delivered automatically).

- [ ] **Step 1: Write failing test** — `test_obfuscation.py`: `start_listener` for `dnscat2` and `iodine` records a run; `operator_oneliner` returns a string containing the operator's domain and does NOT auto-run; source has no executor/agent import. Mirror `test_tunnels.py`.

- [ ] **Step 2: Run → FAIL** (module missing).

- [ ] **Step 3: Implement `obfuscation.py`** mirroring `tunnels.py` lifecycle exactly (human-only listener start/stop inside the engage sandbox, hand back the one-liner, audited). No gate (infra).

- [ ] **Step 4: Run → PASS.**

- [ ] **Step 5: Commit** — `git commit -m "cockpit: add dnscat2/iodine DNS-tunnel obfuscation lifecycle (human-only)"`

### Task 7: Sliver + obfuscation safety tests + main.py routes + frontend panel

**Files:**
- Create: `backend/test_sliver_safety.py`, `backend/test_obfuscation_safety.py` (or fold obfuscation into the sliver safety test)
- Modify: `backend/main.py` (HTTP routes: `/api/sliver/*`, `/api/obfuscation/*` — human-only)
- Create/Modify: frontend panel (TSX) for the Sliver + obfuscation surface (mirror the tunnels/session panels)

**Interfaces:**
- Consumes: `sliver`, `obfuscation` public fns.
- Produces: the safety invariants (regression-locked): AST/source scan proving no orchestrator/agent/executor path; lifecycle human-only; generation gated + scope-checked; `<listener>` never substituted; every action audited.

- [ ] **Step 1: Write `test_sliver_safety.py`** — mirror `test_repeater`/`test_session` safety scans:

```python
"""SAFETY INVARIANTS for the Sliver C2 surface (build #4, item A). Hermetic."""
import ast, sys, pathlib
ROOT = pathlib.Path("backend")

def test_no_orchestrator_or_agent_path_to_sliver():
    """No orchestrator/loop/agent module may import cockpit.sliver.generate_* or start_*."""
    offenders = []
    for p in ROOT.rglob("*.py"):
        if p.name in {"sliver.py", "test_sliver.py", "test_sliver_safety.py"}: continue
        src = p.read_text(encoding="utf-8", errors="ignore")
        if "orchestrat" in p.name or "loop" in p.name or "adorch" in p.name:
            assert "sliver" not in src, f"{p} references sliver — no agent path allowed"
    print("  no orchestrator/agent path to Sliver: PASS")

def test_generate_is_gated():
    from cockpit import sliver as S
    # validate_generate routes through executor.validate_request (the real gates)
    import cockpit.executor as E
    assert S.validate_generate.__module__.endswith("sliver")
    # a request with approved=False is refused (gate fires)
    ...

def test_listener_placeholder_never_substituted():
    from cockpit import sliver as S
    argv = S._implant_argv(S.ImplantRequest(listener="<listener>", target="10.0.0.9"))
    assert "<listener>" in argv and "10.0.0.9" not in argv
    print("  <listener> is operator-side, never target-substituted: PASS")

if __name__ == "__main__":
    test_no_orchestrator_or_agent_path_to_sliver()
    test_listener_placeholder_never_substituted()
    print("ALL sliver safety tests pass")
```

- [ ] **Step 2: Run → confirm PASS** (the modules already satisfy the invariants; if a test fails it's a real leak — fix the module, not the test).

Run: `backend/.venv/Scripts/python.exe backend/test_sliver_safety.py`

- [ ] **Step 3: Wire routes in `main.py`** — add human-only endpoints that call `sliver.*` / `obfuscation.*` (mirror the tunnels/session routes). NO orchestrator wiring. Keep routes in `main.py` (decoupling rule).

- [ ] **Step 4: Add the frontend panel** — mirror the existing tunnels/session panel TSX; a "Sliver C2 / Obfuscation" surface with start/stop + generate (generate shows the red-confirm). Run the frontend typecheck/build.

- [ ] **Step 5: Run both safety tests + frontend build**

Run: `backend/.venv/Scripts/python.exe backend/test_sliver_safety.py && backend/.venv/Scripts/python.exe backend/test_obfuscation_safety.py`
Then the frontend build command (mirror how other panels are built/verified).

- [ ] **Step 6: Commit** — `git commit -m "cockpit: wire Sliver + obfuscation routes/panel + safety tests"`

---

## PHASE 4 — Bespoke evasion engine

### Task 8: `backend/evasion/` package — generate-only artifact producer with forced honesty

**Files:**
- Create: `backend/evasion/__init__.py`, `backend/evasion/engine.py`, `backend/evasion/templates/amsi_patch.ps1.tmpl`, `backend/evasion/templates/etw_blind.ps1.tmpl`
- Test: `backend/test_evasion.py`

**Interfaces:**
- Consumes: `config.KALI_OPEN_CONTAINER` (donut/scarecrow argv, mirror repeater's hardcoded container), `loot.host_dir`/`container_path`, `detection.resolver.footprint(..., include_opsec=True)` + `assert_opsec_is_separate`, `runstore.save_run`.
- Produces:
  - `generate(req: EvasionRequest) -> EvasionResult` (GATED + scope-checked; GENERATES ONLY)
  - `EvasionRequest(payload_path, target_os, techniques: list[str], target: str = "", engagement_id, approved, dangerous_ack)`
  - `EvasionResult(artifact_path, techniques, footprint: dict, opsec_note: dict)` — `footprint` and `opsec_note` are MANDATORY and non-None; `opsec_note["still_recorded"]` non-empty.
  - `_donut_argv(req)`, `_scarecrow_argv(req)`, `_render_stub(technique)` (PURE)

- [ ] **Step 1: Write failing tests** in `test_evasion.py`:

```python
"""Functional tests for the bespoke evasion engine. Hermetic: docker monkeypatched."""
import sys; sys.path.insert(0, "backend")
from evasion import engine as G

def test_generate_emits_artifact_and_mandatory_honest_footprint(monkeypatch):
    # monkeypatch the docker exec so 'generation' writes a dummy artifact
    res = G.generate(G.EvasionRequest(payload_path="/loot/in.exe", target_os="windows",
                                      techniques=["donut-pack", "amsi-patch"],
                                      approved=True, dangerous_ack=True))
    assert res.artifact_path, "an artifact must be produced"
    assert res.footprint and res.footprint.get("activity"), "blue-view footprint is mandatory"
    assert res.opsec_note and res.opsec_note["still_recorded"].strip(), \
        "every generation must carry a still_recorded honesty marker"

def test_generate_never_runs_the_payload(monkeypatch):
    # assert the only subprocess call is the generator (donut/scarecrow), never the artifact itself
    ...

def test_amsi_stub_template_renders_with_honesty_note():
    stub = G._render_stub("amsi-patch")
    assert stub.strip(), "stub must render"
    # the paired footprint/opsec must name what still records an AMSI patch
    ...

if __name__ == "__main__":
    # run all
    print("ALL evasion functional tests pass")
```

- [ ] **Step 2: Run → FAIL** (package missing).

- [ ] **Step 3: Implement `evasion/engine.py`.** Load-bearing structure:

```python
"""Bespoke evasion engine (build #4, item C) — GENERATES ONLY, never runs/deploys.

CONTAINMENT (mirrors repeater.py):
* generate() runs generators (donut/scarecrow) as argv-only `docker exec` inside the HARDCODED
  config.KALI_OPEN_CONTAINER — the container is a code constant, never a request field, and no
  shell parses any request value.
* It GENERATES an artifact into the loot dir. It NEVER runs or deploys the artifact — deployment
  is a separate gated command elsewhere.
* HUMAN-invoked via the main.py endpoint only; the orchestrator/agent/executor have ZERO path
  here (AST-asserted by test_evasion_safety.py).
* GATED (red-confirm) + scope-checked when the artifact targets a scoped host + audited.

FORCED HONESTY (build #4, D-guard): every generate() result carries BOTH the blue-view detection
footprint for the artifact's technique(s) AND an OPSEC/evasion note whose still_recorded names
what still catches it. A result missing either is a bug — generate() raises rather than return
a footprint-less artifact. The footprint is never suppressed.
"""
from __future__ import annotations
import sys, subprocess, uuid
from pathlib import Path
from pydantic import BaseModel, Field
# detection is a peer top-level package
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # or rely on existing sys.path setup
from cockpit import config, loot, runstore, executor
from cockpit.models import ExecRequest, RunRecord
from detection import resolver as det

_TECHNIQUE_TO_SPEC = {           # map each technique to a detection spec key for the blue footprint
    "amsi-patch": "c2_malleable_profile",   # replace with a dedicated evasion spec (see note)
    "etw-blind": "c2_malleable_profile",
    "donut-pack": "c2_malleable_profile",
}

def generate(req: "EvasionRequest") -> "EvasionResult":
    rejected = executor.validate_request(_gate_request(req))
    if rejected is not None:
        raise EvasionRefused(rejected.reason, gate=rejected.gate)
    resolved = executor.resolve_mode(_gate_request(req))
    run_id = uuid.uuid4().hex[:12]
    out_name = f"evasive-{run_id}.bin"
    argv = _donut_argv(req, out_name) if "donut-pack" in req.techniques else _scarecrow_argv(req, out_name)
    argv = ["docker", "exec", config.KALI_OPEN_CONTAINER, *argv]   # hardcoded container
    # subprocess.run(argv) ; write stub templates into the loot dir for amsi-patch/etw-blind
    footprint, opsec = _honest_footprint(req.techniques)          # MANDATORY
    if not (footprint and footprint.get("activity")) or not (opsec and opsec["still_recorded"].strip()):
        raise EvasionError("refusing to emit an artifact without a blue footprint + still_recorded note")
    runstore.save_run(RunRecord(run_id=run_id, command="evasion-generate",
                                args=list(req.techniques), target=req.target, mode=resolved.mode, ...))
    return EvasionResult(artifact_path=str(loot.host_dir(req.engagement_id or "default") / out_name),
                         techniques=req.techniques, footprint=footprint, opsec_note=opsec)

def _honest_footprint(techniques: list[str]) -> tuple[dict, dict]:
    key = _TECHNIQUE_TO_SPEC.get(techniques[0])
    fp = det.footprint("evasion-artifact", techniques, allow_llm=False, include_opsec=True)
    opsec = fp.get("opsec") or {
        "grounded": True, "still_recorded": "The loader/patch has its own known-bad signatures "
        "(image-load, memory-write, AMSI-bypass rules); the process, its child processes and "
        "network callbacks are still recorded.", "quieter": ["..."], "loud_because": "...", "tradeoff": "..."}
    det.assert_opsec_is_separate(opsec, "evasion generate")       # honesty marker enforced
    return fp, opsec
```

**Note for the implementer:** add a *dedicated* evasion footprint spec (e.g. `evasion_packed_loader`, `evasion_amsi_patch`, `evasion_etw_blind`) to `detection/catalog.py` in this task (mapped to TA0005 ids — T1027 obfuscated files, T1562.001 impair defenses / disable-or-modify-tools, T1562.006 impair command history / ETW) with paired OpsecNotes, rather than reusing `c2_malleable_profile`. That keeps `_TECHNIQUE_TO_SPEC` honest and `test_knowledge_is_internally_consistent` green.

Stub templates (`amsi_patch.ps1.tmpl`, `etw_blind.ps1.tmpl`) are text the engine writes into the loot dir alongside the artifact — real, minimal AMSI-patch / ETW-blind stubs (this is authorized CRTP tradecraft), each with a header comment naming what still records it.

- [ ] **Step 4: Run → PASS** — `backend/.venv/Scripts/python.exe backend/test_evasion.py`.

- [ ] **Step 5: Verify no repo file trips Defender** — the artifacts land in the loot dir (data/engagements), which is gitignored; confirm no generated artifact is staged and the stub *templates* (inert `.tmpl`) don't match a live signature. `git status` shows only source.

- [ ] **Step 6: Commit** — `git commit -m "evasion: add generate-only engine (donut/scarecrow + amsi/etw stubs) with forced honest footprint"`

### Task 9: main.py endpoint + gating wiring for the evasion engine

**Files:**
- Modify: `backend/main.py` (route `/api/evasion/generate` — human-only, red-confirm surfaced, calls `evasion.engine.generate`)
- Create/Modify: frontend evasion panel (TSX)

- [ ] **Step 1:** Add the route (mirror the session-start route: it accepts `approved`/`dangerous_ack`, returns the `EvasionResult` incl. the footprint + opsec note so the UI always shows the honest footprint).
- [ ] **Step 2:** Add the frontend panel; the generate button flows through the red-confirm; the result view ALWAYS renders the blue footprint + still_recorded note (never hideable).
- [ ] **Step 3:** Frontend typecheck/build.
- [ ] **Step 4: Commit** — `git commit -m "evasion: wire generate endpoint + panel (footprint always shown)"`

### Task 10: `test_evasion_safety.py` — the AST/containment lock

**Files:**
- Create: `backend/test_evasion_safety.py`

- [ ] **Step 1: Write the safety tests** (mirror `test_detection_safety.py` + `test_repeater` safety):

```python
"""SAFETY INVARIANTS for the evasion engine (build #4, item C). Hermetic."""
import ast, pathlib
PKG = pathlib.Path("backend/evasion")

def test_no_orchestrator_or_agent_path_to_evasion():
    for p in pathlib.Path("backend").rglob("*.py"):
        if "orchestrat" in p.name or "loop" in p.name or "adorch" in p.name:
            assert "evasion" not in p.read_text(encoding="utf-8", errors="ignore"), \
                f"{p} references evasion — no agent path allowed"
    print("  no orchestrator/agent path to evasion: PASS")

def test_generate_is_gated_and_scope_checked():
    from evasion import engine as G
    # approved=False -> refused; out-of-scope target under an engagement -> refused
    ...

def test_every_result_carries_footprint_and_still_recorded(monkeypatch):
    from evasion import engine as G
    res = G.generate(G.EvasionRequest(payload_path="/loot/in.exe", target_os="windows",
                                      techniques=["donut-pack"], approved=True, dangerous_ack=True))
    assert res.footprint.get("activity") and res.opsec_note["still_recorded"].strip()
    print("  every artifact carries a blue footprint + still_recorded note: PASS")

def test_engine_never_executes_the_artifact():
    # only donut/scarecrow argv is ever exec'd; the produced artifact path is never a subprocess arg[0]
    ...

if __name__ == "__main__":
    test_no_orchestrator_or_agent_path_to_evasion()
    print("ALL evasion safety tests pass")
```

- [ ] **Step 2: Run → PASS** (fix the module, never the invariant, if a test fails).
- [ ] **Step 3: Commit** — `git commit -m "evasion: safety invariants (no agent path / gated / generate-only / forced honesty)"`

---

## PHASE 5 — Image build + smoke tests

### Task 11: Install + smoke-test the new tools in `docker/Dockerfile.sandbox`

**Files:**
- Modify: `docker/Dockerfile.sandbox` (new RUN layer(s) + smoke tests)

**Interfaces:** none (build-time only).

- [ ] **Step 1: Add an install layer** after the existing tool layers. Use RELEASE BINARIES to dodge the Go trap:

```dockerfile
# --- 8. C2 + evasion (build #4) -----------------------------------------------
# Sliver: official release binaries (NOT `go install` — avoids the Go-toolchain floor).
RUN set -eux; \
    curl -fsSL -o /usr/local/bin/sliver-server https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux; \
    curl -fsSL -o /usr/local/bin/sliver-client https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux; \
    chmod +x /usr/local/bin/sliver-server /usr/local/bin/sliver-client
# DNS tunneling
RUN apt-get update && apt-get install -y --no-install-recommends dnscat2 iodine && rm -rf /var/lib/apt/lists/*
# Donut (shellcode gen) + ScareCrow (loader gen, release binary)
RUN pip install --no-cache-dir donut-shellcode
RUN set -eux; \
    curl -fsSL -o /tmp/scarecrow https://github.com/optiv/ScareCrow/releases/latest/download/ScareCrow_$(uname -m); \
    install -m 0755 /tmp/scarecrow /usr/local/bin/ScareCrow; rm -f /tmp/scarecrow
```
(If `dnscat2`/`iodine` are not in the base repos, build dnscat2 from git and iodine from source; confirm the exact package names against the Kali base at build time.)

- [ ] **Step 2: Add a smoke-test layer** that FAILS the build if any binary is missing:

```dockerfile
RUN set -eux; \
    sliver-server version; \
    sliver-client version || true; \
    command -v dnscat2 || dpkg -s dnscat2; \
    iodine --version 2>&1 | head -1 || true; \
    python3 -c "import donut; print('donut', donut.__file__)"; \
    ScareCrow -h >/dev/null 2>&1 || ScareCrow --help >/dev/null 2>&1 || true
```

- [ ] **Step 3: Build in the BACKGROUND** (~9 GB):

Run (background): `docker build -f docker/Dockerfile.sandbox -t hackpit-kali:build4 .`

- [ ] **Step 4: When the build finishes, report per-tool smoke-test results** — parse the smoke-test layer output; note any tool that fell back to reference-only (e.g. Shellter if wine build failed). If a tool can't be installed cleanly, drop it to reference-only in `tools.json` (Task 4 follow-up) and note it.

- [ ] **Step 5: Commit** — `git commit -m "image: install + smoke-test Sliver/dnscat2/iodine/donut/ScareCrow (build #4)"`

---

## PHASE 6 — Runner, assessment, push

### Task 12: Wire new safety tests into the runner + full green run

**Files:**
- Modify: `backend/run_safety_tests.sh`

- [ ] **Step 1:** Add lines for the new tests:

```sh
echo "== Sliver C2 SAFETY (no agent path / lifecycle human-only / generation gated+scoped / audited) =="
"$PY" test_sliver_safety.py
echo "== obfuscation SAFETY (human-only listener / one-liner not auto-delivered) =="
"$PY" test_obfuscation_safety.py
echo "== evasion engine SAFETY (no agent path / gated / generate-only / forced honest footprint) =="
"$PY" test_evasion_safety.py
```

- [ ] **Step 2: Run the WHOLE suite**

Run: `sh backend/run_safety_tests.sh`
Expected: every section PASS, INCLUDING the rewritten detection tests (new contract).

- [ ] **Step 3: Commit** — `git commit -m "safety: add Sliver/obfuscation/evasion suites to run_safety_tests.sh"`

### Task 13: Fold #4 into the assessment + regenerate .html/.pdf

**Files:**
- Modify: `docs/ASSESSMENT-2026-07-26.md` (new PART III subsection + amend D10 / add a D-entry)
- Regenerate: `docs/ASSESSMENT-2026-07-26.html`, `docs/ASSESSMENT-2026-07-26.pdf`

- [ ] **Step 1: Write the PART III subsection** "AV/EDR evasion + traffic obfuscation" covering: Sliver (option A, human-only lifecycle + gated implant gen, live beacon deferred); traffic obfuscation (dnscat2/iodine, jitter/profile config, domain-fronting describe-only); the bespoke evasion engine (generate-only, loot-dir output, forced honest footprint); the **guard rewrite** (what changed: `_opsec_has_tamper` removed, honesty marker + always-on blue footprint are the surviving invariants; and that gate/scope/audit/no-autonomy are UNTOUCHED); the persistence OpsecNote backfill. Be honest about the public-repo posture shift. **No `~~` strikethrough.**

- [ ] **Step 2: Amend D10 / add a D-entry** recording the guard change as an explicit decision (mirror the existing D-entry style in Part II).

- [ ] **Step 3: Regenerate the .html** — split the CURRENT `.html` on the literal marker `<div class="toc"><span class="toctitle">Contents</span>` to reuse head/style/cover VERBATIM, then append that marker + a FRESH ToC (the Markdown instance's `.toc`) + `</div></div>` + converted body + `</body></html>`. Convert with `backend/.venv/Scripts/python.exe` + python-markdown extensions `[tables, fenced_code, toc, sane_lists, attr_list]`. (Reuse the generator approach from obs 1992 / the reconFTW regen.)

- [ ] **Step 4: Regenerate the .pdf** with Edge headless:

```
"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu --no-pdf-header-footer --print-to-pdf="C:\Users\zaid_\Downloads\HackPit\docs\ASSESSMENT-2026-07-26.pdf" "file:///C:/Users/zaid_/Downloads/HackPit/docs/ASSESSMENT-2026-07-26.html"
```

- [ ] **Step 5: Verify** — `.html` has the reused `<style>` + cover + a fresh ToC INCLUDING the #4 section; `.pdf` starts with `%PDF` and is multi-page:

```
python -c "print(open('docs/ASSESSMENT-2026-07-26.pdf','rb').read(4))"   # b'%PDF'
```

- [ ] **Step 6: Commit** — `git commit -m "assessment: fold in build #4 (evasion + obfuscation); record the guard-change decision; regen .html/.pdf"`

### Task 14: Push

- [ ] **Step 1:** `git push origin sandbox-kali-image`
- [ ] **Step 2:** Confirm `git rev-list --left-right --count origin/sandbox-kali-image...HEAD` is `0 0`.
- [ ] **Step 3:** Report the per-tool image smoke-test results and the final test-suite status to the operator.

---

## Self-review (completed)

- **Spec coverage:** A→Tasks 5,7; B→Tasks 6,7; C→Tasks 8,9,10; D→Tasks 1,2 (+ dedicated evasion specs in Task 8); E→Task 3; F→Tasks 4,11. Assessment→Task 13. Push→Task 14. All spec sections mapped.
- **Placeholders:** the `...` inside a few test bodies mark where the implementer fills mechanics that mirror a named existing test (`test_session.py` for gate assertions, `test_tunnels.py` for lifecycle) — each is anchored to a concrete mirror file and the exact assertion is stated in prose. The load-bearing code (guard rewrite, forced-honesty, argv/containment) is given in full.
- **Type consistency:** `ImplantRequest`/`Implant`/`EvasionRequest`/`EvasionResult` field and method names are consistent across Tasks 5/7/8/10; `assert_opsec_is_separate(opsec, where)` signature matches its consumers; `footprint(..., include_opsec=True)` matches the verbatim interface block.
- **Ordering:** Phase 0 (guard) precedes every consumer of the new contract; Task 8 adds the dedicated evasion detection specs before wiring so `_TECHNIQUE_TO_SPEC` resolves and the consistency test stays green.
