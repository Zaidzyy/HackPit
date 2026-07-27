# Backend conventions

## Running the tests

The safety suites are PLAIN SCRIPTS. No pytest, no fixtures, no collection — each file has a
`if __name__ == "__main__":` block that calls its tests in order, and monkeypatching is done by
hand with save/restore in `try/finally`.

```sh
backend/.venv/Scripts/python.exe backend/test_winrm_safety.py   # one file, from the REPO ROOT
sh backend/run_safety_tests.sh                                  # the whole suite, repo root only
```

`run_safety_tests.sh` `cd`s to its own directory, so it only works with the repo root as cwd
despite the path starting with `backend/`.

---

# THE SAFETY-TEST RULE

**A safety test must iterate real data, assert on what it actually checked, and prove it can
fail.**

This is not style advice. Every critical finding in the 2026-07-27 gate audit was a guard whose
*condition* was narrower than the thing it was meant to catch, sitting behind a test that could
not fail. The guards looked correct, printed a passing line, and did nothing:

| Guard | What it checked | What it claimed to catch |
|---|---|---|
| Danger heuristic (WinRM) | `argv[0]` | a whole PowerShell script |
| `:kali` human-only lock | `backend/*.py` + `cockpit/*.py` (30 of 69) | "the whole source tree" |
| cockpit→arsenal lock | 5 hardcoded filenames | "the cockpit package" (22 modules) |
| `test_arsenal_safety:144` | `python3`, absent from the catalog | "a catalogued dangerous invocation" |
| evasion agent-path scan | 5 files, counted as 99 | every agent-ish module |

That last one hid eight tools that generate a webshell, open a DNS C2 channel or drop to a
remote OS shell — all passing on a plain `approved=true`. The test that would have caught them
was permanently green because of one choice: it tested a synthetic value the real system never
produces.

## 1. Draw inputs from the real source of truth

Never hand-write an example when the real population is enumerable. Iterate `tools.json`, the
real module tree, the real route table, the real technique catalog.

```python
# NO — the assertion this advertises is never executed. python3 is not in the catalog.
flagged = validate_request(ExecRequest(command="python3", args=["-c", "print(1)"], approved=True))

# YES — every name, alias and template argv[0] the catalog can actually produce.
for name in sorted(_catalog_invocations()):
    ...
```

The payoff is that a tool or module added tomorrow is covered by *nobody remembering to add
it*. A test keyed to a hand-written list rots the moment the system grows, and it rots silently,
because a shorter list still passes.

## 2. Assert on what you CHECKED, not on what you opened

A count is only evidence if it counts the right thing. Build #4 asserted `scanned > 40` where
`scanned` was incremented **before** the filter that decided whether to read the file: 99
counted, 5 inspected, and renaming `orchestrator.py` would have collapsed the scan to nothing
while still printing a passing "99 modules scanned".

`test_support/scans.py` returns `checked` and `skipped` separately for exactly this reason.
Assert on `checked`. If you write your own loop, put the counter **below** every `continue`.

## 3. Carry a positive control — in the same test

A guard test with no demonstration that it can fail is not evidence. "No offenders" is what a
working guard reports *and* what a broken one reports; the two are indistinguishable without a
control.

```python
scans.assert_catches_a_planted_violation(          # it CAN fail
    plant="from cockpit.kali import run_kali",
    patterns=_KALI_PATTERNS, allowed=_KALI_ALLOWED, ast_targets=_KALI_AST_TARGETS,
)
```

Plant the violation somewhere the *old, broken* version would have missed —
`adgraph/orchestrator.py` is the default for that reason. And assert the clean tree still
passes: a scan that fires on everything is as useless as one that fires on nothing.

Where a planted tree does not fit, the equivalent is an `ALLOWED_REFERENCES`-style control: the
files you allow-listed must still MATCH the patterns, so a rename cannot quietly empty them.
`scans.assert_clean(..., require_controls=...)` does this.

## 4. Use the shared scanner for any source-scan lock

`from test_support import scans`. Do not write a new glob.

- `scans.source_files()` — the whole backend, minus venv/caches. Never a hand-rolled glob:
  eleven copies drifted, and nine of them were wrong.
- Allow-lists are keyed on **repo-relative POSIX paths**. Never basenames. `{"router.py"}`
  matched against `f.name` exempted `adgraph/router.py`, `detection/router.py`,
  `arsenal/router.py` and every other `router.py` in the tree by accident.
- Pass `ast_targets=` as well as `patterns=`. Substrings cannot see an aliased import, an
  import opened inside a function body, `import_module("cockpit." + "kali")` or
  `getattr(m, "run_" + "kali")`. The audit planted all four; all four were missed.
- Prose is stripped so a module that *documents* a rule does not violate it — but ordinary
  string literals are **kept**, because blanking them would go blind to
  `import_module("cockpit.kali")`, which is the indirection the lock exists to catch.

`test_scans.py` runs first in the suite and demonstrates each of these on a planted violation.
Ten locks rest on that module; if it cannot fail, nothing after it means much.

## 5. When a wider scan produces a false positive, fix the PREDICATE

Widening coverage will surface matches that are not violations. Two showed up in build #5:
`cockpit/reconcile.py` "referenced the arsenal" (as a *parameter name* — it takes the catalog
as an injected opaque object precisely so it has no import-time dependency), and the detection
package "reached the evasion engine" (it is the *anti*-evasion guard, the code that refuses
prescriptive evasion copy).

The response to a false positive is a better predicate — assert the claim the invariant
actually makes, e.g. "no import, in any form the AST can see" — **never a narrower file set**.
Narrowing the file set to silence a false positive is how these guards got broken originally.

---

## Related invariants worth knowing before you edit

- **cockpit ↔ arsenal may not reference each other in either direction.** Cross-cutting
  endpoints belong in `main.py`.
- **The AD orchestrator may not construct an `ExecRequest`.** A proposer that can build one is
  one line from firing it (`test_adorch_safety.py`). Shared helpers therefore take
  `(command, args)`, not a request object.
- **The gate must classify the string that actually executes.** On the WinRM path both sides
  derive it from `executor.join_ps_command()`; a test asserts on the source, transitively, that
  they still do. Classifying a *different* string than the one that runs is the Critical 2 bug
  reappearing somewhere new.
