# :code scan — static application-security analysis

Point it at a codebase folder, run the scanners, read the findings.

This is the **defensive** half of HackPit. Everything else in the project is about reaching a
target; this reads source code to find the bugs *before* anyone reaches it. It is deliberately
a self-contained utility that happens to share a backend — no target, no network, no
engagement, no gates.

---

## The framing

**SAST is static.** The scanners parse source files. They do not run the program, import it,
or evaluate anything in it. Everything below follows from that.

Because a code scan has no target and no execution path, it is **orthogonal to the entire
attack surface**: the engagement model, the executor, the target-lock, the program scope and
the sandbox isolation are all uninvolved. `codescan/` imports none of them, and a test asserts
it (see [Safety](#safety-what-is-actually-guarded)).

---

## Tools and rulesets

Both are **optional** dependencies — every other route works without them, and the scan
endpoints report a clean "not installed" with the exact install command rather than crashing.

```
cd backend && uv pip install semgrep bandit     # or: pip install semgrep bandit
```

| Tool | Covers | Invocation |
|---|---|---|
| **Semgrep** | multi-language (Python, JS/TS, and more) | `semgrep --json --config <ruleset> <path>` |
| **Bandit** | Python only, run when the tree contains `.py` | `bandit -r <path> -f json` |

Semgrep is the required half — it is what makes the scan multi-language. Bandit is
**never fatal**: missing, slow or broken, it degrades to a warning and the results are
semgrep-only.

### The bundled ruleset (offline by default)

Semgrep's registry configs (`--config auto`, `p/security-audit`) fetch rules **over the
network** and can require an account. The default here is instead
`backend/codescan/rules/hackpit-security.yaml` — 19 rules that ship with the repo:

injection (SQL, OS command, eval) · XSS (DOM sinks, `dangerouslySetInnerHTML`) ·
path traversal · SSRF · XXE · insecure deserialization · weak hashing · disabled TLS
verification · insecure randomness · JWT verification disabled · hardcoded credentials ·
debug mode · permissive CORS.

Each carries **CWE + OWASP** metadata, which is what the category grouping and the KB tie-in
are derived from.

So a scan needs **no network, no account, no registry availability**, and returns the same
findings today and next year. Telemetry and the version check are explicitly disabled
(`--metrics off --disable-version-check`).

**You can still pass a registry ruleset** — `semgrep_config: "p/security-audit"` on the scan
request — when you want the full catalogue. That form **requires network access**; the
dependency is documented rather than silent.

---

## The normalized schema

Semgrep and Bandit describe the same defect differently. `codescan/findings.py` flattens both:

```jsonc
{
  "rule_id":  "hp-python-sql-string-build",   // or "B602:subprocess_popen_with_shell_equals_true"
  "tool":     "bandit+semgrep",               // both tools reported it
  "tools":    ["semgrep", "bandit"],
  "severity": "high",                         // critical | high | medium | low | info
  "tool_severity": "ERROR",                   // the scanner's OWN word, before mapping
  "file":     "app/db.py",                    // relative to the scan root
  "line":     41,
  "message":  "SQL statement built by string concatenation…",
  "category": "injection",                    // derived from the CWE — tool-independent
  "cwe":      "CWE-89",
  "owasp":    "A03:2021 - Injection",
  "confidence": "MEDIUM",                     // bandit only
  "kb_entry_id": "patt-sql-injection",        // null when nothing matched confidently
  "kb_title":    "SQL Injection"
}
```

Two rules govern it:

* **Faithful to the tool.** Id, message, severity and location come from the scanner. Severity
  is *mapped* between vocabularies, never re-judged — and `tool_severity` keeps the original
  word so the mapping is auditable.
* **Defensive parsing.** A missing key, a null, a wrong type or a truncated record drops that
  one finding, never the run.

### Dedupe is corroboration, not duplication

Identity is **location + CWE** (falling back to category) — deliberately *not* the rule id,
since the whole point is that two tools name the same defect differently. When both report the
same defect they collapse into one finding carrying both tool names, the **worse** severity and
the more specific rule id. The UI shows it as "bandit + semgrep agree".

---

## The KB tie-in

A scanner says *SQL injection, line 41*. The KB knows *what that is and how it gets exploited*.
Where a finding's category maps to a real technique, the finding links to it.

**Never fabricated** — same discipline as grounded vs `ai_suggested` steps in the attack path.
A candidate must be step-eligible (a technique page, not a writeup or grab-bag) **and** its
title or summary must actually contain one of the category's own words. No confident match →
no link.

That check earned its keep during the build: a loose `tls` token matched **"Evil Twin
EAP-TLS"** — a WiFi attack — for the crypto category. Tokens now have to name the *class*, not
a protocol the page happens to mention.

One search per distinct **category**, not per finding, so a hundred SQLi findings share one
lookup. With no KB the scan runs identically, just unlinked.

---

## Bounding

A scanner pointed at a huge tree is the only real failure mode, so it is bounded three ways.

| Bound | Value | Behaviour |
|---|---|---|
| **Timeout** (per scanner) | 120 s default, 600 s ceiling | process killed, reported as a clean timeout — never left running |
| **Output cap** | 16 MB | stdout is spooled to a **file** and its SIZE is checked *before* any read, so oversized output never enters memory |
| **File count** | 20,000 | an oversized tree is refused **before** a scanner launches |
| **Path** | — | must exist, must be a **directory**, resolved to an absolute real path |

Dependency and build trees (`node_modules`, `.git`, `.venv`, `dist`, `target`, …) are skipped:
they dominate the runtime and their findings aren't the reviewer's code.

---

## Safety: what is actually guarded

The concerns here are mundane, and all of them are tested (`test_codescan_safety.py`).

### 1. Static only — the scanned code is never executed

The guarantee is enforced, not asserted in prose. `runner._spawn()` checks that `argv[0]` is
one of `("semgrep", "bandit")` **before every subprocess call**, so a path from the codebase
can only ever be an *argument* to a scanner, never the program that runs.

The test hands `_spawn` python, `sh`, `cmd.exe`, `node`, a planted `./configure` from the
scanned tree, and the near-miss name `semgreppy` — all refused. A source-scan adds: no `eval`,
no `exec`, no `compile` builtin, no `__import__`/`importlib`, no `pickle`, no `shell=True`,
**exactly one** subprocess site, and it pins `shell=False`.

### 2. Orthogonal to the attack model

Asserted by source-scan: `codescan/` imports none of `cockpit`, `adgraph`, `engagement`,
`executor`, `sandbox`, `allowlist`, `orchestrator`, `attack_path`, and references none of
`validate_request`, `check_target_lock`, `run_kali`, `resolve_mode`, `engagement_id`,
`in_scope`. A code scan cannot reach a gate, a target or a sandbox.

A companion test re-asserts that the LAB target-lock wording and all four executor gates
(`target`, `approval`, `danger`, `sandbox`) are byte-for-byte unchanged, and that
`executor.py` knows nothing about code scanning.

### 3. Read-only on the codebase

A real scan over a temp tree is compared file-for-file (sizes + mtimes) before and after: the
tree must be byte-for-byte identical with no new files.

### 4. No network of its own

No `requests`, no `urllib`, no sockets anywhere in the package; Semgrep telemetry and the
version check are disabled explicitly.

---

## API

| Route | Purpose |
|---|---|
| `GET /codescan/tools` | which scanners are installed, + the exact install command |
| `POST /codescan/scan` | `{path, timeout_s?, semgrep_config?, use_bandit?}` → summary + findings |
| `POST /codescan/report` | takes a scan result **back** → Markdown report |

Failure modes are distinct codes rather than one generic 500: **400** invalid path / oversized
tree · **503** scanner not installed · **504** timeout · **502** unparseable tool output.

The report endpoint deliberately does **not** re-scan — it renders the run you are looking at,
so the document cannot drift from the panel and the tree isn't walked twice.

---

## Two pieces of copy chosen on purpose

The panel states the framing once: *static only, nothing executed, no target or network,
read-only.*

And the zero-findings state says **"these rules matched nothing"**, not *"you're clean"*. A
scanner finding nothing is a statement about the rules, not a clean bill of health, and neither
the empty state nor the report's closing caveat lets that ambiguity stand.

---

## Tests

`sh backend/run_safety_tests.sh` runs both files with everything else:

| File | Covers |
|---|---|
| `test_codescan.py` | normalisation per tool; empty/null/wrong-typed/5,000-record output; merge + ordering; the KB tie-in refusing to fabricate; report fidelity; a live scan when semgrep is installed |
| `test_codescan_safety.py` | static-only (both directions), orthogonality, path validation, timeout, output cap, oversized-tree refusal, read-only, gates unchanged |

Scanner-dependent tests skip loudly when semgrep/bandit aren't installed, so the suite runs
either way.
