# Tool arsenal — the curated toolbox the planner writes from

34 tools, 85 invocation templates, six categories. The planner draws on them so the commands
it proposes are well-formed and consistent across a broad toolset instead of improvised per
goal.

---

## What this is, and what it is not

**It is DATA + TEMPLATES.** A catalog, not an engine.

It closes the one real non-safety gap against hexstrike-style tooling — and that gap was
never *tool access*. HackPit's executor has **no allowlist**: any binary was always
proposable and runnable, gated by human approval. What was missing was the **pre-wired
catalog and structured invocation**, so the planner had to invent flag combinations from
memory. That is what this fixes, and it is entirely on the generative side.

**It changes nothing about how anything runs.** Every arsenal-templated command goes through
the same cockpit executor as any other: target/scope lock → human approval of *that* command
→ heuristic red-confirm → argv-only, no shell. The arsenal is never a gate and never a
bypass, and it executes nothing itself.

> A bigger catalog buys no shortcut. It only improves the quality and breadth of what gets
> proposed — the proposal still has to clear every gate.

---

## Catalog schema

`backend/arsenal/tools.json`:

```jsonc
{
  "name": "netexec",
  "aliases": ["nxc", "crackmapexec", "cme"],
  "category": "network-ad",
  "purpose": "Swiss-army knife for SMB/WinRM/LDAP/MSSQL across a network…",
  "phases": ["enumeration", "exploitation", "post-exploitation"],
  "techniques": ["SMB enumeration", "password spraying", "lateral movement"],
  "docs": "https://www.netexec.wiki/",
  "templates": [
    { "label": "Password spray a user list",
      "template": "netexec smb <target> -u <userlist> -p <password> --continue-on-success",
      "note": "ONE password across many users. Check lockout thresholds first." }
  ],
  "flags": [ { "flag": "--continue-on-success", "what": "keep going after the first hit" } ]
}
```

| Category | Tools |
|---|---|
| **recon** (8) | nmap, masscan, amass, subfinder, assetfinder, theHarvester, dnsx, httpx |
| **web** (9) | ffuf, feroxbuster, gobuster, nuclei, nikto, sqlmap, wpscan, dalfox, whatweb |
| **network-ad** (7) | netexec/crackmapexec, enum4linux-ng, smbmap, kerbrute, hydra, ldapsearch, bloodhound-python |
| **credentials** (2) | hashcat, john |
| **cloud** (4) | prowler, scoutsuite, trivy, kube-hunter |
| **binary** (4) | ghidra, radare2, gdb, strings |

`flags` is **informational documentation**, never a restriction — the executor has no
allowlist, so nothing here narrows what may be proposed or run.

### Sourcing

Templates are written from each tool's own documentation and standard usage, and the notes
carry the operational judgement that makes a template usable rather than merely correct:

* ffuf's `-fs` must filter the baseline response size or every response matches;
* hydra's `F=` string must match the real failure text or every attempt reads as a success;
* kerbrute password spraying **locks accounts** — read the policy first;
* bloodhound `-c DCOnly` is far quieter than `-c All`.

### Placeholders

All 21 are declared once at the top of the catalog and **validated by test** — an undeclared
placeholder would render as literal `<angle-brackets>` inside a command the operator is
invited to run.

Nine templates were corrected during the build after a first pass reused declared
placeholders for the wrong thing: `-D <domain>` for a *database* name, `-m <ports>` for a
*hash mode*, `-b <file>` for a *base DN*. Rendering those would have produced confidently
wrong commands, so `<database>`, `<hash-mode>`, `<base-dn>`, `<project>`, `<pattern>`,
`<size>` and `<technique>` are now their own placeholders.

---

## KB links — resolved, never stored, never fabricated

The catalog carries **no entry ids**. They are resolved at load time against the live KB, so
a link can never dangle as the KB changes.

**Both halves required:** the entry's *title* must name the tool (word-boundary) **and** the
entry must actually *invoke* it — the tool at the head of a command, allowing a leading
`sudo`/`env` or a pipe segment. The entry must also be step-eligible.

The second half is not redundant. A title match alone linked the `strings` tool to a page
called **"Format Strings"** — a binary-exploitation concept with nothing to do with the tool.
Result: **14 of 34 linked**, every one an entry that really runs that tool, and 20 honestly
unlinked because the KB doesn't document them.

---

## How the planner draws on it

**Into the prompt.** `planner.prompt_block()` renders the catalog's invocations for the
relevant phases into the composer prompt and the guided loop's proposer prompt. Bounded at
4,000 chars and cut at a **line boundary** — a template truncated mid-flag would read as a
real invocation with a mangled argument.

The block states what it is, and a test asserts the wording: *"a REFERENCE, not a
restriction: you may propose any tool that fits the goal, and a command still needs the
operator's approval before it runs."* A reference that read like an allowlist would
misdescribe an executor that has none.

**Out of the result.** `planner.tag_steps()` reads back over the composed steps and records
which catalogued tool each one actually runs — deterministically, from the command's own
program name, through wrappers (`sudo`, `env`), absolute paths and pipe segments. Nothing is
asked of the model and nothing taken on trust, so **the provenance cannot be hallucinated**:
either the step runs `nmap` or it doesn't.

The resulting `arsenal` tag is **provenance, not authority**. It says "this step uses a
catalogued tool, here is its entry". It does *not* mean the command was verified, it does not
touch grounded/`ai_suggested` labelling, and it changes nothing about how the step runs.

**Degrades to nothing.** A missing or malformed catalog yields an empty arsenal: empty prompt
block, no-op tagging, and composition behaves byte-for-byte as it did pre-arsenal.

---

## Target-faithful templating

`<target>` is filled through the composer's `substitute_target`, the same function the attack
path uses, so a rendered command points at the real engagement target and nothing else.

**An unfilled placeholder stays visible.** A command the operator can *see* is incomplete is
safe; one where a host or wordlist was silently guessed is not. `/arsenal/render` reports
`ready: false` and lists exactly what is missing:

```
ffuf -u https://shop.example.com/FUZZ -w <wordlist> -mc 200,… -o <output>
unfilled: ["<output>", "<wordlist>"]   ready: false
```

A test asserts that **no template hardcodes an address or a hostname** — the target always
comes from the engagement.

---

## Safety: the two guarantees, and their tests

`backend/test_arsenal_safety.py`, in `sh backend/run_safety_tests.sh`.

### 1. The arsenal executes nothing

Source-scanned: no `subprocess`, `os.system`/`popen`/`exec*`/`spawn*`, `pty`, `eval`, `exec`,
the `compile` builtin, `__import__`, `requests`, `urllib`, sockets, or `shell=True` anywhere
in the package. No import of `cockpit`, `sandbox`, `executor`, `allowlist`, `engagement` or
`kali`; no reference to `validate_request`, `iter_run`, `run_kali`, `resolve_mode` or
`ExecRequest`. A rendered invocation is a string.

> The scan blanks comment and string spans **in place** via `tokenize` before matching. A
> naive grep scans prose as if it were code — the docstring sentence *"no subprocess, no
> network"* tripped the subprocess ban on the very module that has neither. These tests
> assert what the code **does**, not what its documentation claims.

### 2. No gate is bypassed

A real catalogued invocation, rendered against the lab, is pushed through the executor:

| Condition | Result |
|---|---|
| unapproved | refused at the **approval** gate |
| pointed off-target | refused at the **target** gate |
| dangerous (interpreter) | still needs the **red-confirm** |

Checked in the other direction too: the **cockpit package has zero references to the
arsenal**, so the gates cannot be arsenal-aware even in principle. And the LAB target-lock
wording plus all four executor gates (`target`, `approval`, `danger`, `sandbox`) are asserted
byte-for-byte unchanged.

---

## API

| Route | Purpose |
|---|---|
| `GET /arsenal` | the catalog, filterable by `category` / `phase` / `q` |
| `GET /arsenal/tool/{name}` | one tool, by name or alias |
| `GET /arsenal/render/{name}?target=` | templates rendered — **strings**, with `ready` + `unfilled` |
| `GET /arsenal/suggest` | the tools worth reaching for in a phase / for a technique |

Every response carries `executes_nothing: true`. The Companion page at **`/arsenal`** browses
the same data with copy buttons, search, and category filters.
