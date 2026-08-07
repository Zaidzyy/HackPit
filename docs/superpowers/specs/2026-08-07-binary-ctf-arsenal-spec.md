# Build spec — Binary / RE / pwn + CTF / forensics arsenal expansion

**Status:** ready to execute in a fresh session. **Author:** planning session, 2026-08-07.
**One line:** add the **binary-reversing, exploit-dev, and forensics/CTF** tooling HackPit's arsenal lacks (the HexStrike coverage gap) to the **gated** arsenal — catalog entries + sandbox-image install + install-proofs + 100%-classification — so the planner can propose them and the operator runs them through the same approve-each executor. **DATA + image only; auto-exec is explicitly NOT added.**

---

## 0. Guiding constraint (read first, do not weaken)

Adds **NO new gate** and **NO execution path.** The arsenal is **DATA + TEMPLATES** — it executes nothing (`test_arsenal_safety.py` invariant #1) and buys no shortcut around the executor (invariant #2). Every new tool is a **template the planner PROPOSES**; it runs only through the existing gated executor / `:kali` shell / `:terminal`, **approve-each**, exactly like every other tool. Keep it **maximally broad** (real Ghidra/pwntools/volatility available to reach for), gated identically. **Do NOT adopt HexStrike's autonomous execution** — these are proposable tools, not an auto-run pipeline.

Note on the gate model: these are **local-artifact** tools (analyze a `<binary>` / `<file>`), not network-target tools. The `<target>`/scope-lock substitution mostly does not apply — templates use the existing `<binary>` / `<file>` / `<output>` local-path placeholders. They are low-danger (no network, no directory mutation) but **must still be classified** (below).

## 1. Read-first

- `backend/arsenal/tools.json` — the catalog schema (`schema_version` 1.0; entries: `name`, `aliases`, `category`, `purpose`, `techniques`, `docs`, `actions[{flag,label,template,note}]`). `<binary>` and `<file>` placeholders **already exist** — reuse them; do NOT invent `<lhost>`-style names (`arsenal-expand-polish`). Watch **CRLF-vs-LF** (`reconftw-incorporation`).
- `backend/arsenal/loader.py` — `_coerce_tool`; how a catalog entry is validated/loaded. Binary-name **aliases** matter (memory: Sliver/Empire alias lesson) — a tool's package name ≠ its binary name.
- `backend/test_arsenal_safety.py` + `cockpit/allowlist.py` — **the arsenal safety test enforces 100% tool classification coverage** against the allowlist's danger catalog / `_MUST_NOT_FIRE`. Every new tool MUST be classified or the test fails. Most of these are read-only local analysis → low-danger/safe, but classify each honestly (e.g. a debugger that can spawn a process, `patchelf` that mutates a local file).
- `docker/Dockerfile.sandbox` + `docker/proof/` — the install pattern + install-proof scripts (the `zap_install_proof` / `cloud_install_proof` discipline). Respect **`kali-sandbox-image-traps`**: verify the ACTUAL installed binary name, watch setcap / `no-new-privileges`, packages install under different binary names.
- The **substrate probe harness** (measures tool availability in the sandbox image) — extend it to cover the new binaries.
- `frontend/src/app/arsenal/page.tsx` — the browsable arsenal surface.
- **cockpit/arsenal decoupling** — do NOT add any arsenal reference into cockpit (a stray comment tripped this before). Classification lives in `cockpit/allowlist.py`; the arsenal never imports cockpit.

## 2. What to build

### 2a. Catalog entries (`backend/arsenal/tools.json`) — two new categories
**`binary-re` (reversing / exploit-dev / pwn):**
- `ghidra` (aliases: `analyzeHeadless`) — headless decompile: `analyzeHeadless <project-dir> <project> -import <binary> -postScript <script>`. (Note: the **ghidra MCP is already wired this session** — cross-reference it.)
- `radare2` (aliases: `r2`, `rizin`) — `r2 -A <binary>` / `r2 -q -c 'aaa;afl' <binary>`.
- `gdb` (+ `pwndbg`/`gef`/`peda` as plugin notes, NOT separate binaries) — `gdb -q <binary>`.
- `pwntools` (python lib — template a `python3 -c 'from pwn import *; ...'` skeleton), `ROPgadget` (`ROPgadget --binary <binary>`), `ropper` (`ropper --file <binary> --search 'pop rdi'`), `one_gadget` (ruby gem — `one_gadget <libc>`), `angr` (python lib skeleton), `libc-database` (git repo, not a package — `./find <symbol> <offset>`), `pwninit` (`pwninit --bin <binary> --libc <libc>`), `checksec` (`checksec --file=<binary>`), `patchelf` (mutates a local file — classify accordingly), `objdump`/`readelf`/`nm`/`strings`/`xxd`/`nasm`.

**`forensics-ctf` (forensics / stego / carving):**
- `volatility3` (aliases: `vol`, `vol.py`) — `vol -f <file> windows.pslist`.
- `binwalk` (`binwalk -e <file>`), `foremost` (`foremost -i <file> -o <output>`), `scalpel`, `steghide` (`steghide extract -sf <file>`), `zsteg` (`zsteg <file>`), `stegseek` (`stegseek <file> <wordlist>`), `exiftool` (`exiftool <file>`), `bulk_extractor`, `testdisk`/`photorec`.

Each entry: real `docs` URL, honest `techniques` tags, `actions` with correct `template`s using existing placeholders, and **binary-name `aliases`** where the package name differs. Keep the user's named list as the spine; the siblings above are the obvious completions — flag any you add in the PR.

### 2b. Classification (`cockpit/allowlist.py`)
Add a danger/allowlist classification for **every** new tool so `test_arsenal_safety.py`'s 100%-coverage assertion passes. Most → low-danger/safe (read-only local analysis, no network, no directory mutation). Honest exceptions: `patchelf` (mutates a local file), `gdb`/`pwntools`/`angr` (can spawn/run a local process). Do not over-classify read-only decompilers as dangerous.

### 2c. Sandbox image (`docker/Dockerfile.sandbox` + `docker/proof/`)
Install the binaries (apt + pip + gem + git-clone as appropriate). Add `docker/proof/binre_install_proof.sh` and `docker/proof/forensics_install_proof.sh` that verify the launcher accepts each invocation the catalog templates hardcode (the `zap_install_proof` lesson: an install that the template can't actually invoke is not installed). Respect `kali-sandbox-image-traps` (real binary names — e.g. `analyzeHeadless` not `ghidra`; `vol` not `volatility`; gef/pwndbg are gdb plugins; libc-database/pwninit are non-apt). **The `docker build` rebuild is the operator's manual step** — add catalog + Dockerfile + proof and flag the rebuild.

### 2d. Frontend — `/arsenal`
The new tools appear in the browsable arsenal under the two new categories (`binary-re`, `forensics-ctf`); add category filters/labels. `hp-tn-*`; **look at the screen**.

## 3. Tests
- `backend/test_arsenal_safety.py` — still green: arsenal **executes nothing** (tokenize scan), **no gate bypassed**, and **100% classification coverage** now includes every new tool. Add the new tools to whatever fixture/blocklist the coverage assertion reads.
- Extend the **substrate probe harness** to assert the new binaries are present-or-report-until-installed in the image.
- `backend/test_arsenal.py` (or the loader test) — every new entry loads, aliases resolve, templates use only defined placeholders, no `<lhost>`-style names, no invented host reaches a step.

## 4. Acceptance criteria
- The binary-RE/pwn + forensics/CTF tools appear in `/arsenal`, load cleanly, and are proposable with correct templates using `<binary>`/`<file>`/`<output>`.
- Every new tool is classified (100%-coverage test green); arsenal executes nothing; no gate bypassed; running any of them still goes approve-each through the executor / `:kali` / `:terminal`.
- Tools added to `Dockerfile.sandbox` + install-proofs; substrate probe covers them (rebuild flagged for the operator).
- `run_safety_tests.sh` green; `next build` exits 0; screen looked at; assessment + README updated (same commit).

## 5. Assumptions (flip any)
- Scope = the user's named list + obvious siblings (gef/pwndbg for gdb, ropper alongside ROPgadget, zsteg/stegseek for stego, bulk_extractor). If a session runs short, ship `binary-re` first (higher-signal for pwn/RE), then `forensics-ctf` — say so in the PR.
- These are **proposable tools, not a new surface or pipeline** — no auto-exec, no CTF-solver agent (that would be HexStrike's autonomy). If a dedicated `/ctf` surface is wanted later, it's a separate build.
- `hashcat`/`john` are already catalogued (cracking) — don't duplicate.

---

## 6. README + screenshot + assessment (do exactly like prior sessions)

**Not done until README + a real screenshot ship.** Screen route: **`/arsenal`** (new categories).
- Headless-Edge screenshot (`headless-edge-screenshots`), app running:
  ```
  EDGE="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  "$EDGE" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --user-data-dir=<tmp-profile> --window-size=1440,950 --virtual-time-budget=8000 \
    --screenshot=out.png "http://localhost:3000/arsenal"
  ```
  **View it** — the binary-re / forensics-ctf categories render with the new tools (not blank/error).
- Add screenshot to `assets/screenshots/`; README feature section + "at a glance" row (binary/RE + forensics/CTF arsenal).
- Update `docs/ASSESSMENT-2026-07-26.md` + regen html/pdf (`python docs/build-assessment.py`) same commit (`keep-assessment-current`; verify vs html).
- **Look at the screen** (`frontend-class-vocabulary`): `hp-tn-*`, never a bare `hp-card`.
