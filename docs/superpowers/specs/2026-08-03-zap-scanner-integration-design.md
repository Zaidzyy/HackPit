# ZAP scanner integration — design spec

**Date:** 2026-08-03
**Branch:** `main`
**Build:** #14, part 1 of 2 (part 2 = the proxy surface, not yet specced)
**Pattern:** ZAP becomes what nuclei already is — a catalogued tool the executor gates and the
ingest parses. No new execution channel, no new module, no new endpoint.

## 1. What this unblocks

HackPit catalogues 115 tools and has an HTTP repeater, but it has **no active web vulnerability
scanner**. The gap shows up on every web target: recon finds endpoints, nuclei matches known
templates, and nothing systematically probes discovered parameters for injection classes. ZAP
closes that gap with a spider + passive analysis pass and an active-scan pass.

### Why ZAP and not Burp Suite Professional

Burp Pro is $499/user/year and its REST API is narrow — launch a scan, poll status, fetch issues,
read issue definitions. Anything richer needs a Montoya extension loaded inside a running Burp,
which is not drivable over a wire. More decisively, Burp Pro's license is a named-user seat and
the process assumes a desktop session; running it as a shared service backend is the use case
PortSwigger sells Burp DAST/Enterprise for. ZAP is Apache 2.0, headless-first, and has no
activation to break when a container is rebuilt.

**A cracked Burp distribution was considered and rejected outright.** Aside from being pirated
commercial software and a DMCA risk to a public repo, it means running an unaudited third-party
JAR patch as the interception proxy that sees every credential and session token pushed through
it. Cracked security tooling is a documented malware delivery channel precisely because its
audience has interesting access.

## 2. Scope

**In:** the image layer, the arsenal catalog entry, the danger classification, the report parser
and its registry wiring, the detection alias fix, the safety and unit tests, and the assessment
update.

**Out — and stated so it is not quietly assumed:**

- **The ZAP daemon and its REST API.** See §3. This is the whole reason the build is small.
- **The proxy surface.** ZAP as a live intercepting proxy feeding the repeater and state is a
  separate build with its own spec and its own safety review.
- **A generic "scanner driver" abstraction** so a Burp driver could slot in later. That is
  speculative generality for a single implementation. The real extension points already exist:
  `tools.json` for the catalog and `STDOUT_PARSERS`/`FILE_PARSERS` for output. A future driver
  plugs into those.
- **`zap.sh -cmd -autorun <plan>.yaml`.** See §4 — the plan file defeats the danger gate.

## 3. Why the daemon is excluded

ZAP can run as a long-lived server driven over HTTP. That is rejected for this build, for two
reasons, the second structural.

**It would be a second execution channel that never passes `validate_request`.** Every gate in
this project — approval, target-lock, scope, red-confirm, isolation — inspects *a command*. Once
"scan this target" is an HTTP request rather than a command, it goes around all of them unless a
second, parallel gate system is built to inspect HTTP requests. That second system is exactly the
failure mode this codebase keeps finding: the WinRM `argv[0]` classification bug (Critical 2), the
proxychains-laundered red-confirm (D22), the collector FQDN classifier (D24). `tunnels.py:277`
already encodes the lesson — the gate and the spawn come through one function specifically
because a separate path "reproduces the bug in a new place."

**The stack's only channel into a sandbox is `docker exec`.** The executor, `:kali`, the PTY
terminal and `lifecycle.py` all reach containers that way. The lab sandbox sits on
`hackpit-isolated` (`internal: true`) so that there is no route between it and the host — the
property `assert_isolation_proven()` exists to verify and `docker/proof/isolation_proof.sh`
demonstrates. Reaching a ZAP HTTP API inside it would require publishing a port or attaching the
backend to the isolated network. That is not a tradeoff; it is dismantling the safety net.

### Why the existing listener pattern does not transfer

HackPit already runs three long-lived servers in the engage sandbox: the Sliver C2 daemon, the
pivot listener and the DNS-tunnel listener. All three were solved the same way, in two parts:

1. **The start is gated** — engagement + approval + red-confirm (`tunnels.py:54`, finding I2 of
   the 2026-07-27 gate audit; before that fix a listener could be raised by a plain POST carrying
   no `approved` field at all).
2. **The ability to drive it is then deliberately discarded** — `lifecycle.py` holds each
   listener's stdin open with a raw file descriptor rather than a pipe object, so `proc.stdin is
   None` and no caller has anything to write to. Regression-locked by
   `test_lifecycle_safety.py::test_watched_listeners_expose_no_stdin_writer`. The running process
   is only ever *observed*, via a read-only `ss` probe.

That works because a C2 listener's job is to sit and wait for something to call home, so
"send it further instructions" is a capability that can be thrown away. **A ZAP daemon's entire
purpose is to receive further instructions**, so step 2 is unavailable for it and the pattern
does not transfer as-is.

**But the objection is to an UNGATED control channel, not to a daemon as such** — and that
distinction matters for the proxy build, so it is recorded here rather than left to be
rediscovered:

- **A recording proxy may reuse the pattern almost directly.** A ZAP proxy that captures traffic
  and never accepts attack commands *observes* — the same shape as the existing listeners. Gate
  the start, hold liveness, expose no writer, read the recorded history.
- **A scan-control channel has a known solution shape, already proven here.** Starting a pivot
  listener is also a POST rather than a command, and `tunnels.py` gates it by constructing a
  synthetic `ExecRequest` and running the *real* gates against it. `server_argv_for()` is "THE
  SINGLE DERIVATION" — both `_gate_request()` and `start_tunnel()` come through it, and a test
  asserts the gated argv equals the spawned argv. A scan-control API would do the same: build an
  `ExecRequest` for "active scan against `<target>`", pass `validate_request`, and only then make
  the call.

So the later build is not blocked on inventing a gating model; it is blocked on the **network
path**, which splits by sandbox: the engage sandbox is already open and breaks no property by
hosting a daemon, while the lab sandbox keeps `internal: true` and keeps command-path scanning.
That decision belongs in that spec, not this one.

## 4. Why the autorun plan file is excluded

ZAP's Automation Framework takes a YAML plan: `zap.sh -cmd -autorun plan.yaml`. It is the more
capable interface, and it is rejected here because **whether the run is passive or active lives
inside the plan file**. The command string the danger gate classifies would not reveal what the
run actually does.

That is the Critical 2 bug shape exactly — `backend/AGENTS.md`: *"The gate must classify the
string that actually executes."* A plan file makes the executed behaviour invisible to the string.

The packaged scan scripts are self-describing instead: the program name states the aggression
level. Activeness is therefore determinable from the command, and the existing gate works
unmodified.

## 5. Components

Seven touch points. No new module, no new route, no frontend.

| # | Change | File |
|---|---|---|
| 1 | Install ZAP + bake add-ons | `docker/Dockerfile.sandbox` |
| 2 | Catalog entry with scan templates | `backend/arsenal/tools.json` |
| 3 | Active scan classified dangerous | `backend/cockpit/allowlist.py` |
| 4 | `parse_zap` + registry entries | `backend/state/parsers.py` |
| 5 | Detection aliases for the real program names | `backend/detection/catalog.py` |
| 6 | Safety + unit tests | `backend/test_zap.py`, `backend/test_zap_safety.py` |
| 7 | Assessment + regenerate | `docs/ASSESSMENT-2026-07-26.md` |

**Naming constraint:** `test_scans.py` and `test_support/scans.py` are the shared source
scanner. The tests here are `test_zap.py` and `test_zap_safety.py` — never `test_scans.py`.

### 5.1 Image (`docker/Dockerfile.sandbox`)

A new layer in the web/recon group installing `zaproxy` and a headless JRE, following the file's
existing conventions:

- **Add-ons baked at build time.** The lab sandbox has no egress and can never fetch them at
  runtime — the same reason `nuclei-templates` is baked rather than updated live.
- **The layer ends in a `zap.sh -version` smoke test**, so a bad package name fails the build
  loudly instead of shipping an image missing a tool the arsenal advertises.
- **ZAP needs a writable home** for its `~/.ZAP` directory. The image's default user is
  `sandbox` (uid 1000); the layer must ensure that path is writable, or pass an explicit `-dir`.

**Verification item, not an assumption:** the build must confirm the Kali `zaproxy` package
actually provides `zap-baseline.py` and `zap-full-scan.py`. If it does not, they are fetched as
pinned files in layer 8 alongside ffuf/nuclei, each with its own smoke test. This is checked
against the real package during implementation, never assumed.

**This is the build #9 defect class, and it must not repeat.** `ingest.program_name()`'s own
docstring records it: Kali installs the impacket examples as `impacket-secretsdump` while
upstream ships `secretsdump.py`. The parser registry was keyed only on upstream's spelling, so a
live DCSync dumped four NTLM hashes including krbtgt and ingested **none** of them — "two halves
of this codebase disagreed about the name of the same tool, and only a live run could show it:
every hermetic test fed the parser a string it had chosen itself."

ZAP has exactly the same exposure: Kali may install the scan scripts under a different name or
path than upstream. Therefore the parser registry keys in §5.4 are derived from **what the image
actually installs**, confirmed by running the tool in the built image — not from upstream's
documented spelling. Both spellings are registered where they differ, as the codebase already
does for `secretsdump.py` / `secretsdump`.

### 5.2 Catalog (`backend/arsenal/tools.json`)

One new entry, `category: "web"`, following the existing schema (`name`, `purpose`, `phases`,
`techniques`, `docs`, `templates[]`, `flags[]`). Templates cover a passive baseline pass and an
active full scan, each in both a stdout-report and a file-report form (§5.4).

**Trap:** `tools.json` is hand-formatted with CRLF line endings. Patch it in place. Rewriting it
via `json.dump` reformats the whole file and produces an unreviewable diff.

Adding the entry makes the planner able to propose ZAP runs. The planner proposes; it never
executes (D18), so this adds no capability.

### 5.3 Danger classification (`backend/cockpit/allowlist.py`)

`dangerous_command_heuristic()` gains a rule splitting the two scripts:

| Invocation | Verdict | Reason |
|---|---|---|
| `zap-baseline.py` | not dangerous | spider + passive analysis; observes, never attacks |
| `zap-full-scan.py` | **dangerous** | active scan; sends real SQLi/XSS/command-injection payloads at every discovered parameter |

An active scan therefore requires `dangerous_ack` — the explicit red-confirm — **on top of**
per-command approval, in both lab and engagement mode. A passive baseline requires approval only.
This is the D17 split-gating precedent applied unchanged.

**This split is enforced by an existing test, not by discipline.**
`test_arsenal_safety._catalog_invocations()` iterates every template's `argv[0]` from the real
catalog and fails if any invocation has no danger verdict in `_MUST_FIRE`, `_MUST_NOT_FIRE`,
`_ARGUMENT_DEPENDENT` or `_CONSOLE_SUBCOMMANDS`. Adding these templates *forces* the
classification — the "draw inputs from the real source of truth" rule doing its job. Placement:
`zap-full-scan.py` → `_MUST_FIRE`; `zap-baseline.py` → `_MUST_NOT_FIRE`.

Because §4 excludes the plan-file form, `zap.sh` never appears as a template `argv[0]` and so
never needs an `_ARGUMENT_DEPENDENT` verdict it could not honestly be given.

### 5.4 Results into the state model (`backend/state/parsers.py`)

`parse_zap` maps a ZAP JSON report onto existing records — no schema change:

- **Each alert → a `Finding`**: `title` from the alert name, `severity` from `riskcode`
  (0→info, 1→low, 2→medium, 3→high; ZAP never emits critical), `target` from the first
  instance URI, `tool="zap"`, `reference="pluginid:<id>"`, `evidence` from the instance evidence,
  truncated to 2000 chars as `parse_nuclei` does.
- **Each alert instance → an `Endpoint`**: its URI, method, and the affected parameter.

**A real problem the existing helper does not solve.** `_json_objects()` tries a whole-document
parse and falls back to line-delimited. ZAP's scan scripts interleave progress text with a
pretty-printed multi-line report, so the whole-document branch fails outright.

**The fallback branch is worse than failing** — measured during implementation, not assumed. It
does not return nothing: it matches the alert *instance* fragments that happen to sit on a
single line, and returns those. On the test fixture it yields exactly one object, carrying
`{method, param, uri}` and no `site` key. A parser resting on it would therefore emit quiet
rubbish rather than obvious nothing, which is the harder failure to notice.

`parse_zap` performs its own extraction instead: locate the object carrying a `site` key and
`raw_decode` it out of the surrounding noise. Self-contained in the new parser.
`_json_objects()` is not modified, so no existing parser changes behaviour. The regression test
asserts the fallback never reaches the *report* — not that it returns nothing, which would be a
false claim that later broke.

Two delivery paths, because the sandboxes genuinely differ and that difference is a safety
property:

- **Engagement mode** — the report is written into the loot dir, which the existing
  `ingest.new_loot_files()` sweep already picks up and hands to `parse_file()`. Registered in
  `FILE_PARSERS` under the distinctive suffix `-zap.json`, **not** `.json`. A bare `.json`
  registration would claim every JSON loot file any tool ever writes.
- **Lab mode** — the lab sandbox deliberately has no `/loot` mount, and that stays true; it is
  the container the safety layer leans on and the host for unattended agent runs, so it gets no
  writable host directory. The report comes back on stdout instead, parsed via `STDOUT_PARSERS`
  keyed on the script names as `ingest.program_name()` produces them. That function basenames,
  lowercases and strips a `.exe` suffix, but **does not strip `.py`** — so the keys are
  `zap-baseline.py` and `zap-full-scan.py`, confirmed against the installed names per §5.1, with
  both spellings registered if Kali and upstream differ.

### 5.5 Detection (`backend/detection/catalog.py`)

`ALIASES` already maps `zap` and `zaproxy` → `web_vuln_scan`. **Neither is the program name that
will execute.** Runs will be `zap-baseline.py` and `zap-full-scan.py`, so without this change the
detection panel goes silent on every ZAP run while appearing healthy. Both names are added.

This is a gap created by the §4 decision to use the packaged scripts, and it is the kind of
silent-hole finding the gate audit was about: a surface that reports nothing looks identical to a
surface with nothing to report.

## 6. Tests

Per `backend/AGENTS.md`, each drawing inputs from the real source of truth and carrying a
positive control **in the same test**, so a test that has stopped checking anything fails loudly
instead of passing quietly.

1. **Danger classification** (`test_zap_safety.py`) — iterate the real catalog; assert every
   active ZAP invocation fires the heuristic and every passive one does not. Positive control in
   the same test: a known-dangerous non-ZAP command still fires and a known-benign one still does
   not, so a heuristic that has been broken into always-false or always-true cannot pass.
2. **Gated string == executed string** (`test_zap_safety.py`) — the argv the gate classifies is
   the argv that runs, asserted transitively on the source as the WinRM and tunnels paths do.
   This is the Critical 2 invariant; ZAP must not reintroduce it.
3. **Parser** (`test_zap.py`) — a real ZAP report fixture wrapped in progress noise; assert
   extracted findings, severity mapping across all four risk codes, and endpoints. Control:
   garbage input yields an empty `Parsed` and never raises, matching the "a parser must never
   break a completed run" invariant.
4. **Suffix scoping** (`test_zap.py`) — a non-ZAP `.json` loot file is not claimed by the ZAP
   parser. This is the guard on the §5.4 decision to register `-zap.json` rather than `.json`.

Both files are added to `backend/run_safety_tests.sh`.

## 7. Open constraints to resolve during planning

Neither blocks the design; both are stated so they are checked rather than discovered live.

- **Scan duration vs the executor's run model.** A full active scan against a real application
  runs for tens of minutes. The executor is built for commands that finish. Whether it imposes a
  timeout that would kill a long scan must be checked during planning; if it does, that is a real
  constraint to handle explicitly rather than hit during a live engagement.
- **Juice Shop is a SPA.** ZAP's traditional spider handles single-page apps poorly, so the lab
  run may need the AJAX spider to find anything worth scanning. Worth knowing up front so a thin
  first result is read as a spider limitation rather than a broken integration.

## 8. Safety invariants this build must not weaken

Restated so the implementation has an explicit checklist to verify against:

1. The lab sandbox stays egress-less and keeps **no** `/loot` mount.
2. No new execution channel. Every ZAP run passes `validate_request` as an ordinary command.
3. An active scan requires `dangerous_ack` on top of approval, in both modes.
4. The string the gate classifies is the string that executes.
5. `cockpit` and `arsenal` still do not reference each other in either direction.
6. Ingestion stays additive enrichment and never gates a run — a parser failure must not affect
   a run that already completed.

## 9. Definition of done

- The image builds and `zap.sh -version` passes in the layer's smoke test.
- **The installed program names are read out of the built image** and the `STDOUT_PARSERS` /
  `FILE_PARSERS` keys match them. Per §5.1 this cannot be established by a hermetic test — a
  hermetic test feeds the parser a string it chose itself, which is precisely how the build #9
  ingest gap survived a green suite.
- A passive baseline scan runs against the lab target and its findings appear in the state panel.
  This is the end-to-end check that the registry keys are right: wrong key, zero findings.
- An active scan is refused without `dangerous_ack` and runs with it.
- `sh backend/run_safety_tests.sh` passes, including the four new checks.
- The detection panel describes a ZAP run rather than showing nothing.
- `docs/ASSESSMENT-2026-07-26.md` updated and regenerated with `python docs/build-assessment.py`,
  **in the same commit**. Verify against the generated HTML — the PDF cannot be grepped, because
  Edge subsets fonts to glyph IDs.
