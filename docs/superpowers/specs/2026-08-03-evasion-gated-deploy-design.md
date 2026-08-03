# Evasion gated deploy — design spec

**Date:** 2026-08-03
**Branch:** `main`
**Build:** #13, part 2 of 4
**Pattern:** the Sliver / tunnel-listener reversal, applied to the evasion engine. Those two were
once refused outright and became **gated-and-allowed** (engagement + approval + red-confirm) in
build #7 / I2. This is the same move, and like D16 it is a deliberate policy reversal, not a fix.

## 1. What changes, and what this is

`backend/evasion/engine.py` opens with *"GENERATES ONLY, never runs or deploys"*, and two tests
enforce it: `test_the_package_has_no_deploy_or_execute_primitive` and
`test_the_artifact_is_never_executed`. This build removes that property on purpose.

**It is a policy reversal, and it should be reviewed as one.** The honest arguments for it:

* The artifact already lands in the loot directory, which is mounted into `engage-sandbox` and
  `kali-open` and sits on the host. An operator can already copy it out and run it by hand, so
  this is convenience over a capability that exists — not a new one in the abstract.
* HackPit already owns authenticated remote execution (WinRM to a Windows profile host) and
  already runs arbitrary approved commands in the engage sandbox. Delivery is the one step that
  currently has to leave the tool.
* The precedent is the project's own: the Sliver server and the pivot/DNS listeners were once
  "never runs" and became gated runs, on the argument that the gate — not the absence of the
  feature — is the control.

**What does NOT change:** the mandatory detection footprint. `generate()` raises rather than
return a footprint-less artifact, and deploy inherits that rule. An evasion tool that told you
only how to be quieter, and never what still sees you, would be an evasion how-to; the footprint
is what keeps it a purple-team tool, and it is the thing that justified lifting the OPSEC
sensor-tamper ban (D16) in the first place.

## 2. Two primitives, deliberately separated

Splitting these is the core design decision. Putting the artifact somewhere and running it are
different acts with different blast radii, and collapsing them into one `deploy()` would mean the
gate could not tell them apart.

### 2.1 `deliver()` — put the artifact on the target

**Fixed kinds only, argv-built, never a free-form command.** This is the load-bearing constraint.
A `deliver(command=...)` taking an arbitrary delivery string would hand the evasion package a
general execution path with none of the executor's gates — the exact shape of hole the
whole-tree scans exist to catch. So `kind` comes from a closed set, exactly as
`obfuscation.KINDS` does:

| kind | how | target comes from |
|---|---|---|
| `winrm` | chunked base64 → `[Convert]::FromBase64String` → `Set-Content -Encoding Byte` | the Windows **profile host** (target-locked) |
| `smb` | `smbclient //<host>/<share> -c "put <artifact> <name>"`, argv list | the **engagement scope** (scope-locked) |

Chunking is not optional for `winrm`: WinRM caps a command string, so a real artifact must go in
bounded pieces with an append per chunk and a size/hash check at the end. A truncated payload
that reports success is worse than a failed transfer.

### 2.2 `invoke()` — run what was delivered

**WinRM only.** It is the sole remote execution path HackPit owns. There is deliberately no
sandbox `invoke`: running the artifact *inside our own sandbox* detonates our own payload on our
own box and is never what the operator wants. Refused, not merely unimplemented.

## 3. The gates

Both primitives build a real `ExecRequest` and run **the same** `executor.validate_request` the
cockpit uses — never a local copy. `test_evasion_safety` already asserts that for `generate`; the
assertion extends to both new entry points.

| Gate | `deliver(winrm)` / `invoke` | `deliver(smb)` |
|---|---|---|
| mode | active Windows profile required | active engagement required |
| target-lock | profile host | engagement program scope |
| approval | `approved=true`, per call | same |
| red-confirm | `dangerous_ack=true` | same |
| footprint | emitted, mandatory | emitted, mandatory |
| audit | `runstore.save_run` | same |

The red-confirm is **not** left to the heuristic to discover. Delivering and invoking an evasion
artifact is categorically dangerous, so both primitives require `dangerous_ack` unconditionally —
a build #5 lesson: a gate that depends on a classifier noticing is a gate that a rename defeats.

**No autonomous path.** The orchestrator, agent and reasoning modules keep ZERO route here. The
existing AST scan asserting no agent path to the evasion package is unchanged and now covers two
more entry points.

## 4. What replaces the two safety tests

They are **replaced by gate tests, not deleted** — the property changes from "impossible" to
"gated", and the tests must assert the new property just as hard.

* `test_the_package_has_no_deploy_or_execute_primitive` → `test_delivery_is_a_closed_set`: the
  package has delivery primitives, and `kind` is a fixed set no request value can escape. Asserts
  no free-form command string reaches a shell, and that argv is built as a list.
* `test_the_artifact_is_never_executed` → `test_the_artifact_is_only_a_program_on_the_invoke_path`:
  `generate` still never puts the artifact in a program position (unchanged assertion), and
  `invoke` does so **only** through the gated WinRM path.

New cases, each in **both** directions plus a control:
* deliver/invoke refused without approval, permitted with it;
* refused without `dangerous_ack`, permitted with it;
* refused with no active engagement / no Windows profile;
* an out-of-scope SMB host refused at the target gate;
* `invoke` on the sandbox path refused outright (the deliberate asymmetry);
* an unknown `kind` refused;
* **negative control**: stripping the footprint makes deliver **refuse** rather than degrade —
  the same control `generate` already carries.

## 5. Verification

Hermetic. WinRM is faked by monkeypatching `winrm_transport._send`, exactly as `test_winrm` does;
`subprocess.run` is spied the way `test_evasion_safety._Spy` already does. No VM, no network, no
`pywinrm` — the property that keeps the suite runnable in CI.

Chunking gets its own case: an artifact larger than the chunk size produces more than one write,
the reassembled bytes match, and a short write is detected rather than reported as success.

## 6. Assessment doc + PDF

Same commit. This is a policy reversal and the section must say so plainly — what was removed,
why, what replaced it, and the standing argument against it (the tool can now put an
AV-evading artifact on a real host and run it). Regenerate with `python docs/build-assessment.py`;
verify against the HTML and page-count delta, never by grepping the PDF.

## 7. Not in scope

Parts 1a and 1b. No new evasion techniques, no new C2. No sandbox `invoke`. No credential
handling beyond what the existing profile store and credential vault already provide.
