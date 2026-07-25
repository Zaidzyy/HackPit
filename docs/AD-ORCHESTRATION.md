# AD orchestration — the agent reasons over the graph

The AD graph already rendered a BloodHound collection, computed the route to Domain Admin, and
let a human **walk** it one gated command at a time. This adds the **reasoning**: the agent
reads the graph and the current state and proposes *which edge to abuse next*.

It is the guided loop applied to the AD attack path — and it is the highest-stakes surface in
the system, because AD abuse is destructive in a way web recon is not.

---

## Why this one is different

DCSync replicates every secret in the domain. `ForceChangePassword` overwrites a real person's
password. `psexec`/`wmiexec` drop a service on a production host. None of it is undone by
clicking undo.

So **never-auto-run is not one safety layer among several here — it is carrying essentially the
whole load**, and everything below exists to keep it load-bearing.

---

## The safety model

### The agent proposes; it never runs and never approves

`backend/adgraph/orchestrator.py` builds a proposal and hands it back. Source-scanned: no
process spawning, no path into the executor's run entrypoints, no `:kali` path, and nothing
that can set `approved` or `dangerous_ack`. A proposal does not even carry those fields.

### There is no second execution path

Approval sends the step to `POST /cockpit/exec` — the **same gated executor** the manual
walk-the-path button already used, which re-checks approval, target/scope and the danger
confirm. The orchestrator exposes exactly two endpoints and **neither runs anything**:

| endpoint | what it does |
|---|---|
| `POST /cockpit/ad/orchestrate/propose` | returns the next edge to abuse. Executes nothing. |
| `POST /cockpit/ad/orchestrate/advance` | records that a step succeeded. Executes nothing. |

A test asserts the orchestrate routes contain no run/exec path, and that no
batch/approve-all/auto-run affordance exists in either the backend or the UI panel.

### The model chooses an EDGE, never a command

This is the structural choice that matters most. The model is handed a numbered list of
candidates — the abusable edges leaving principals the operator already owns — and returns an
**index**. The command is then resolved by the existing deterministic, KB-grounded technique
catalog for that edge.

So the model **cannot author a command, cannot invent a host, and cannot reach an edge that is
not really in the collected graph**. A pick outside the candidate list is *refused, not
repaired* — a proposal we cannot tie back to a real edge is not one a human should be asked to
approve.

### Every step is an individual approval

No batch. No approve-all. No "run the whole path". One proposal, one decision, every time. In
the UI, `approved: true` is set in exactly **one** place — inside the click handler for the one
step being approved.

### Advancement is tied to evidence, not to a claim

The walk moves forward only on a `run_id` naming a recorded run that was **approved and exited
0**. It cannot advance past a step that was refused, never approved, or failed. The one
exception is an edge with no command at all (inherited rights), and the server confirms *that*
from the graph rather than taking the client's word.

`advance()` is a pure function and `propose_next` can never call it — asserted by test.

### The walk never auto-advances

The UI panel contains no effect hook at all, so nothing fires on its own. After a successful
run the operator is shown what it gained and clicks "ask for the next step" by hand.

---

## The destructive-confirm gap this work found and closed

The danger heuristic knew about interpreters, netcat and msfvenom. **It knew nothing about AD
abuse.** Measured against the technique catalog, **10 of its 12 destructive abuses resolved to
commands nothing flagged**:

`DCSync` · `AllExtendedRights` · `WriteDacl` · `WriteOwner` · `Owns` · `AddMember` · `AddSelf` ·
`ForceChangePassword` · `AddKeyCredentialLink` · `AddAllowedToAct`

They are not interpreters, not netcat, not msfvenom — so they sailed through on approval alone.
A human could have approved a domain-wide credential replication with **no red confirm
anywhere**.

The heuristic now recognises AD abuse **by shape, not by binary**:

* credential dump/replication tools (`secretsdump`, `mimikatz`, `lsassy`, `nanodump`, …)
* remote code execution on a domain host (`psexec`, `wmiexec`, `smbexec`, `atexec`, `dcomexec`,
  `evil-winrm`, `winrs`)
* directory-write / coercion / relay tools (`dacledit`, `owneredit`, `rbcd`, `ntlmrelayx`,
  `mitm6`, `responder`, `petitpotam`, …)
* credential-dump argument markers (`-just-dc`, `--ntds`, `--sam`, `-M lsassy`, `--gmsa`, …)
* per-tool write subcommands (`bloodyAD set/add`, `certipy req/shadow/relay`,
  `net rpc password`, `rubeus ptt/golden/s4u`)

impacket's three spellings of the same script (`secretsdump.py`, `impacket-secretsdump`,
`secretsdump`) all normalise to one name. The change is **purely additive** — every command
flagged before is still flagged. **The gap is now 0.**

### Why shape and not binary

`nxc --shares` stays clean while `nxc --sam` trips. A confirm that fires on everything is one
the operator learns to click through, so read-only enumeration — `nmap`, `ldapsearch`,
`bloodhound-python`, `ldapdomaindump`, kerberoasting — is **asserted to stay clean**. Confirm
fatigue is its own safety failure.

### The oracle

The technique catalog independently marks abuses destructive; the executor independently
decides what needs a confirm. **Any edge the catalog calls destructive whose command the
heuristic misses is a hole.** That cross-check found the original 10 and now runs over all 24
edge kinds on every suite run.

---

## A second bug live verification caught

The hermetic tests all passed `grounder=None`, so techniques always fell back to their catalog
template and always produced a command. **With the KB grounder wired, they do not.**

Driving a real model against the running backend, `DCSync` and `ForceChangePassword` came back
with *no usable command* — and because `requires_confirm` mirrors the danger heuristic, which
had nothing to inspect, the proposal reported `requires_confirm: false`. A domain-wide
credential replication rendered **as though it were free**.

"No command" now has to say why:

| resolution | meaning |
|---|---|
| `ready` | we have a program + argv for the executor |
| `note-only` | the technique is prose. Correct and benign for `MemberOf` — inherited rights are not something you run |
| `unparsable` | a real command line came back that would not tokenise |

and `destructive_unresolved` marks a destructive abuse with no runnable command, whichever
flavour. That case gets **no executor gate — there is nothing to send to one** — so the warning
carries the weight instead: the card stays red and says plainly that whatever the operator
works out by hand will change a real domain.

The regression test runs the oracle **with a grounder wired**, which is what the original suite
was missing.

---

## Engagement scoping

Runs in engagement mode; the scope-lock/target-lock refuses an AD host outside the engagement
scope **even when fully approved and acked**. Mode resolution is injected from `main.py`,
reusing the cockpit loop's own helper for the same reason it exists there: the AD proposer has
**no capability to enter or look up an engagement**, only to be handed an inert read-only
description of what it may target. An id that is set but not active fails **closed** with 409
rather than silently degrading to lab mode.

Lab mode is byte-for-byte unchanged.

---

## Tests

`backend/test_adorch_safety.py` (13 invariants) and `backend/test_adorch.py` (8 behaviours),
both in `sh backend/run_safety_tests.sh`.

The synthetic end-to-end walks the sample domain from TYWIN to DOMAIN ADMINS in five proposed
edges — `ForceChangePassword → GenericWrite → WriteDacl → AddSelf → GenericAll` — and asserts
the safety claim **at every hop**: all five runnable steps are refused when submitted
unapproved, and all five demand the red confirm when approved without the ack.

---

## Deferred: the live run

**AO6's live half is deliberately not wired to run.** An agent proposing while a human walks a
**real** domain needs an AD lab and a human present, and it is not something a test suite
should start on its own.

The reasoning is verified against **synthetic** BloodHound data, and the live path is **wired
and ready**: collect → ingest → propose → approve each → run through the gated executor →
advance. What remains is a human-present session against a real (authorized) domain.
