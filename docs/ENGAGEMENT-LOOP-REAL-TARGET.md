# The guided loop on a REAL target

**Branch:** `engagement-wall-a-down` · **Posture:** Wall A **DOWN** (fully-open engagement
egress) · **Status:** supervised, local-only, not pushed.

Until now the guided loop only really worked against the isolated lab. Two things stopped it
from driving a real engagement:

* **GAP 1 — the proposer was lab-hardcoded.** `orchestrator._system_prompt` /
  `build_user_prompt` / `precheck` all used `config.LAB_TARGET_HOST` and told the model *"the
  ONLY target is the lab host … NEVER propose any other host."* `/loop/propose` passed the plan
  and the recorded runs but nothing about the engagement, so on a real target the loop drafted
  lab commands that the engagement target-lock then rejected. Deadlock.
* **GAP 2 — the lock was one exact host.** `_engagement_aliases` was `{target, host_of(target)}`
  and anything else was refused. No subdomains, no services recon found, no scope at all.

Both are closed. The engagement now carries an authorized **program scope**; the proposer drafts
against that scope; the target-lock accepts anything in it; and in-scope hosts that recon reveals
are added to the live allowed set automatically. **Lab mode is byte-for-byte unchanged.**

---

## 1. The scope model (Decision 1C: program scope + recon-driven expansion)

You give the scope when you enter engagement mode — the same shape a bug-bounty program has:

```
example.com, *.example.com, 10.10.10.0/24, !admin.example.com
```

| Pattern | Meaning |
|---|---|
| `example.com` | exactly that host (a URL form is reduced to its bare host) |
| `*.example.com` | every **sub**domain — **not** the apex; list `example.com` too if it is in scope |
| `10.10.10.0/24` | a network range, matched against IP tokens |
| `!pattern` | an **exclusion** (any of the three forms). Exclusions always win. |

Separators are commas, spaces or newlines. Omitting the scope entirely scopes the engagement to
the named target alone — exactly the old single-host behaviour.

**Matching is lexical/numeric and does no DNS at match time** (`cockpit/scope.py`): a *name* is
judged against the host and wildcard patterns, an *IP* against the CIDR patterns plus the
addresses the exact-host includes resolved to at entry. That keeps `in_scope()` deterministic
and testable, and avoids resolving an out-of-scope name just to decide that it is out of scope.

**Fail-closed at entry.** `parse_scope` raises (→ HTTP 422) on an empty spec, a malformed
pattern, a spec with no in-scope pattern (exclusions only allow nothing), or a spec whose only
includes are exact hosts that *all* fail to resolve. `enter()` additionally refuses a target
that is not inside its own scope. A stored scope that somehow fails to re-parse degrades to the
named target alone — narrower, never wider.

**Storage** is on the `EngagementRecord`, migration-safe: `engagement_mode` gains `scope_spec`
and `scope_ips` via `ALTER TABLE`, so a database written before this change still opens and a
pre-scope row reads back as a single-host scope on its `target`.

---

## 2. How the proposer targets *your* scope

`orchestrator.ScopeContext` is an inert, read-only description of what may be targeted: the
primary target, the in-scope patterns, the exclusions, the **live allowed hosts** (scope hosts +
in-scope discoveries) and the out-of-scope discoveries. With one:

* the system prompt never mentions the lab; it states the scope as the hardest rule, says a
  `*.domain` pattern covers subdomains, and forbids third-party hosts, the operator's own
  machine/LAN and the internet at large;
* the user prompt lists the **known in-scope hosts** as legitimate pivots and the **seen but
  out-of-scope** hosts as explicitly forbidden, so the model does not propose them;
* the pre-check runs the **same matcher the executor's target-lock uses**, so the UI's verdict
  matches the run-time one;
* the feedback window widens to **20 runs × 1600 chars** (the lab keeps 12 × 600) — real pivots
  hinge on detail buried in tool output.

Without a context every string is the original lab prompt, regression-locked by
`test_lab_proposer_prompt_unchanged`.

**Where the mode is resolved matters.** `/sessions/{id}/loop/propose` takes an `engagement_id`,
resolves the active engagement in `main.py`, and hands the orchestrator only the inert context.
The orchestrator still cannot enter an engagement, look one up, or tag anything for real-target
mode — `test_engagement_mode.test_orchestrator_has_no_engagement_capability` scans its source
for those capability tokens and still passes unchanged. An id that is set but not active is
refused **409**; the loop is never silently downgraded to lab.

---

## 3. The target-lock, now scope-aware

`executor.check_target_lock(args, command, allowed=…, label=…, in_scope=…)`:

* **Lab mode** — no `allowed`, no `in_scope`: identical logic, identical wording
  (`"target 'x' is not the lab — only the lab is allowed"`), regression-locked.
* **Engagement mode** — a host-shaped token passes if it is in the live allowed set **or** the
  scope matcher covers it (wildcard subdomain, in-CIDR IP, a resolved seed IP). Anything else is
  refused at the `target` gate before the approval gate is even reached. At least one in-scope
  reference is still required, so a command is never silently target-less.

Gate order in engagement mode is unchanged: **engagement → target → approval → danger.**

---

## 4. Recon-driven expansion

After every **engagement** run, `engagement.record_discoveries` mines the run's stdout+stderr
for hosts and IPs and sorts them by the scope:

* **in scope** → added to the live allowed set, streamed to the UI as a `discovered` event, and
  offered to the proposer as a pivot on the next draft;
* **out of scope** → recorded read-only and surfaced (struck through in the UI). Never added,
  never targetable, never shown to the model as a legal target.

Caps, so nothing is unbounded or silently truncated: **25** added and **50** surfaced per run,
**500** rows per engagement; hitting a cap sets `truncated` on the event and the UI says so. The
whole step is wrapped — a failure there can never affect the run that already completed.

Two things expansion deliberately does **not** do:

1. **It never widens the scope.** A host can only be added if the scope *already* covered it, so
   an expansion round can never make a previously-refused target runnable
   (`test_expansion_never_widens_the_scope`).
2. **It never approves anything.** A freshly-discovered, in-scope host still needs an individual
   human approval for every command against it
   (`test_never_auto_run_holds_for_a_discovered_host`).

---

## 5. Network posture (Decision 2i: Wall A stays DOWN)

There is **no firewall on this branch**. The engagement sandbox sits on a plain NAT bridge with
full reach — internet, LAN, your host, cloud metadata — exactly as before this work. Nothing was
added at the network layer and nothing was removed.

Be honest about what that means:

* the argv target-lock is **best-effort defence in depth, not a bound**. It sees argv tokens
  only; it cannot see a host inside `python -c "…"`, `curl @file`, a base64 blob, or a wordlist;
* the scope is therefore **advisory to the machine and binding on the human**. If an approved
  command reaches an out-of-scope host, nothing at the network layer stops the packet;
* **the human approval click is the only real guard**, and this is precisely why never-auto-run
  is enforced in two places (`validate_request` *and* the prevalidated path in `iter_run`).

If Wall A is ever raised again, the scope model is what a firewall sidecar should be
generalised to (multi-pattern allow-list + live-add on expansion + a fail-closed
`assert_scope_locked` before every exec). The scope-lock branch (`engagement-scope-lock`) has
the single-host version to build from. That work is **not** on this branch.

---

## 6. Never-auto-run — the proof

| Where | What holds |
|---|---|
| `_validate_engagement` | `approved=False` → rejected at the `approval` gate, always |
| `iter_run` (even `prevalidated=True`) | engagement branch re-checks approval — belt and suspenders |
| `propose_next` | reaches **no** execution path; an off-scope draft comes back `gate_ok=false`, flagged, not run |
| Expansion | adds hosts, approves nothing |
| UI | one APPROVE button per proposal; no batch, no approve-all, no auto-approve; dangerous commands need a second explicit confirm |

Tests that lock it: `test_never_auto_run_engagement`,
`test_iter_run_prevalidated_still_needs_approval` (test_engagement_mode.py),
`test_never_auto_run_holds_for_a_discovered_host`, `test_loop_proposal_never_runs_anything`
(test_engagement_scope.py).

---

## 7. The honest UI

The engagement panel shows, always: the mode tag, the target, `FULLY OPEN · full reach`, the
in-scope patterns, the exclusions, the live allowed hosts (recon-discovered ones marked), and
the out-of-scope discoveries (struck through). The note under it states plainly that the scope
is what the agent is told and what the argument check enforces, that **nothing stops an
off-scope packet at the network layer**, and that approval of every command — including commands
against hosts recon discovered — is the only guard. The loop's danger-confirm on a real target
no longer claims "the sandbox is isolated"; it says the sandbox is fully open and the target is
real.

---

## 8. Verification

```
sh backend/run_safety_tests.sh              # 8 hermetic suites, all green
sh backend/run_safety_tests.sh --with-proof # + live lab isolation proof + engagement open proof
```

New suites: `test_scope.py` (12 checks — parsing, fail-closed, wildcard/CIDR matching,
extraction) and `test_engagement_scope.py` (13 checks — in-scope passes, out-of-scope/excluded
refused, expansion only adds in-scope, never-auto-run survives expansion, gate order, lab
target-lock unchanged, proposer targets the scope not the lab, lab prompt unchanged, pre-check
uses the same matcher, a proposal never runs anything).

**Deferred on purpose:** the live real-target loop end-to-end (a single-host
`scanme.nmap.org` scope, then a wildcard scope) runs only with Zaid present, approving each
command. Nothing in this work auto-runs a live engagement.
