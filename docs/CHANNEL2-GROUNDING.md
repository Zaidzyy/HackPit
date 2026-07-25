# Channel-2 context grounding — reasoning from the whole KB

The planner used to read only one kind of KB document: a **technique it could
turn into a step**. Everything else in the knowledge base was invisible to it. A
box writeup was surfaced as a *link* — title only, never content. The methodology
and workflow docs weren't fed in at all.

That left the two most useful things in the KB unread. A writeup shows how a box
was actually approached — which technique class to reach for, what followed what.
A methodology doc says what a coherent plan looks like: the phase order, which
bug classes to probe first for this kind of target. Neither can be a *step*, so
neither reached the model.

Channel 2 feeds them in as **background the planner reasons from**.

---

## The two channels

Keeping them separate is the whole design.

| | **Channel 1 — STEP grounding** | **Channel 2 — CONTEXT** |
|---|---|---|
| where | `attack_path.retrieve` / `_ground` | `context_channel.py` |
| what it produces | the steps the operator runs | prompt background the model reads |
| writeups | **excluded** from the pool | **content injected** |
| methodology / meta / arsenal / grab-bag docs | **step-ineligible** | **content injected** |
| changed by this feature | **no** | new |

**Channel 1 is untouched.** `is_step_eligible`, `is_broad_reference`,
`EXCLUDED_STEP_CATEGORIES` and the retrieval pool are byte-identical to what they
were. The reasons they exclude these documents still hold:

* a **writeup step overfits one box** — grounding a step on "Querier" dumps
  another machine's commands where the technique belongs;
* a **methodology step is un-runnable** — it is process guidance, not an action.

Channel 2 does not relax either rule. It reads those documents; it never emits
them. A model that cites a writeup or a methodology doc as an `entry_id` still
gets **no step** — `_ground` rejects it, exactly as before.

Step labelling is likewise unchanged. Channel 2 improves the *quality* of a step;
it never relabels one. A grounded step is still grounded on its own cited KB
entry, and an `ai_suggested` step is still clearly marked.

---

## What gets injected, and the budget

Retrieval is **relevance-selected and hard-capped** — never a whole file.
`excerpt()` splits a document into sections (markdown headings, else paragraphs),
scores each on overlap with the goal's content words, keeps the best ones **in
the document's own order** (so the flow survives), and stops at the cap. Fenced
code is cut to its first lines: enough to see *which tool*, not a command dump.

| source | when | cap |
|---|---|---|
| the matched box **writeup** | KB-first mode, goal names a box `find_box_writeup` matched | `WRITEUP_CHARS` = 2 800 |
| **methodology / workflow** docs | always, when any match | `METHODOLOGY_CHARS` = 1 200 × `METHODOLOGY_DOCS` = 2 |
| excerpt bodies, all sources | | `TOTAL_CONTEXT_CHARS` = 6 000 |
| the whole rendered block (bodies + headers + titles) | | `MAX_BLOCK_CHARS` = 7 600 |

The writeup goes in under a **REFERENCE** header — *here is how this (or a
closely similar) box was approached; inform the approach and technique choice for
the NAMED target; copy no box-specific literal; do not turn it into steps.* The
methodology docs go in under a **METHODOLOGY** header — *follow this flow and
bug-class prioritisation; emit none of it as a step.*

**Writeup mode gets methodology only.** When the goal names a box whose writeup
already *is* the path, re-injecting that writeup would only invite duplicate
steps. Its id is still excluded from the methodology search so it can't return on
a title match.

**Methodology docs are selected by TITLE, not by KB category.** The KB's
`methodology` category is the HackTricks section name and two thirds of its 95
entries are ordinary technique pages ("Docker Forensics", "Telecom Network
Exploitation"). Reading one as "the methodology to follow" would frame a single
technique as the plan's shape — the exact failure Channel 2 exists to avoid. The
process words in the title (methodology, workflow, mindset, playbook, machine
approach, attack paths, threat modeling, testing checklist) are the reliable
signal: 29 focused docs instead of 95 mixed ones.

---

## The leakage guard

Injected background carries another box's identity: `10.10.10.161`,
`dev.forest.htb`, a cracked password, `/home/svc-alfresco/...`, `HTB{...}`. A
model reasoning from that text can echo one into a generated step — and **a step
aimed at another box's host is a wrong step**.

Guarded three ways:

1. **Prompt discipline** — the REFERENCE header names the failure explicitly:
   inform the approach, adapt to THIS target, copy no box literal.
2. **`substitute_target`** still runs on generated commands, unchanged.
3. **A post-generation scan** (`collect_literals` → `scrub_phases`): the literals
   actually present in the injected text are collected, then found in the model's
   output. **Hosts and IPs are re-pointed at the real target** (a lab domain's
   parent — `forest.htb` from `dev.forest.htb` — counts as the same box's
   identity). **Credentials, flags and box-specific paths cannot be re-pointed**,
   so those prose lines and commands are dropped.

What the scan does **not** touch:

* **a grounded step's commands** — they are the cited KB entry's, copied
  verbatim, never model output;
* **a writeup step's commands** — the user's own walkthrough for *this* box.

So the guard is structurally incapable of altering Channel-1 behaviour.

Two things are deliberately *not* leaks: anything the operator named in the goal
or the pasted scope (it is this engagement's own identifier), and public
infrastructure — github, pypi, loopback, `0.0.0.0`, matched by parent domain too
— so a legitimate `git clone` of a tool survives intact.

### The executor is the safety backstop

**This guard is for plan quality, not safety.** The safety boundary is, and
remains, the executor: every command passes the target-lock / scope-lock, so a
leaked off-target host is **refused at execution time** whether or not this guard
catches it. Nothing in Channel 2 executes anything or changes any gate.
`test_context_channel.py` asserts the backstop directly —
`check_target_lock(["-sV", "10.10.10.161"])` is refused.

---

## Provenance

A plan shaped by a writeup's approach should say so. `compose()` returns:

* `context_sources` — `{kind, id, title, chars}` per injected document;
* `context_leaks` — how many box literals were caught and re-pointed or dropped.

The attack-path screen renders an **"informed by"** line linking each document,
labelled *read as background — never a step*. It is deliberately quieter than the
writeup link above it: these documents are not the source of any step.

---

## The no-op guarantee

When the goal names no box we have a writeup for **and** no methodology doc
matches, Channel 2 contributes nothing: empty source list → empty block → the
composer and augmentation prompts are **byte-for-byte** the pre-Channel-2
prompts, and `scrub_phases` returns the same phases object untouched. Channel 2
can only add background when there is background to add. Regression-locked in
`test_no_op_when_nothing_matches`.

The two new response fields are additive and default to `[]` / `0`.

---

## Tests

`backend/test_context_channel.py`, wired into `sh backend/run_safety_tests.sh`:

| test | what it locks |
|---|---|
| `test_channel1_filters_unchanged` | writeups/CTF still step-ineligible; meta docs still are; reading on Channel 2 changes eligibility in neither direction; a technique page miscategorised as `methodology` is not selectable; a cited writeup/methodology yields **no step**, the real technique beside it still grounds one |
| `test_leakage_guard` | a writeup carrying a box IP, hostname, credential, path and flag cannot put any of them into a generated step; the `git clone` survives; the grounded step's KB command and the writeup step's own command are untouched |
| `test_goal_identifiers_are_not_leaks` | an in-scope host the operator named is not scrubbed |
| `test_executor_backstop_still_refuses_off_target` | the target-lock refuses a leaked host at the gate, guard or no guard |
| `test_no_op_when_nothing_matches` | byte-identical prompts, no scrubbing |
| `test_budget_bounded` | a 200-section writeup still fits under the ceiling |
| `test_composer_still_yields_grounded_and_ai` | composition still produces both step kinds correctly |

## Scope

Planner enhancement only — retrieval plus prompt. It **executes nothing** and
**changes no gate**. `context_channel.py` has no import of the cockpit, no
subprocess, no network call of its own; it reuses the same hybrid search Channel
1 already uses.
