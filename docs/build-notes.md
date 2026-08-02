# HackPit — build notes

An engineering log of what I actually built, why, and what broke along the way. This is not the marketing README; it's the honest version, written for another engineer.

> **Note on this document, 2026-08-03.** For about a year this file opened with "**The Cockpit does not exist yet**" and closed by calling the execution engine "still ahead of me." Both were true when written and neither has been true for a long time — the cockpit shipped across eleven builds, and it has since driven a real Active Directory domain live. Leaving that uncorrected was its own kind of dishonesty, just pointed the other way: I wrote this doc to guard against overselling, and it ended up underselling by roughly a year. The failure mode is the same one either way — **the doc stopped tracking the code.** Corrected below; the original framing is preserved in this note rather than quietly deleted.

## Scope, stated plainly

HackPit is two things sharing one knowledge base: a **Companion** (search and reason over my own pentest notes) and a **Cockpit** (a gated execution surface that runs the attack against a real target).

Both exist now. The Companion is the KB, hybrid search, and the attack-path planner. The Cockpit is a real execution substrate: three Docker sandboxes with deliberately different network models, a four-gate executor, a WinRM driver for Windows/AD targets, an engagement state model, a purple-team detection layer, and a reasoning copilot.

**The one thing it is not, and will not be, is autonomous.** The agent proposes; a human approves every single command. That started as a limitation and became a decision — see the admission at the bottom, because it is the most interesting thing about the project and the easiest thing to misrepresent.

## Origin

This came out of cert-prep grind — OSCP/PNPT/eCPPT. My knowledge was real but scattered, and mid-study the friction was always the same: "what's the hashcat mode for this hash," "what was the exact `impacket-GetUserSPNs` line" — and the answer was somewhere across a thousand files in five formats. I wanted one searchable place over my own notes plus the big references, with an LLM on top that answered from *my* library rather than a generic chatbot. There was no single triggering box; it was the cumulative cost of the grind.

## The pipeline / stack

- **Normalization (`pipeline/`).** Every source is parsed by a per-source ingester into one canonical `Entry` (pydantic) — `category → subcategory → steps[]{text, code[], images[]} → body_md`, plus a `meta{}` extension point. Nothing ships raw; sources are transformed, not pasted. `consolidate.py` then does a structural, best-content-wins merge across sources (canonical-key + cosine match) so a technique that appears in five places becomes one entry with "also covered in" attribution — not five near-duplicates. I chose a deterministic structural merge over per-entry LLM synthesis on purpose.
- **The KB, measured today:** 2,743 entries across 33 categories from 22 sources. 128 tier-1 · 350 tier-2 · 2,265 tier-3. 136 entries carry a `hackpit-*` source — written or distilled here rather than ingested.
- **Search (`search.py` + `embed.py`).** Hybrid: Okapi BM25 over title/tags/tools/body for exact identifiers, plus cosine over local `nomic-embed-text` (768-dim, via Ollama), fused with weighted Reciprocal Rank Fusion. Embeddings run **locally** rather than on a hosted vector DB deliberately: free, offline, and it keeps offensive content off third-party servers. Content-hash cached, so `embed.py` only re-embeds what changed.
- **Backend (FastAPI).** 112 routes across six routers — search/entries, cockpit execution, AD graph, detection, code scan, arsenal, exploits.
- **Execution (`backend/cockpit/`).** Argv-only, never a shell. Four ordered gates on every command: target-lock, human approval, a dangerous-command red-confirm, and (lab only) a structural isolation assert. Run records persisted; SSE streamed.
- **Three sandboxes, different on purpose.** The **lab** box is egress-less (`internal: true` — Docker attaches no gateway) and shares that network with an OWASP Juice Shop target. The **`:kali`** box is human-only with full network reach. The **engagement** box is fully open *and* privileged (root + NET_ADMIN + `/dev/net/tun`) because a real target is on the internet. What bounds each one is different, and that is the whole design.
- **Arsenal:** 115 catalogued tools with 286 invocation templates. A probe measured that **97 of 104 Linux tools actually execute** in the live image (93.3%) — the seven that do not are reported as absent rather than assumed present.
- **Frontend (Next.js 16 + React 19 + Tailwind + Framer Motion).** 23 routes. The cinematic command-center UI is the part I consider an original contribution rather than a wrapper.
- **LLM layer (`llm.py`).** One provider-swappable `chat()`. Default is local Ollama (`qwen3:8b`) so the happy path is free and offline; a `claude-agent-sdk` provider shells out to the `claude` CLI for the reasoning-heavy work, falling back to Ollama on any failure.
- **Tests.** 55 files run as one suite (`sh backend/run_safety_tests.sh`). Most exist to prove a guard *fires*, including planted-violation controls — a safety test that cannot fail is not evidence.

Note on data: the KB (`data/kb/*`) is a rebuildable artifact and is gitignored. The repo ships **code** and my own authored content only; no third-party corpora or proprietary PDFs are ever committed.

## What broke, and how I fixed it

### 1. The reversible-exclusion pipeline mangled entries on re-run

`revert_source` located a source's appended body section by its `<!-- merged:name -->` marker and split the body on that marker alone. Several sources append sections in sequence, so splitting on one marker also deleted every *later* source's section. Compounding it, `merge_log` wasn't stored in a deterministic order, so revert-then-reappend didn't reproduce the same bytes.

**Fix.** Excise **only** that source's section — from its marker to the *next* merged-source marker or EOF — and keep `merge_log` sorted so revert-then-reappend is byte-stable. Three rebuilds now produce an identical KB. This one cost me the most: the classic pipeline-state bug where nothing errors, the output just quietly rots across runs, and you don't notice until you diff two rebuilds.

### 2. A retrieval filter was silently hiding my best content

Three of my largest single-topic web entries — SQLi (81 steps), XSS (48), XXE (45) — never appeared in any composed attack path. `attack_path.is_step_eligible()` treats a >20,000-char entry with no `meta.canonical_keys` as an unfocused dump. Right instinct; but `peh-notes` was the one source whose ingester never set `canonical_keys` at all, so these large-but-focused entries got caught by a filter meant for junk.

**Fix.** Derive `canonical_keys` from the title in `ingest_notes.py`, mirroring every other source. Guardrail I checked before shipping: the ineligible count dropped by **exactly three**, not dozens — genuine grab-bags still resolve to no key and stay correctly excluded. (`71ebd90`)

### 3. Valid-looking LLM output broke `json.loads`

Models routinely emit raw backslashes inside command strings — `sqlmap ... \d`, a Windows path — which are **invalid JSON string escapes**. `json.loads` rejected the whole object, and my fallback brace-matcher then found the first *balanced* `{...}`, which was an inner phase object rather than the outer one. Unlocking the SQLi content in fix #2 is what surfaced this — those entries are full of backslash-heavy commands.

**Fix.** A lenient `_repair_escapes` that doubles **only** invalid backslashes (an alternation preserves valid escapes first), running only *after* the raw parse fails. (`71ebd90`)

### 4. Every web target got the same generic playbook

Retrieval seeded every web goal with one hardcoded string. A multi-tenant SaaS and a WordPress blog got near-identical steps.

**Fix.** A pre-retrieval **target-profiler**: the LLM reads the goal and returns `{target_class, priority_bug_classes, out_of_scope}`, which dynamically seeds retrieval. It doubles as scope/RoE ingestion. This is also where local `qwen3:8b` clearly under-performs — the profiler is reasoning-heavy, and a frontier model earns its place. (`da0dbda`)

### 5. I reached for a dependency the project didn't already have

Wrote the PDF ingester with `pdfplumber`, committed it, then realized `pyproject.toml` already declared `pypdf`. The committed script wouldn't run on a fresh `uv sync`.

**Fix.** Rewrote extraction to `pypdf`. Small bug, good discipline lesson: check what the project already has before you `import`. (`cf69cae`, `67dca3c`)

### 6. Six defects that a green test suite could not see

The single most valuable build was the one whose headline result was *defects*, not features. Everything in the C2 and tunnel surfaces passed its tests. Then I ran them against real binaries and real processes:

- the Sliver implant argv named a **subcommand that does not exist** in the pinned version;
- both listener lifecycles reported `status="listening"` for a process that had **already exited**;
- a stop killed the `docker exec` client while the server kept running and holding its port;
- the shipped `proxychains` config pointed at **Tor**, not the SOCKS5 port HackPit's own rewrite targets;
- a status was observed once and never re-observed upward, so a listener that bound just after its settle window stayed permanently unroutable;
- and an image smoke test — `sliver-server version | grep -qi sliver` against a binary that prints only `v1.5.42` — **had never passed**, so that layer had not built since the check was added.

None was a containment failure. But the efficacy claims those surfaces carried were never true. **Every one of the six was a claim asserted structurally that nothing had ever executed.** That is now the rule: a structural assertion is a hypothesis until something runs.

### 7. The same shared-predicate bug, three times

This is the pattern I most want to remember, because it has now bitten in three unrelated subsystems:

1. **The WinRM danger classifier** classified `argv[0]` and stopped. On the Docker path that is fair — an argv list has no shell. On the WinRM path the executor *joins* command and args and PowerShell treats `;` as a live separator, so `Write-Host go ; Invoke-Mimikatz` ran on a real domain-joined host with **no red-confirm**. You defeated the gate by moving a cmdlet one token to the right.
2. **`proxychains` laundered the red-confirm.** The heuristic classified the wrapper, not what it ran, so `weevely` demanded a confirm and `proxychains -q weevely …` demanded nothing — while the tunnels module builds exactly that argv. Routing a command through a tunnel made its gate *weaker*, so the further into a network you reached, the less the confirm applied.
3. **`_version_verdict` had an unstated boundary convention.** The CVE index stores the *fix* version (exclusive `<`); the fingerprint corpus stores the *last vulnerable* version (inclusive `<=`). One predicate, two callers, nothing asserting the obvious — so **35 of 38 versioned fingerprints silently failed to match the very version they were written about.**

In all three the fix was in the **predicate**, never the caller, and every caller now states its convention explicitly. The shape to watch for by name: *a guard or verdict shared by two callers with an unstated convention, sitting behind no test that pins the obvious.*

### 8. Collecting a domain shipped the DA password to the model

The WinRM path never puts a secret on a command line — the profile resolves it server-side. But every credentialed Linux tool carries it as an argv token (`bloodhound-python -p …`), which was stored verbatim in the run record, and from there into rendered reports **and the LLM proposer context**.

**Fix.** `cockpit/secretargs.py` redacts credential *values* out of the argv at the record boundary — per-tool, never a blanket flag list, because `-p` is a password to netexec and a *port list* to nmap. A first cut split the impacket positional on the *first* `@` and leaked a password fragment out the "host" side; the fix anchors to the last `@`. Locked with negative controls (nmap ports survive untouched).

Only a real domain finds that one. Every defect in #6, #7 and #8 lived *between* two components that were each correct alone.

## What I'd do differently

- **Finish the migration I half-did.** Target-type reasoning is still a hybrid: a regex bucket (`parse_goal_context`) sits *underneath* the smarter LLM profiler. Two systems doing one job. I'd make it fully profiler-driven and delete the regex path.
- **Replace the heuristic PDF parser.** The box-writeup extractor is line-heuristic and noisy — one box exploded to 358 "steps." It needs real structured extraction, not regex guessing whether a line looks like a command.
- **Collapse the two representations of the KB.** Each entry is text (`entries.jsonl`) *and* a vector (`embeddings.npy`), kept in sync by a content hash. Authoring an entry leaves it unsearchable until `embed.py` runs — a real operational gotcha I've tripped over.
- **Wire the tests to something that isn't me.** 55 test files, and nothing runs them on push. The entire safety story rests on guards that a refactor could silently unlock, and the only thing standing between that and a merge is my memory.

## The uncomfortable admissions

There are four, and I'd rather list them than let the README imply otherwise.

**1. The headline was autonomous hacking, and I deliberately built the opposite.** The vision was an agent that runs the attack. What exists reasons deeply — working memory, hypothesis-first proposals, a scored candidate frontier, failure diagnosis, a refute-first critic — and then stops and asks. That is not an unfinished feature; risk-tiered approval was designed, reconsidered, and **rejected**, because in engagement mode per-command approval is the *only* thing bounding where a command can go, and a classifier deciding when to skip the human is a new component on the wrong side of the safety boundary. I'd defend the decision. But it means the product is not the thing the name promises, and I have to keep watching myself — in writing and in demos — not to describe the vision as the product.

**2. "Grounded in your own notes" is still mostly "grounded in HackTricks."** 128 of 2,743 entries are tier-1. Search boosts tier-1, but with that ratio the lever has little to pull on. Five enrichment batches added 44 entries and measured their own diminishing returns honestly — 36 cert-note sources yielded 4 entries against 106 narrative writeups yielding 27. The fix isn't another ingest. It's writing, and I haven't done enough of it.

**3. There is no authentication on any route.** Not a `Depends`, not an API key, not a session — and the CORS allowlist is a browser policy that stops nothing which is not a browser. On a laptop, bound to localhost, that is survivable and it is the mitigation. It is also why this cannot move anywhere else: `/cockpit/terminal/ws` is an unauthenticated interactive PTY into a container that reaches my host and LAN. I scoped the fix in full once and then chose not to build it, which is a decision I should stop re-deferring.

**4. The parts I'm proudest of are the parts that say "no."** The AD orchestrator picks an *edge*, never a command. `advance` requires a run that was approved and exited 0, verified server-side. `foreign_refs` reports a host it can't safely rewrite instead of guessing. Grounded steps cite entry ids that must resolve or get downgraded. Report evidence is spliced by code because the model was caught mis-transcribing a port number. None of that demos well. All of it is why I'd trust the output.
