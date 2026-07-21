# HackPit — build notes

An engineering log of what I actually built, why, and what broke along the way. This is not the marketing README; it's the honest version, written for another engineer.

## Scope, stated plainly

HackPit is meant to become two things sharing one knowledge base: a **Companion** (search and reason over my own pentest notes) and a **Cockpit** (an autonomous agent that runs the attack live). **The Cockpit does not exist yet.** What's built is the Companion and the attack-path engine on top of it.

The attack-path engine composes an ordered, grounded plan — recon → enumeration → exploitation → privesc → post-ex — where every step cites a real command from my library. It *plans*; it does not *execute*. No tool is run, no target is touched. That planner is the deliberate bridge toward the Cockpit: same retrieval, same grounding, but a human runs the commands. When I say "attack path," I mean a decision aid, not an exploitation engine. Everything below is about that Companion + planner as it stands.

## The approach, and what made it interesting

The interesting problem wasn't the UI or the LLM — it was that my knowledge was scattered across five incompatible formats (a Notion export of my TCM PEH notes, a local HackTricks mirror, PayloadsAllTheThings, OSCP/CPTS GitBooks, my own box notes), and finding my own answer meant `ctrl-F` across a thousand files. So the core is a normalization pipeline that folds ~1,600 entries from 17 sources into one schema, plus a retrieval-grounded LLM layer where the model may only cite real `entry_id`s and reuses their exact commands — so a generated plan can't hand me a hallucinated flag. Most of the actual engineering turned out to be in the seams: keeping that KB idempotent across re-ingests, and keeping the grounding honest.

## Origin

This came out of cert-prep grind — OSCP/PNPT/eCPPT. My knowledge was real but scattered, and mid-study the friction was always the same: "what's the hashcat mode for this hash," "what was the exact `impacket-GetUserSPNs` line" — and the answer was somewhere across a thousand files in five formats. I wanted one searchable place over my own notes plus the big references, with an LLM on top that answered from *my* library rather than a generic chatbot. There was no single triggering box; it was the cumulative cost of the grind.

## The pipeline / stack

- **Normalization (`pipeline/`).** Every source is parsed by a per-source ingester into one canonical `Entry` (pydantic) — `category → subcategory → steps[]{text, code[], images[]} → body_md`, plus a `meta{}` extension point. Nothing ships raw; sources are transformed, not pasted. `consolidate.py` then does a structural, best-content-wins merge across sources (canonical-key + cosine match) so a technique that appears in five places becomes one entry with "also covered in" attribution — not five near-duplicates. I chose a deterministic structural merge over per-entry LLM synthesis on purpose (see below).
- **Search (`search.py` + `embed.py`).** Hybrid: Okapi BM25 over title/tags/tools/body for exact identifiers, plus cosine over local `nomic-embed-text` (768-dim, via Ollama) for meaning, fused with weighted Reciprocal Rank Fusion. I run embeddings **locally** rather than on a hosted vector DB deliberately: it's free, offline, and keeps offensive content off third-party servers — which matters for this content specifically. Embeddings are content-hash cached so `embed.py` only re-embeds changed entries.
- **Backend (FastAPI).** Python because that's where the KB/RAG/LLM work lives and what I know best. Serves search, entry lookup, attack-path composition, engagements, and report generation.
- **Frontend (Next.js + React + Tailwind + Framer Motion).** The cinematic command-center UI is the part I consider an original contribution rather than a wrapper — true-black, single accent, animated. It's the reason the thing feels like a product and not a docs skin.
- **LLM layer (`llm.py`).** One provider-swappable `chat()`. Default is local Ollama (`qwen3:8b`) so the happy path is free and offline. There's also a `claude-agent-sdk` provider that shells out to the `claude` CLI (`claude -p --output-format json --model <m> --system-prompt <system> --allowedTools ""`, user turn piped on stdin) — zero new dependencies, fits the existing synchronous `chat()`, reuses the machine's Claude Code login so there's no API key, and `--allowedTools ""` forces a single non-agentic completion. It falls back to Ollama on any failure. I used the CLI over the Python Agent SDK / LiteLLM specifically to avoid adding a dependency and a key just to reach a frontier model for the reasoning-heavy profiler.
- **Persistence (SQLite, stdlib).** Engagements (checked steps, pasted evidence) live in a local gitignored DB.
- **Decepticon's LangGraph + two-network isolation** is a pattern reference I read while thinking about the eventual Cockpit — not adopted code.

Note on data: the KB (`data/kb/*`) is a rebuildable artifact and is gitignored. The repo ships **code** and my own authored content only; no third-party corpora or proprietary PDFs are ever committed.

## What broke, and how I fixed it

### 1. The reversible-exclusion pipeline mangled entries on re-run

**What happened.** The consolidation engine supports reverting a source's contribution so a re-ingest is clean. On re-run, entries came out mangled — the "revert" was excising too much.

**Why.** `revert_source` located a source's appended body section by its `<!-- merged:name -->` marker and split the body on that marker alone. But several sources append sections in sequence, so splitting on one marker also deleted every *later* source's section that came after it. Compounding it, `merge_log` wasn't stored in a deterministic order, so a revert-then-reappend didn't reproduce the same bytes.

**The fix.** Excise **only** that source's section — from its `---` + marker up to the *next* merged-source marker or EOF — and keep `merge_log` sorted so revert-then-reappend is byte-stable. The pipeline is now idempotent: three rebuilds produce an identical KB. This was the one that cost me the most; it's the classic subtle pipeline-state bug where nothing errors, the output just quietly rots across runs, and you don't notice until you diff two rebuilds.

### 2. A retrieval filter was silently hiding my best content

**What happened.** Three of my largest single-topic web entries — "sql injection resource" (81 steps), "xss resource" (48), "xml injection resource" / XXE (45) — never appeared as steps in any composed attack path, even though they're exactly the focused techniques the planner should reach for.

**Why.** `attack_path.is_step_eligible()` has a grab-bag backstop: an entry with `len(body_md) >= 20000` **and** no `meta.canonical_keys` is treated as an unfocused dump and made ineligible for grounding. That's the right instinct — it keeps real "misc resources" pages out of plans. But `peh-notes` was the one source whose ingester never set `canonical_keys` at all (only `consolidate.py` did, for the sources it processed), so these large-but-focused entries had empty keys and got caught by a filter meant for junk.

**The fix.** Derive `canonical_keys` from the title in `ingest_notes.py`, mirroring what every other source already does. Root-cause, not a patch: it's durable through a full re-ingest because `consolidate.py` and the curation pass both preserve existing keys. Guardrail I checked before shipping: the count of ineligible entries dropped by **exactly three**, not dozens — genuine grab-bags whose titles name no single technique ("privilage escalation resources", "oscp cheatsheet") still resolve to no key and stay correctly excluded. (`71ebd90`)

### 3. Valid-looking LLM output broke `json.loads`

**What happened.** The composer would sometimes return a full, well-formed-looking JSON plan and `compose()` would still 503 with "the model did not produce any usable steps."

**Why.** Models routinely emit raw backslashes inside command strings — `sqlmap ... \d`, a Windows path like `C:\Users\...` — which are **invalid JSON string escapes**. `json.loads` rejected the whole object, and my fallback brace-matcher then found the first *balanced* `{...}`, which was an inner phase object (`{"phase":..., "steps":...}`) rather than the outer `{"phases":[...]}`. Grounding got a dict with no `phases` key and returned nothing. Unlocking the SQLi content in fix #2 is what surfaced this — those entries are the ones full of backslash-heavy commands.

**The fix.** A lenient `_repair_escapes` in `llm.py` that doubles **only** invalid backslashes — an alternation matches and preserves a valid escape first (including an already-escaped `\\` and `\uXXXX`), so nothing correct is corrupted — and it runs only *after* the raw parse fails, so working outputs are never touched. Unit-tested against the corruption edge cases before wiring it in. (`71ebd90`)

### 4. Every web target got the same generic playbook

**What happened.** Any web goal produced roughly the same IDOR-first path. A multi-tenant SaaS and a WordPress blog got near-identical, generic steps.

**Why.** Retrieval seeded every web goal with one hardcoded string ("web application bug bounty http api"). That's a flat bucket — the retriever had no idea what *kind* of web target it was, so it returned a generic web checklist every time.

**The fix.** A pre-retrieval **target-profiler** stage: the LLM reads the goal (and optional pasted scope) and returns `{target_class, priority_bug_classes, out_of_scope}`, which then dynamically seeds retrieval and steers composition. It doubles as scope/RoE ingestion — out-of-scope hosts and paths are dropped from the final path. Verified end-to-end with the `claude-agent-sdk` provider: it classed a real target (Aikido) as "multi-tenant AppSec SaaS" and produced product-specific bug classes (cross-tenant IDOR, GitHub-App token handling, SSRF via integrations) instead of a generic checklist; 8 of 14 steps were grounded, 7 carried conditional branches. This is also where the local `qwen3:8b` clearly under-performs — the profiler is reasoning-heavy, and a frontier model earns its place here. (`da0dbda`)

### 5. I reached for a dependency the project didn't already have

**What happened.** I wrote the HTB box-writeup PDF ingester with `pdfplumber`, committed it, then realized `pyproject.toml` already declared `pypdf`. The committed script wouldn't run on a fresh `uv sync` — it imported a package that wasn't a declared dependency.

**The fix.** Rewrote extraction to `pypdf.PdfReader` (no new dependency), and hardened box-name parsing along the way: `pypdf` glues the box name to the following date line, so a title came out as "Principal11th March 2026" — I now take the leading alphabetic token, which keeps the title, the `htb-box-{slug}` id, and the writeup-match lookup correct. Small bug, but a good dependency-discipline lesson: check what the project already has before you `import`. (`cf69cae`, `67dca3c`)

## What I'd do differently

Three things I'd rebuild, grounded in what's actually in the code:

- **Finish the migration I half-did.** Target-type reasoning is a hybrid: a regex bucket (`parse_goal_context`) still sits *underneath* the smarter LLM profiler. It works, but it's two systems doing one job. I'd make it fully profiler-driven and delete the regex path.
- **Replace the heuristic PDF parser.** The box-writeup extractor is line-heuristic and noisy — one box (Odyssey) exploded to 358 "steps," and some command-vs-prose lines land in the wrong field. It needs real structured extraction, not regex that guesses whether a line looks like a command.
- **Collapse the two representations of the KB.** Each entry is text (`entries.jsonl`) *and* a vector (`embeddings.npy`), kept in sync by a content hash. Authoring a new entry leaves it unsearchable until `embed.py` runs — a real operational gotcha I've tripped over. I'd want a single source of truth that can't drift.

**The uncomfortable admission:** the headline of this project is autonomous live hacking, and that's the one part I haven't built. What exists is the knowledge base, the search, and a planner that decides *what* to do — not the thing that *does* it. I've built the cockpit's instruments, not its engine. And I have to actively watch myself, in writing and in demos, not to describe the vision as if it's the product. The honest version is: this is a very good grounded planner and reference tool, and the autonomous execution engine is still ahead of me.
