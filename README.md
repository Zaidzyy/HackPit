# HackPit

**An AI-powered offensive-security companion — and a gated cockpit that actually runs the work.**

HackPit started as a way to make a career's worth of scattered pentest notes recallable: one deduplicated, source-attributed knowledge base with hybrid semantic search over it. It still is that. But it now also **executes** — a containerised Kali cockpit where a human approves every single command, against an isolated lab or a scoped real target, with the defender's view of each action shown alongside it.

It runs **local-first** on your own machine. Every answer cites a real technique from your own library, and every command is one you explicitly approved.

> **This public repo ships code only.** The knowledge sources and raw technique material the KB is built from — course notes, write-ups, cloned repos, PDFs, cheat sheets — are kept **local and git-ignored** and never committed. What *is* committed is the pipeline that builds the KB, plus per-batch **source manifests** (`sources/*-manifest.md`) recording each source's URL, date, commit SHA, and verdict, so provenance stays traceable without redistributing anyone's content. The KB data itself (`/data/`) is generated locally.

<p align="center">
  <img src="assets/screenshots/02-home.png" alt="HackPit home — category grid and live knowledge-base counters" width="100%">
</p>

> **Authorized use only.** The cockpit runs real tools against real hosts. It is built for engagements you are authorized to perform — your own lab, an HTB/PG box, or a client with a signed scope. Every execution path is gated on explicit human approval and, in engagement mode, on a target you declared in scope. See [Safety model](#safety-model) — it is not a footnote, it is the core of the design.

---

## What it is

Two halves that feed each other.

**The companion** is the original idea: offensive-security practitioners accumulate technique notes everywhere — course notes, HackTricks, PayloadsAllTheThings, OSCP/CPTS write-ups, box walkthroughs, cheat sheets — until it is scattered, duplicated, and impossible to recall mid-engagement. A normalization pipeline folds **15+ sources into one consolidated KB (2,621 entries, 33 categories)**, and the UI makes it instantly usable: recall by meaning, compose guided attack paths from your own tested commands, run engagements as living checklists, draft grounded reports.

**The cockpit** is what got built on top: a real execution surface. A Kali container, a **110-tool catalog** with 274 invocation templates, an engagement state model that remembers hosts/services/creds/findings, an AD attack-path graph you can walk, a WinRM driver for Windows targets, and a purple-team detection layer that tells you what a defender sees while you do it.

**Who it's for:** pentesters, red teamers, bug bounty hunters, and anyone grinding HTB boxes or OSCP/CPTS/PNPT certs who wants their own knowledge — and their own tooling — under their own hand.

---

## Safety model

This is the part worth reading before the feature list, because it constrains everything else.

**Four gates, on every command.** Nothing executes without passing all of them:

| Gate | What it does |
|---|---|
| **Human approval** | Every single command needs an explicit approve. There is no batch approval, no risk-tiered auto-run, no autonomous loop. |
| **Scope lock** | In engagement mode the target must be in a scope you declared. Default-deny; an out-of-scope host is refused, not warned about. |
| **Red confirm** | A heuristic flags dangerous commands (interpreters, reverse shells, payload generators, tunnels, RCE tooling) and demands a second, explicit acknowledgement naming *what* it flagged. |
| **Audit** | Every action — including refusals that ran nothing — is recorded. |

**No autonomy.** The agent proposes; it never executes. That is enforced structurally, not by convention: source-scan tests assert that no orchestrator, loop, or agent module has any code path to an execution surface, and those tests fail the build if one appears.

**Two sandboxes, deliberately different.** The **lab** container is egress-less — it cannot reach the internet, your LAN, or your host, proven by a live Docker isolation check. The **engagement** container is fully open by design, because a real target is on the internet; the bound there is the scope lock and per-command approval, not network isolation.

**Describe, then prescribe — never one without the other.** The detection layer is describe-only: it tells you what a defender observes and is guarded against drifting into evasion advice. The operator-facing OPSEC channel *is* allowed to be prescriptive, including in-process sensor tradecraft — but only under one hard invariant: **every note must name what still records the activity anyway**, and the blue-team footprint is always produced alongside and cannot be suppressed. An evasion tool that told you only how to be quieter, and never what still sees you, would be an evasion how-to. This one is not.

**42 test files, 459 assertions**, run as one suite (`sh backend/run_safety_tests.sh`). Most of them exist to prove a guard *fires* — including planted-violation controls, because a safety test that cannot fail is not evidence.

---

## Key features

### Consolidated knowledge base + hybrid semantic search

Every entry is a focused, copy-ready technique with real commands, tool tags, and full source attribution. Where the same technique appeared in multiple sources they are merged into one entry showing **how many sources** it came from and which others **also cover it** — provenance stays traceable without duplicate clutter. Search is **hybrid BM25 + vector**, so `⌘K` finds the right technique by meaning, not keyword match.

<p align="center">
  <img src="assets/screenshots/03-command-palette-search.png" alt="Command palette showing ranked hybrid search results with source badges" width="49%">
  <img src="assets/screenshots/04-consolidated-entry.png" alt="A consolidated Kerberoasting entry — 4 sources, also-covered-in chips, tool tags, copy-ready steps" width="49%">
</p>

Some entries are **your own authored techniques** — original methodology written for your library, badged `HACKPIT-AUTHORED` and tier-1 "your notes."

<p align="center">
  <img src="assets/screenshots/11-authored-entry.jpg" alt="An authored technique badged HACKPIT-AUTHORED, tier-1, with copy-ready curl steps" width="80%">
</p>

### Guided attack paths — writeup-first, KB-grounded, AI-gap-filled

Describe a target and HackPit composes an ordered **recon → enumeration → exploitation → privesc → post-ex** walkthrough. The grounding hierarchy is deliberate:

1. **Your own box write-up first** — if you have a walkthrough for the named box, its steps lead, in order, marked with a green banner.
2. **KB-grounded next** — every other step cites a real technique from your library and reuses its exact commands.
3. **AI-suggested gap-fill, clearly marked** — where the library has a gap the model may add a step, badged `AI-SUGGESTED · VERIFY`, so grounded fact is never confused with generation.

A **target-profiler** reads your goal (and optional scope / rules of engagement) and classes the target, so a multi-tenant SaaS and a WordPress blog get different playbooks. Pivotal steps carry **conditional branches** (green *if it works →*, amber *if blocked →*), and any out-of-scope host you paste is dropped from the path.

<p align="center">
  <img src="assets/screenshots/05-attack-path-writeup.png" alt="Writeup-first attack path with the green 'from your writeup' banner" width="49%">
  <img src="assets/screenshots/06-attack-path-profiled.jpg" alt="A profiled attack path showing inferred target class and priority bug classes" width="49%">
</p>

### The cockpit — gated execution

A Kali container driven from the UI, one approved command at a time. Three execution modes behind the same four gates: the **isolated lab**, a **scoped engagement** against a real authorized target, and **Windows over WinRM** for AD work that cannot run from Linux.

Around it:

- **`:kali`** — the one arbitrary-shell surface, deliberately scoped as such and human-only.
- **`:terminal`** — a real PTY inside the container, so `top`, `vim` and interactive tools work.
- **Live sessions** — catch and drive one shell, with human-only stdin.
- **HTTP repeater** — send, replay and diff requests, argv-only with no shell.
- **Pivots and tunnels** — chisel / ligolo, with the proxychains wrap made visible before you approve it.
- **Engagement state** — hosts, services, credentials, findings and a task tree that persist across the engagement, populated from what your commands actually returned.

### Purple-team detection footprint

For any command or run, the **defender's view**: the ATT&CK techniques it maps to, the telemetry it generates, the Sigma rules that would fire, and a loudness rating. Curated from **53 footprint specs, 65 ATT&CK techniques and 49 Sigma rules**, verified against live upstream ATT&CK and SigmaHQ rather than written from memory.

Paired with each is an **OPSEC note** — the honest operator counterpart: why it is loud, what a quieter approach costs, and what records it regardless. That last field is mandatory.

### AD attack-path graph

Ingest BloodHound data, get a typed graph, route to Domain Admin, and walk the path — each edge proposed by the agent, each command still approved by you, executed live over WinRM against a Windows target you control.

### Tool arsenal · exploit index · code scan

**110 tools / 274 templates** catalogued with what each is for, which phase it belongs to, and whether it actually runs in this image — the planner draws on it so proposed commands are well-formed. A **CVE→exploit index** turns "vsftpd 2.3.4" into the specific exploit and its CVE. A **code-scan** surface runs an 8-language SAST rule bundle over source you point it at.

### Engagements, assistant, reports

Turn an attack path into a live engagement with evidence capture that persists; a session-aware assistant that answers against your actual progress and cites real techniques; and a one-click grounded report — exec summary, scope, methodology, attack narrative — built from your checked steps and pasted evidence, with **OSCP-style proof tables and computed CVSS 3.1** rather than asserted scores.

<p align="center">
  <img src="assets/screenshots/07-engagement.png" alt="A live engagement with checked steps and pasted results" width="49%">
  <img src="assets/screenshots/09-report.png" alt="A generated pentest report with executive summary and methodology" width="49%">
</p>
<p align="center">
  <img src="assets/screenshots/08-assistant-drawer.png" alt="The engagement assistant mid-conversation, citing real techniques" width="49%">
  <img src="assets/screenshots/06b-attack-path-branches.jpg" alt="A grounded step with copy-ready commands and conditional branches" width="49%">
</p>

### Scripts arsenal

Every runnable script and payload across the whole KB — **extracted, deduped and grouped by type** (reverse shells, web payloads, delivery, persistence, privesc, enumeration), each with a reuse count and links back to the entries it came from. The operator's copy-ready view of the entire library.

<p align="center">
  <img src="assets/screenshots/10-scripts-arsenal.png" alt="The Scripts Arsenal — deduped runnable scripts grouped by type" width="80%">
</p>

### Multi-provider LLM — local-first, key-swappable

Defaults to a **local Ollama** runtime — `qwen3:8b` for composition and chat, `nomic-embed-text` for embeddings, `llava` for note-image captions — so engagement data never leaves your machine. Prefer a hosted model? Drop a key for OpenAI, Anthropic, Groq, OpenRouter or xAI and swap without touching code.

---

## How it works

```
                    ┌────────────────────────────────────────────────┐
  raw sources  ──▶  │  pipeline/  — ingest · normalize · consolidate  │
  (external,        │  dedupe (alias-key + cosine) · embed (Ollama)   │
   gitignored)      └────────────────────────────────────────────────┘
                                         │  builds
                                         ▼
                    ┌────────────────────────────────────────────────┐
                    │  data/kb/  — one deduplicated, attributed KB   │
                    │  entries.jsonl · embeddings.npy  (gitignored)  │
                    └────────────────────────────────────────────────┘
                                         │  served by
                                         ▼
   FastAPI backend  ──  hybrid search · attack paths · engagement state
        │                detection footprints · reports                 ──  local Ollama
        │  the four gates: approve → scope → red-confirm → audit
        ▼
   cockpit  ──▶  docker exec (argv-only, never a shell)
        ├─ lab container         egress-less, isolation-proven
        ├─ engagement container  fully open, scope-locked
        └─ WinRM                 an external Windows/AD target you run
                                         │  HTTP
                                         ▼
   Next.js frontend  ──  search · paths · cockpit · AD graph · detection · reports
```

- **Frontend** — Next.js 16 (App Router), React 19, TypeScript, Tailwind v4.
- **Backend** — FastAPI. Loads the KB into memory at startup, then serves search, composition, execution gating, state, detection and reports. Packages: `cockpit/` (execution + gates), `detection/`, `state/`, `arsenal/`, `adgraph/`, `exploits/`, `codescan/`, `evasion/`.
- **Hybrid search** — BM25 fused with vector similarity over local embeddings; falls back to pure lexical if the vector half is unavailable, so a query never fails on infrastructure state.
- **Pipeline** — folds each new source into the KB without duplicates (alias-key + cosine matching, structural merge, idempotent re-runs).

### The grounding philosophy

**Answers cite real techniques, and anything generated beyond the library is marked.** Attack-path steps prefer your write-ups, then KB-grounded techniques; only where the library has no fit does the model gap-fill, badged `AI-SUGGESTED · VERIFY`. Whole-box write-ups and index pages are kept out of the grounding pool so a step is always a focused technique. The same rule extends to the cockpit: a detection footprint is built from the curated map, and a model-suggested one is re-grounded and can never introduce a Sigma rule of its own.

---

## Knowledge base

**2,621 entries synthesized from 15+ sources** into one deduplicated, source-attributed library across 33 categories — web & bug bounty (636), cloud (534), network services, Active Directory, privilege escalation, pwn, methodology, reference and more.

1. **Ingest** each source in its native shape (Markdown, exported cheat sheets, structured course notes, box write-ups, PDFs).
2. **Normalize** to one canonical entry schema — title, summary, tested commands, tool tags, category, tier.
3. **Consolidate** — an alias-keyed canonical class plus cosine similarity finds the merge target, content is structurally merged rather than concatenated, and provenance from every contributing source is recorded. Re-runs are idempotent.
4. **Embed** every entry locally to power the vector half of search.
5. **Attribute** — the richest home wins as the spine; the rest surface as "also covered in" chips.

> **On third-party sources.** The knowledge base is **adapted and synthesized** from the author's own notes plus public community resources (HackTricks, PayloadsAllTheThings and others — some used with permission and attributed). Those raw sources are **not redistributed**: they are ingested locally into a private index, and both the raw source trees and the built KB are **gitignored and never committed**. **This repository ships code only** — the engine that builds and serves a knowledge base, not anyone else's content.

---

## Tech stack

| Layer | Stack |
|---|---|
| **Frontend** | Next.js 16 (App Router), React 19, TypeScript 5, Tailwind CSS v4 |
| **Backend** | FastAPI, Uvicorn, NumPy, Python 3.14 |
| **Execution** | Docker — one Kali image, three containers with different runtime postures |
| **Search** | Hybrid BM25 (lexical) + vector (cosine over local embeddings) |
| **LLM (local)** | Ollama — `qwen3:8b`, `nomic-embed-text`, `llava` |
| **LLM (optional)** | OpenAI · Anthropic · Groq · OpenRouter · xAI (key-swappable) |
| **Detection data** | ATT&CK v19 + SigmaHQ, verified against live upstream |
| **Tests** | 42 plain-script suites, 459 assertions, no pytest |

---

## Running it

**Prerequisites:** [Ollama](https://ollama.com), Python 3.14+, Node 18+, and Docker (for the cockpit).

```bash
# 1. Local models (one-time)
ollama pull qwen3:8b
ollama pull nomic-embed-text

# 2. Config
cp .env.example .env      # set OLLAMA_BASE_URL (and any provider keys you want)

# 3. Backend  (KB + search + attack paths + cockpit API on :8000)
cd backend
uv run uvicorn main:app --reload

# 4. Frontend (the companion UI on :3000)
cd frontend
npm install
npm run dev
```

Then open **http://localhost:3000**.

For the cockpit, bring the sandboxes up and verify the safety invariants:

```bash
docker compose -f docker/docker-compose.yml up -d --build
sh backend/run_safety_tests.sh              # 42 suites, hermetic
sh backend/run_safety_tests.sh --with-proof # + live Docker isolation proof
```

> The consolidated knowledge base (`data/`) is built by `pipeline/` from external source trees and is gitignored. Point `HACKPIT_SOURCES_ROOT` at your own sources and run the pipeline, or wire the backend to your own `entries.jsonl`.

---

## Project structure

```
HackPit/
├── frontend/    Next.js UI — search, paths, cockpit, AD graph, detection, reports
├── backend/     FastAPI — KB, search, composition, gated execution, state, reports
│   ├── cockpit/     execution + the four gates + sandboxes + sessions + tunnels
│   ├── detection/   ATT&CK / Sigma footprints and the OPSEC channel
│   ├── state/       hosts · services · creds · findings · task tree
│   ├── arsenal/     the 110-tool catalog and its templates
│   ├── adgraph/     BloodHound ingest → typed graph → routing
│   ├── exploits/    CVE → exploit index
│   ├── codescan/    multi-language SAST rules
│   └── evasion/     generate-only artifact producer
├── pipeline/    ingest → normalize → consolidate → embed  (the KB build engine)
├── docker/      the Kali image, compose postures, isolation proofs
├── docs/        design notes, decision log, capability assessment
├── data/        built KB + embeddings            (gitignored — never committed)
├── sources/     raw external source trees        (gitignored — never committed)
└── assets/      screenshots for this README
```

---

## Project state

Actively built. The KB, search, attack paths, engagements, reports, cockpit, detection layer, AD graph, state model and Windows/WinRM driver are all implemented and covered by the safety suite.

Known limits, stated plainly rather than left to be discovered:

- **The C2 and covert-channel surfaces are verified structurally, not in the field.** Their containment properties are locked by tests; what has not happened is a live beacon calling back, a real delegated DNS zone, or a generated artifact detonated on an instrumented host to confirm the telemetry claims match reality. Efficacy is documented, not demonstrated.
- **The WinRM driver's live-box verification** waits on a Windows VM being stood up.
- **An open gate-integrity finding** is tracked and prioritised: the danger heuristic classifies the first token of a WinRM command, while the transport executes the whole joined script — so the red-confirm can be sidestepped on that path. It is the next thing being fixed.
- Thin KB categories (mobile, IoT, forensics, ICS) are unfilled by choice.

`docs/` carries the full capability assessment and the decision log (D1–D17), including the reasoning for the ones that were reversed.

---

## A note on this project

HackPit is a **personal portfolio project** — built to explore what a genuinely useful, grounded AI companion for offensive security looks like when it is anchored to a real curated knowledge base instead of open-ended generation, and what it takes to let such a thing *act* without handing it autonomy. It reflects choices I care about: local-first so sensitive engagement data stays on your machine, honest provenance so you always know where an answer came from, a hard line between grounded fact and AI suggestion, and a human in the loop on every command that touches a real host.

**License / use.** For authorized security testing and educational use only.

<p align="center">
  <img src="assets/screenshots/01-intro-splash.png" alt="HackPit — offensive security companion" width="70%">
</p>

<p align="center"><sub>Every technique you know, one keystroke away.</sub></p>
