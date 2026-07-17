# HackPit

**AI-powered pentest platform** — a hacking **companion** first, an autonomous
pentest **cockpit** later.

HackPit pairs an LLM with a curated pentest knowledge base to help security
professionals move faster: recall techniques, reason about attack surface, and
(eventually) drive tooling. It ships in phases, companion first.

## Phased plan

- **Phase 1 — Companion (ships first).** An assistant that augments a human
  operator: answers methodology questions, suggests next steps, and surfaces
  relevant techniques from the local knowledge index. Human stays in the loop.
- **Phase 2 — Cockpit (later).** Progressive automation of recon, ranking, and
  validation workflows under operator supervision, moving toward an autonomous
  pentest cockpit.

## Monorepo layout

```
HackPit/
  frontend/   Next.js (App Router, TS, Tailwind, Framer Motion, shadcn/ui)
  backend/    Python FastAPI service (managed with uv)
  pipeline/   Knowledge ingestion / normalization (built later)
  data/       Built knowledge index (gitignored — not committed)
  sources/    Raw knowledge sources / notes (gitignored — never committed)
  docs/       Project documentation
```

## Development

**Frontend**

```bash
cd frontend
npm install
npm run dev        # http://localhost:3000
```

**Backend**

```bash
cd backend
uv run uvicorn main:app --reload    # http://127.0.0.1:8000
# GET /health -> {"status":"ok"}
```

## Knowledge sources

Knowledge sources are **ingested locally** into a private index and are **NOT
redistributed**. Raw sources (`/sources`) and the built index (`/data`) are
gitignored and never committed. This repository ships **code only** — no
third-party content and no raw notes.

## License / use

For authorized security testing and educational use only.
