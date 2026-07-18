# pipeline

Knowledge ingestion & normalization for HackPit (data layer only — no UI, no LLM).

Every knowledge source normalizes into one canonical schema (`Entry`), so
downstream search / retrieval / (later) the LLM sees a uniform shape regardless
of where the knowledge came from.

## Layout

| File                  | Purpose                                                      |
| --------------------- | ----------------------------------------------------------- |
| `schema.py`           | Canonical `Entry` Pydantic model + JSON Schema emitter.     |
| `entry.schema.json`   | Emitted JSON Schema (committed spec artifact).              |
| `ingest.py`           | Ingester for the "some hacking resources" markdown source.  |
| `ingest_notes.py`     | Ingester for the personal PEH course notes (tier-1).        |
| `images.py`           | Image text/caption extraction (OCR + local vision model).   |
| `manual_captions.json`| Hand-authored caption overrides (committed).                |
| `exclude.json`        | Explicit, reversible KB exclusion list (committed).         |
| `embed.py`            | Local vector embeddings (Ollama `nomic-embed-text`).        |
| `search.py`           | Hybrid (BM25 + vector, RRF-fused) search CLI.               |

## Schema (`Entry`)

`id`, `title`, `category`, `subcategory?`, `source`, `tier` (trust, default 2),
`tags[]`, `tools[]`, `summary`, `steps[]` (`{n, text, code[]{lang,cmd,copyable}, images[]}`),
`body_md`, `references[]` (urls), plus `meta{}` — an extension point that
preserves source-specific metadata (os, phase, type, related links, ports, …)
so future sources (HackTricks, notes with images) lose nothing.

## Usage

Dependencies are managed with **uv**.

```bash
cd pipeline
uv sync

# (re)emit the JSON Schema
uv run python schema.py

# ingest the external source -> data/kb/entries.jsonl + data/kb/index.json
uv run python ingest.py
uv run python ingest.py --source-path "C:\path\to\source" --out ../data/kb

# build local vector embeddings (needs Ollama running + nomic-embed-text pulled)
uv run python embed.py            # hash-cached; re-embeds only changed entries

# search the normalized KB (hybrid by default)
uv run python search.py "kerberoasting"
uv run python search.py "crack service account tickets offline"   # semantic
uv run python search.py "sqlmap" --mode lexical   # {hybrid,lexical,vector}
uv run python search.py "asrep roasting" --top 3 --json
```

## Hybrid search (`search.py` + `embed.py`)

Two retrievers are fused:

- **Lexical** — Okapi BM25 over title/tags/tools/summary/`body_md` (which carries
  folded screenshot OCR) and extracted commands.
- **Semantic** — cosine over local `nomic-embed-text` vectors. `embed.py` embeds
  a composite doc per entry (title + summary + tags + tools + every `step.text`
  + `body_md`) with nomic's required `search_document:` / `search_query:` task
  prefixes, and stores `data/kb/embeddings.npy` + `ids.json` (gitignored,
  hash-cached). Everything is local and free — no cloud, no paid API.

Rankings are combined with **weighted Reciprocal Rank Fusion** (lexical favored
slightly, so exact identifiers aren't buried by semantic neighbours), then a
small **tier boost** lifts tier-1 (the author's notes) so they compete fairly
without dominating. Excluded entries are filtered defensively. `--mode` selects
`hybrid` (default), `lexical`, or `vector` for comparison.

## Image extraction (`images.py`)

Course notes (a Notion markdown export) carry knowledge *inside* screenshots
(terminal output, Burp requests, commands). `images.py` turns those into
searchable text so the notes ingester can attach it.

Per image: **tesseract OCR** → classify `terminal` (dense text) vs `gui`
(sparse) → for GUI/low-text images, a **local Ollama vision model** caption
(free, offline). Output is cached to `data/images/captions.json` (gitignored);
re-runs skip processed images and one bad image never aborts the run.

Prereqs: `tesseract` on PATH (with `eng` traineddata) and Ollama running with a
vision model. `llama3.2-vision` is preferred but needs an Ollama build that
supports the `mllama` architecture; otherwise `llava` is used automatically
(the module warms up each model and skips any that won't load).

```bash
uv run python images.py                 # process all (uses cache)
uv run python images.py --force         # reprocess everything
uv run python images.py --limit 5       # smoke test
uv run python images.py --model llava   # force a specific vision model
uv run python images.py --no-vision     # OCR only
```

## Data flow & privacy

- Reads raw markdown / images from **external absolute paths** — sources are
  **never copied into the repo**.
- Writes normalized output to `/data/` (`kb/` JSONL + manifest, `images/`
  captions), which is **gitignored**. No third-party content is ever committed.
