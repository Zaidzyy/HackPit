# pipeline

Knowledge ingestion & normalization for HackPit (data layer only — no UI, no LLM).

Every knowledge source normalizes into one canonical schema (`Entry`), so
downstream search / retrieval / (later) the LLM sees a uniform shape regardless
of where the knowledge came from.

## Layout

| File                | Purpose                                                        |
| ------------------- | ------------------------------------------------------------- |
| `schema.py`         | Canonical `Entry` Pydantic model + JSON Schema emitter.       |
| `entry.schema.json` | Emitted JSON Schema (committed spec artifact).                |
| `ingest.py`         | Ingester for the "some hacking resources" markdown source.    |
| `search.py`         | BM25 full-text search CLI over the normalized KB.             |

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

# search the normalized KB
uv run python search.py "kerberoasting"
uv run python search.py "smb enumeration" --top 3
uv run python search.py "sqlmap" --json
```

## Data flow & privacy

- Reads raw markdown from an **external absolute path** — the source is **never
  copied into the repo**.
- Writes normalized output to `/data/kb/` (JSONL + `index.json` manifest), which
  is **gitignored**. No third-party knowledge content is ever committed.
