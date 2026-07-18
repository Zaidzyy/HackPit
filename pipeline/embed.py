"""Local, free vector embeddings for the HackPit knowledge base.

Builds one embedding per KB entry with Ollama's `nomic-embed-text` (already
pulled) — no cloud, no paid API. The embeddings power the semantic half of the
hybrid search in `search.py`.

Per entry we embed a COMPOSITE document:
    title + summary + tags + tools + every step.text + body_md
`body_md` already carries the folded screenshot OCR, and step.text is included
here on purpose (it is NOT in the lexical search fields), so image/step
knowledge becomes reachable semantically.

nomic-embed-text requires task prefixes:
    documents -> "search_document: <text>"
    queries   -> "search_query: <text>"
Both are implemented (`embed_query` is imported by search.py).

Outputs (both under data/kb/, gitignored — never committed):
    embeddings.npy   float32 matrix [N, dim], row order == ids.json "ids"
    ids.json         model/dim/prefix + parallel id list + per-id content hash

Caching: an entry is re-embedded only when its composite content hash changes
(or the model changes). Unchanged entries reuse their stored vector.

Usage:
    uv run python embed.py                # build / update (uses cache)
    uv run python embed.py --force        # re-embed everything
    uv run python embed.py --host http://localhost:11434 --model nomic-embed-text
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KB = REPO_ROOT / "data" / "kb" / "entries.jsonl"
EMB_PATH = REPO_ROOT / "data" / "kb" / "embeddings.npy"
IDS_PATH = REPO_ROOT / "data" / "kb" / "ids.json"

OLLAMA_HOST = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"
DOC_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "

# nomic-embed-text runs with a 2048-token context in Ollama by default. Cap the
# composite document so it always fits (dense command/OCR text tokenizes to
# roughly 3 chars/token, so ~6000 chars stays safely under the window). The head
# — title, summary, tags, tools, step text, and the start of body_md — is the
# most representative part for retrieval; only the tail of very long notes is
# dropped.
MAX_DOC_CHARS = 6000


# --------------------------------------------------------------------------- #
# composite document + content hash
# --------------------------------------------------------------------------- #
def composite_doc(e: dict) -> str:
    """Build the text embedded for one entry. Includes step.text (which the
    lexical index does NOT cover) so image/step knowledge is semantically
    reachable, plus body_md which already contains folded OCR."""
    parts: list[str] = [e.get("title", ""), e.get("summary", "")]
    parts.append(" ".join(e.get("tags", []) or []))
    parts.append(" ".join(e.get("tools", []) or []))
    parts += [s.get("text", "") for s in e.get("steps", []) or []]
    parts.append(e.get("body_md", ""))
    doc = "\n".join(p for p in parts if p and p.strip()).strip()
    return doc[:MAX_DOC_CHARS]


def content_hash(doc: str, model: str) -> str:
    h = hashlib.sha256()
    h.update(model.encode("utf-8"))
    h.update(b"\x00")
    h.update(doc.encode("utf-8"))
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Ollama embeddings (graceful when the server is down)
# --------------------------------------------------------------------------- #
class OllamaUnavailable(RuntimeError):
    """Ollama could not be reached / the model isn't usable."""


def _embed(text: str, host: str, model: str) -> list[float]:
    # nomic-embed-text supports an 8192-token window; request it explicitly so
    # Ollama's default 2048 doesn't reject token-dense docs (command/OCR text).
    payload = {"model": model, "prompt": text, "options": {"num_ctx": 8192}}
    req = urllib.request.Request(
        f"{host}/api/embeddings",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:200]
        raise OllamaUnavailable(
            f"Ollama HTTP {e.code} for model '{model}': {body}\n"
            f"Is the model pulled?  ollama pull {model}"
        ) from e
    except (urllib.error.URLError, ConnectionError, OSError) as e:
        raise OllamaUnavailable(
            f"Cannot reach Ollama at {host} ({e}). "
            "Start it with `ollama serve` and ensure the model is pulled."
        ) from e
    emb = data.get("embedding")
    if not emb:
        raise OllamaUnavailable(
            f"Ollama returned no embedding for model '{model}': {str(data)[:200]}"
        )
    return emb


def embed_document(text: str, host: str = OLLAMA_HOST,
                   model: str = EMBED_MODEL) -> list[float]:
    """Embed a document. Token-dense docs (paths/hex/symbols) can exceed the
    model's context even under MAX_DOC_CHARS; shrink and retry until it fits so
    one dense entry never aborts the whole build."""
    budget = len(text)
    while True:
        try:
            return _embed(DOC_PREFIX + text[:budget], host, model)
        except OllamaUnavailable as e:
            if "context length" in str(e).lower() and budget > 512:
                budget = int(budget * 0.75)
                continue
            raise


def embed_query(text: str, host: str = OLLAMA_HOST,
                model: str = EMBED_MODEL) -> list[float]:
    """Embed a search query (nomic 'search_query:' task prefix)."""
    return _embed(QUERY_PREFIX + text, host, model)


# --------------------------------------------------------------------------- #
# load / save the vector index
# --------------------------------------------------------------------------- #
def load_index(emb_path: Path = EMB_PATH, ids_path: Path = IDS_PATH):
    """Return (ids: list[str], vectors: np.ndarray[N,dim], meta: dict) or
    (None, None, {}) if the index has not been built yet."""
    if not emb_path.exists() or not ids_path.exists():
        return None, None, {}
    meta = json.loads(ids_path.read_text(encoding="utf-8"))
    vectors = np.load(emb_path)
    return meta.get("ids", []), vectors, meta


def load_entries(kb_path: Path) -> list[dict]:
    if not kb_path.exists():
        raise SystemExit(
            f"Knowledge base not found: {kb_path}\nRun the ingesters first."
        )
    with kb_path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def build(kb_path: Path, emb_path: Path, ids_path: Path,
          host: str, model: str, force: bool) -> dict:
    entries = load_entries(kb_path)

    # reuse cache: id -> (vector, hash) from a prior build with the same model
    old_ids, old_vecs, old_meta = load_index(emb_path, ids_path)
    reusable: dict[str, np.ndarray] = {}
    old_hashes: dict[str, str] = {}
    if (not force and old_ids is not None and old_vecs is not None
            and old_meta.get("model") == model):
        old_hashes = old_meta.get("hashes", {})
        for i, _id in enumerate(old_ids):
            if i < len(old_vecs):
                reusable[_id] = old_vecs[i]

    t0 = dt.datetime.now()
    vectors: list[np.ndarray] = []
    ids: list[str] = []
    hashes: dict[str, str] = {}
    embedded = reused = 0

    for n, e in enumerate(entries, 1):
        eid = e["id"]
        doc = composite_doc(e)
        h = content_hash(doc, model)
        hashes[eid] = h
        cached = reusable.get(eid)
        if cached is not None and old_hashes.get(eid) == h:
            vec = np.asarray(cached, dtype=np.float32)
            reused += 1
        else:
            vec = np.asarray(embed_document(doc, host, model), dtype=np.float32)
            embedded += 1
            if embedded % 25 == 0:
                print(f"  embedded {embedded} (reused {reused}) / {len(entries)}…")
        vectors.append(vec)
        ids.append(eid)

    arr = np.vstack(vectors).astype(np.float32)
    dim = int(arr.shape[1])
    elapsed = (dt.datetime.now() - t0).total_seconds()

    emb_path.parent.mkdir(parents=True, exist_ok=True)
    np.save(emb_path, arr)
    meta = {
        "model": model,
        "dim": dim,
        "count": len(ids),
        "doc_prefix": DOC_PREFIX,
        "query_prefix": QUERY_PREFIX,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "embedded": embedded,
        "reused": reused,
        "elapsed_sec": round(elapsed, 2),
        "ids": ids,
        "hashes": hashes,
    }
    ids_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    return {"count": len(ids), "dim": dim, "embedded": embedded,
            "reused": reused, "elapsed_sec": round(elapsed, 2),
            "emb_path": emb_path, "ids_path": ids_path}


def main() -> None:
    ap = argparse.ArgumentParser(description="Embed the HackPit KB (local nomic).")
    ap.add_argument("--kb", default=str(DEFAULT_KB))
    ap.add_argument("--emb", default=str(EMB_PATH))
    ap.add_argument("--ids", default=str(IDS_PATH))
    ap.add_argument("--host", default=OLLAMA_HOST)
    ap.add_argument("--model", default=EMBED_MODEL)
    ap.add_argument("--force", action="store_true", help="re-embed everything")
    args = ap.parse_args()

    try:
        stats = build(Path(args.kb), Path(args.emb), Path(args.ids),
                      args.host, args.model, args.force)
    except OllamaUnavailable as e:
        raise SystemExit(f"ERROR: {e}")

    print(f"\nEmbedded KB: {stats['count']} entries, dim={stats['dim']} "
          f"({stats['embedded']} new, {stats['reused']} cached) in "
          f"{stats['elapsed_sec']}s")
    print(f"  -> {stats['emb_path']}")
    print(f"  -> {stats['ids_path']}")


if __name__ == "__main__":
    main()
