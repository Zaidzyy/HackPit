"""Hybrid search over the normalized HackPit knowledge base.

Two retrievers, fused:

  * Lexical  — Okapi BM25 (pure stdlib) over title, tags, tools, summary,
    body_md (which carries folded screenshot OCR), and extracted commands.
  * Semantic — cosine similarity over local `nomic-embed-text` vectors
    (see embed.py). Reaches step.text / paraphrases the lexical index misses.

Fusion is Reciprocal Rank Fusion (RRF), then a small tier boost lifts tier-1
(the author's own notes) so they compete fairly with terse tier-2 entries
without dominating — this is where `tier` is finally wired into ranking.

Entries on the committed exclude list are filtered out defensively (they are
already dropped at ingest time, but never trust that at query time).

Usage:
    python pipeline/search.py "kerberoasting"
    python pipeline/search.py "crack service account tickets offline" --top 5
    python pipeline/search.py "sqlmap" --mode lexical   # {hybrid,lexical,vector}
    python pipeline/search.py "asrep roasting" --json
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# The KB can contain unicode (e.g. Notion notes use → and — arrows); keep the
# CLI from dying on a legacy console codepage (Windows cp1252).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KB = REPO_ROOT / "data" / "kb" / "entries.jsonl"
EXCLUDE_PATH = Path(__file__).with_name("exclude.json")

TOKEN_RE = re.compile(r"[a-z0-9]+")

RRF_K = 60          # RRF damping constant (standard default)
# Weighted RRF: lexical is favored slightly over semantic. A hacking KB is full
# of exact identifiers (hostnames, IPs, error strings, flags) that embeddings
# treat as noise; down-weighting the vector list keeps those exact matches from
# being buried by topically-similar neighbours, while still gaining semantic
# recall for paraphrased / typo queries.
LEX_WEIGHT = 1.0
VEC_WEIGHT = 0.5
# Additive nudge for tier-1 (the author's notes). Tuned so notes rise into the
# top few for topical queries (they were #4–6) without sweeping #1 — the curated
# tier-2 entries still lead on exact-keyword queries.
TIER_BOOST = 0.004
BASELINE_TIER = 2   # tiers below this (i.e. tier 1) get the boost; >=2 get none.

# Small additive bonus when the *whole* query is the literal name of an entry.
# Typing a technique's exact title (or a leading-word prefix of it), an exact
# tag, or the entry id should float that canonical entry to the top. This is
# gated on a whole-query match, so natural-language queries — which never equal
# a title — are completely unaffected and the semantic/tier ranking stands.
TITLE_EXACT_BONUS = 0.03
TITLE_PREFIX_BONUS = 0.015
TAG_ID_BONUS = 0.012
MIN_PREFIX_LEN = 4  # don't prefix-boost on 1–3 char fragments


def tokenize(text: str) -> list[str]:
    return [t for t in TOKEN_RE.findall((text or "").lower()) if len(t) >= 2]


def load_entries(kb_path: Path) -> list[dict]:
    if not kb_path.exists():
        raise SystemExit(
            f"Knowledge base not found: {kb_path}\n"
            "Run `python pipeline/ingest.py` / `ingest_notes.py` first."
        )
    with kb_path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


# --------------------------------------------------------------------------- #
# exclusion safety filter (defense-in-depth; excluded pages are already dropped)
# --------------------------------------------------------------------------- #
def load_exclude(path: Path = EXCLUDE_PATH) -> tuple[set, set]:
    if not path.exists():
        return set(), set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set(), set()
    items = data.get("exclude", data) if isinstance(data, dict) else data
    ids = {x["id"] for x in items if isinstance(x, dict) and x.get("id")}
    files = {x["file"] for x in items if isinstance(x, dict) and x.get("file")}
    return ids, files


def filter_excluded(entries: list[dict]) -> list[dict]:
    ids, files = load_exclude()
    if not ids and not files:
        return entries
    return [
        e for e in entries
        if e.get("id") not in ids
        and (e.get("meta", {}) or {}).get("src_file") not in files
    ]


# --------------------------------------------------------------------------- #
# lexical retriever (BM25)
# --------------------------------------------------------------------------- #
def doc_tokens(e: dict) -> list[str]:
    """Field-weighted token bag (title x3, tags/tools x2, then the rest)."""
    meta = e.get("meta", {}) or {}
    extra = " ".join(str(meta.get(k, "")) for k in ("phase", "os", "type"))
    cmds = " ".join(
        c.get("cmd", "") for s in e.get("steps", []) for c in s.get("code", [])
    )
    return (
        tokenize(e.get("title", "")) * 3
        + tokenize(" ".join(e.get("tags", []))) * 2
        + tokenize(" ".join(e.get("tools", []))) * 2
        + tokenize(extra)
        + tokenize(e.get("summary", ""))
        + tokenize(e.get("body_md", ""))
        + tokenize(cmds)
    )


class BM25:
    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.N = len(docs)
        self.k1, self.b = k1, b
        self.tf = [Counter(d) for d in docs]
        self.dl = [len(d) for d in docs]
        self.avgdl = (sum(self.dl) / self.N) if self.N else 0.0
        df: Counter = Counter()
        for c in self.tf:
            df.update(c.keys())
        self.idf = {
            t: math.log(1 + (self.N - n + 0.5) / (n + 0.5)) for t, n in df.items()
        }

    def score(self, q: list[str], i: int) -> float:
        tf, dl = self.tf[i], self.dl[i]
        s = 0.0
        for t in q:
            f = tf.get(t)
            if not f:
                continue
            denom = f + self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1))
            s += self.idf.get(t, 0.0) * (f * (self.k1 + 1)) / denom
        return s


def lexical_ranking(entries: list[dict], query: str) -> list[tuple[float, int]]:
    """Return [(bm25_score, entry_idx)] with score>0, ranked desc."""
    bm = BM25([doc_tokens(e) for e in entries])
    q = tokenize(query)
    scored = [(bm.score(q, i), i) for i in range(len(entries))]
    scored = [x for x in scored if x[0] > 0]
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored


# --------------------------------------------------------------------------- #
# semantic retriever (vector cosine)
# --------------------------------------------------------------------------- #
def vector_ranking(entries: list[dict], query: str,
                   host: str, model: str) -> list[tuple[float, int]]:
    """Return [(cosine, entry_idx)] ranked desc, using stored embeddings."""
    import numpy as np  # local import so lexical mode needs no numpy/ollama
    import embed

    ids, vectors, meta = embed.load_index()
    if ids is None or vectors is None:
        raise SystemExit(
            "No embeddings found. Build them first:  uv run python embed.py"
        )
    id_to_idx = {e["id"]: i for i, e in enumerate(entries)}

    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    unit = vectors / np.clip(norms, 1e-9, None)
    try:
        qv = np.asarray(embed.embed_query(query, host, model), dtype=np.float32)
    except embed.OllamaUnavailable as e:
        raise SystemExit(f"ERROR embedding query: {e}")
    qv = qv / max(float(np.linalg.norm(qv)), 1e-9)

    sims = unit @ qv
    out: list[tuple[float, int]] = []
    for row, _id in enumerate(ids):
        ei = id_to_idx.get(_id)
        if ei is not None:
            out.append((float(sims[row]), ei))
    out.sort(key=lambda x: x[0], reverse=True)
    return out


# --------------------------------------------------------------------------- #
# fusion
# --------------------------------------------------------------------------- #
def rrf(rankings: list[list[tuple[float, int]]],
        weights: list[float] | None = None, k: int = RRF_K) -> dict[int, float]:
    """(Weighted) Reciprocal Rank Fusion over ranked [(score, idx)] lists."""
    weights = weights or [1.0] * len(rankings)
    fused: dict[int, float] = defaultdict(float)
    for ranking, w in zip(rankings, weights):
        for rank, (_score, idx) in enumerate(ranking, 1):
            fused[idx] += w / (k + rank)
    return fused


def tier_bonus(entry: dict, boost: float) -> float:
    tier = int(entry.get("tier", BASELINE_TIER))
    return boost * max(0, BASELINE_TIER - tier)  # tier1 -> +boost; tier>=2 -> 0


def _norm(s: str) -> str:
    return " ".join((s or "").lower().split())


def title_bonus(entry: dict, q_norm: str) -> float:
    """Reward entries whose *name* the query literally is (exact > prefix > tag/id).

    Only fires on a whole-query match, so it lifts `ad-kerberoasting` for the
    query "kerberoasting" without touching natural-language queries.
    """
    if not q_norm:
        return 0.0
    title = _norm(entry.get("title", ""))
    if q_norm == title:
        return TITLE_EXACT_BONUS
    if len(q_norm) >= MIN_PREFIX_LEN and title.startswith(q_norm + " "):
        return TITLE_PREFIX_BONUS
    if q_norm == _norm(entry.get("id", "")):
        return TAG_ID_BONUS
    if any(q_norm == _norm(t) for t in entry.get("tags", [])):
        return TAG_ID_BONUS
    return 0.0


# --------------------------------------------------------------------------- #
# top-level search
# --------------------------------------------------------------------------- #
def make_snippet(e: dict, q: list[str], width: int = 160) -> str:
    hay = e.get("body_md") or e.get("summary") or ""
    low = hay.lower()
    pos = -1
    for t in q:
        p = low.find(t)
        if p != -1 and (pos == -1 or p < pos):
            pos = p
    if pos == -1:
        frag = (e.get("summary") or hay)[:width]
    else:
        start, end = max(0, pos - 60), min(len(hay), pos + 100)
        frag = ("…" if start else "") + hay[start:end] + ("…" if end < len(hay) else "")
    frag = " ".join(frag.split())
    for t in sorted(set(q), key=len, reverse=True):
        frag = re.sub(rf"(?i)({re.escape(t)})", r"**\1**", frag)
    return frag


def search(entries: list[dict], query: str, top: int, mode: str = "hybrid",
           host: str = "http://localhost:11434", model: str = "nomic-embed-text",
           tier_boost: float = TIER_BOOST) -> list[dict]:
    entries = filter_excluded(entries)
    q_tokens = tokenize(query)
    q_norm = _norm(query)

    lex = lexical_ranking(entries, query) if mode in ("hybrid", "lexical") else []
    vec = vector_ranking(entries, query, host, model) if mode in ("hybrid", "vector") else []

    lex_rank = {idx: r for r, (_, idx) in enumerate(lex, 1)}
    vec_rank = {idx: r for r, (_, idx) in enumerate(vec, 1)}
    lex_score = {idx: s for s, idx in lex}
    vec_score = {idx: s for s, idx in vec}

    if mode == "lexical":
        order = [(s, idx) for s, idx in lex]
    elif mode == "vector":
        order = [(s, idx) for s, idx in vec]
    else:  # hybrid: weighted RRF + tier boost
        fused = rrf([lex, vec], [LEX_WEIGHT, VEC_WEIGHT])
        for idx in fused:
            fused[idx] += tier_bonus(entries[idx], tier_boost)
            fused[idx] += title_bonus(entries[idx], q_norm)
        order = sorted(((s, idx) for idx, s in fused.items()),
                       key=lambda x: x[0], reverse=True)

    results = []
    for rank, (score, i) in enumerate(order[:top], 1):
        e = entries[i]
        results.append({
            "rank": rank,
            "score": round(float(score), 5),
            "id": e["id"],
            "title": e["title"],
            "category": e["category"],
            "source": e["source"],
            "tier": e.get("tier"),
            "lex_rank": lex_rank.get(i),
            "vec_rank": vec_rank.get(i),
            "bm25": round(lex_score[i], 3) if i in lex_score else None,
            "cosine": round(vec_score[i], 3) if i in vec_score else None,
            "snippet": make_snippet(e, q_tokens),
        })
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="Hybrid search over the HackPit KB.")
    ap.add_argument("query", nargs="+", help="search terms")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--mode", choices=("hybrid", "lexical", "vector"),
                    default="hybrid")
    ap.add_argument("--kb", default=str(DEFAULT_KB))
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--model", default="nomic-embed-text")
    ap.add_argument("--tier-boost", type=float, default=TIER_BOOST)
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    entries = load_entries(Path(args.kb))
    query = " ".join(args.query)
    results = search(entries, query, args.top, mode=args.mode,
                     host=args.host, model=args.model, tier_boost=args.tier_boost)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    print(f'\nSearch [{args.mode}]: "{query}"  —  {len(results)} result(s)\n')
    if not results:
        print("  (no matches)")
    for r in results:
        prov = f"lex#{r['lex_rank']} vec#{r['vec_rank']}"
        print(f"{r['rank']}. [{r['category']}] {r['title']}  "
              f"({r['source']}, tier {r['tier']})  score={r['score']}  [{prov}]")
        print(f"   id: {r['id']}")
        print(f"   {r['snippet']}\n")


if __name__ == "__main__":
    main()
