"""Simple BM25 search over the normalized knowledge base.

Full-text ranking (Okapi BM25, pure stdlib — no vectors yet) over title, tags,
tools, summary, body, and extracted commands, with light field weighting.

Usage:
    python pipeline/search.py "kerberoasting"
    python pipeline/search.py "smb enumeration" --top 3
    python pipeline/search.py "sqlmap" --json
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KB = REPO_ROOT / "data" / "kb" / "entries.jsonl"

TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return [t for t in TOKEN_RE.findall((text or "").lower()) if len(t) >= 2]


def load_entries(kb_path: Path) -> list[dict]:
    if not kb_path.exists():
        raise SystemExit(
            f"Knowledge base not found: {kb_path}\n"
            "Run `python pipeline/ingest.py` first."
        )
    with kb_path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def doc_tokens(e: dict) -> list[str]:
    """Field-weighted token bag (title x3, tags/tools x2, then the rest)."""
    meta = e.get("meta", {}) or {}
    extra = " ".join(
        str(meta.get(k, "")) for k in ("phase", "os", "type")
    )
    cmds = " ".join(
        c.get("cmd", "")
        for s in e.get("steps", [])
        for c in s.get("code", [])
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


def search(entries: list[dict], query: str, top: int) -> list[dict]:
    bm = BM25([doc_tokens(e) for e in entries])
    q = tokenize(query)
    scored = [(bm.score(q, i), i) for i in range(len(entries))]
    scored = [x for x in scored if x[0] > 0]
    scored.sort(key=lambda x: x[0], reverse=True)
    results = []
    for rank, (score, i) in enumerate(scored[:top], 1):
        e = entries[i]
        results.append(
            {
                "rank": rank,
                "score": round(score, 3),
                "id": e["id"],
                "title": e["title"],
                "category": e["category"],
                "source": e["source"],
                "snippet": make_snippet(e, q),
            }
        )
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="BM25 search over the HackPit KB.")
    ap.add_argument("query", nargs="+", help="search terms")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--kb", default=str(DEFAULT_KB))
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    entries = load_entries(Path(args.kb))
    query = " ".join(args.query)
    results = search(entries, query, args.top)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    print(f'\nSearch: "{query}"  —  {len(results)} result(s)\n')
    if not results:
        print("  (no matches)")
    for r in results:
        print(f"{r['rank']}. [{r['category']}] {r['title']}  "
              f"({r['source']})  score={r['score']}")
        print(f"   id: {r['id']}")
        print(f"   {r['snippet']}\n")


if __name__ == "__main__":
    main()
