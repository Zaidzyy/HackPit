"""Relevance-first ranking regression (pipeline/search.py) — the #5 rebalance.

Trust (tier) must not manufacture relevance. These tests lock the two changes:

  1. The tier-1 boost is GATED on substance — a thin tier-1 stub (no commands, little body)
     gets no boost, so it can't ride its tier past a richer, more relevant lower-tier page.
  2. A completeness nudge (command-rich, any tier) lets content decide close calls, so a
     command-rich tier-3 page ties/beats a thin tier-1 one — while a rich tier-1 still leads.

Hermetic: no embeddings, no Ollama, no network — the vector retriever is monkeypatched to
empty, so search() runs its hybrid fusion (weighted RRF + the bonuses) over the lexical list
alone. Run:  python test_search_ranking.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "pipeline"))
import search as S  # noqa: E402  (pipeline/search.py)


def _entry(eid, tier, *, cmds=0, body="", title="Kerberoast"):
    steps = [{"n": 1, "text": "run", "code": [{"lang": "bash", "cmd": f"c{i}"} for i in range(cmds)]}] if cmds else []
    return {
        "id": eid, "title": title, "category": "active-directory", "source": "x",
        "tier": tier, "summary": "", "body_md": body, "steps": steps, "tags": [], "tools": [],
    }


# --------------------------------------------------------------------------- #
# 1. the helpers (pure)
# --------------------------------------------------------------------------- #
def test_substance_gate_and_bonuses() -> None:
    thin_t1 = _entry("thin", 1, cmds=0, body="short")
    rich_t1 = _entry("rt1", 1, cmds=3, body="x" * 100)
    rich_t3 = _entry("rt3", 3, cmds=3)
    prose_t1 = _entry("prose", 1, cmds=0, body="y" * 500)  # substantive by body length

    # tier bonus: only a SUBSTANTIVE tier-1 gets it
    assert S.tier_bonus(thin_t1, S.TIER_BOOST) == 0.0, "a thin tier-1 stub must get NO boost"
    assert S.tier_bonus(rich_t1, S.TIER_BOOST) > 0.0, "a command-rich tier-1 gets the boost"
    assert S.tier_bonus(prose_t1, S.TIER_BOOST) > 0.0, "a long-body tier-1 is substantive too"
    assert S.tier_bonus(rich_t3, S.TIER_BOOST) == 0.0, "tier-3 never gets the tier boost"

    # completeness bonus: command-rich, ANY tier; saturates; none without commands
    assert S.completeness_bonus(thin_t1) == 0.0
    assert S.completeness_bonus(rich_t3) > 0.0, "a command-rich tier-3 earns completeness"
    assert S.completeness_bonus(rich_t3) == S.completeness_bonus(rich_t1), "tier-agnostic"
    assert S.completeness_bonus(_entry("z", 3, cmds=99)) <= S.COMPLETENESS_BONUS, "capped"
    print("  substance gate + completeness/ tier bonuses behave: PASS")


# --------------------------------------------------------------------------- #
# 2. end-to-end ordering through search() (vector mocked empty → hermetic)
# --------------------------------------------------------------------------- #
def test_rich_lowtier_beats_thin_hightier() -> None:
    orig = S.vector_ranking
    S.vector_ranking = lambda *a, **k: []  # no embeddings/ollama
    try:
        entries = [
            _entry("thin_t1", 1, cmds=0, body="kerberoast note"),   # thin, top-trust
            _entry("rich_t3", 3, cmds=3, body="kerberoast steps"),  # rich, low-trust
            _entry("rich_t1", 1, cmds=3, body="kerberoast steps"),  # rich, top-trust
        ]
        order = [h["id"] for h in S.search(entries, "kerberoast", top=3, mode="hybrid")]
        # rich tier-1 leads (relevance + substance + trust), the rich tier-3 beats the thin
        # tier-1 (content over trust), and the thin tier-1 comes last.
        assert order.index("rich_t1") < order.index("rich_t3") < order.index("thin_t1"), order
        print(f"  rich tier-3 outranks a thin tier-1; rich tier-1 leads — order={order}: PASS")
    finally:
        S.vector_ranking = orig


def test_exact_title_still_floats() -> None:
    """The title-exact bonus is untouched — typing an entry's name still floats it."""
    orig = S.vector_ranking
    S.vector_ranking = lambda *a, **k: []
    try:
        entries = [
            _entry("other", 1, cmds=3, title="Kerberoast Cheatsheet", body="kerberoast"),
            _entry("exact", 3, cmds=1, title="Kerberoast", body="kerberoast"),
        ]
        order = [h["id"] for h in S.search(entries, "kerberoast", top=2, mode="hybrid")]
        assert order[0] == "exact", f"exact-title match must float to #1, got {order}"
        print("  exact-title bonus still floats the named entry: PASS")
    finally:
        S.vector_ranking = orig


if __name__ == "__main__":
    test_substance_gate_and_bonuses()
    test_rich_lowtier_beats_thin_hightier()
    test_exact_title_still_floats()
    print("ALL relevance-first ranking tests pass")
