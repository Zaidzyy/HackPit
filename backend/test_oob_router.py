"""OOB router — the dual-backend surface (spec 2026-08-06 §4.6).

Calls the route functions directly (no TestClient, so the Docker-touching lifespan never runs),
with every OOB store pointed at a temp database and the interact.sh HTTP seam stubbed. Proves
the panel state carries both backends, register works, mint renders per configured backend, and
the auto-poll toggle round-trips with a floored interval.

Run: python test_oob_router.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from oob import config as oob_config  # noqa: E402
from oob import interactsh as ish  # noqa: E402
from oob import router as R  # noqa: E402
from oob import settings as st  # noqa: E402
from oob import tokens as tokens_mod  # noqa: E402


def _fresh(dirpath: str) -> None:
    """Point every OOB store at one temp DB and create the tables."""
    db = Path(dirpath) / "oob.db"
    oob_config.DB_PATH = db
    tokens_mod.DB_PATH = db
    ish.DB_PATH = db
    st.DB_PATH = db
    oob_config.init_db()
    tokens_mod.init_db()
    ish.init_db()
    st.init_db()


def test_get_oob_carries_both_backends_and_autopoll() -> None:
    d = tempfile.mkdtemp()
    saved = (oob_config.DB_PATH, tokens_mod.DB_PATH, ish.DB_PATH, st.DB_PATH, ish._http_post)
    try:
        _fresh(d)
        ish._http_post = lambda path, body: {"message": "ok"}
        state = R.get_oob()
        assert state["interactsh"] is None  # not registered yet
        assert "autopoll" in state and state["autopoll"]["enabled"] is True
        assert state["interactsh_default_server"] == ish.DEFAULT_SERVER
        # register, then it appears
        pub = R.post_interactsh_register(R.InteractshRegisterRequest(server="oast.fun"))
        assert pub["has_secret"] is True
        state = R.get_oob()
        assert state["interactsh"]["server"] == "oast.fun"
        assert "secret" not in repr(state["interactsh"]).lower() or "has_secret" in state["interactsh"]
    finally:
        (oob_config.DB_PATH, tokens_mod.DB_PATH, ish.DB_PATH, st.DB_PATH, ish._http_post) = saved
        shutil.rmtree(d, ignore_errors=True)
    print("  GET /oob carries both backends + autopoll: OK")


def test_mint_renders_only_configured_backends() -> None:
    d = tempfile.mkdtemp()
    saved = (oob_config.DB_PATH, tokens_mod.DB_PATH, ish.DB_PATH, st.DB_PATH, ish._http_post)
    try:
        _fresh(d)
        ish._http_post = lambda path, body: {"message": "ok"}
        # only interact.sh configured
        R.post_interactsh_register(R.InteractshRegisterRequest(server="oast.fun"))
        out = R.post_mint(R.MintRequest(engagement_id="eng-1", note="blind ssrf"))
        assert out["backends"]["self_hosted"] is None
        assert out["backends"]["interactsh"] is not None
        assert out["backends"]["interactsh"]["host"].endswith(".oast.fun")
        assert out["backends"]["interactsh"]["payloads"]
    finally:
        (oob_config.DB_PATH, tokens_mod.DB_PATH, ish.DB_PATH, st.DB_PATH, ish._http_post) = saved
        shutil.rmtree(d, ignore_errors=True)
    print("  mint renders only configured backends: OK")


def test_mint_with_no_backend_is_refused() -> None:
    from fastapi import HTTPException

    d = tempfile.mkdtemp()
    saved = (oob_config.DB_PATH, tokens_mod.DB_PATH, ish.DB_PATH, st.DB_PATH)
    try:
        _fresh(d)
        try:
            R.post_mint(R.MintRequest(engagement_id="eng-1"))
        except HTTPException as exc:
            assert exc.status_code == 400
        else:
            raise AssertionError("expected a 400 when no backend is configured")
    finally:
        (oob_config.DB_PATH, tokens_mod.DB_PATH, ish.DB_PATH, st.DB_PATH) = saved
        shutil.rmtree(d, ignore_errors=True)
    print("  mint with no backend is refused: OK")


def test_autopoll_toggle_round_trips_with_floor() -> None:
    d = tempfile.mkdtemp()
    saved = (st.DB_PATH,)
    try:
        st.DB_PATH = Path(d) / "oob.db"
        st.init_db()
        out = R.post_autopoll(R.AutopollRequest(enabled=False, interval=5))
        assert out["autopoll"]["enabled"] is False
        assert out["autopoll"]["interval"] == 30  # floored
    finally:
        (st.DB_PATH,) = saved
        shutil.rmtree(d, ignore_errors=True)
    print("  autopoll toggle round-trips with floor: OK")


if __name__ == "__main__":
    print("== OOB router dual-backend surface (spec 2026-08-06 §4.6) ==")
    test_get_oob_carries_both_backends_and_autopoll()
    test_mint_renders_only_configured_backends()
    test_mint_with_no_backend_is_refused()
    test_autopoll_toggle_round_trips_with_floor()
    print("ALL OOB router tests pass")
