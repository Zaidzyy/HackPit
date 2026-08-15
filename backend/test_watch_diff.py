"""Invariants for CONTINUOUS HUNTING (watch.py) — snapshot / diff / new-asset alert.

  1. The FIRST check is a silent baseline — alerting on "everything is new the first time" would be
     noise, not signal.
  2. A newly-appeared asset (a subdomain/host/endpoint/finding) shows up in the diff AND is recorded
     as an alert.
  3. No change → no new alert.
  4. It is READ-ONLY over state — it snapshots what recon/scan already ingested and fires nothing.

Hermetic (state.store.load is stubbed; a temp DB holds the snapshots). Run:  python test_watch_diff.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import watch  # noqa: E402
from state import store  # noqa: E402


def _summary(hosts=(), endpoints=(), findings=()) -> SimpleNamespace:
    return SimpleNamespace(
        hosts=[SimpleNamespace(address=h) for h in hosts],
        services=[],
        endpoints=[SimpleNamespace(url=u) for u in endpoints],
        credentials=[],
        findings=[SimpleNamespace(title=t, target="acme.com") for t in findings],
    )


def test_snapshot_diff_and_alert_lifecycle() -> None:
    orig_load, orig_db = store.load, watch.DB_PATH
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        watch.DB_PATH = str(Path(td) / "sessions.db")
        try:
            watch.init_db()

            # 1. first check — baseline, no alert even though there are assets
            store.load = lambda sid: _summary(hosts=["a.acme.com"], endpoints=["https://a/x"])
            first = watch.check("E1", "s1")
            assert first["first"] is True and first["new"] == {}, first
            assert watch.alerts("E1") == [], "the baseline check raised an alert"

            # 2. a new subdomain + endpoint appear -> diff + alert
            store.load = lambda sid: _summary(
                hosts=["a.acme.com", "new.acme.com"],
                endpoints=["https://a/x", "https://new/y"],
                findings=["IDOR on /orders"],
            )
            second = watch.check("E1", "s1")
            assert second["first"] is False
            assert second["new"].get("hosts") == ["new.acme.com"], second["new"]
            assert second["new"].get("endpoints") == ["https://new/y"], second["new"]
            assert "IDOR on /orders|acme.com" in second["new"].get("findings", []), second["new"]
            al = watch.alerts("E1")
            assert len(al) == 1 and "hosts" in al[0]["new_assets"], al

            # 3. no change -> no new alert
            third = watch.check("E1", "s1")
            assert third["new"] == {}, third
            assert len(watch.alerts("E1")) == 1, "an unchanged snapshot raised a spurious alert"

            # 4. another new host -> a second alert, newest first
            store.load = lambda sid: _summary(
                hosts=["a.acme.com", "new.acme.com", "newer.acme.com"],
                endpoints=["https://a/x", "https://new/y"],
                findings=["IDOR on /orders"],
            )
            watch.check("E1", "s1")
            al2 = watch.alerts("E1")
            assert len(al2) == 2 and al2[0]["new_assets"]["hosts"] == ["newer.acme.com"], al2
        finally:
            store.load, watch.DB_PATH = orig_load, orig_db
    print("  first check is a silent baseline; a new asset diffs + alerts; no change is silent: PASS")


def test_watch_is_read_only_over_state() -> None:
    # watch imports state.store and reads .load; it must not import an execution/delivery surface.
    import ast
    import inspect

    src = inspect.getsource(watch)
    tree = ast.parse(src)
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
        elif isinstance(node, ast.Import):
            imported.extend(a.name for a in node.names)
    forbidden = [m for m in imported if any(x in m for x in ("executor", "sliver", "intruder",
                                                             "credattack", "smuggle", "cache"))]
    assert not forbidden, f"watch reached an execution surface: {forbidden}"
    print("  watch imports only read/state paths — no execution surface: PASS")


if __name__ == "__main__":
    test_snapshot_diff_and_alert_lifecycle()
    test_watch_is_read_only_over_state()
    print("ALL continuous-hunting (watch) invariants hold")
