"""ZAP alert ingest — the ROUTE, end to end into a real store.  Run:  python test_zap_scan_ingest.py

WHAT THIS COVERS THAT test_zap_scan.py DOES NOT. That file tests the mapping functions:
alerts -> Finding/Endpoint. This drives `POST /cockpit/proxy/alerts/ingest` through FastAPI and
asserts the rows are READABLE BACK OUT of SQLite afterwards. The gap it closes is *wiring*, not a
control — the exact shape of build #13 part 1's four `/cockpit/exposure` endpoints that shipped
with no caller, and of part 1's "not run: a scan through the approve-and-run path".

TWO DELIBERATE CHOICES ABOUT THE FIXTURE AND THE DATABASE:

* ``store.DB_PATH`` is pointed at a TEMPORARY file. The house style elsewhere (test_state.py)
  writes to the real ``sessions.db`` under a throwaway session id and clears it, which is fine
  for that file but not for one whose whole subject is "did the write land?" — a test that
  cannot distinguish its own rows from the operator's has to trust a delete to be correct.
  Nothing here touches the operator's data at all.

* ``proxy._api_get`` is patched to return the REAL captured response, not ``scan_alerts`` to
  return ready-made models. Patching one layer lower means this exercises ZAP's actual JSON
  through ``scan_alerts``'s own parsing, the route, the mapper AND the store — everything except
  the ``docker exec`` hop, which the proof covers live.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from state import store  # noqa: E402

# *** BEFORE ANYTHING OPENS A CONNECTION. *** `_connect()` reads this module global on every
# call, so redirecting it here is enough — but only if it happens before the first write.
_TMP = Path(tempfile.mkdtemp(prefix="hackpit-zap-ingest-")) / "sessions.db"
store.DB_PATH = _TMP
store.init_db()

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from cockpit import proxy  # noqa: E402

FIXTURE = Path(__file__).with_name("test_support") / "zap_api_alerts_fixture.json"
SESSION = "s-ingest-test"
BODY = {"session_id": SESSION, "container": "hackpit-kali-sandbox", "port": 8090}


def _client_with_fixture() -> TestClient:
    """A client whose ZAP reads return the real captured response instead of hitting a container."""
    raw = FIXTURE.read_text(encoding="utf-8")

    def fake_api_get(container, port, path, timeout=10):
        # THE PREDICATE IS "NO ACTION URL", not "only the alerts view".
        #
        # This used to assert the path WAS `/JSON/core/view/alerts/`, which was a faithful
        # stand-in while the ingest made exactly one ZAP call. It stopped being one when the
        # ingest also began reading the message history to judge session health — a call from
        # the same READ group, which the rule explicitly permits from ungated code.
        #
        # The rule being guarded (see cockpit/proxy.py) is that an UNGATED route may reach the
        # READ group and never the ACTION group. Naming one read endpoint was a proxy for
        # that, and the proxy broke before the rule did. So the check now says what it means:
        # any `/view/` path is fine, any `/action/` path is the violation. That is a sharper
        # test than the one it replaces, not a looser one — it now fails on EVERY action URL
        # rather than only on the ones that are not the alerts view.
        assert "/action/" not in path, (
            f"the ingest path asked ZAP for {path!r} — an ACTION URL reached from an ungated "
            "route is the residual risk the one-module decision accepted"
        )
        assert "/view/" in path, f"the ingest path asked ZAP for a non-view URL: {path!r}"
        if "/JSON/core/view/messages/" in path:
            # the session-health read: no captured history in this fixture
            return '{"messages": []}'
        return raw

    proxy._api_get = fake_api_get  # type: ignore[assignment]
    return TestClient(main.app)


def test_the_ingest_route_persists_findings_and_endpoints() -> None:
    """*** THE WIRING, END TO END. *** Route -> mapper -> SQLite -> read back."""
    client = _client_with_fixture()
    store.clear(SESSION)

    resp = client.post("/cockpit/proxy/alerts/ingest", json=BODY)
    assert resp.status_code == 200, f"{resp.status_code}: {resp.text[:300]}"
    counts = resp.json()
    # TWO endpoints, not one: the passive CORS alert names the clean URL (`?q=measure`) while the
    # SQL injection names the one carrying the payload (`?q=measure%27`). Both are worth keeping
    # — the second IS the reproduction — and they are genuinely distinct URLs.
    assert {k: counts[k] for k in ("alerts", "findings", "endpoints")} == {
        "alerts": 2, "findings": 2, "endpoints": 2
    }, counts
    # The ingest also reports whether the scan's traffic still looked AUTHENTICATED, because
    # this is where a zero-finding scan gets persisted and "0 findings" and "the session died"
    # look identical afterwards. With no captured history it must say `unknown` — never `ok`.
    health = counts.get("session_health")
    assert health is not None, "the ingest dropped the session-health verdict entirely"
    assert health["verdict"] == "unknown", (
        f"an empty history produced {health['verdict']!r} — a scan with nothing to judge must "
        "never come back clean"
    )

    # and the rows must be READABLE BACK. A route that returns "2" having written nothing is the
    # failure this test exists to catch, and it would satisfy any assertion on the response alone.
    findings = store.load(SESSION).findings
    assert len(findings) == 2, f"the route claimed 2 findings; the store holds {len(findings)}"
    by_title = {f.title: f for f in findings}
    sqli = by_title.get("SQL Injection")
    assert sqli is not None, f"the High SQL injection did not persist: {sorted(by_title)}"
    assert sqli.severity == "high", f"it persisted as {sqli.severity!r}"
    assert sqli.reference == "pluginid:40018", sqli.reference
    assert sqli.tool == "zap" and sqli.target.startswith("http://")
    print(f"  the ingest route persisted {counts} and they read back: PASS")


def test_re_ingesting_does_not_duplicate() -> None:
    """*** THE PANEL HAS A BUTTON, SO IT WILL BE PRESSED TWICE. ***

    Findings are identified by a fingerprint over (title, target, reference) precisely so a
    re-detection updates in place. If this ever doubles, every report grows a duplicate for each
    click, which is the kind of defect that is embarrassing rather than dangerous — and invisible
    until a client reads the report.
    """
    client = _client_with_fixture()
    store.clear(SESSION)

    client.post("/cockpit/proxy/alerts/ingest", json=BODY)
    first = len(store.load(SESSION).findings)
    client.post("/cockpit/proxy/alerts/ingest", json=BODY)
    second = len(store.load(SESSION).findings)

    assert first == second == 2, (
        f"re-ingesting the same alerts grew the store from {first} to {second} — the upsert is "
        "not collapsing on the fingerprint"
    )
    print(f"  ingesting twice leaves {second} findings, not {first * 2}: PASS")


def test_the_ingest_route_is_scoped_to_its_session() -> None:
    """A second session must not inherit the first one's findings — the store is keyed by
    session, and a report is rendered per session."""
    client = _client_with_fixture()
    other = "s-ingest-other"
    store.clear(SESSION)
    store.clear(other)

    client.post("/cockpit/proxy/alerts/ingest", json=BODY)
    assert len(store.load(SESSION).findings) == 2
    assert store.load(other).findings == [], (
        "findings ingested for one session are visible in another — they would appear in the "
        "wrong client's report"
    )
    store.clear(other)
    print("  ingested findings belong to exactly one session: PASS")


def test_a_bad_request_is_refused_rather_than_writing_nothing_silently() -> None:
    """A missing session_id must be a 422, not a 200 that quietly persisted nothing.

    `upsert_findings` drops rows with no session_id, so without validation the route would answer
    `{"findings": 0}` cheerfully and the operator would conclude ZAP found nothing.
    """
    client = _client_with_fixture()
    resp = client.post("/cockpit/proxy/alerts/ingest", json={"container": "c", "port": 8090})
    assert resp.status_code == 422, f"expected 422, got {resp.status_code}: {resp.text[:200]}"
    print("  a request with no session_id is refused, not silently dropped: PASS")


def test_the_ingest_route_executes_nothing() -> None:
    """*** THE STATE PACKAGE'S STANDING INVARIANT, RESTATED AT THIS ENTRY POINT. ***

    Ingest runs on data an already-gated attack produced; it must never become a second way to
    run something. Asserted on the source of the route rather than by trusting the name.
    """
    import ast
    import inspect

    from cockpit import router as router_mod

    src = inspect.getsource(router_mod.ingest_scan_alerts)
    tree = ast.parse(src.lstrip())
    called = {
        n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
        for n in ast.walk(tree) if isinstance(n, ast.Call)
    }
    for banned in {"run", "Popen", "system", "exec_argv", "spawn_watched", "start_scan"}:
        assert banned not in called, (
            f"the ingest route calls {banned!r} — it must read ZAP and write the store, nothing "
            f"else. Calls found: {sorted(c for c in called if c)}"
        )
    # THE PROPERTY, NOT THE NAME (build #18). This has now fired TWICE on a rename — first when
    # `scan_alerts` became `alerts_snapshot`, then again when that became `alerts_page` so the
    # route could also report how many alerts FAILED TO PARSE. Both times the property held and
    # only the spelling moved. Enumerating spellings would just defer the same failure, so the
    # assertion is now the shape: the route reads alerts through SOME alert reader.
    readers = {c for c in called if c.startswith(("scan_alerts", "alerts_"))}
    assert readers, (
        f"the route no longer reads alerts at all: {sorted(c for c in called if c)}"
    )
    print("  the ingest route reads and writes only — it executes nothing: PASS")


def _cleanup() -> None:
    """Remove the temp database. VERIFIED to actually work, which the first version was not.

    ``store._connect()`` uses the connection as a CONTEXT MANAGER, and sqlite3's context manager
    commits or rolls back — it does NOT close. So the handles stay open until they are collected,
    and on Windows an open handle makes the file undeletable. The first version of this quietly
    swallowed that OSError and left a directory in %TEMP% on every run: a cleanup that cannot
    fail visibly is a cleanup nobody notices is broken.

    ``gc.collect()`` finalises the stray connections; the assert is what stops this regressing
    back into silent litter.
    """
    import gc
    import shutil

    gc.collect()
    shutil.rmtree(_TMP.parent, ignore_errors=True)
    assert not _TMP.parent.exists(), (
        f"the temp database survived cleanup at {_TMP.parent} — every run of this suite now "
        "leaves a directory behind. A connection is being held open somewhere."
    )


if __name__ == "__main__":
    try:
        test_the_ingest_route_persists_findings_and_endpoints()
        test_re_ingesting_does_not_duplicate()
        test_the_ingest_route_is_scoped_to_its_session()
        test_a_bad_request_is_refused_rather_than_writing_nothing_silently()
        test_the_ingest_route_executes_nothing()
        print("ALL ZAP alert-ingest route tests pass")
    finally:
        _cleanup()
