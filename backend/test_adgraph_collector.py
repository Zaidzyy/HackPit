"""Regression-lock for G1 — the BloodHound collector wiring (built, not run live).

The collector is read-only enumeration, but on a real domain it is still a command against a
real host, so it must flow through the SAME gated executor as everything else. These tests
fail loudly if that weakens:

  1. ARGV: the collector builds a correct argv-only bloodhound-python invocation; auth is by
     password OR NT hash; the DC/domain/nameserver are inspectable argv tokens.
  2. NEVER PRE-APPROVED: build_collector_request returns approved=False and requires an active
     engagement id (collection can't run outside a scoped engagement).
  3. SCOPE-LOCK COVERS THE COLLECTOR: routed through the executor's engagement gates, a collector
     aimed at an IN-SCOPE DC passes the target gate; one aimed at an OUT-OF-SCOPE DC is refused
     at the 'target' gate — before anything runs. (The AD-host scope requirement, proven.)
  4. NEVER-AUTO-RUN: the collector request with approved=False is refused at the approval gate,
     same as any command; there is no batch/auto path.
  5. FAILURE: classify_failure turns bad-creds / unreachable / DNS / skew into clean messages.
  6. INGEST: a captured collection parses + persists; junk raises ParseError.
  7. THE COLLECTOR MODULE HAS NO EXECUTION / NO :kali PATH (it builds requests + ingests only).

Hermetic: no Docker, no LLM, no network. The executor's engagement resolution is monkeypatched;
ingest uses a throwaway temp DB. Run:  python test_adgraph_collector.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from adgraph import collector as C
from adgraph import sample_data as S
from adgraph import store
from cockpit import executor as E
from cockpit.models import EngagementRecord, ExecRequest


def _eng(scope: str, target: str = "dc01.sevenkingdoms.local") -> EngagementRecord:
    include = [p.strip() for p in scope.split(",") if not p.strip().startswith("!")]
    exclude = [p.strip().lstrip("!") for p in scope.split(",") if p.strip().startswith("!")]
    return EngagementRecord(
        engagement_id="eng-ad0000000000",
        target=target,
        authorization="authorized AD engagement",
        active=True,
        entered_at="2026-07-25T00:00:00+00:00",
        scope=scope,
        scope_include=include,
        scope_exclude=exclude,
        allowed_hosts=[target],
    )


def _patch_active(rec: EngagementRecord | None):
    orig = E.engagement.get_active
    E.engagement.get_active = lambda _id: rec  # type: ignore[assignment]
    return orig


_PARAMS = C.CollectorParams(
    domain="sevenkingdoms.local", username="tywin",
    dc="dc01.sevenkingdoms.local", password="pw",
    nameserver="10.10.10.10",
)


# --------------------------------------------------------------------------- #
# 1-2. argv + never-pre-approved
# --------------------------------------------------------------------------- #
def test_argv_is_correct_and_argv_only() -> None:
    argv = C.build_collector_argv(_PARAMS)
    assert argv[0] == "bloodhound-python"
    assert "dc01.sevenkingdoms.local" in argv and "sevenkingdoms.local" in argv
    assert "-c" in argv and argv[argv.index("-c") + 1] == "All"
    # hash auth path
    h = C.build_collector_argv(C.CollectorParams(
        domain="d.local", username="u", dc="dc.d.local", nthash="a" * 32))
    assert "--hashes" in h and h[h.index("--hashes") + 1] == ":" + "a" * 32
    print("  collector builds a correct argv-only invocation (password + hash auth): PASS")


def test_request_never_preapproved_and_needs_engagement() -> None:
    req = C.build_collector_request(_PARAMS, "eng-ad0000000000")
    assert req.approved is False, "the collector request must never be pre-approved"
    assert req.engagement_id == "eng-ad0000000000"
    for bad in ("", "   ", None):
        try:
            C.build_collector_request(_PARAMS, bad)  # type: ignore[arg-type]
        except ValueError:
            continue
        raise AssertionError("the collector must require an active engagement id")
    print("  collector request is unapproved + requires an active engagement: PASS")


# --------------------------------------------------------------------------- #
# 3. the engagement scope-lock covers the collector
# --------------------------------------------------------------------------- #
def test_scope_lock_covers_the_collector() -> None:
    # scope includes the DC + the domain APEX + wildcard + the DC subnet -> collector passes.
    # NOTE the apex `sevenkingdoms.local` is listed explicitly: a *.wildcard covers subdomains
    # only, and `-d sevenkingdoms.local` is the apex token — so an AD scope must include it.
    eng = _eng("sevenkingdoms.local, *.sevenkingdoms.local, dc01.sevenkingdoms.local, 10.10.10.0/24")
    orig = _patch_active(eng)
    try:
        req = C.build_collector_request(_PARAMS, eng.engagement_id)
        req.approved = True  # simulate the human approval so we reach past the approval gate
        rej = E.validate_request(req)
        assert rej is None, f"an in-scope collector must pass all gates, got: {rej}"

        # a DC OUTSIDE the scope WARNS at the scope gate (handrail, override-able), nothing runs
        off = C.CollectorParams(domain="evil.corp", username="u", dc="dc.evil.corp",
                                password="pw", nameserver="8.8.8.8")
        req2 = C.build_collector_request(off, eng.engagement_id)
        req2.approved = True
        rej2 = E.validate_request(req2)
        assert rej2 is not None and rej2.gate == "scope", rej2
        print("  scope-lock covers the collector: in-scope DC passes, out-of-scope refused: PASS")
    finally:
        E.engagement.get_active = orig


def test_collector_never_auto_runs() -> None:
    eng = _eng("sevenkingdoms.local, dc01.sevenkingdoms.local, 10.10.10.0/24")
    orig = _patch_active(eng)
    try:
        req = C.build_collector_request(_PARAMS, eng.engagement_id)  # approved=False
        rej = E.validate_request(req)
        assert rej is not None and rej.gate == "approval", rej
        # belt-and-suspenders: the prevalidated iter_run path also refuses
        events = list(E.iter_run(req, prevalidated=True))
        assert events and events[0]["type"] == "rejected" and events[0]["gate"] == "approval"
        print("  NEVER-AUTO-RUN: the collector needs explicit human approval like any command: PASS")
    finally:
        E.engagement.get_active = orig


# --------------------------------------------------------------------------- #
# 5. failure classification
# --------------------------------------------------------------------------- #
def test_failure_classification() -> None:
    assert C.classify_failure(1, "", "STATUS_LOGON_FAILURE")[0] is True
    assert "auth" in C.classify_failure(1, "", "invalid credentials")[1].lower()
    assert "unreachable" in C.classify_failure(1, "", "connection timed out")[1].lower()
    assert "dns" in C.classify_failure(1, "", "could not resolve host")[1].lower()
    assert "clock" in C.classify_failure(1, "", "KRB_AP_ERR_SKEW")[1].lower()
    assert C.classify_failure(0, "ok", "")[0] is False

    # Build #9's FIRST live collection against a real domain failed here and the classifier had
    # nothing to say about it: bloodhound-python refuses an IP for -dc. Its own error text also
    # mentions a "DNS server IP", so this signature must WIN over the generic DNS one — ordered
    # the other way the operator is told to fix their nameserver when -dc is the real problem.
    real_stderr = (
        "ERROR: The specified domain controller 192.168.13.140 looks like an IP address, but "
        "requires a hostname (FQDN).\nUse the -ns flag to specify a DNS server IP if the "
        "hostname does not resolve on your default nameserver."
    )
    failed, reason = C.classify_failure(1, "", real_stderr)
    assert failed is True
    assert "fqdn" in reason.lower() and "-dc" in reason.lower(), reason
    assert "nameserver" not in reason.lower().split("—")[0], (
        "the generic DNS signature must not shadow the FQDN one"
    )
    print("  failure classification: bad-creds / unreachable / DNS / skew / -dc-needs-FQDN: PASS")


# --------------------------------------------------------------------------- #
# 6. ingest a captured collection
# --------------------------------------------------------------------------- #
def test_ingest_and_persist() -> None:
    tmp = Path(tempfile.mkdtemp()) / "ad.db"
    orig = store.DB_PATH
    store.DB_PATH = tmp
    try:
        store.init_db()
        res = C.ingest_collection(S.sample_collection(), session_id="s-ad", origin="sample")
        assert res["domain"] == "SEVENKINGDOMS.LOCAL"
        assert res["stats"]["nodes"] > 0 and res["stats"]["edges"] > 0
        got = store.latest_for_session("s-ad")
        assert got is not None and got["graph"]["domain"] == "SEVENKINGDOMS.LOCAL"
        # junk raises ParseError
        try:
            C.ingest_collection({"nonsense": 1}, session_id="s-ad")
        except C.ParseError:
            print("  ingest parses + persists a collection; junk raises ParseError: PASS")
            return
        raise AssertionError("junk input must raise ParseError")
    finally:
        store.DB_PATH = orig


# --------------------------------------------------------------------------- #
# 7. the collector module has no execution / no :kali path
# --------------------------------------------------------------------------- #
def test_collector_has_no_execution_or_kali_path() -> None:
    src = Path(C.__file__).read_text(encoding="utf-8")
    for tok in ("subprocess", "docker exec", "run_kali", "kali", "iter_run(", "Popen", "os.system"):
        assert tok not in src, f"the collector module must not execute anything ({tok})"
    print("  the collector builds requests + ingests only — no execution, no :kali path: PASS")


if __name__ == "__main__":
    test_argv_is_correct_and_argv_only()
    test_request_never_preapproved_and_needs_engagement()
    test_scope_lock_covers_the_collector()
    test_collector_never_auto_runs()
    test_failure_classification()
    test_ingest_and_persist()
    test_collector_has_no_execution_or_kali_path()
    print("ALL adgraph collector tests pass")
