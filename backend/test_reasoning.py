"""Reasoning-copilot plumbing tests (backend/reasoning/) — Task 2 (2.1–2.8) + Tasks 3 & 4.

Deterministic tests of the PLUMBING: a structured, cited proposal in/out; the ledger respected;
the critic catching a version-mismatched CVE (positive control); the frontier persisting and
recovering a dead-end; specialist routing; fingerprint retrieval; inert model-tier config; the
web-exploit and privesc drafts. Reasoning QUALITY is validated interactively against Ollama
(local-ui-testing-setup) — that is not what these lock. Nothing here executes anything.

Hermetic: the ledger + frontier tables are pointed at a temp SQLite file. Run:  python test_reasoning.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from reasoning import (
    critic,
    diagnosis,
    frontier,
    ledger,
    privesc,
    retrieval,
    schema,
    specialists,
    tiering,
    webexploit,
)
from state.models import Credential, Finding, Host, Service, StateSummary

SID = "test-reasoning-session"


class _TempDB:
    """Point ledger + frontier at a throwaway SQLite file; restore on exit."""

    def __enter__(self):
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        path = Path(self._dir.name) / "t.db"
        self._orig = (ledger.DB_PATH, frontier.DB_PATH)
        ledger.DB_PATH = path
        frontier.DB_PATH = path
        ledger.init_db()
        frontier.init_db()
        return self

    def __exit__(self, *exc):
        ledger.DB_PATH, frontier.DB_PATH = self._orig
        self._dir.cleanup()
        return False


# --------------------------------------------------------------------------- #
# 2.2 — hypothesis-first schema (invariant 3)
# --------------------------------------------------------------------------- #
def test_schema_validate_rejects_uncited() -> None:
    good = {
        "hypothesis": "the q param is SQL-injectable",
        "expected_signal": "sqlmap reports an injectable parameter",
        "citations": [{"type": "kb", "id": "kb-42"}],
    }
    ok, problems = schema.validate(good)
    assert ok and not problems, problems
    # each required field, removed in turn, FAILS — the invariant-3 gate can fail
    for missing in ("hypothesis", "expected_signal", "citations"):
        bad = dict(good)
        bad[missing] = "" if missing != "citations" else []
        ok, problems = schema.validate(bad)
        assert not ok and problems, f"a proposal missing {missing} must be rejected"
    # normalize copes with a bare-string citation list (small-model degradation)
    norm = schema.normalize({"hypothesis": "h", "expected_signal": "s", "citations": ["kb-1", "host:10.0.0.5"]})
    assert len(norm["citations"]) == 2 and norm["citations"][1]["type"] == "state"
    print("  2.2 schema: uncited/unreasoned proposal is rejected; citations normalize: PASS")


# --------------------------------------------------------------------------- #
# 2.1 — working-memory ledger
# --------------------------------------------------------------------------- #
def test_ledger_tracks_and_blocks_dead_leads() -> None:
    runs = [
        {"command": "nmap", "args": ["-sV", "h"], "exit_code": 0, "stdout": "80/tcp open http"},
        {"command": "curl", "args": ["http://h:8080/"], "exit_code": 7,
         "stderr": "Failed to connect to h port 8080: Connection refused"},
    ]
    entries = {e.command: e for e in ledger.build(runs)}
    assert entries["nmap"].outcome == "success"
    assert entries["curl"].outcome == "failed", "a connection-refused run must read as failed"
    # is_tried sees a run; a novel command is not tried
    assert ledger.is_tried(runs, "curl", ["http://h:8080/"])
    assert not ledger.is_tried(runs, "gobuster", ["-u", "http://h/"])
    # render carries the ledger into the prompt with the do-not-repeat instruction
    block = ledger.render(runs, [])
    assert "FAILED" in block and "curl" in block and "Do NOT re-propose" in block
    with _TempDB():
        ledger.record_dead(SID, "hydra", ["-l", "root", "ssh://h"], "no valid creds", "critic")
        assert ledger.is_dead(SID, "hydra", ["-l", "root", "ssh://h"])
        assert not ledger.is_dead(SID, "hydra", ["-l", "admin", "ssh://h2"])
        assert "DEAD END" in ledger.render(runs, [], SID)
        assert ledger.is_tried(runs, "hydra", ["-l", "root", "ssh://h"], SID)
    print("  2.1 ledger: failed lead recorded, blocks re-proposal, present in prompt: PASS")


# --------------------------------------------------------------------------- #
# 2.3 — candidate frontier
# --------------------------------------------------------------------------- #
def test_frontier_persists_and_recovers() -> None:
    assert frontier.score_lead(1.0, 1.0) > frontier.score_lead(0.5, 0.5) > frontier.score_lead(0.1, 0.1)
    with _TempDB():
        leads = [
            frontier.Lead(hypothesis="weak", command="nikto", args=["-h", "h"], evidence=0.2, payoff=0.3),
            frontier.Lead(hypothesis="strong", command="sqlmap", args=["-u", "http://h/?id=1"],
                          evidence=0.9, payoff=0.9),
        ]
        added = frontier.push(SID, leads)
        assert added == 2
        opened = frontier.open_leads(SID)
        assert len(opened) == 2, "the frontier persists untried leads"
        assert frontier.top(SID).command == "sqlmap", "highest evidence×payoff floats to the top"
        # dead-end recovery: the pursued top is skipped, the next-best is proposed (not a loop)
        top_sig = frontier.top(SID).signature
        nxt = frontier.recover(SID, avoid_signatures={top_sig})
        assert nxt is not None and nxt.command == "nikto", "recover pivots to the next untried lead"
        # marking dead removes it and it never resurrects
        frontier.mark(SID, "nikto", ["-h", "h"], "dead")
        assert frontier.push(SID, [leads[0]]) == 0, "a dead lead is not resurrected"
        assert all(l.command != "nikto" for l in frontier.open_leads(SID))
        assert "CANDIDATE FRONTIER" in frontier.render(SID)
    print("  2.3 frontier: persists untried leads, recovers a dead-end, no resurrection: PASS")


# --------------------------------------------------------------------------- #
# 2.4 — failure diagnosis
# --------------------------------------------------------------------------- #
def test_diagnosis_diagnoses_not_repeats() -> None:
    refused = {"command": "curl", "args": ["http://10.0.0.5:8080/"], "exit_code": 7,
               "stderr": "curl: (7) Failed to connect to 10.0.0.5 port 8080: Connection refused"}
    f = diagnosis.detect_failure(refused)
    assert f is not None and f.kind == "connection-refused"
    diag = diagnosis.diagnostic_for(f, "curl", ["http://10.0.0.5:8080/"])
    assert diag and diag["command"] == "nmap" and "10.0.0.5" in diag["args"], "propose a reachability check"
    adv = diagnosis.advice([refused])
    assert "Do NOT simply repeat" in adv and "connection-refused" in adv
    # a healthy run yields no advice — the prompt is unchanged
    assert diagnosis.advice([{"command": "nmap", "args": ["h"], "exit_code": 0, "stdout": "open"}]) == ""
    print("  2.4 diagnosis: failure -> reachability diagnostic, not a blind repeat: PASS")


# --------------------------------------------------------------------------- #
# 2.5 — critic (POSITIVE CONTROL: version-mismatched CVE is caught)
# --------------------------------------------------------------------------- #
def _fixture_index():
    from exploits.index import ExploitIndex

    return ExploitIndex(
        {
            "entries": [
                {
                    "title": "Apache 2.4.49 - Path Traversal (CVE-2021-41773)",
                    "tokens": ["apache", "httpd"], "versions": ["2.4.49"],
                    "version_kind": "exact", "cves": ["CVE-2021-41773"], "verified": True,
                }
            ],
            "by_cve": {"CVE-2021-41773": [0]},
            "by_token": {"apache": [0], "httpd": [0]},
        }
    )


def test_critic_catches_version_mismatched_cve() -> None:
    index = _fixture_index()
    proposal = {
        "command": "curl", "args": ["http://h/cgi-bin/"],
        "hypothesis": "exploit CVE-2021-41773 path traversal on this Apache",
        "citations": [{"type": "kb", "id": "CVE-2021-41773"}],
    }
    # observed version DOES NOT match the CVE's target (2.4.58 != 2.4.49) -> caught + downranked
    mismatch = StateSummary(services=[Service(SID, "h", 443, product="Apache httpd", version="2.4.58")])
    verdict = critic.critique(proposal, mismatch, index)
    assert not verdict.ok and verdict.downrank, "a version-mismatched CVE must be downranked"
    assert any("does not apply" in c for c in verdict.concerns)
    assert verdict.confidence < 0.5
    # observed version DOES match -> the same proposal passes
    match = StateSummary(services=[Service(SID, "h", 443, product="Apache httpd", version="2.4.49")])
    ok_verdict = critic.critique(proposal, match, index)
    assert ok_verdict.ok, "the CVE applies to the observed version — must pass"
    assert any("exact" in c for c in ok_verdict.checks)
    # REGRESSION (found in the first live Ollama run): an IP octet / query value must NOT be
    # misread as a port by the service check. sqlmap against http://10.10.10.5/x?id=1 while
    # state has :80 must raise NO port concern.
    inject = {"command": "sqlmap", "args": ["-u", "http://10.10.10.5/x?id=1", "--batch"],
              "hypothesis": "the id parameter is SQL-injectable"}
    v = critic.critique(inject, StateSummary(services=[Service(SID, "10.10.10.5", 80, name="http")]), None)
    assert not any("port that is not among" in c for c in v.concerns), \
        "an IP octet / query value must not be misread as a port"
    print("  2.5 critic: version-mismatched CVE caught+downranked; matching version passes: PASS")


# --------------------------------------------------------------------------- #
# 2.6 — domain-specialist routing
# --------------------------------------------------------------------------- #
def test_specialist_routing() -> None:
    web = StateSummary(services=[Service(SID, "h", 80, name="http", product="nginx")])
    assert specialists.route(web, "gobuster -u http://h/").domain == "web"
    ad = StateSummary(services=[
        Service(SID, "dc", 445, name="microsoft-ds"), Service(SID, "dc", 389, name="ldap")
    ])
    assert specialists.route(ad, "netexec smb dc").domain == "active-directory"
    foothold = StateSummary(hosts=[Host(SID, "h", local_txt="flag")])
    assert specialists.route(foothold, "").domain == "privesc"
    # generalist when there is no signal, and the fragment is empty then (prompt unchanged)
    assert specialists.route(StateSummary(), "").domain == "generalist"
    assert specialists.prompt_fragment(specialists.route(StateSummary(), "")) == ""
    assert "WEB" in specialists.prompt_fragment(specialists.route(web, ""))
    print("  2.6 specialists: web/AD/privesc route from evidence; generalist is inert: PASS")


# --------------------------------------------------------------------------- #
# 2.7 — fingerprint-keyed retrieval
# --------------------------------------------------------------------------- #
def test_fingerprint_retrieval_outranks_token_match() -> None:
    assert retrieval.fingerprint("Apache httpd", "2.4.49") == "apache/2.4.49"
    entries = [
        {"title": "General Apache hardening guide", "text": "apache tips"},          # token only
        {"title": "Apache 2.4.49 path traversal PoC", "text": "apache 2.4.49 exploit"},  # fingerprint
        {"title": "nginx notes", "text": "nginx"},
    ]
    ranked = retrieval.rerank(entries, "apache/2.4.49")
    assert ranked[0].fingerprint_match and "2.4.49" in ranked[0].entry["title"], \
        "the exact service+version write-up must rank first"
    assert not ranked[-1].fingerprint_match
    # end-to-end with an injected base retriever
    svc = Service(SID, "h", 443, product="Apache httpd", version="2.4.49")
    out = retrieval.retrieve(svc, lambda q: entries)
    assert out and out[0].fingerprint_match
    print("  2.7 retrieval: exact fingerprint outranks token matches: PASS")


def test_fingerprint_range_alignment() -> None:
    """The exploitation-writeup corpus is keyed by a STRUCTURED meta.fingerprint (service +
    version_kind + versions, the CVE-index shape). Retrieval must range-match it: an in-range
    version floats the writeup above token matches, and an OUT-OF-RANGE version does NOT match —
    the version verdict outranks token similarity, so a wrong version can't ride the product name.
    """
    # a structured-fingerprint writeup + a same-product token-only page
    apache_wu = {"title": "Apache 2.4.49 traversal writeup", "text": "path traversal rce",
                 "meta": {"fingerprint": {"service": "apache", "version_kind": "exact",
                                          "versions": ["2.4.49", "2.4.50"]}}}
    apache_generic = {"title": "General Apache hardening", "text": "apache tuning notes"}
    samba_wu = {"title": "Samba usermap writeup", "text": "command injection",
                "meta": {"fingerprint": {"service": "samba", "version_kind": "range",
                                         "versions": ["3.0.20", "3.0.26"]}}}
    pool = [apache_generic, apache_wu, samba_wu]

    # in-range exact -> the writeup leads, ahead of the generic token match
    r = retrieval.rerank(pool, "apache/2.4.49")
    assert r[0].entry is apache_wu and r[0].fingerprint_match, "in-range writeup must lead"
    # OUT-OF-RANGE version -> the writeup is NOT a fingerprint match (does not wrongly match)
    r = retrieval.rerank(pool, "apache/2.4.58")
    apache_ranked = next(x for x in r if x.entry is apache_wu)
    assert not apache_ranked.fingerprint_match, "2.4.58 is patched — must NOT match the 2.4.49/.50 writeup"
    # range fingerprint: inside the [3.0.20, 3.0.26) window matches, outside does not
    assert retrieval.rerank([samba_wu], "samba/3.0.25")[0].fingerprint_match
    assert not retrieval.rerank([samba_wu], "samba/3.0.30")[0].fingerprint_match
    print("  Task 4 alignment: fingerprint writeup range-matches; out-of-range does not: PASS")


# --------------------------------------------------------------------------- #
# 2.8 — model-tier routing (inert unless configured)
# --------------------------------------------------------------------------- #
def test_tiering_inert_by_default() -> None:
    base = {"model": "local", "num_predict": 500}
    assert tiering.select(base, "hard") is base, "no tiers configured -> cfg returned UNCHANGED"
    assert tiering.select(base, "routine") is base
    assert not tiering.active(base)
    tiered = {"model": "local", "reasoning_tiers": {"hard": {"model": "big", "num_predict": 1200}}}
    assert tiering.active(tiered)
    hard = tiering.select(tiered, "exploit")
    assert hard["model"] == "big" and hard["num_predict"] == 1200 and "reasoning_tiers" not in hard
    assert tiering.select(tiered, "recon")["model"] == "local", "routine step keeps the base model"
    print("  2.8 tiering: inert when unset; routes the hard step when configured: PASS")


# --------------------------------------------------------------------------- #
# Task 3 — web-exploitation drafting (human fires)
# --------------------------------------------------------------------------- #
def test_webexploit_drafts_grounded_exploit() -> None:
    kb = lambda q: [{"id": "kb-sqli-1", "title": "SQLi via sqlmap"}]
    sqli = {"title": "SQL injection in q parameter", "target": "http://h/search?q=1", "params": ["q"]}
    draft = webexploit.draft_exploit(sqli, StateSummary(), kb)
    assert draft.applicable and draft.bug_class == "sqli" and draft.command == "sqlmap"
    assert "-p" in draft.args and "q" in draft.args and draft.dangerous
    assert draft.citations and any(c["type"] == "kb" for c in draft.citations), "must be grounded"
    assert any(c["type"] == "state" for c in draft.citations), "must cite the finding"
    ssrf = webexploit.draft_exploit({"title": "SSRF in url", "target": "http://h/f?url=x", "params": ["url"]}, None, kb)
    assert ssrf.bug_class == "ssrf" and "169.254.169.254" in " ".join(ssrf.args)
    assert ssrf.delivery == webexploit.DELIVERY_REPEATER
    idor = webexploit.draft_exploit({"title": "IDOR on /api/user", "target": "http://h/api/user?id=5"}, None, kb)
    assert idor.bug_class == "idor" and idor.applicable
    # an unclassifiable finding is honestly reported not-applicable
    assert not webexploit.draft_exploit({"title": "something odd", "target": "http://h/"}, None, kb).applicable
    print("  Task 3 web-exploit: finding -> grounded, cited, drafted exploit (human fires): PASS")


# --------------------------------------------------------------------------- #
# Task 4 — privesc from linpeas/winpeas
# --------------------------------------------------------------------------- #
_LINPEAS = """
[+] Checking sudo -l
User www-data may run the following commands:
    (root) NOPASSWD: /usr/bin/find
[+] SUID - Check easy privesc
-rwsr-xr-x 1 root root /usr/bin/find
[+] Checking polkit / pkexec
/usr/bin/pkexec  (polkit)  possibly CVE-2021-4034 PwnKit
"""
_WINPEAS = "SeImpersonatePrivilege  Enabled\nAlwaysInstallElevated is set to 1"


def test_privesc_ingests_and_drafts() -> None:
    kb = lambda q: [{"id": "kb-gtfo-find", "title": "GTFOBins find"}]
    vectors = privesc.parse_peas(_LINPEAS)
    kinds = {v.kind for v in vectors}
    assert "sudo" in kinds and "pwnkit" in kinds, kinds
    out = privesc.ingest_and_propose(_LINPEAS, StateSummary(), kb)
    draft = out["draft"]
    assert draft["applicable"] and draft["vector"] is not None
    assert draft["citations"] and any(c["type"] == "kb" for c in draft["citations"]), "grounded"
    assert any(c["type"] == "state" for c in draft["citations"])
    assert draft["shell_line"], "a concrete escalation one-liner is drafted for the human to run"
    # windows path
    win = privesc.parse_peas(_WINPEAS)
    wkinds = {v.kind for v in win}
    assert "se-impersonate" in wkinds and "always-install-elevated" in wkinds
    # empty input -> honest not-applicable, no crash
    assert not privesc.propose(privesc.parse_peas("nothing interesting here")).applicable
    print("  Task 4 privesc: linpeas/winpeas -> identified vector + grounded drafted step: PASS")


if __name__ == "__main__":
    test_schema_validate_rejects_uncited()
    test_ledger_tracks_and_blocks_dead_leads()
    test_frontier_persists_and_recovers()
    test_diagnosis_diagnoses_not_repeats()
    test_critic_catches_version_mismatched_cve()
    test_specialist_routing()
    test_fingerprint_retrieval_outranks_token_match()
    test_fingerprint_range_alignment()
    test_tiering_inert_by_default()
    test_webexploit_drafts_grounded_exploit()
    test_privesc_ingests_and_drafts()
    print("ALL reasoning-copilot plumbing tests pass")
