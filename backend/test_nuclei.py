"""nuclei surface — argv building, JSONL -> Finding mapping, dedupe.  Run:  python test_nuclei.py

Hermetic: every function under test is PURE. The JSONL is a captured sample string this file
CHOOSES (like the ZAP scan tests feed a chosen alert string) — see test_nuclei_safety.py's note
that a hermetic parse test cannot prove the image's `nuclei` accepts the flags; that is the image
proof's job (docker/proof/nuclei_proof.sh), stated NOT-RUN here honestly.
"""

from __future__ import annotations

from cockpit import config, nuclei

# A captured-shape nuclei `-jsonl` sample: one JSON object per line, hyphenated keys, exactly the
# shape `nuclei -jsonl` streams to stdout. Two lines share (template-id, matched-at) to prove dedupe.
SAMPLE_JSONL = "\n".join([
    '{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical",'
    '"tags":["cve","rce","log4j"],"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]},'
    '"type":"http","host":"http://juice-shop.local","matched-at":"http://juice-shop.local/api",'
    '"extracted-results":["jndi:ldap://x"],"curl-command":"curl -X GET http://juice-shop.local/api"}',
    # DUPLICATE of the line above by (template-id, matched-at) — must collapse to one finding.
    '{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical"},'
    '"host":"http://juice-shop.local","matched-at":"http://juice-shop.local/api"}',
    '{"template-id":"tech-detect:nginx","info":{"name":"Nginx","severity":"info","tags":["tech"]},'
    '"matched-at":"http://juice-shop.local","matcher-name":"nginx"}',
    'GARBAGE progress line that is not json and must be skipped',
    '{"template-id":"weak-cors","info":{"name":"Permissive CORS","severity":"medium"},'
    '"matched-at":"http://juice-shop.local/socket.io"}',
])


def test_argv_from_explicit_targets() -> None:
    req = nuclei.NucleiRequest(
        targets=["http://juice-shop.local", "example.com"],
        severities=["high", "critical", "bogus"], tags=["cve", "rce"],
        templates=["/usr/share/nuclei-templates/http/cves"], rate_limit=50,
    )
    targets, warnings = nuclei.resolve_targets(req)
    assert targets == ["http://juice-shop.local", "example.com"], targets
    argv = nuclei.nuclei_argv(targets, req)
    assert argv[0] == "nuclei"
    assert "-jsonl" in argv and "-duc" in argv, "JSONL to stdout + update-check disabled"
    # every target rides as -u so check_target_lock sees it
    assert argv.count("-u") == 2 and "http://juice-shop.local" in argv and "example.com" in argv
    # severity filter drops the bogus value and keeps a comma-joined list
    i = argv.index("-severity")
    assert set(argv[i + 1].split(",")) == {"high", "critical"}, argv[i + 1]
    assert argv[argv.index("-tags") + 1] == "cve,rce"
    assert "-t" in argv and "/usr/share/nuclei-templates/http/cves" in argv
    assert argv[argv.index("-rate-limit") + 1] == "50"
    print("  argv: -u per target, -jsonl/-duc, severity filtered, tags/-t/-rate-limit: PASS")


def test_default_template_dir_is_always_pointed_at() -> None:
    """LIVE-FIRE FINDING: `nuclei -tags tech` with no -t dies 'no templates provided for scan' — a
    docker exec resolves no default template directory. So when no explicit templates are given,
    the argv points -t at the baked repo the sandbox image ships."""
    argv = nuclei.nuclei_argv(["http://juice-shop.local"], nuclei.NucleiRequest(tags=["tech"]))
    assert argv[argv.index("-t") + 1] == nuclei.DEFAULT_TEMPLATE_DIR, argv
    print("  a scan with no explicit templates points -t at the baked template repo: PASS")


def test_default_targets_seed_from_state() -> None:
    """With no explicit targets, the default set is the session's in-scope endpoints (URLs), and a
    session with nothing in state warns rather than building an empty, targetless scan."""
    from state import store

    # Create the state tables if absent. Locally the gitignored sessions.db already carries them,
    # but on a clean CI checkout store.clear() below would hit `no such table: state_hosts`. This
    # test drives the store directly (no app lifespan runs), so it must init the schema itself.
    store.init_db()

    sid = "test-nuclei-seed"
    store.clear(sid)  # idempotent across re-runs — start from a known-empty session
    # No state yet -> warns, no targets.
    empty, warns = nuclei.resolve_targets(nuclei.NucleiRequest(session_id=sid))
    assert empty == [] and warns, "an empty session must warn, not scan nothing silently"

    from state.models import Endpoint
    store.upsert_endpoints([
        Endpoint(session_id=sid, url="http://juice-shop.local/rest/products", method="GET"),
        Endpoint(session_id=sid, url="http://juice-shop.local/api/users", method="GET"),
    ])
    seeded, _ = nuclei.resolve_targets(nuclei.NucleiRequest(session_id=sid))
    assert set(seeded) == {
        "http://juice-shop.local/rest/products", "http://juice-shop.local/api/users"
    }, seeded
    store.clear(sid)
    print("  default target set seeds from state endpoints; empty session warns: PASS")


def test_jsonl_maps_to_findings_and_dedupes() -> None:
    findings = nuclei.parse_findings(SAMPLE_JSONL, session_id="s1", run_id="run1")
    # 3 unique (template-id, matched-at) rows: the two Log4j lines collapse to one, plus nginx and
    # CORS; the garbage line is skipped.
    assert len(findings) == 3, [f.title for f in findings]
    top = findings[0]  # ranked most-severe first
    assert top.severity == "critical" and top.title == "Apache Log4j RCE", top
    assert top.target == "http://juice-shop.local/api", top.target
    assert top.reference == "CVE-2021-44228", "reference is the template id"
    assert top.tool == "nuclei" and top.source_run_id == "run1"
    assert "jndi:ldap://x" in top.evidence, "evidence carries the extracted result"
    # ranked info < medium < critical => info last
    assert findings[-1].severity == "info", [f.severity for f in findings]
    print("  JSONL -> Finding (name/severity/matched-at/template-id/evidence) + dedupe + rank: PASS")


def test_ui_findings_and_severity_counts() -> None:
    ui = nuclei.parse_ui_findings(SAMPLE_JSONL)
    assert len(ui) == 3 and ui[0].template_id == "CVE-2021-44228"
    assert "log4j" in ui[0].tags, ui[0].tags
    counts = nuclei._severity_counts(ui)
    assert counts == {"critical": 1, "medium": 1, "info": 1}, counts
    print("  UI findings carry tags + template id; severity counts omit empty buckets: PASS")


def test_template_list_count() -> None:
    out = "http/cves/2021/CVE-2021-1.yaml\nhttp/exposures/x.yml\nREADME.md\n\ndns/a.yaml\n"
    assert nuclei.parse_template_list(out) == 3, "counts only .yaml/.yml template paths"
    print("  parse_template_list counts installed templates from `nuclei -tl` output: PASS")


def test_lab_target_resolves_for_argv() -> None:
    """A scan against the lab target builds an argv whose -u is the lab host — the smoke test that
    the default lab flow produces a runnable command line."""
    req = nuclei.NucleiRequest(targets=[config.LAB_TARGET_HOST])
    targets, _ = nuclei.resolve_targets(req)
    argv = nuclei.nuclei_argv(targets, req)
    assert argv[argv.index("-u") + 1] == config.LAB_TARGET_HOST
    print("  a lab-target scan builds a runnable -u <lab> argv: PASS")


if __name__ == "__main__":
    test_argv_from_explicit_targets()
    test_default_template_dir_is_always_pointed_at()
    test_default_targets_seed_from_state()
    test_jsonl_maps_to_findings_and_dedupes()
    test_ui_findings_and_severity_counts()
    test_template_list_count()
    test_lab_target_resolves_for_argv()
    print("\nnuclei surface: all mappings hold.")
    print("NOT-RUN (honest): the image proof that `nuclei` accepts these flags is "
          "docker/proof/nuclei_proof.sh — a hermetic parse test cannot prove it.")
