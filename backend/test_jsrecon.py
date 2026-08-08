"""JavaScript-recon (:jsrecon) tests.  Run:  python test_jsrecon.py

Covers the halves the :jsrecon feature rests on:

  * THE ENGINE (docker/js_mine.py, imported directly): a JS blob -> the right endpoints (relatives
    resolved to the JS origin), parameter NAMES, and secrets; a .map -> recovered source paths +
    comments; collect -> the <script src> set.
  * THE BACKEND PARSE: parse_mine_output splits the engine JSON into Endpoint rows (via
    state.parsers.parse_jsmine) + secret dicts + source-map dicts.
  * SCOPE: filter_urls_in_scope + filter_endpoints_in_scope keep in-scope + drop/collect
    out-of-scope, each with a control (the correctness property).
  * SECRETS -> LOOT, NEVER FINDING TEXT: a verified secret is a High Finding whose text carries the
    value nowhere, and the value is written to the loot file. Unverified is Low.

Hermetic: no Docker, no network, no live DB — the engine's fetch is never called (fixtures only) and
the loot dir is a temp path.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

from cockpit import jsrecon
from cockpit import scope as SC
from state.models import Endpoint

# Import the in-repo engine directly so the mining is proven, not just the backend parse.
_ENGINE_PATH = Path(__file__).parent.parent / "docker" / "js_mine.py"
_spec = importlib.util.spec_from_file_location("js_mine", _ENGINE_PATH)
jm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jm)  # type: ignore[union-attr]

_SID = "s-jsrecon-0001"
_SCOPE = SC.parse_scope("example.com, *.example.com", resolve=False)

# A Stripe-shaped TEST value, assembled at runtime so no contiguous `sk_live_` literal sits in the
# committed source (GitHub push-protection flags the prefix; this is a fabricated fixture, not a key).
_STRIPE_KEY = "sk_" + "live_" + "0123456789abcdef01234567"

_FIXTURE_JS = "\n".join([
    "var api='/api/v2/account?id=1&role=admin';",
    "axios.get('https://api.example.com/v2/orders?oid=7&include=items');",
    "fetch('https://cdn.thirdparty.net/track.js');",  # OUT of scope
    "const AWS='AKIAIOSFODNN7EXAMPLE';",
    f"const stripe='{_STRIPE_KEY}';",
    'const cfg={api_key:"abcdef0123456789abcdef0123456789"};',
    "//# sourceMappingURL=/static/app.js.map",
])
_JS_URL = "https://app.example.com/static/app.js"


# --------------------------------------------------------------------------- #
# the engine mines correctly
# --------------------------------------------------------------------------- #
def test_engine_mines_endpoints_params_secrets() -> None:
    m = jm.mine_js(_FIXTURE_JS, _JS_URL)
    eps = m["endpoints"]
    # a relative path is resolved to the JS ORIGIN (so it is scope-checkable) ...
    assert "https://app.example.com/api/v2/account?id=1&role=admin" in eps, eps
    # ... an absolute one is kept as-is ...
    assert "https://api.example.com/v2/orders?oid=7&include=items" in eps, eps
    # ... and an out-of-scope one is still surfaced by the engine (the BACKEND filters scope).
    assert "https://cdn.thirdparty.net/track.js" in eps, eps
    assert "id" in m["params"] and "role" in m["params"] and "oid" in m["params"], m["params"]
    types = {s["type"] for s in m["secrets"]}
    assert "aws-access-key-id" in types and "stripe-secret-key" in types, types
    # a value is present on the engine's own output (the backend moves it to loot).
    assert any(s["value"] == "AKIAIOSFODNN7EXAMPLE" for s in m["secrets"])
    print("  engine: relatives resolve to the JS origin, absolutes kept, params + AWS/Stripe secrets mined: PASS")


def test_engine_recovers_source_map() -> None:
    mp = json.dumps({
        "sources": ["src/api/client.ts", "src/config/secret.ts"],
        "sourcesContent": ["// TODO remove hardcoded key before ship\nconst k=1;"],
    })
    sm = jm.parse_source_map(mp, "https://app.example.com/static/app.js.map")
    assert "src/api/client.ts" in sm["recovered_sources"], sm["recovered_sources"]
    assert "src/config/secret.ts" in sm["recovered_sources"]
    assert any("hardcoded key" in c for c in sm["comments"]), sm["comments"]
    print("  engine: a .map recovers original source paths + top-of-file comments: PASS")


def test_engine_collect_lists_script_srcs() -> None:
    html = (
        '<html><head>'
        '<script src="/static/app.js"></script>'
        "<script src='https://cdn.thirdparty.net/vendor.js'></script>"
        '<script src="//assets.example.com/lib.js"></script>'
        '</head></html>'
    )
    srcs = jm.extract_script_srcs(html, "https://app.example.com/")
    assert "https://app.example.com/static/app.js" in srcs, srcs
    assert "https://cdn.thirdparty.net/vendor.js" in srcs
    assert "https://assets.example.com/lib.js" in srcs  # protocol-relative resolved to the page scheme
    print("  engine: collect resolves every <script src> (relative/absolute/protocol-relative) to absolute: PASS")


def test_engine_selftest_passes() -> None:
    assert jm.selftest() == 0
    print("  engine --selftest returns 0 (mines the planted endpoint/param/secret + map): PASS")


# --------------------------------------------------------------------------- #
# the backend parses the engine JSON
# --------------------------------------------------------------------------- #
def _mine_json() -> str:
    return json.dumps({
        "action": "mine",
        "results": [{
            "url": _JS_URL,
            "endpoints": [
                "https://app.example.com/api/v2/account?id=1&role=admin",
                "https://api.example.com/v2/orders?oid=7",
                "https://cdn.thirdparty.net/track.js",  # OUT of scope
            ],
            "params": ["id", "role", "oid"],
            "secrets": [
                {"type": "aws-access-key-id", "value": "AKIAIOSFODNN7EXAMPLE", "verified": True, "context": "x"},
                {"type": "generic-api-key", "value": "abcdef0123456789abcdef0123456789", "verified": False},
            ],
            "source_map": {"map_url": "https://app.example.com/static/app.js.map",
                           "recovered_sources": ["src/api/client.ts"], "comments": ["// todo"]},
        }],
        "error": "",
    })


def test_parse_mine_output_splits_endpoints_secrets_maps() -> None:
    eps, secrets, maps, err = jsrecon.parse_mine_output(_mine_json())
    assert err == "", err
    urls = [e.url for e in eps]
    assert "https://app.example.com/api/v2/account?id=1&role=admin" in urls
    assert any(e.url.endswith("/v2/orders?oid=7") and e.params == ["oid"] for e in eps)
    # secrets carry their source JS url + the value (for the worker to move to loot)
    assert {s["type"] for s in secrets} == {"aws-access-key-id", "generic-api-key"}
    assert all(s["source_url"] == _JS_URL for s in secrets)
    assert any(s["verified"] for s in secrets)
    assert maps and maps[0]["recovered_sources"] == ["src/api/client.ts"]
    print("  parse_mine_output: endpoints (via parse_jsmine) + secrets w/ source + source maps split out: PASS")


# --------------------------------------------------------------------------- #
# scope discipline — the correctness property, both filters, with controls
# --------------------------------------------------------------------------- #
def test_filter_urls_in_scope_keeps_in_drops_out() -> None:
    urls = [
        "https://app.example.com/static/app.js",
        "https://cdn.thirdparty.net/vendor.js",   # OUT
        "https://assets.example.com/lib.js",       # in (wildcard)
    ]
    kept, out_hosts = jsrecon.filter_urls_in_scope(urls, _SCOPE)
    assert "https://app.example.com/static/app.js" in kept
    assert "https://assets.example.com/lib.js" in kept
    assert "cdn.thirdparty.net" in out_hosts
    # CONTROL: an in-scope host is NEVER in the out list -> its JS IS fetched.
    assert "app.example.com" not in out_hosts and "assets.example.com" not in out_hosts
    print("  filter_urls_in_scope: only in-scope JS is fetched, out-of-scope <script src> dropped (control): PASS")


def test_filter_endpoints_in_scope_keeps_in_drops_out() -> None:
    eps = [
        Endpoint(session_id=_SID, url="https://app.example.com/api/x?id=1", params=["id"]),
        Endpoint(session_id=_SID, url="https://cdn.thirdparty.net/track?u=1", params=["u"]),  # OUT
    ]
    kept, out_hosts = jsrecon.filter_endpoints_in_scope(eps, _SCOPE)
    assert [e.url for e in kept] == ["https://app.example.com/api/x?id=1"], [e.url for e in kept]
    assert "cdn.thirdparty.net" in out_hosts
    assert "app.example.com" not in out_hosts  # control
    print("  filter_endpoints_in_scope: a URL mined from a bundle but pointing off-scope never lands (control): PASS")


# --------------------------------------------------------------------------- #
# SECRETS -> LOOT, NEVER FINDING TEXT; verified -> High, unverified -> Low
# --------------------------------------------------------------------------- #
def test_secret_finding_carries_no_value_and_ranks_by_verification() -> None:
    verified = {"type": "aws-access-key-id", "value": "AKIAIOSFODNN7EXAMPLE", "verified": True,
                "source_url": _JS_URL}
    unverified = {"type": "generic-api-key", "value": "abcdef0123456789abcdef0123456789",
                  "verified": False, "source_url": _JS_URL}
    fv = jsrecon._secret_finding(verified, "/loot/eng/jsrecon-x-secrets.txt", _SID, "r1")
    fu = jsrecon._secret_finding(unverified, "/loot/eng/jsrecon-x-secrets.txt", _SID, "r1")
    assert fv.severity == "high", fv.severity          # trufflehog-verified -> High (spec)
    assert fu.severity == "low", fu.severity           # unverified regex match -> Low
    # THE VALUE IS IN NO FIELD OF THE FINDING — the whole serialized record must not contain it.
    blob = json.dumps(vars(fv)) + json.dumps(vars(fu))
    assert "AKIAIOSFODNN7EXAMPLE" not in blob, "a verified secret VALUE must never reach the finding"
    assert "abcdef0123456789abcdef0123456789" not in blob, "an unverified secret VALUE must never reach the finding"
    assert fv.vuln_class == "exposed-secret" and fv.tool == "js-mine"
    print("  a secret -> Finding carrying TYPE+source+masked+loot path, NEVER the value; verified High, unverified Low: PASS")


def test_secret_values_are_written_to_loot() -> None:
    """The value lands in the loot file (the ONLY place it lives), not in an argv or a finding."""
    tmp = Path(tempfile.mkdtemp())
    orig_host, orig_container = jsrecon.loot.host_dir, jsrecon.loot.container_dir
    jsrecon.loot.host_dir = lambda _e: tmp                        # type: ignore[assignment]
    jsrecon.loot.container_dir = lambda _e: "/loot/eng"           # type: ignore[assignment]
    try:
        secrets = [{"type": "aws-access-key-id", "value": "AKIAIOSFODNN7EXAMPLE", "verified": True,
                    "source_url": _JS_URL}]
        path = jsrecon._write_secret_loot("eng", "job1", secrets)
        assert path == "/loot/eng/jsrecon-job1-secrets.txt", path
        written = (tmp / "jsrecon-job1-secrets.txt").read_text(encoding="utf-8")
        assert "AKIAIOSFODNN7EXAMPLE" in written, "the value MUST be in the loot file"
        assert "aws-access-key-id" in written and "True" in written
    finally:
        jsrecon.loot.host_dir = orig_host
        jsrecon.loot.container_dir = orig_container
    print("  the secret VALUE is written to the loot file (the one place it lives): PASS")


# --------------------------------------------------------------------------- #
# gate surface — honest, every named host on the line
# --------------------------------------------------------------------------- #
def test_gate_argv_names_the_engine_and_every_host() -> None:
    argv = jsrecon.gate_argv(jsrecon.JsReconRequest(
        target="https://app.example.com", js_urls=["https://app.example.com/static/app.js"],
        maps=True, verify=True))
    assert argv[0] == "js-mine" and "--mine" in argv
    assert argv.count("-u") == 2, argv           # target + the one JS url both on the surface
    assert "--maps" in argv and "--verify" in argv
    print("  gate_argv: names js-mine + every operator host as -u (the honest surface): PASS")


if __name__ == "__main__":
    test_engine_mines_endpoints_params_secrets()
    test_engine_recovers_source_map()
    test_engine_collect_lists_script_srcs()
    test_engine_selftest_passes()
    test_parse_mine_output_splits_endpoints_secrets_maps()
    test_filter_urls_in_scope_keeps_in_drops_out()
    test_filter_endpoints_in_scope_keeps_in_drops_out()
    test_secret_finding_carries_no_value_and_ranks_by_verification()
    test_secret_values_are_written_to_loot()
    test_gate_argv_names_the_engine_and_every_host()
    print("\nall jsrecon tests pass.")
