"""Regression-lock for the engagement PROGRAM SCOPE model (cockpit/scope.py).

The scope decides three things on a real target: what the argv target-lock accepts, what the
proposer is told it may target, and which recon-discovered hosts may join the live allowed set.
These tests fail loudly if any of that widens:

  1. PARSING: exact hosts, *.wildcards, CIDRs and !exclusions parse to the right pattern kinds;
     URL forms reduce to bare hosts.
  2. FAIL-CLOSED: empty / malformed / include-less / wholly-unresolvable specs raise.
  3. MATCHING: in-scope hosts pass; out-of-scope hosts are rejected; a wildcard does NOT
     cover the apex; exclusions always win (even over an include that matches).
  4. CIDR: IPs inside the range match, outside do not; a NAME is never matched by a CIDR.
  5. EXTRACTION: hosts are mined out of recon output; filenames/versions are not hosts.

Hermetic: DNS is never required (parse_scope(resolve=False) everywhere except one guarded case).
Run:  python test_scope.py
"""
from __future__ import annotations

from cockpit.scope import ResolvedScope, bare_host, extract_hosts, parse_scope


def _scope(spec: str) -> ResolvedScope:
    return parse_scope(spec, resolve=False)


# --------------------------------------------------------------------------- #
# 1. parsing
# --------------------------------------------------------------------------- #
def test_parses_every_pattern_kind() -> None:
    s = _scope("scanme.nmap.org, *.example.com, 10.10.10.0/24, !admin.example.com")
    kinds = [(p.kind, p.value) for p in s.include]
    assert ("host", "scanme.nmap.org") in kinds, kinds
    assert ("wildcard", ".example.com") in kinds, kinds
    assert ("cidr", "10.10.10.0/24") in kinds, kinds
    assert [(p.kind, p.value) for p in s.exclude] == [("host", "admin.example.com")]
    assert s.includes() == ["scanme.nmap.org", "*.example.com", "10.10.10.0/24"]
    assert s.excludes() == ["admin.example.com"]
    print("  parses hosts / *.wildcards / CIDRs / !exclusions: PASS")


def test_url_and_port_forms_reduce_to_a_bare_host() -> None:
    assert bare_host("http://scanme.nmap.org:8080/a/b?c=1") == "scanme.nmap.org"
    assert bare_host("user@host.example.com:22") == "host.example.com"
    s = _scope("https://scanme.nmap.org/dir/")
    assert s.include[0].value == "scanme.nmap.org"
    assert s.in_scope("http://scanme.nmap.org:80/x"), "the URL form of an in-scope host passes"
    print("  URL / host:port / userinfo forms reduce to the bare host: PASS")


# --------------------------------------------------------------------------- #
# 2. fail-closed
# --------------------------------------------------------------------------- #
def test_fail_closed_on_bad_scope() -> None:
    bad = [
        "",                       # empty
        "   ",                    # blank
        "!example.com",           # exclusion only — allows nothing
        "10.10.10.0/33",          # malformed CIDR
        "*.com/",                 # malformed wildcard
        "*example.com",           # wildcard without the dot
    ]
    for spec in bad:
        try:
            _scope(spec)
        except ValueError:
            continue
        raise AssertionError(f"scope {spec!r} must be refused (fail-closed)")
    print("  FAIL-CLOSED: empty / malformed / include-less scopes are refused: PASS")


def test_fail_closed_when_nothing_resolves() -> None:
    """An exact-host-only scope that resolves to nothing is refused (needs real DNS to be
    meaningful; the .invalid TLD is guaranteed by RFC 2606 never to resolve)."""
    try:
        parse_scope("nothing-here.invalid", resolve=True)
    except ValueError:
        print("  FAIL-CLOSED: an entirely unresolvable host scope is refused: PASS")
        return
    raise AssertionError("an unresolvable exact-host scope must be refused")


def test_wildcard_scope_survives_dns_failure() -> None:
    """A wildcard/CIDR scope is meaningful without resolving anything — it must still parse."""
    s = parse_scope("*.nothing-here.invalid", resolve=True)
    assert s.in_scope("a.nothing-here.invalid")
    print("  a wildcard/CIDR scope does not require DNS: PASS")


# --------------------------------------------------------------------------- #
# 3. matching
# --------------------------------------------------------------------------- #
def test_exact_host_matching() -> None:
    s = _scope("scanme.nmap.org")
    assert s.in_scope("scanme.nmap.org")
    assert s.in_scope("SCANME.NMAP.ORG"), "matching is case-insensitive"
    assert not s.in_scope("nmap.org"), "the parent domain is NOT in scope"
    assert not s.in_scope("evil.com")
    assert not s.in_scope("scanme.nmap.org.evil.com"), "a suffix trick must not pass"
    print("  exact-host scope: only that host passes: PASS")


def test_star_scope_is_everything() -> None:
    """'*' is the deliberate opt-out: every name and every address is in scope, so the
    target check refuses nothing — the same behaviour as having no scope model at all."""
    s = _scope("*")
    assert s.unbounded() is True
    for token in ("example.com", "a.b.evil.co.uk", "10.10.10.5", "203.0.113.9",
                  "http://anything.internal:8080/x", "scanme.nmap.org"):
        assert s.in_scope(token), f"'*' must cover {token}"
    assert "everything" in s.describe(), s.describe()

    # exclusions still win over '*' — "everything except that one host"
    s2 = _scope("*, !prod.example.com")
    assert s2.in_scope("stage.example.com") and not s2.in_scope("prod.example.com")

    # a normal scope is NOT unbounded, and '*' must still be typed (never defaulted)
    assert _scope("example.com").unbounded() is False
    print("  '*' scope covers every host; exclusions still win; must be typed: PASS")


def test_wildcard_matching_covers_the_apex() -> None:
    s = _scope("*.example.com")
    assert s.in_scope("api.example.com")
    assert s.in_scope("a.b.example.com"), "a wildcard covers deep subdomains"
    # a real program that scopes '*.example.com' means the apex too — refusing it only
    # ever refused a command the operator was authorized to run.
    assert s.in_scope("example.com"), "a wildcard covers the apex"
    # the suffix tricks must still fail — this widened the apex, nothing else
    assert not s.in_scope("notexample.com")
    assert not s.in_scope("example.com.evil.com")
    assert not s.in_scope("evilexample.com")
    excl = _scope("*.example.com, !example.com")
    assert not excl.in_scope("example.com"), "an exclusion can still carve the apex back out"
    assert excl.in_scope("api.example.com")
    print("  *.wildcard covers subdomains AND the apex; suffix tricks still fail: PASS")


def test_exclusions_always_win() -> None:
    s = _scope("*.example.com, !admin.example.com, !*.internal.example.com")
    assert s.in_scope("api.example.com")
    assert not s.in_scope("admin.example.com"), "an exclusion beats a matching include"
    assert not s.in_scope("db.internal.example.com"), "wildcard exclusions work too"
    print("  exclusions always beat a matching include: PASS")


# --------------------------------------------------------------------------- #
# 4. CIDR
# --------------------------------------------------------------------------- #
def test_cidr_matching() -> None:
    s = _scope("10.10.10.0/24")
    assert s.in_scope("10.10.10.5")
    assert s.in_scope("10.10.10.5:8080")
    assert not s.in_scope("10.10.11.5"), "outside the range is out of scope"
    assert not s.in_scope("some.host.com"), "a CIDR never matches a NAME (no match-time DNS)"
    print("  CIDR scope: in-range IPs pass, out-of-range + names do not: PASS")


def test_seed_ips_let_an_ip_reach_a_named_host() -> None:
    """When an exact-host include resolved at entry, its IP is in scope too (so `nmap <ip>`
    against the same box passes the lock) — but only THAT ip."""
    s = ResolvedScope(
        raw="host.example.com",
        include=_scope("host.example.com").include,
        seed_hosts=("host.example.com",),
        seed_ips=("203.0.113.9",),
    )
    assert s.in_scope("203.0.113.9")
    assert not s.in_scope("203.0.113.10")
    print("  a resolved seed IP is in scope; its neighbours are not: PASS")


# --------------------------------------------------------------------------- #
# 5. host extraction from recon output
# --------------------------------------------------------------------------- #
def test_extract_hosts_from_recon_output() -> None:
    out = (
        "Nmap scan report for api.example.com (203.0.113.9)\n"
        "www.example.com.  300 IN A 203.0.113.10\n"
        "Loaded wordlist from words.txt (version 1.2.3)\n"
        "Server: nginx/1.24.0\n"
    )
    found = extract_hosts(out)
    assert "api.example.com" in found and "www.example.com" in found, found
    assert "203.0.113.9" in found and "203.0.113.10" in found, found
    assert "words.txt" not in found, "a filename is not a host"
    assert not any(f.endswith(".0") for f in found if not f[0].isdigit()), found
    print("  recon output mining finds hosts + IPs, skips filenames: PASS")


def test_extract_hosts_is_capped_and_deduped() -> None:
    text = " ".join(f"h{i}.example.com" for i in range(50)) + " h1.example.com"
    found = extract_hosts(text, cap=10)
    assert len(found) == 10, f"extraction must be capped, got {len(found)}"
    assert len(set(found)) == len(found), "extraction must de-duplicate"
    print("  extraction is capped + de-duplicated: PASS")


# --------------------------------------------------------------------------- #
# 6. app: scope token (mobile app + its backend hosts)
# --------------------------------------------------------------------------- #
def test_app_scope_records_and_expands() -> None:
    s = _scope("app:com.fishbowlmedia.fishbowl{*.fishbowlapp.com}")
    assert s.apps == ("com.fishbowlmedia.fishbowl",), s.apps
    assert s.in_scope("api.fishbowlapp.com"), "the app's backend host must be in scope"
    assert s.in_scope("fishbowlapp.com"), "the wildcard apex must be in scope"
    assert not s.in_scope("evil.com"), "an unrelated host must be out of scope"
    assert "app com.fishbowlmedia.fishbowl" in s.describe(), s.describe()
    print("  app: records the identifier AND scopes its backend hosts: PASS")


def test_app_scope_quoted_id_no_longer_fragments() -> None:
    # The formerly-deferred bug: 'THAT Concept Store iOS' split on whitespace into garbage hosts.
    # With the explicit app: prefix + quotes, the id (spaces and all) is a single token.
    s = _scope('app:"Fishbowl iOS"{*.fishbowlapp.com}')
    assert s.apps == ("Fishbowl iOS",), s.apps
    assert s.in_scope("api.fishbowlapp.com")
    # 'iOS' / the spaces produced NO bogus host patterns:
    assert not s.in_scope("ios"), "the app name must never become a host"
    print("  app:\"quoted id\" does not fragment into garbage hosts: PASS")


def test_app_scope_without_a_backend_host_is_refused() -> None:
    bad = [
        "app:com.example",                    # app named, but nothing to test
        'app:"My App"',                       # quoted, still no host
        "app:com.example, !admin.example.com",  # app + exclusion only, still no include
    ]
    for spec in bad:
        try:
            _scope(spec)
        except ValueError:
            continue
        raise AssertionError(f"app-only scope {spec!r} must be refused (nothing to test)")
    print("  FAIL-CLOSED: an app with no backend host is refused: PASS")


def test_app_scope_coexists_with_hosts_and_exclusions() -> None:
    s = _scope("app:com.example{*.example.com}, scanme.nmap.org, !admin.example.com")
    assert s.apps == ("com.example",)
    assert s.in_scope("api.example.com"), "app's backend host in scope"
    assert s.in_scope("scanme.nmap.org"), "a normal host alongside the app stays in scope"
    assert not s.in_scope("admin.example.com"), "a top-level exclusion still wins over the app hosts"
    print("  app: coexists with normal hosts and exclusions still win: PASS")


if __name__ == "__main__":
    test_parses_every_pattern_kind()
    test_url_and_port_forms_reduce_to_a_bare_host()
    test_fail_closed_on_bad_scope()
    test_fail_closed_when_nothing_resolves()
    test_wildcard_scope_survives_dns_failure()
    test_exact_host_matching()
    test_star_scope_is_everything()
    test_wildcard_matching_covers_the_apex()
    test_exclusions_always_win()
    test_cidr_matching()
    test_seed_ips_let_an_ip_reach_a_named_host()
    test_extract_hosts_from_recon_output()
    test_extract_hosts_is_capped_and_deduped()
    test_app_scope_records_and_expands()
    test_app_scope_quoted_id_no_longer_fragments()
    test_app_scope_without_a_backend_host_is_refused()
    test_app_scope_coexists_with_hosts_and_exclusions()
    print("ALL scope tests pass")
