"""Authenticated-scan + scan-policy locks (build #18 items 3, 6 and 7).
Run:  python test_auth_scan.py

THE INVARIANTS:
  * items 6/7 — the LOGIN PASSWORD reaches ZAP on stdin and exists on no model, in no argv and
    in no record. Tier 2 needs no credential at all.
  * item 3 — a policy is applied FROM A KNOWN BASELINE and READ BACK, because ZAP persists its
    configuration and "what is set" is otherwise whatever a previous run wrote.
  * neither adds a gate. An unknown policy name falls back to the default; an auth context that
    would not fully take WARNS and is still returned.
"""

from __future__ import annotations

import ast
import inspect

from cockpit import proxy


def _scan(**kw):
    base = dict(target_url="https://lab.example.com/api?q=1", approved=True, dangerous_ack=True)
    base.update(kw)
    return proxy.ScanStartRequest(**base)


# --------------------------------------------------------------------------- #
# item 3 — scan policy
# --------------------------------------------------------------------------- #
def test_an_unknown_policy_name_is_a_DEFAULT_and_never_a_refusal() -> None:
    """A typo'd policy name should cost a wider scan the operator can see reported back, not a
    403 that reads like a safety verdict. Nothing about a policy decides whether a scan happens."""
    assert proxy.scan_policy_for("targetted-web").name == proxy.DEFAULT_SCAN_POLICY
    assert proxy.scan_policy_for("").name == proxy.DEFAULT_SCAN_POLICY
    assert proxy.scan_policy_for("targeted-web").name == "targeted-web"
    # and it is genuinely reachable, so the fallback is not hiding a broken name
    assert proxy.SCAN_POLICIES["targeted-web"].disabled_scanners, "targeted-web disables nothing"
    print("  an unknown policy falls back to the default rather than refusing: PASS")


def test_every_disabled_rule_carries_a_REASON() -> None:
    """A bare list of plugin ids is unreviewable. 'off because the target is not a C server' is a
    claim a human can disagree with, which is the only kind worth writing down."""
    for name, policy in proxy.SCAN_POLICIES.items():
        for plugin_id, reason in policy.disabled_scanners.items():
            assert isinstance(plugin_id, int), f"{name}: plugin id {plugin_id!r} is not an int"
            assert len(reason) > 25, (
                f"{name}: rule {plugin_id} is disabled with the non-reason {reason!r}"
            )
    print("  every disabled rule states why, in a sentence: PASS")


def test_the_policy_is_applied_from_a_KNOWN_BASELINE() -> None:
    """ZAP persists `-config` values and scanner state alike. A disable-only apply would inherit
    whatever the previous scan switched off and call it this policy — the same class of mistake
    as measuring `api.key` against a config a previous run wrote."""
    src = inspect.getsource(proxy.apply_scan_policy)
    enable_at = src.find("_ACTION_ENABLE_ALL_SCANNERS")
    disable_at = src.find("_ACTION_DISABLE_SCANNERS")
    assert enable_at != -1, "apply_scan_policy never re-enables everything first"
    assert disable_at != -1, "apply_scan_policy never disables anything"
    assert enable_at < disable_at, (
        "the disable runs before the enable-all, so enable-all would undo it — the policy would "
        "be whatever ZAP already held"
    )
    assert "_ACTION_POLICY_STRENGTH" in src and "_ACTION_POLICY_THRESHOLD" in src, (
        "strength and threshold are not stated explicitly, so they inherit the daemon's history"
    )
    assert "observed_scan_policy" in src, "apply_scan_policy does not read the policy back"
    print("  enable-all, then state strength/threshold, then disable, then READ BACK: PASS")


def test_a_failed_policy_read_is_told_apart_from_nothing_disabled() -> None:
    """`scanners_seen == 0` means THE READ FAILED. Reporting it as 'no rules are disabled' is the
    confident zero build #17 found three of."""
    doc = proxy.ObservedPolicy.model_fields["scanners_seen"].description or ""
    assert "read FAILED" in doc, "the model does not say what a zero means"
    assert "not_held" in proxy.ObservedPolicy.model_fields, (
        "a plugin id requested off but not reported off is silently counted as a success"
    )
    print("  a failed read and an empty disabled set are different fields: PASS")


def test_applying_a_policy_never_refuses_a_scan() -> None:
    """A scan with the default policy is a WORSE scan, not an unsafe one. Refusing over a policy
    would be a prohibition build #18 is explicitly not allowed to add."""
    src = inspect.getsource(proxy.apply_scan_policy)
    tree = ast.parse(src)
    raises = [n for n in ast.walk(tree) if isinstance(n, ast.Raise)]
    assert not raises, f"apply_scan_policy raises ({len(raises)} sites) — it must warn and continue"
    print("  a policy that would not apply leaves a wider scan, not a refusal: PASS")


# --------------------------------------------------------------------------- #
# items 6 and 7 — the authenticated context
# --------------------------------------------------------------------------- #
def test_no_model_anywhere_has_a_PASSWORD_field() -> None:
    """The version of the property a future edit cannot quietly undo: there is nowhere for a
    login password to live. The credential is NAMED and resolved server-side out of the vault."""
    fields = set(proxy.AuthContextRequest.model_fields) | set(proxy.CredentialRef.model_fields)
    fields |= set(proxy.AuthContext.model_fields)
    for banned in ("password", "secret", "passwd", "pass", "credentials"):
        assert banned not in fields, (
            f"a {banned!r} field exists on the auth models — the whole point is that there is "
            "no field for it and the secret is resolved from the vault server-side"
        )
    # control: the ACCOUNT NAME is reported, because an operator needs to know who a scan ran as
    assert "user_name" in proxy.AuthContext.model_fields
    print("  no password field on any auth model; the account name is reported: PASS")


def test_the_login_secret_goes_on_STDIN() -> None:
    """A GET would put the password into ZAP's own recorded history, onto the `docker exec` argv
    that `ps` can read, and into the artefact a report is rendered from.

    AST, not substring: the prose in that function names both call paths."""
    tree = ast.parse(inspect.getsource(proxy.apply_auth_context))
    creds_posted = False
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id != "_api_post":
            continue
        rendered = ast.unparse(node)
        if "_ACTION_SET_USER_CREDS" in rendered:
            creds_posted = True
    assert creds_posted, (
        "setAuthenticationCredentials is not called through _api_post — the password would go "
        "into a URL"
    )
    # ...and it is NOT also sent by the GET path
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_api_get"):
            assert "_ACTION_SET_USER_CREDS" not in ast.unparse(node), (
                "the credential setter is reachable through _api_get"
            )
    print("  the login credential is delivered on stdin, never in a URL: PASS")


def test_the_vault_is_the_only_source_of_a_login_secret() -> None:
    """Credentials come from state/credvault's store, never from an argv and never from a request
    body. One reader, and it is named."""
    src = inspect.getsource(proxy._resolve_login_secret)
    assert "state_store.load" in src or "store.load" in src, (
        "_resolve_login_secret does not read the state vault"
    )
    # every other function in the module must go through it rather than reading creds itself
    module_src = inspect.getsource(proxy)
    assert module_src.count("state_store.load") <= 1, (
        "more than one place in cockpit/proxy.py reads the credential store"
    )
    print("  exactly one function reads a stored credential: PASS")


def test_a_named_credential_that_is_missing_is_a_NOT_FOUND_not_a_silent_downgrade() -> None:
    """Scanning unauthenticated instead would report zero findings off a login page — which reads
    exactly like a secure application. That is the failure shape this whole area exists around."""
    src = inspect.getsource(proxy._resolve_login_secret)
    assert "ProxyRefused" in src and 'gate="notfound"' in src, (
        "a missing credential does not raise, so the scan would quietly run unauthenticated"
    )
    assert "zero findings" in src, "the refusal does not say WHY it matters"
    print("  a missing credential refuses loudly instead of scanning unauthenticated: PASS")


def test_the_context_regex_quotes_the_origin() -> None:
    """A host contains dots. An unquoted regex would read every dot as 'any character' and pull
    unrelated domains into the context — the same class of bug as a target smuggling a `&` into
    the scan URL."""
    regex = proxy.context_regex_for("https://shop.example.com/en/cart")
    assert regex.startswith(r"\Q") and r"\E" in regex, regex
    assert "shop.example.com" in regex and "/en/cart" not in regex, (
        f"the context is not the ORIGIN: {regex}"
    )
    # a port survives, because an origin includes it
    assert ":8443" in proxy.context_regex_for("https://h.example.com:8443/x")
    print("  the include regex quotes the literal origin, path excluded: PASS")


def test_a_context_carries_a_prefix_so_cleanup_owns_only_its_own() -> None:
    """A context created by a human in ZAP's UI is somebody else's decision, and removing it
    would be this module reaching outside what it owns."""
    name = proxy.context_name_for("https://Shop.Example.COM/x")
    assert name == "hackpit-shop.example.com", name
    src = inspect.getsource(proxy.clear_auth_contexts)
    assert "CONTEXT_NAME_PREFIX" in src, "the cleanup does not filter by prefix — it removes all"
    print("  contexts are prefixed and the cleanup removes only HackPit's: PASS")


def test_apply_auth_context_WARNS_and_continues() -> None:
    """A missing indicator, an auth method that would not take — each is a weaker scan, not a
    refusal. The one thing that stops is a named credential that is not in the vault."""
    src = inspect.getsource(proxy.apply_auth_context)
    assert "warnings.append" in src, "nothing warns; failures are swallowed"
    # the ONLY refusals are the two not-founds
    tree = ast.parse(src)
    gates = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            for kw in node.exc.keywords:
                if kw.arg == "gate":
                    gates.add(ast.literal_eval(kw.value))
    assert gates <= {"notfound"}, (
        f"apply_auth_context refuses at {sorted(gates)} — the only legitimate refusal here is a "
        "not-found, because everything else is a weaker context rather than an unsafe one"
    )
    print("  it warns and continues; the only refusal is a not-found: PASS")


def test_the_password_token_omission_is_warned_about() -> None:
    """ZAP substitutes `{%password%}` LITERALLY. Without it the login POST sends the token text,
    authenticates nothing, and the scan runs unauthenticated while every indicator says the login
    failed — a confidently wrong scan."""
    src = inspect.getsource(proxy.apply_auth_context)
    assert "ZAP_PASSWORD_TOKEN not in" in src, "a login body missing the password token is silent"
    assert proxy.ZAP_PASSWORD_TOKEN == "{%password%}"
    assert proxy.ZAP_USERNAME_TOKEN == "{%username%}"
    print("  a login body with no password token is warned about: PASS")


# --------------------------------------------------------------------------- #
# the scan URL — the existing lock, extended rather than replaced
# --------------------------------------------------------------------------- #
def test_a_scan_with_no_context_is_UNCHANGED() -> None:
    """Build #18 is additive. A target with no configured context must produce exactly the URL it
    produced before, or every existing measurement stops comparing."""
    url = proxy.scan_url_for(_scan())
    assert url.startswith(proxy._ACTION_SCAN), url
    assert "contextId" not in url and "userId" not in url, url
    assert "inScopeOnly=false" in url, url
    print("  with no context the scan URL is exactly what it was: PASS")


def test_a_user_switches_the_scan_to_scanAsUser() -> None:
    """ZAP can only RE-AUTHENTICATE mid-scan if it knows who to re-authenticate as, and that is
    what `scanAsUser` carries. Without a user it stays `scan` with the context attached."""
    ctx_only = proxy.scan_url_for(_scan(), context_id="3")
    assert ctx_only.startswith(proxy._ACTION_SCAN) and "contextId=3" in ctx_only, ctx_only

    as_user = proxy.scan_url_for(_scan(), context_id="3", user_id="0")
    assert as_user.startswith(proxy._ACTION_SCAN_AS_USER), as_user
    assert "contextId=3" in as_user and "userId=0" in as_user, as_user
    print("  a user switches to scanAsUser; a bare context stays on scan: PASS")


def test_the_target_still_cannot_smuggle_a_parameter_through_the_context_path() -> None:
    """Part 3's lock, restated for the new branches. A target carrying `&recurse=true` must not
    broaden a scan, on ANY of the three URL shapes."""
    smuggle = _scan(target_url="https://lab.example.com/api?q=1&recurse=true")
    for kwargs in ({}, {"context_id": "3"}, {"context_id": "3", "user_id": "0"}):
        url = proxy.scan_url_for(smuggle, **kwargs)
        assert "&recurse=true" not in url.split("?", 1)[1].replace("recurse=false", ""), url
        assert "recurse=false" in url, f"the scan's own recurse parameter went missing: {url}"
    # control: recursion can still be turned on legitimately
    assert "recurse=true" in proxy.scan_url_for(_scan(recurse=True), context_id="3")
    print("  a smuggled parameter is encoded on every URL shape, control holds: PASS")


def test_scan_url_for_stays_PURE() -> None:
    """It is one half of 'the thing the gate scoped is the thing that gets attacked'. A lookup
    inside it is the mistake clash_refusal records having made — a pure check that reached for
    Docker passed locally and failed in CI, twice."""
    tree = ast.parse(inspect.getsource(proxy.scan_url_for))
    called = {
        (n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", ""))
        for n in ast.walk(tree) if isinstance(n, ast.Call)
    }
    for banned in ("_api_get", "_api_post", "observed_auth_context", "run", "Popen"):
        assert banned not in called, (
            f"scan_url_for calls {banned!r} — it must stay pure and take the ids as arguments"
        )
    print("  scan_url_for takes the ids as arguments and stays pure: PASS")


if __name__ == "__main__":
    print("== scan policy + authenticated scanning (build #18 items 3, 6, 7) ==")
    test_an_unknown_policy_name_is_a_DEFAULT_and_never_a_refusal()
    test_every_disabled_rule_carries_a_REASON()
    test_the_policy_is_applied_from_a_KNOWN_BASELINE()
    test_a_failed_policy_read_is_told_apart_from_nothing_disabled()
    test_applying_a_policy_never_refuses_a_scan()
    test_no_model_anywhere_has_a_PASSWORD_field()
    test_the_login_secret_goes_on_STDIN()
    test_the_vault_is_the_only_source_of_a_login_secret()
    test_a_named_credential_that_is_missing_is_a_NOT_FOUND_not_a_silent_downgrade()
    test_the_context_regex_quotes_the_origin()
    test_a_context_carries_a_prefix_so_cleanup_owns_only_its_own()
    test_apply_auth_context_WARNS_and_continues()
    test_the_password_token_omission_is_warned_about()
    test_a_scan_with_no_context_is_UNCHANGED()
    test_a_user_switches_the_scan_to_scanAsUser()
    test_the_target_still_cannot_smuggle_a_parameter_through_the_context_path()
    test_scan_url_for_stays_PURE()
    print("ALL authenticated-scan and scan-policy locks pass")
