"""Build #13 part 3 — the payload templates (spec §3.4).

These templates exist because the ways to get a token out of a target are class-specific and
the failure mode of getting one subtly wrong is SILENCE — indistinguishable from a target that
was not vulnerable. So the properties worth locking are the ones whose violation would be
invisible in use:

  * **Every payload actually carries the token, against the configured zone.** A payload
    rendered with an empty zone still looks like a payload.
  * **The token is the label immediately LEFT of the zone in every name.** This is the one that
    would rot quietly. `oob/server.py` reads that label, so an exfil template that appended
    output on the right — `<token>.<data>.<zone>` — would produce hits that correlate to
    nothing, in production, on a real engagement, and look exactly like no callback at all.
    Checked by feeding every DNS name in every rendered payload to the SERVER'S OWN parser
    rather than to a regex written here.
  * **The module has no transport.** It renders a string and stops. A generator that could also
    deliver is a different tool, and every gate in this project assumes a human in that loop.

Run: python test_oob_templates.py
"""

from __future__ import annotations

import ast
import importlib.util
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from oob import config as oob_config  # noqa: E402
from oob import templates, tokens  # noqa: E402

# SCRATCH STORE — see test_oob_poll.py for why. clear() on the real store would destroy a live
# canary's read secret, whose only other copy is a 0700 file on a VPS.
_SCRATCH = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
oob_config.DB_PATH = Path(_SCRATCH.name) / "oob-test.db"
tokens.DB_PATH = oob_config.DB_PATH

BACKEND = Path(__file__).resolve().parent
TEMPLATES_PATH = BACKEND / "oob" / "templates.py"
SERVER_PATH = BACKEND.parent / "oob" / "server.py"

# The deployable, loaded by path — the same way test_oob_server.py loads it. Its parser is the
# authority on what the canary will read out of a qname, which is exactly why the templates are
# checked against it instead of against a second regex.
_spec = importlib.util.spec_from_file_location("hackpit_oob_server_tpl", SERVER_PATH)
assert _spec and _spec.loader, f"cannot load {SERVER_PATH}"
S = importlib.util.module_from_spec(_spec)
sys.modules["hackpit_oob_server_tpl"] = S
_spec.loader.exec_module(S)

ZONE = "oob.example.net"
ENGAGEMENT = "_test-oob-templates"

# Runs of characters that are legal inside a DNS name. Everything else in a payload — a
# backtick, a quote, a slash, a colon, `${` — terminates the run, which is exactly how the
# name is delimited at the point it is actually resolved.
_NAME_RUN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-]*")


def _names_in(payload: str, zone: str) -> list[str]:
    """Every DNS name inside a rendered payload that lands in the canary's zone."""
    return [
        run.rstrip(".") for run in _NAME_RUN.findall(payload)
        if run.rstrip(".").lower().endswith("." + zone)
    ]


def _token() -> str:
    oob_config.init_db()
    tokens.init_db()
    return tokens.mint(ENGAGEMENT, "step-1", "template test")["token"]


def _cleanup() -> None:
    tokens.clear(ENGAGEMENT)
    oob_config.clear()


# --------------------------------------------------------------------------- #
# every template renders, and renders the real token
# --------------------------------------------------------------------------- #
def test_every_template_renders_a_payload_carrying_the_token_and_zone() -> None:
    """Drawn from the real TEMPLATES tuple, so a template added tomorrow is covered by nobody
    remembering to add it here (backend/AGENTS.md §1)."""
    token = _token()
    rendered = templates.render_all(token, zone=ZONE)
    assert len(rendered) == len(templates.TEMPLATES), rendered
    for item in rendered:
        payload = item["payload"]
        assert payload.strip(), f"{item['id']} rendered an empty payload"
        assert token in payload, f"{item['id']} does not carry the token: {payload!r}"
        assert ZONE in payload, f"{item['id']} does not carry the zone: {payload!r}"
        assert item["proves"].strip(), f"{item['id']} has no `proves` line for the write-up"
        assert item["sink"].strip(), f"{item['id']} does not say where to paste it"
    _cleanup()
    print(f"  all {len(rendered)} templates render a payload carrying the token and zone: PASS")


def test_the_token_is_the_label_left_of_the_zone_in_every_rendered_name() -> None:
    """THE correctness property, and the one whose violation would be silent.

    Every DNS name in every payload is handed to the canary's own `token_from_qname`. An exfil
    template that put command output to the RIGHT of the token would still look like a working
    payload, still be pasted into a real target, and produce hits that correlate to nothing.
    """
    token = _token()
    checked = 0
    for item in templates.render_all(token, zone=ZONE):
        names = _names_in(item["payload"], ZONE)
        assert names, f"{item['id']} contains no resolvable name in the zone: {item['payload']!r}"
        for name in names:
            got = S.token_from_qname(name, ZONE)
            assert got == token, (
                f"{item['id']}: the canary would read {got!r} out of {name!r}, not {token!r} — "
                f"every hit from this payload would correlate to nothing"
            )
            checked += 1
    _cleanup()
    print(f"  the canary's own parser reads the right token out of all {checked} rendered "
          "names: PASS")


def test_the_exfil_template_puts_output_to_the_left_and_says_so() -> None:
    """The specific case the property above generalises — asserted directly so the reason
    survives if the loop is ever narrowed."""
    token = _token()
    exfil = templates.render("rce-exfil-unix", token, zone=ZONE)
    payload = exfil["payload"]
    assert payload.index("whoami") < payload.index(token), (
        f"command output is to the RIGHT of the token in {payload!r} — the canary reads the "
        f"label left of the zone, so this would correlate to nothing"
    )
    assert "left" in exfil["note"].lower(), (
        "the note must say which side output goes on — it is the one thing an operator "
        "editing this payload has to know"
    )
    # And the Callback helper's own contract.
    cb = templates.Callback(token=token, zone=ZONE)
    assert cb.prefixed("data") == f"data.{token}.{ZONE}", cb.prefixed("data")
    assert S.token_from_qname(cb.prefixed("whoami"), ZONE) == token
    _cleanup()
    print("  the exfil template prefixes output and documents the side: PASS")


def test_all_five_classes_from_the_spec_are_covered() -> None:
    """SSRF, XXE, blind RCE, blind SQLi, JNDI — the classes §3.4 names."""
    covered = set(templates.VULN_CLASSES)
    for required in ("ssrf", "xxe", "rce", "sqli", "jndi"):
        assert required in covered, f"spec §3.4 names {required!r}; the catalog has {covered}"
        assert templates.render_all(_token(), zone=ZONE, vuln_class=required), (
            f"{required} is declared but renders nothing"
        )
    _cleanup()
    print(f"  all 5 spec classes are covered by {len(templates.TEMPLATES)} templates: PASS")


# --------------------------------------------------------------------------- #
# refusing to render something that can never work
# --------------------------------------------------------------------------- #
def test_rendering_without_a_zone_or_token_is_refused() -> None:
    """A payload built against no zone can never produce a hit — and would be pasted into a
    real target before anyone noticed, then read as "not vulnerable"."""
    oob_config.init_db()
    oob_config.clear()  # no configured zone
    for token, zone in ((_token(), ""), ("", ZONE), ("", "")):
        try:
            templates.callback_for(token, zone)
        except ValueError:
            continue
        raise AssertionError(f"rendered a payload with token={token!r} zone={zone!r}")

    # With nothing configured, the implicit-zone path must refuse too rather than rendering
    # `<token>.` against an empty string.
    try:
        templates.render("ssrf-url", _token())
    except ValueError:
        pass
    else:
        raise AssertionError("rendered against the configured zone while none is configured")
    _cleanup()
    print("  rendering with no zone or no token is refused, including implicitly: PASS")


def test_the_catalog_carries_no_payload() -> None:
    """The picker is shown BEFORE a token exists. A catalog entry with a payload in it would
    be a payload with no mint record behind it — a name that correlates to nothing."""
    for entry in templates.catalog():
        assert "payload" not in entry, f"{entry['id']} leaks a payload into the catalog"
    assert len(templates.catalog()) == len(templates.TEMPLATES)
    print("  the pre-mint catalog carries descriptions and no payloads: PASS")


def test_placeholders_are_visibly_placeholders() -> None:
    """[[arsenal-expand-polish]]: a placeholder that looks like a value gets pasted as one."""
    token = _token()
    for item in templates.render_all(token, zone=ZONE):
        for suspect in ("<lhost>", "<rhost>", "127.0.0.1", "example.com", "attacker.com"):
            assert suspect not in item["payload"], (
                f"{item['id']} contains {suspect!r} — a plausible-looking value an operator "
                f"would paste without substituting"
            )
    assert templates.PLACEHOLDER == "<FILL>", templates.PLACEHOLDER
    _cleanup()
    print("  no template contains a plausible-looking fake value: PASS")


# --------------------------------------------------------------------------- #
# it renders, and that is all it does
# --------------------------------------------------------------------------- #
_BANNED_IMPORTS = {"socket", "subprocess", "urllib", "httpx", "requests", "os", "http",
                   "ftplib", "smtplib", "asyncio", "pickle"}
_BANNED_CALLS = {"eval", "exec", "compile", "system", "popen", "Popen", "urlopen",
                 "connect", "sendto", "send", "run", "check_output", "iter_run"}


def test_the_template_module_has_no_transport() -> None:
    """It renders a string and stops — the same line obfuscation.operator_oneliner draws."""
    tree = ast.parse(TEMPLATES_PATH.read_text(encoding="utf-8"))
    offences: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offences += [f"line {node.lineno}: import {a.name}"
                         for a in node.names if a.name.split(".")[0] in _BANNED_IMPORTS]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in _BANNED_IMPORTS:
                offences.append(f"line {node.lineno}: from {node.module} import ...")
        elif isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in _BANNED_CALLS:
                offences.append(f"line {node.lineno}: {name}()")
    assert not offences, "the template module can deliver what it renders:\n  " + "\n  ".join(offences)

    # POSITIVE CONTROL — the same walk on each planted delivery form.
    for planted in (
        "import socket\n",
        "from urllib.request import urlopen\n",
        "def f(p):\n    return executor.iter_run(p)\n",
    ):
        found = False
        for node in ast.walk(ast.parse(planted)):
            if isinstance(node, ast.Import):
                found |= any(a.name.split(".")[0] in _BANNED_IMPORTS for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                found |= (node.module or "").split(".")[0] in _BANNED_IMPORTS
            elif isinstance(node, ast.Call):
                fn = node.func
                found |= isinstance(fn, ast.Name) and fn.id in _BANNED_CALLS
                found |= isinstance(fn, ast.Attribute) and fn.attr in _BANNED_CALLS
        assert found, f"the no-transport scan missed a planted {planted!r}"
    print("  the template module imports no client and makes no delivery call (3 controls): PASS")


if __name__ == "__main__":
    print("== OOB canary payload templates (spec §3.4) ==")
    test_every_template_renders_a_payload_carrying_the_token_and_zone()
    test_the_token_is_the_label_left_of_the_zone_in_every_rendered_name()
    test_the_exfil_template_puts_output_to_the_left_and_says_so()
    test_all_five_classes_from_the_spec_are_covered()
    test_rendering_without_a_zone_or_token_is_refused()
    test_the_catalog_carries_no_payload()
    test_placeholders_are_visibly_placeholders()
    test_the_template_module_has_no_transport()
    print("ALL OOB payload template tests pass")
