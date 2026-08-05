"""Build #13 part 3 — OOB canary token minting and correlation.

A blind SSRF proof is a hit that lands on a canary minutes after the request that caused it,
often from an address that has nothing to do with the target you poked. The hit on its own
says only "something reached the internet". What makes it a finding is knowing WHICH TEST
caused it — so the correlation, not the hit, is the product (spec §3.2).

That puts three properties under test here:

  * **DNS-label-safe.** The token travels as a hostname label through a resolver chain that
    HackPit does not control. A token that a resolver mangles, rejects or normalises into a
    different string arrives as an uncorrelatable hit — the exact failure the whole component
    exists to prevent. Locked by the label grammar and the case-insensitive lookup.
  * **Unguessable.** The canary is internet-facing and its log holds a client's internal
    hostnames. A predictable token lets an outsider poison an engagement's evidence or probe
    for one. `secrets`, never `random` — locked structurally, because both read identically
    at the call site and only one is a CSPRNG.
  * **Executes nothing.** This module is imported by the app and, later, driven by the poll
    client on a timer with no approval of its own. Same position the state package sits in,
    so it gets the same AST lock.

Hermetic: no network, no sockets, no server. Writes to the real gitignored sessions.db under
a throwaway engagement id that each test clears, the way test_state.py does.

Run: python test_oob_tokens.py
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from oob import tokens  # noqa: E402

tokens.init_db()

_ENG = "test-oob-engagement"
_ENG2 = "test-oob-engagement-other"

OOB_DIR = Path(__file__).resolve().parent / "oob"

# RFC 1123 host label, tightened: lowercase alphanumeric, letter-first, no hyphens.
# Letter-first because a leading digit is legal in a label but still trips validators in
# older resolvers and libraries; hyphen-free because a leading/trailing hyphen is not, and
# excluding the character entirely removes the class of bug rather than checking for it.
_LABEL = re.compile(r"^[a-z][a-z0-9]*$")


def _reset() -> None:
    tokens.clear(_ENG)
    tokens.clear(_ENG2)


# --------------------------------------------------------------------------- #
# the label has to survive a resolver chain we do not control
# --------------------------------------------------------------------------- #
def test_every_minted_token_is_dns_label_safe() -> None:
    """Minted tokens are lowercase, letter-first, alphanumeric and inside the 63-byte limit.

    Asserted over a real population from the real generator rather than one hand-written
    example, per backend/AGENTS.md: a change to the alphabet is covered by nobody
    remembering to update this test.
    """
    _reset()
    minted = [tokens.mint(_ENG)["token"] for _ in range(200)]
    for tok in minted:
        assert _LABEL.match(tok), f"{tok!r} is not a safe DNS label"
        assert len(tok) <= 63, f"{tok!r} is {len(tok)} bytes; a DNS label caps at 63"
        assert tok == tok.lower(), f"{tok!r} is not lowercase"
        assert tokens.is_token(tok), f"the generator produced {tok!r} which its own validator rejects"
    print(f"  all {len(minted)} minted tokens are DNS-label-safe and self-validating: PASS")


def test_a_token_is_long_enough_to_be_unguessable() -> None:
    """Length and alphabet together have to put the token out of brute-force reach.

    A canary token is a bearer secret in the DNS: anyone who guesses one can write into a
    client's evidence log. 60 bits is the floor this asserts.
    """
    _reset()
    tok = tokens.mint(_ENG)["token"]
    assert len(tok) >= 12, f"a {len(tok)}-char token is too short to be unguessable"
    bits = len(tok) * (len(tokens.ALPHABET).bit_length() - 1)
    assert bits >= 60, f"{len(tok)} chars over a {len(tokens.ALPHABET)}-symbol alphabet is only ~{bits} bits"
    assert len(set(tokens.ALPHABET)) == len(tokens.ALPHABET), "the alphabet repeats a symbol"
    print(f"  a token carries ~{bits} bits over a {len(tokens.ALPHABET)}-symbol alphabet: PASS")


def test_minted_tokens_do_not_collide() -> None:
    """Two live tokens that collide would cross-correlate two engagements' evidence."""
    _reset()
    minted = [tokens.mint(_ENG)["token"] for _ in range(300)]
    minted += [tokens.mint(_ENG2)["token"] for _ in range(200)]
    assert len(set(minted)) == len(minted), "the minter produced a duplicate token"
    print(f"  {len(minted)} tokens minted across 2 engagements, no collision: PASS")


def test_the_minter_uses_a_csprng() -> None:
    """Structural lock: `secrets`, never `random`.

    `random.choice` and `secrets.choice` are the same line to read and the same result to
    eyeball — one is seeded from the clock and predictable from a handful of outputs. No
    behavioural test can tell them apart, so this is asserted against the AST.
    """
    tree = ast.parse((OOB_DIR / "tokens.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "secrets" in imported, "tokens.py does not import secrets — what is minting the token?"
    assert "random" not in imported, (
        "tokens.py imports `random`. A canary token is a bearer secret in the DNS; it must "
        "come from a CSPRNG."
    )
    print("  the minter draws from secrets, never random: PASS")


# --------------------------------------------------------------------------- #
# correlation: the hit that lands ten minutes later
# --------------------------------------------------------------------------- #
def test_a_hit_resolves_back_to_the_test_that_caused_it() -> None:
    """The product: token -> (engagement, step, note, minted-at)."""
    _reset()
    rec = tokens.mint(_ENG, step_id="step-7", note="blind SSRF on /api/fetch?url=")
    got = tokens.correlate(rec["token"])
    assert got is not None, "a freshly minted token did not correlate"
    assert got["engagement_id"] == _ENG, got
    assert got["step_id"] == "step-7", got
    assert got["note"] == "blind SSRF on /api/fetch?url=", got
    assert got["at"], "a correlation with no mint time cannot order evidence"
    print("  a hit correlates back to its engagement, step and note: PASS")


def test_correlation_survives_a_resolver_changing_the_case() -> None:
    """Resolvers randomise query case (DNS 0x20) and echo the qname as they please.

    A case-sensitive lookup turns a real hit into an uncorrelated one — silently, and only
    against some resolvers, which is the worst way to find out.
    """
    _reset()
    tok = tokens.mint(_ENG, step_id="step-1")["token"]
    for variant in (tok.upper(), tok.capitalize(), tok.swapcase(), f"  {tok}  "):
        got = tokens.correlate(variant)
        assert got is not None and got["token"] == tok, (
            f"{variant!r} did not correlate to {tok!r} — a 0x20-randomising resolver would "
            f"make this hit unattributable"
        )
    print("  a token correlates regardless of case or surrounding whitespace: PASS")


def test_an_unminted_or_malformed_token_correlates_to_nothing() -> None:
    """correlate() is called with attacker-controlled labels off the wire.

    Anyone on the internet can query anything under the zone. Every one of those becomes a
    correlate() argument, so it returns None for junk — it never raises, and never matches
    on a partial or wildcard.
    """
    _reset()
    tok = tokens.mint(_ENG)["token"]
    junk = [
        "", " ", "nope", tok[:-1], tok + "x", "%", "'; DROP TABLE oob_tokens;--", "*",
        "_hp", "a" * 500, "tok.with.dots", "tok\x00null", "../../etc/passwd", "%25",
    ]
    for value in junk:
        assert tokens.correlate(value) is None, f"{value!r} correlated to something"
    assert tokens.correlate(tok) is not None, "the control token stopped correlating"
    print(f"  {len(junk)} malformed/unminted labels correlate to nothing, none raised: PASS")


def test_tokens_list_per_engagement() -> None:
    """An engagement's canaries are listable without reading another engagement's."""
    _reset()
    mine = {tokens.mint(_ENG, step_id=f"s{i}")["token"] for i in range(3)}
    theirs = {tokens.mint(_ENG2)["token"] for i in range(2)}
    listed = {r["token"] for r in tokens.list_for(_ENG)}
    assert listed == mine, f"expected {mine}, got {listed}"
    assert not (listed & theirs), "one engagement's listing leaked another's tokens"
    print("  tokens list per engagement and never cross over: PASS")


# --------------------------------------------------------------------------- #
# position: imported by the app, polled on a timer, approved by nobody
# --------------------------------------------------------------------------- #
_BANNED_IMPORTS = {
    "subprocess", "socket", "requests", "httpx", "urllib", "docker", "pty", "ctypes",
    "multiprocessing", "asyncio", "http",
}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "os.system", "os.popen", "os.execv"}


def _violations(source: str) -> list[str]:
    """Every banned import or call in `source`, from the AST — not the text.

    Parsed rather than grepped so this prose, which names `subprocess` several times over,
    does not read as a violation, and so `subprocess` hidden in a string does not read as
    clean.

    Calls are matched on the DOTTED name (test_state.py:73), which is the distinction that
    matters here: bare `compile` is the builtin that turns a string into code, while
    `re.compile` is how every module in this repo builds a pattern. Matching on the bare
    attribute would ban the second along with the first — a rule the codebase cannot keep,
    and a rule nobody keeps is deleted rather than obeyed.
    """
    out: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _BANNED_IMPORTS:
                    out.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in _BANNED_IMPORTS:
                out.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Call):
            fn = node.func
            dotted = ""
            if isinstance(fn, ast.Name):
                dotted = fn.id
            elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                dotted = f"{fn.value.id}.{fn.attr}"
            if dotted in _BANNED_CALLS:
                out.append(f"call {dotted}()")
    return out


# The ONLY modules in this package permitted to touch the network, pinned by name.
#
# THIS SET IS THE CONTROL, not an exemption. When §3.3 landed, the single invariant below was
# "the OOB package executes nothing and reaches no network" — and the second half stopped being
# true of a poll client, whose entire job is to fetch the hit log. The wrong fix was available
# and tempting: drop `urllib` from the banned list, which would have silently un-banned it for
# all six modules. The right one is to notice it was always TWO claims, keep the execution half
# absolute, and make the network half a PINNED SET so that a third module gaining reach fails
# here — which is a stronger statement than the original made, not a weaker one.
#
#   poll.py      — fetches the read API (spec §3.3). Locked further in test_oob_poll.py: fixed
#                  destination from the config store, fixed paths, no redirects, no proxy.
#   verify.py    — resolves <token>.<zone> through the system resolver to prove NS delegation
#                  (spec §3.5), and now also runs the interact.sh live round-trip.
#   interactsh.py — the second OOB backend (spec 2026-08-06). register/poll/deregister over HTTP
#                  against the CONFIGURED interact.sh server, resolved server-side, with the same
#                  containment poll.py has (no redirects, no ambient proxy, capped, parse-never-
#                  execute). Locked in test_oob_interactsh.py + test_oob_interactsh_safety.py.
#                  (autopoll.py drives a sweep but imports NO client itself — it reaches the
#                  network only through poll_all, so it is not — and must not be — pinned here.)
_MAY_REACH_NETWORK = {"poll.py", "verify.py", "interactsh.py"}

# What those two are allowed to reach: the stdlib client and the resolver, nothing more. The
# ban on subprocess/docker/pty/ctypes still applies to them in full.
_NETWORK_IMPORTS = {"urllib", "socket"}


def test_no_module_in_the_oob_package_executes_anything() -> None:
    """The execution half, and it is absolute — no module, no exception.

    This package is imported by the app and driven on a timer, which is precisely the position
    from which code would sit outside every approval gate. Nothing here runs a command; the one
    thing in build #13 part 3 that executes is the deploy, and it lives at the gated execution
    point in cockpit/executor.py (test_oob_deploy_safety.py).
    """
    modules = sorted(OOB_DIR.glob("*.py"))
    assert modules, f"no modules found under {OOB_DIR} — this scan would pass vacuously"
    for path in modules:
        found = [v for v in _violations(path.read_text(encoding="utf-8"))
                 if not any(n in v for n in _NETWORK_IMPORTS)]
        assert not found, f"{path.name} executes: {found}"
    print(f"  all {len(modules)} backend/oob modules execute nothing: PASS")


def test_only_the_two_named_modules_reach_the_network() -> None:
    """The network half — a pinned set, so growth fails rather than passing quietly."""
    modules = sorted(OOB_DIR.glob("*.py"))
    reaching = {
        path.name for path in modules
        if any(n in v for v in _violations(path.read_text(encoding="utf-8"))
               for n in _NETWORK_IMPORTS)
    }
    unexpected = reaching - _MAY_REACH_NETWORK
    assert not unexpected, (
        f"{sorted(unexpected)} gained network reach. That may well be correct — but it is a new "
        f"egress path out of the operator's own machine, so it needs the same treatment poll.py "
        f"got (fixed destination, no redirects, no proxy) and a line in this set saying so."
    )
    missing = _MAY_REACH_NETWORK - reaching
    assert not missing, (
        f"{sorted(missing)} is pinned as network-capable but reaches nothing — either it was "
        f"gutted or renamed, and this control is now guarding a module that does not exist"
    )
    print(f"  exactly {sorted(reaching)} reach the network, as pinned: PASS")


def test_the_execution_scan_can_fail() -> None:
    """Control: the scan above reports "all clear" when working AND when broken."""
    planted = {
        "subprocess": "import subprocess\nsubprocess.run(['id'])\n",
        "a socket": "import socket\ns = socket.socket()\n",
        "eval": "def f(x):\n    return eval(x)\n",
        "os.system": "import os\nos.system('id')\n",
        "urllib": "from urllib.request import urlopen\n",
    }
    for label, source in planted.items():
        assert _violations(source), f"the scan missed a planted {label} — it cannot fail"
    assert not _violations("import json\nimport secrets\njson.dumps({})\n"), (
        "the scan flagged clean code; it would be disabled within a week"
    )
    print(f"  control: {len(planted)} planted violations are all detected: PASS")


if __name__ == "__main__":
    test_every_minted_token_is_dns_label_safe()
    test_a_token_is_long_enough_to_be_unguessable()
    test_minted_tokens_do_not_collide()
    test_the_minter_uses_a_csprng()
    test_a_hit_resolves_back_to_the_test_that_caused_it()
    test_correlation_survives_a_resolver_changing_the_case()
    test_an_unminted_or_malformed_token_correlates_to_nothing()
    test_tokens_list_per_engagement()
    test_no_module_in_the_oob_package_executes_anything()
    test_only_the_two_named_modules_reach_the_network()
    test_the_execution_scan_can_fail()
    _reset()
    print("ALL OOB token minting/correlation tests pass")
