"""Is the canary actually working? (spec §3.5, the verify button)

This is the valuable button. Everything else in part 3 assumes a chain that spans a registrar,
a VPS, a resolver you do not control and a daemon you started once over SSH — and the failure
mode of every link in it is SILENCE. A blind SSRF that produces no hit looks identical whether
the target was not vulnerable, the NS records were never delegated, the daemon died on a
missing interpreter, or the zone in the payload does not match the zone the server answers
for. "Is my canary working" has to be a re-runnable check rather than an assumption, or the
whole part reduces to a more elaborate way of not knowing.

EACH CHECK REPORTS ITSELF, AND NOT-RUN IS NOT A PASS
----------------------------------------------------
Three checks, reported individually and never rolled into one boolean:

  1. ``health``   — the server answers its authenticated health endpoint, and the zone it
                    believes it is authoritative for is the zone payloads are rendered against.
  2. ``http``     — a request carrying a freshly minted token arrives and is recorded. This is
                    the full round trip through the real code: mint, arrive, correlate, read
                    back.
  3. ``dns``      — resolving ``<token>.<zone>`` through the SYSTEM resolver lands a DNS hit.
                    This is the only one that genuinely needs public infrastructure: it
                    exercises NS delegation, which no amount of local wiring can stand in for.

Checks 1 and 2 run for real against a canary on loopback with no VPS, no domain and no
internet — that is how this part was built and verified. Check 3 reports **NOT-RUN**, with the
reason, until a zone is actually delegated. It is never quietly folded into a pass; the panel
prints it as its own line for the same reason ``test_proof_honesty.py`` exists.
"""

from __future__ import annotations

import socket
import time
from typing import Any

from . import config, interactsh, poll, tokens

# The engagement id throwaway verify tokens are minted under. Namespaced so a verify run can
# never file a finding into a real engagement, and so its tokens are trivially clearable.
VERIFY_ENGAGEMENT = "_oob-verify"

# How long to wait for a hit to appear in the log after it was sent. The canary appends
# synchronously, but the poll is a separate round trip over the internet.
SETTLE_SECONDS = 1.5
POLL_ATTEMPTS = 3


def _check(name: str, status: str, detail: str, **extra: Any) -> dict[str, Any]:
    """One reported check. ``status`` is pass | fail | not-run and is never inferred."""
    return {"check": name, "status": status, "detail": detail, **extra}


def _hits_for(token: str, after: int) -> list[dict[str, Any]]:
    """Every hit newer than ``after`` carrying this token, retried while it settles.

    Reads with an explicit ``after`` so this never touches the stored poll cursor — a verify
    run must not consume hits the real poll has not seen yet, or it would silently swallow a
    genuine callback that arrived in the same window.
    """
    for attempt in range(POLL_ATTEMPTS):
        if attempt:
            time.sleep(SETTLE_SECONDS)
        try:
            page = poll.fetch(after=after)
        except poll.PollError:
            return []
        found = [h for h in page["hits"] if h.get("token") == token]
        if found:
            return found
    return []


def _self_hosted_checks() -> list[dict[str, Any]]:
    """The three self-hosted checks (health/http/dns), or three not-run when unconfigured.

    Returns a list rather than short-circuiting the whole verify, so the interact.sh check still
    runs when only interact.sh is set up.
    """
    if not config.is_configured():
        return [
            _check(name, "not-run", "the self-hosted canary is not configured")
            for name in ("health", "http", "dns")
        ]

    zone = config.zone()
    checks: list[dict[str, Any]] = []

    # ---- 1. the server answers, and answers for the right zone --------------- #
    try:
        state = poll.health()
    except poll.PollError as exc:
        checks.append(_check("health", "fail", str(exc)))
        # Everything below needs the server to be readable, so stop rather than reporting two
        # more failures that all mean the same thing.
        checks.append(_check("http", "not-run", "the canary could not be read"))
        checks.append(_check("dns", "not-run", "the canary could not be read"))
        return checks

    if not state["zone_matches"]:
        checks.append(_check(
            "health", "fail",
            f"the server is authoritative for {state['zone']!r} but payloads are rendered "
            f"against {zone!r} — every hit would land at a name it does not answer for",
            server_zone=state["zone"], expected_zone=zone,
        ))
    else:
        checks.append(_check(
            "health", "pass",
            f"the canary answers for {zone} and has recorded {state['cursor']} hit(s)",
            cursor=state["cursor"],
        ))

    baseline = state["cursor"]

    # ---- 2. a real round trip: mint -> arrive -> correlate ------------------- #
    minted = tokens.mint(VERIFY_ENGAGEMENT, note="canary verify")
    token = minted["token"]
    sent = poll.probe(token)
    if not sent["ok"]:
        checks.append(_check(
            "http", "fail",
            f"could not reach the canary over HTTP: {sent.get('error', 'unknown')}",
        ))
    else:
        found = _hits_for(token, baseline)
        if not found:
            checks.append(_check(
                "http", "fail",
                "the request was accepted but no hit carrying the token came back — the "
                "server is answering but not recording, or something else is on that port",
            ))
        else:
            correlated = tokens.correlate(token)
            checks.append(_check(
                "http", "pass",
                f"a request carrying a freshly minted token arrived and correlated back to "
                f"{correlated['note'] if correlated else 'the mint record'}",
                token=token,
            ))

    # ---- 3. NS delegation: the one that needs public infrastructure --------- #
    fqdn = f"{token}.{zone}"
    resolve_error = ""
    try:
        socket.getaddrinfo(fqdn, None, family=socket.AF_INET)
        resolved = True
    except OSError as exc:
        resolved = False
        resolve_error = str(exc)

    if not resolved:
        checks.append(_check(
            "dns", "not-run",
            f"{fqdn} does not resolve from this machine — this check needs the zone to be "
            f"NS-delegated to the canary at a registrar, which is the one part of this that "
            f"cannot be stood in for locally ({resolve_error})",
        ))
    else:
        found = _hits_for(token, baseline)
        dns_hits = [h for h in found if h.get("kind") == "dns"]
        if dns_hits:
            checks.append(_check(
                "dns", "pass",
                f"resolving {fqdn} reached the canary — NS delegation is live",
                source_ip=dns_hits[0].get("source_ip", ""),
            ))
        else:
            checks.append(_check(
                "dns", "fail",
                f"{fqdn} resolves, but the query never reached the canary — the zone is "
                f"delegated somewhere else, or a resolver answered from cache",
            ))

    tokens.clear(VERIFY_ENGAGEMENT)
    return checks


def _interactsh_check() -> dict[str, Any]:
    """The interact.sh live round-trip — the one check that can run WITHOUT owning infrastructure.

    Generates a verify host, resolves it through the system resolver (which reaches interact.sh's
    authoritative DNS), and looks for the interaction to come back. Reads with ``mark_seen=False``
    so a verify never consumes a real pending callback the auto-poll has not filed yet. The verify
    token is minted under ``VERIFY_ENGAGEMENT``, which has no state session, so even if it did get
    filed it could never land as a real finding.
    """
    if not interactsh.is_registered():
        return _check("interactsh", "not-run", "no interact.sh session is registered")
    try:
        generated = interactsh.generate(VERIFY_ENGAGEMENT, note="canary verify")
    except interactsh.InteractshError as exc:
        return _check("interactsh", "fail", str(exc))

    host, suffix = generated["host"], generated["suffix"]
    try:
        # The resolution reaching interact.sh's DNS is the hit; whether it "succeeds" locally
        # (an address is returned) does not matter and often it will not.
        socket.getaddrinfo(host, None, family=socket.AF_INET)
    except OSError:
        pass

    try:
        for attempt in range(POLL_ATTEMPTS):
            if attempt:
                time.sleep(SETTLE_SECONDS)
            hits = interactsh.poll_correlated(mark_seen=False)
            match = [h for h in hits if h.get("token") == suffix]
            if match:
                return _check(
                    "interactsh", "pass",
                    f"resolving {host} reached interact.sh and correlated back",
                    source_ip=match[0].get("source_ip", ""),
                )
        return _check(
            "interactsh", "fail",
            f"resolved {host} but no interaction came back from interact.sh within the window — "
            f"the session may have expired, or outbound DNS is blocked from this machine",
        )
    except interactsh.InteractshError as exc:
        return _check("interactsh", "fail", f"could not poll interact.sh: {exc}")
    finally:
        interactsh.clear(VERIFY_ENGAGEMENT)


def verify() -> dict[str, Any]:
    """Run every check and report each one. Never raises for a failing check.

    Both backends are checked: the self-hosted health/http/dns triad, and the interact.sh live
    round-trip. When a backend is not set up its checks report NOT-RUN — never folded into a pass.
    """
    self_hosted = config.is_configured()
    ish = interactsh.is_registered()
    if not self_hosted and not ish:
        checks = [
            _check(name, "not-run",
                   "no canary is configured — set up the self-hosted canary or register an "
                   "interact.sh session")
            for name in ("health", "http", "dns", "interactsh")
        ]
        return {"ok": False, "checks": checks, "not_run": [c["check"] for c in checks]}

    checks = _self_hosted_checks()
    checks.append(_interactsh_check())
    return {
        "ok": all(c["status"] == "pass" for c in checks),
        "checks": checks,
        "not_run": [c["check"] for c in checks if c["status"] == "not-run"],
    }
