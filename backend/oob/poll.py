"""The poll client and state ingest (spec §3.3).

A hit landing on the VPS is not yet evidence. It becomes evidence when it is joined to the
test that caused it and filed where the report can find it — otherwise an OOB confirmation is
a thing you screenshot, which is what this part exists to stop. So the cycle is: fetch what is
new since the cursor, correlate each hit's token back to the step that minted it, and upsert a
finding into engagement state like any other.

WHY AN OUTBOUND REQUEST IS ALLOWED HERE, WHEN THE REPEATER REFUSED ONE
---------------------------------------------------------------------
``cockpit/repeater.py`` deliberately does NOT send from the backend process — it execs curl
inside the open sandbox — because sending operator-composed requests to arbitrary hosts from
the backend would create a new egress path originating on the operator's own machine, able to
reach host-local services. That reasoning does not carry over, and the difference is worth
naming rather than assuming:

  * the destination is **one host, read from the config store** (:func:`config.base_url`), not
    a URL anyone composed. There is no argument to this module that can change where it
    connects;
  * the **path set is fixed** — two constants, ``/_hp/hits`` and ``/_hp/health``;
  * **redirects are not followed**. This is the one that would actually matter: a canary that
    has been tampered with, or simply misconfigured behind a proxy, could answer ``302
    http://169.254.169.254/...`` and turn a poll into an SSRF *from the backend host*. The
    opener below has no redirect handler, so a 3xx is an error, not a second request;
  * the response is **parsed as JSON and never executed**, and every field is capped before it
    reaches a record.

That is the same containment shape ``backend/llm.py`` already has for the configured model
endpoint: a fixed destination resolved server-side, not a general egress capability.

This module runs no command and opens no listener.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Iterable

from state.models import Finding
from state import store as state_store

from . import config, interactsh, tokens

# The read API's two routes. Constants, so "which URL does the poll client fetch" has one
# answer that is visible in the source.
HITS_PATH = "/_hp/hits"
HEALTH_PATH = "/_hp/health"

# One page. The server caps at 500 of its own accord; asking for more than it will give just
# makes the client's expectations a lie.
PAGE_LIMIT = 200

# Wall-clock ceiling for one poll. A canary on a small VPS across the internet is slow
# sometimes; a poll that hangs holds a request thread.
TIMEOUT_SECONDS = 15

# A canary's whole log is small by construction (capped bodies, capped headers). This is a
# backstop against a compromised or wildly misbehaving endpoint streaming forever into memory.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

# What a finding records from a hit. Capped again on this side: the server caps what it
# stores, but this side must not assume the server that answered is the server we shipped.
MAX_EVIDENCE = 1200


class PollError(RuntimeError):
    """The canary could not be read. Carries a message meant for the operator."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect handler that refuses to redirect.

    Note the shape: this SUBCLASSES the default handler rather than being left out of the
    opener. ``build_opener`` re-adds every default handler that is not overridden by an
    instance of the same class, so simply not passing one would have left redirects being
    followed while the code above said they were not — a comment that describes the opposite
    of what the socket does. Returning None makes urllib raise ``HTTPError`` for the 3xx,
    which :func:`_get` turns into a named refusal.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _opener() -> urllib.request.OpenerDirector:
    """An opener that follows NO redirect and honours NO ambient proxy.

    Both are load-bearing. A canary that has been tampered with — or simply sits behind a
    proxy that was not expected — could answer ``302 http://169.254.169.254/...`` and turn a
    poll into an SSRF *from the backend host*; :class:`_NoRedirect` makes that an error rather
    than a second request. And an ambient ``http_proxy`` in the operator's environment must
    not quietly re-route a request that carries the read secret, so the proxy handler is
    replaced with an empty one.
    """
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _get(path: str, query: str = "") -> dict[str, Any]:
    """GET one of the two fixed read-API routes from the CONFIGURED canary.

    Takes a path from this module's constants, never a URL. The base comes from the store.
    """
    base = config.base_url()
    if not base:
        raise PollError("no canary is configured — set the zone and VPS address first")
    secret = config.read_secret()
    if not secret:
        raise PollError("the canary has no read secret stored — reconfigure it")

    request = urllib.request.Request(
        base + path + query,
        headers={"Authorization": f"Bearer {secret}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with _opener().open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise PollError(
                "the canary refused the read secret (401) — HackPit's stored secret and the "
                "server's HACKPIT_OOB_TOKEN have diverged; redeploy or reconfigure"
            ) from exc
        if exc.code == 429:
            raise PollError("the canary rate-limited this poll (429) — try again shortly") from exc
        if 300 <= exc.code < 400:
            raise PollError(
                f"the canary answered a redirect ({exc.code}), which is never followed — "
                f"something is in front of it that should not be"
            ) from exc
        raise PollError(f"the canary answered HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise PollError(f"could not reach the canary at {base}: {exc.reason}") from exc
    except OSError as exc:  # pragma: no cover - socket-level failures
        raise PollError(f"could not reach the canary at {base}: {exc}") from exc

    if len(raw) > MAX_RESPONSE_BYTES:
        raise PollError("the canary returned more than this client will read — refusing")
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except ValueError as exc:
        raise PollError("the canary returned something that is not JSON") from exc
    if not isinstance(payload, dict):
        raise PollError("the canary returned JSON that is not an object")
    return payload


def health() -> dict[str, Any]:
    """Ask the canary whether it is up, and which zone it believes it is authoritative for.

    The zone comparison is the useful half: a canary answering for a DIFFERENT zone than the
    one payloads are being rendered against is a live misconfiguration that otherwise shows up
    as "no hits ever arrive".
    """
    payload = _get(HEALTH_PATH)
    reported = str(payload.get("zone") or "")
    expected = config.zone()
    return {
        "ok": bool(payload.get("ok")),
        "zone": reported,
        "cursor": int(payload.get("cursor") or 0),
        "zone_matches": bool(reported) and reported == expected,
        "expected_zone": expected,
    }


def probe(token: str) -> dict[str, Any]:
    """Fetch ``<base>/<token>`` UNAUTHENTICATED, so the canary records a hit. For verify only.

    The one request in this module that is deliberately not on the read API: it is pretending
    to be a target, so it must arrive the way a target's request would. Same fixed
    destination, same no-redirect opener; the path is a minted token and nothing else, which
    is why it cannot be used to fetch an arbitrary path.
    """
    if not tokens.is_token(token):
        raise PollError("probe takes a minted token and nothing else")
    base = config.base_url()
    if not base:
        raise PollError("no canary is configured")
    request = urllib.request.Request(
        f"{base}/{token}",
        headers={"User-Agent": "hackpit-verify"},
        method="GET",
    )
    try:
        with _opener().open(request, timeout=TIMEOUT_SECONDS) as response:
            return {"ok": True, "status": response.status}
    except urllib.error.HTTPError as exc:
        # The canary answers 200 to everything, so any status at all still means it recorded
        # the request — which is the thing being verified.
        return {"ok": True, "status": exc.code}
    except (urllib.error.URLError, OSError) as exc:
        return {"ok": False, "status": 0, "error": str(getattr(exc, "reason", exc))}


def fetch(after: int | None = None, limit: int = PAGE_LIMIT) -> dict[str, Any]:
    """One page of hits newer than ``after`` (default: the stored cursor)."""
    since = config.cursor() if after is None else max(0, int(after))
    bounded = max(1, min(int(limit), PAGE_LIMIT))
    payload = _get(HITS_PATH, f"?after={since}&limit={bounded}")
    hits = payload.get("hits")
    return {
        "hits": [h for h in hits if isinstance(h, dict)] if isinstance(hits, list) else [],
        "cursor": int(payload.get("cursor") or 0),
        "after": since,
    }


# --------------------------------------------------------------------------- #
# correlation — the part that is actually the product
# --------------------------------------------------------------------------- #
def correlate(hits: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Join each hit to the token record that explains it.

    A hit with no token, or with a token this HackPit never minted, is KEPT and marked
    ``correlated: False``. Dropping it would hide the two things the stray hits are for:
    noticing the zone is delegated and being crawled, and seeing a misconfigured payload land
    at the wrong name instead of appearing as silence.
    """
    out: list[dict[str, Any]] = []
    for hit in hits:
        token = hit.get("token")
        record = tokens.correlate(token) if isinstance(token, str) else None
        out.append({
            **hit,
            "correlated": record is not None,
            "engagement_id": record["engagement_id"] if record else None,
            "step_id": record["step_id"] if record else None,
            "note": record["note"] if record else "",
            "minted_at": record["at"] if record else None,
        })
    return out


def _describe(hit: dict[str, Any]) -> str:
    """The one-line evidence a finding carries: what arrived, from where, when."""
    source = str(hit.get("source_ip") or "?")
    at = str(hit.get("at") or "")
    if hit.get("kind") == "dns":
        what = f"DNS {hit.get('qtype') or 'A'} query for {hit.get('qname') or '?'}"
    else:
        what = f"HTTP {hit.get('method') or '?'} {hit.get('path') or '/'}"
        host = hit.get("host")
        if host:
            what += f" (Host: {host})"
    body = str(hit.get("body") or "")
    extra = f" body[{len(body)}]: {body}" if body else ""
    return f"{what} from {source} at {at}.{extra}"[:MAX_EVIDENCE]


def _title(hit: dict[str, Any]) -> str:
    kind = "DNS" if hit.get("kind") == "dns" else "HTTP"
    note = str(hit.get("note") or "").strip()
    subject = note or f"canary token {hit.get('token')}"
    return f"Out-of-band {kind} callback confirmed — {subject}"[:300]


def findings_for(
    correlated: Iterable[dict[str, Any]], sessions: dict[str, str] | None = None
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """(findings to file, hits that could not be filed).

    A hit becomes a finding only when it correlates to a minted token AND that token's
    engagement resolves to a state session. Anything else is returned in the second list
    rather than dropped — an uncorrelated hit is still information, and silently discarding it
    would make "nothing arrived" and "something arrived that I could not attribute" look
    identical.

    Severity is ``high``, and deliberately not a judgement call made here: a callback from
    inside a target's network is the proof for the whole blind class, and grading it
    ``medium`` because the module cannot see the payload would understate every one of them.
    """
    lookup = sessions or {}
    findings: list[Finding] = []
    unfiled: list[dict[str, Any]] = []
    for hit in correlated:
        engagement_id = hit.get("engagement_id")
        session_id = lookup.get(engagement_id or "")
        if not hit.get("correlated") or not session_id:
            unfiled.append({
                **hit,
                "reason": (
                    "no session is attached to this engagement" if hit.get("correlated")
                    else "this token was never minted by this HackPit"
                ),
            })
            continue
        findings.append(
            Finding(
                session_id=session_id,
                title=_title(hit),
                severity="high",
                target=str(hit.get("qname") or hit.get("host") or hit.get("source_ip") or ""),
                evidence=_describe(hit),
                tool="oob-canary",
                reference=str(hit.get("token") or ""),
            )
        )
    return findings, unfiled


def ingest(
    correlated: Iterable[dict[str, Any]], sessions: dict[str, str] | None = None
) -> dict[str, Any]:
    """File the correlated hits as findings. Returns what was filed and what was not."""
    findings, unfiled = findings_for(correlated, sessions)
    filed = state_store.upsert_findings(findings) if findings else 0
    return {"filed": filed, "unfiled": unfiled}


def poll(sessions: dict[str, str] | None = None, after: int | None = None) -> dict[str, Any]:
    """The whole cycle: fetch since the cursor, correlate, file, advance.

    The cursor advances ONLY after the ingest returns, and only to the server's reported
    cursor — so a failure anywhere above leaves the position untouched and the same hits are
    re-read on the next poll. Re-reading is free (findings upsert on a fingerprint); missing a
    hit is not.
    """
    page = fetch(after=after)
    joined = correlate(page["hits"])
    result = ingest(joined, sessions)
    if after is None and page["cursor"]:
        config.set_cursor(page["cursor"])
    return {
        "hits": joined,
        "cursor": page["cursor"],
        "after": page["after"],
        "filed": result["filed"],
        "unfiled": result["unfiled"],
    }


def poll_all(sessions: dict[str, str] | None = None, after: int | None = None) -> dict[str, Any]:
    """Sweep BOTH backends, merge, and file once.

    Each backend is polled independently: a failure in one is recorded in ``errors`` and does
    NOT stop the other or advance the failed one's position. The self-hosted cursor advances
    only on its own successful fetch (unchanged from :func:`poll`); interact.sh dedup lives in
    its own ``seen`` set. ``ingest`` is called once on the merged list, so a hit that correlates
    on either backend becomes a finding the same way.

    ``after`` is honoured for the self-hosted backend only (it is the cursor's meaning); the
    interact.sh backend has no integer cursor to seek. Auto-poll and the /oob/poll route both
    call this with ``after=None``.
    """
    correlated: list[dict[str, Any]] = []
    out: dict[str, Any] = {
        "self_hosted": None, "interactsh": None, "hits": [], "filed": 0, "unfiled": [], "errors": [],
    }
    advance_to: int | None = None

    if config.is_configured():
        try:
            page = fetch(after=after)
            sh = correlate(page["hits"])
            correlated.extend(sh)
            out["self_hosted"] = {"hits": len(sh), "cursor": page["cursor"], "after": page["after"]}
            if after is None and page["cursor"]:
                advance_to = page["cursor"]
        except PollError as exc:
            out["errors"].append({"backend": "self_hosted", "reason": str(exc)})

    if interactsh.is_registered():
        try:
            ish_hits = interactsh.poll_correlated()
            correlated.extend(ish_hits)
            out["interactsh"] = {"hits": len(ish_hits)}
        except interactsh.InteractshError as exc:
            out["errors"].append({"backend": "interactsh", "reason": str(exc)})

    filed = ingest(correlated, sessions)
    out["hits"] = correlated
    out["filed"] = filed["filed"]
    out["unfiled"] = filed["unfiled"]
    # Advance the self-hosted cursor only AFTER a successful ingest, matching poll()'s rule that
    # a failure anywhere above leaves the position untouched so the same hits are re-read.
    if advance_to:
        config.set_cursor(advance_to)
    return out
