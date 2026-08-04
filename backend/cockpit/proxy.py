"""ZAP as a recording proxy inside a sandbox — GATED START, read-only history.

WHY THIS IS NOT THE THING BUILD #14 PART 1 REFUSED. Part 1 excluded a ZAP daemon because an HTTP
control channel bypasses :func:`executor.validate_request`, and because reaching one inside the
lab sandbox would mean opening the ``internal: true`` network that ``assert_isolation_proven()``
exists to deny.

Neither happens here, and it was MEASURED before it was designed (2026-08-03, ZAP 2.17.0):

    zaproxy -daemon -host 127.0.0.1 -port 8090     API answers after ~7s
    curl 127.0.0.1:8090/... FROM THE HOST          refused — unreachable
    the same call via `docker exec`                {"version":"2.17.0"}

The daemon binds loopback INSIDE the container. No port is published, so the backend has no
socket to it; the only way in is ``docker exec``, which is the one channel into a sandbox and the
thing the gates already classify. The API exists and is still unreachable from anywhere that
could bypass a gate.

*** BUILD #15 MAKES HALF OF THAT PARAGRAPH DELIBERATELY OPTIONAL, AND REPLACES THE ARGUMENT. ***

An engagement proxy started with ``publish=True`` binds every interface inside its container so
that a host port published through ``cockpit/exposure.py`` can reach it — because a real browser
on Windows is the only client that gets past Akamai's bot management, and nine of eleven assets
in a live bug bounty program refused a bare HTTP client outright (h2 stream reset, h1.1 timeout:
two different failure modes on two protocols is an edge refusing the client, not a quirk).

The safety argument is NOT weakened, but it is different and it is stated in full, because the
old one no longer applies:

  1. The bind is narrow BY DEFAULT and every widening is chosen. ``publish`` is engagement-only
     (:func:`publish_refusal`), and the HOST port is a separate, explicit step through an
     exposure profile whose broad binds carry a machine-readable acknowledgement.
  2. THE API KEY IS ENFORCED AND RANDOM PER START. Measured on views AND actions, 2026-08-04.
     What is published unauthenticated is an HTTP PROXY — which is the entire point — while the
     control channel behind the same listener refuses everything without a secret only this
     process holds. That is what makes a published port an acceptable choice rather than an
     unacceptable one: the exposure is a proxy, not scan control.
  3. THE LAB IS UNTOUCHED. ``hackpit-isolated`` stays ``internal: true``, the lab proxy stays
     loopback-bound, and ``docker/proof/zap_proxy_proof.sh``'s load-bearing check — the ZAP API
     is UNREACHABLE from this host — still runs against the lab sandbox and must still pass.
  4. RESIDUAL, ACCEPTED, WRITTEN DOWN: anything that can reach the bound address can USE the
     proxy (it cannot scan — that needs the key). On loopback that is a privacy annoyance on a
     single-user machine. On a wildcard bind it is an open proxy with full egress, which is why
     that case carries a red-confirm rather than being forbidden or being free.

WHAT IT CAPTURES: tools run inside the sandbox, pointed at the proxy (the executor's ``proxy``
flag). It RECORDS.

*** BUILD #14 PART 3 ADDED A SECOND, GATED HALF: IT NOW ALSO SCANS. ***

The line "it never scans" was true of parts 1-2 and is no longer. This module drives ZAP's ACTIVE
SCANNER over the same ``docker exec`` transport, aimed at the endpoints the proxy already
captured — the thing neither earlier part could do, because part 1's ``-quickurl`` can only attack
what its own spider happens to crawl, and an API route reached by USING the app is not crawlable.

Two halves now live here, and the difference between them is the most important thing in the file:

    history / status / alerts   READ.   UNGATED. A panel refreshes; approval per refresh is not
                                        a thing that can work.
    start_scan                  ATTACK. GATED. Builds an ExecRequest, passes
                                        executor.validate_request, and only then execs — the
                                        tunnels.py shape. 376 real attack requests were measured
                                        against ONE endpoint, finding a live SQL injection.

THAT THEY SHARE A MODULE IS A DECISION, NOT AN OVERSIGHT (2026-08-04, Zaid). Part 2's spec §7.3
made "a URL parameter appears in this module" a review trigger; this build tripped it, the
decision was reopened, and Zaid chose ONE MODULE WITH NO GUARD over the structural split that
would have made an action URL unreachable from the read path. What was accepted is the RESIDUAL
risk — that nothing structural stops a future edit from calling an action URL from the ungated
read path. What was NOT accepted, and what no layout choice could grant, is ungated scan control:
every scan start goes through the real gates. See the constants below, and spec §6.

A THIRD BOUND, enforced by ZAP rather than by us: ``ascan/action/scan`` on a URL that is not
already in the Sites tree answers ``{"code":"url_not_found"}`` (measured). The active scanner's
reach is therefore bounded by what was proxied — a host never captured cannot be attacked through
this path even if every gate here were bypassed. A bound, not a control; the gates are the control.
"""

from __future__ import annotations

import json
import secrets
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, quote_plus

from pydantic import BaseModel, Field, field_validator

from . import config
from .listener_ports import ZAP_PROXY_PORT

#: ZAP's API and its proxy share one listener.
#:
#: *** THE BIND ADDRESS IS NO LONGER A CONSTANT, AND BUILD #15 IS WHY. ***
#: Parts 1-3 pinned this to 127.0.0.1 and called it "the isolation property". It still is, for
#: every run that is not deliberately published. But a container process bound to loopback
#: cannot be reached through a published port at all: `docker -p` forwards to the container's
#: bridge interface, and nothing is listening there. So a proxy the operator has chosen to
#: publish MUST bind 0.0.0.0 inside its own container or the feature is simply inert — this was
#: the first thing part 1's design did not state and the implementation had to answer.
#:
#: The two are therefore separate constants with separate meanings, never one value with a flag.
PROXY_HOST = "127.0.0.1"          # the default: unreachable from outside the container
PUBLISHED_PROXY_HOST = "0.0.0.0"  # noqa: S104 - required for a published port to have a listener

#: The SYSTEM chromedriver, which matches the image's Chromium. ZAP bundles its own and prefers
#: it, and the bundled one targets a different Chrome major version — see :func:`server_argv_for`.
SPIDER_DRIVER_PATH = "/usr/bin/chromedriver"
#: Re-exported from listener_ports so `exposure.py` can publish this port without importing this
#: module. ONE definition, two readers — see listener_ports.py for why that file exists.
DEFAULT_PROXY_PORT = ZAP_PROXY_PORT

#: The JVM needs this long before the API answers. MEASURED at ~7s; the headroom is for a loaded
#: host. lifecycle's default settle is far shorter, so both values are passed explicitly.
READY_TIMEOUT_SECONDS = 60
SETTLE_SECONDS = 8.0

# --------------------------------------------------------------------------- #
# THE URLS THIS MODULE ISSUES — SPLIT BY WHAT THEY DO, WHICH IS THE WHOLE POINT
#
# Until build #14 part 3 this list was "all reads", and the note here said an ``action/`` call
# was not expressible without writing a visibly new function. Part 3 wrote those functions. The
# review rule in part 2's spec §7.3 fired exactly as intended, the decision was reopened, and
# Zaid chose to keep one module and decline a guard (spec §6). So the boundary is now stated
# here instead of being implied by the absence of action URLs.
#
# *** THE RULE, FOR WHOEVER EDITS THIS NEXT ***
#   * The READ group is reachable from UNGATED code (:func:`history`, :func:`scan_status`,
#     :func:`scan_alerts`). A panel that refreshes cannot demand approval per refresh, and
#     ``lifecycle.port_is_bound()`` sets the precedent by running ``ss`` the same way.
#   * The ACTION group may be reached ONLY after :func:`executor.validate_request` has returned
#     None for that specific request. Today exactly one function does that: :func:`start_scan`.
#   * ``_ACTION_STOP`` is the deliberate exception: stopping an in-flight scan REMOVES attack
#     traffic, so gating it would make the system less safe (§5.4). It is an action URL that is
#     ungated ON PURPOSE, and it is the only one.
#
# NOTHING ENFORCES ANY OF THIS. Both candidate guards were declined (2026-08-03: a runtime
# allowlist and a static source test; 2026-08-04: the module split). It is a convention with a
# written boundary, and adding a URL to the ACTION group without a gate in front of it is the
# specific mistake this comment exists to make visible in review.
# --------------------------------------------------------------------------- #
# read, ungated
_VIEW_VERSION = "/JSON/core/view/version/"
_VIEW_COUNT = "/JSON/core/view/numberOfMessages/"
_VIEW_MSGS = "/JSON/core/view/messages/"
_VIEW_SCANS = "/JSON/ascan/view/scans/"
_VIEW_SCAN_STATUS = "/JSON/ascan/view/status/"
_VIEW_ALERTS = "/JSON/core/view/alerts/"

_VIEW_SPIDER_STATUS = "/JSON/ajaxSpider/view/status/"
_VIEW_SPIDER_RESULTS = "/JSON/ajaxSpider/view/numberOfResults/"
_VIEW_SPIDER_BROWSER = "/JSON/ajaxSpider/view/optionBrowserId/"

_VIEW_REPLACER_RULES = "/JSON/replacer/view/rules/"
_VIEW_SCAN_POLICIES = "/JSON/ascan/view/policies/"
_VIEW_SCANNERS = "/JSON/ascan/view/scanners/"
_VIEW_CONTEXTS = "/JSON/context/view/contextList/"
_VIEW_CONTEXT = "/JSON/context/view/context/"
_VIEW_SESSION_METHOD = "/JSON/sessionManagement/view/getSessionManagementMethod/"
_VIEW_AUTH_METHOD = "/JSON/authentication/view/getAuthenticationMethod/"
_VIEW_LOGGED_IN = "/JSON/authentication/view/getLoggedInIndicator/"
_VIEW_LOGGED_OUT = "/JSON/authentication/view/getLoggedOutIndicator/"
_VIEW_USERS = "/JSON/users/view/usersList/"

# action, GATED (except the two stops — see above)
_ACTION_SCAN = "/JSON/ascan/action/scan/"
_ACTION_STOP = "/JSON/ascan/action/stop/"
_ACTION_SPIDER_SCAN = "/JSON/ajaxSpider/action/scan/"
_ACTION_SPIDER_STOP = "/JSON/ajaxSpider/action/stop/"
# Configuration actions, reached ONLY from inside the gated :func:`start_spider` — after
# validate_request has returned None for that request, never from the read path. They set the
# crawl's own bounds, so they are part of performing the approved action rather than a second
# capability: a browser id and a depth that could be set WITHOUT approval would let one operator
# silently change what the next one's approved crawl actually does.
_ACTION_SPIDER_BROWSER = "/JSON/ajaxSpider/action/setOptionBrowserId/"
_ACTION_SPIDER_DEPTH = "/JSON/ajaxSpider/action/setOptionMaxCrawlDepth/"
_ACTION_SPIDER_DURATION = "/JSON/ajaxSpider/action/setOptionMaxDuration/"

# --------------------------------------------------------------------------- #
# A THIRD GROUP, AND IT IS A DELIBERATE ADDITION TO THE BOUNDARY ABOVE (build #18).
#
# `_ACTION_STOP` was described above as "an action URL that is ungated ON PURPOSE, and it is the
# only one". It is no longer the only one, so the rule is restated rather than quietly broken.
#
# CONFIGURATION ACTIONS THAT SEND NOTHING. Setting a replacer rule, a scan policy, a context or
# a session-management method changes how OUR OWN next request is shaped. None of them emits a
# single packet at the target, and none of them can be made to: what they take is a header name,
# a plugin id or a regex, never a URL to fetch. The traffic they shape is emitted by
# `start_scan` / `start_spider` / a human's browser, each of which is gated (or is the human)
# exactly as before.
#
# THEY ARE UNGATED BECAUSE GATING THEM WOULD BE A NEW CONFIRM, and build #18 is explicitly a
# build that adds none. Demanding a red-confirm to type in the header a program issued would
# teach the operator that the red-confirm means "a form has fields", which is precisely how the
# `-daemon` red-confirm went wrong: a control whose stated meaning is not the one it enforces.
#
# WHAT DOES BOUND THEM is stated instead of implied: every one of these settings is READ BACK
# from ZAP, and every read-back is what gets reported. An OK is not a result — measured here on
# `setOptionBrowserId`, which answered `{"Result":"OK"}` for a browser it could not use.
# --------------------------------------------------------------------------- #
#: *** TWO SPELLINGS, AND THE READ-BACK IS THE ARBITER. ***
#: The Replacer add-on renamed these actions across versions: older builds expose
#: `addReplacerRule` / `removeReplacerRule`, current ones `addRule` / `removeRule`. This daemon
#: was NOT running while build #18 was written (build #17's teardown stopped it), so which pair
#: this image's add-on holds is UNMEASURED — and guessing one would produce the exact failure
#: this module keeps finding: a confident `{}` from a 404 that reads as "the rule is not there".
#: So both are tried in order and :func:`observed_replacer_rules` decides whether anything took.
#: The proof script prints which spelling answered, which is how the guess becomes a measurement.
_ACTION_REPLACER_ADD = (
    "/JSON/replacer/action/addRule/",
    "/JSON/replacer/action/addReplacerRule/",
)
_ACTION_REPLACER_REMOVE = (
    "/JSON/replacer/action/removeRule/",
    "/JSON/replacer/action/removeReplacerRule/",
)

_ACTION_ENABLE_ALL_SCANNERS = "/JSON/ascan/action/enableAllScanners/"
_ACTION_DISABLE_SCANNERS = "/JSON/ascan/action/disableScanners/"
_ACTION_POLICY_STRENGTH = "/JSON/ascan/action/setPolicyAttackStrength/"
_ACTION_POLICY_THRESHOLD = "/JSON/ascan/action/setPolicyAlertThreshold/"

_ACTION_NEW_CONTEXT = "/JSON/context/action/newContext/"
_ACTION_REMOVE_CONTEXT = "/JSON/context/action/removeContext/"
_ACTION_INCLUDE_IN_CONTEXT = "/JSON/context/action/includeInContext/"
_ACTION_SET_SESSION_METHOD = "/JSON/sessionManagement/action/setSessionManagementMethod/"
_ACTION_SET_AUTH_METHOD = "/JSON/authentication/action/setAuthenticationMethod/"
_ACTION_SET_LOGGED_IN = "/JSON/authentication/action/setLoggedInIndicator/"
_ACTION_SET_LOGGED_OUT = "/JSON/authentication/action/setLoggedOutIndicator/"
_ACTION_NEW_USER = "/JSON/users/action/newUser/"
_ACTION_SET_USER_CREDS = "/JSON/users/action/setAuthenticationCredentials/"
_ACTION_SET_USER_ENABLED = "/JSON/users/action/setUserEnabled/"
_ACTION_REMOVE_USER = "/JSON/users/action/removeUser/"
_ACTION_SET_FORCED_USER = "/JSON/forcedUser/action/setForcedUser/"
_ACTION_SET_FORCED_USER_MODE = "/JSON/forcedUser/action/setForcedUserModeEnabled/"

_lock = threading.Lock()
_models: dict[str, "Proxy"] = {}
_watched: dict[str, Any] = {}

# --------------------------------------------------------------------------- #
# THE API KEY (build #15)
#
# *** THE FINDING THIS RESTS ON WAS ORIGINALLY RECORDED BACKWARDS. ***
# Build #14 part 2 measured `api.key` as enforcing NOTHING, and that finding blocked browser
# interception for a day. Re-measured 2026-08-04 against the same ZAP 2.17.0, started with the
# flag stated EXPLICITLY, it enforces on views AND on actions; the proxy meanwhile still serves
# normally. The original test had passed `-config api.key=…` with no explicit `disablekey` and
# inherited `true` from `$HOME/.ZAP/config.xml` — which HackPit itself had written on an earlier
# `server_argv_for` start. We disabled our own lock and blamed the tool.
#
# GENERALISE IT, because it outlives this feature: A DAEMON THAT PERSISTS ITS CONFIGURATION MAKES
# EVERY MEASUREMENT CONDITIONAL ON WHAT A PREVIOUS RUN WROTE. State the flag explicitly or you
# are measuring history. That is why `api.disablekey=false` is passed on every start below even
# though false is ZAP's own default: the default is not what is in that file.
#
# The key is RANDOM PER START and lives only here, in memory. Nothing persists it, so there is no
# long-lived secret to leak.
#
# *** THIS BLOCK USED TO SAY A BACKEND RESTART "SIMPLY LOSES THE ABILITY TO READ THAT DAEMON —
# HONEST, AND NO WORSE THAN TODAY". THE POSITION WAS DEFENSIBLE; THE WORD "HONEST" WAS NOT. ***
# Measured 2026-08-04 (build #17): with a daemon holding 1,076 captured messages still running,
# `GET /cockpit/proxy` returned `[]` and the history route returned zero exchanges. Losing the key
# is fine. What was NOT fine is how the loss reported itself: `_api_get` omits the header, ZAP
# answers with an EMPTY BODY, and `history()` parses that into `[]` — indistinguishable from "this
# proxy captured nothing". A backend restart is an ordinary event across a multi-day engagement,
# and it silently turned the whole read surface into a confident zero.
#
# So the key is now RECOVERABLE: a daemon states its own key in its own argv, and that argv is
# readable inside the container we own. `/proc/<pid>/cmdline` is already the accepted residual of
# passing `-config api.key=` at all (see the build #15 section) — this reads what that residual
# already exposes rather than widening anything. Recovered keys live in `_adopted`, kept SEPARATE
# from `_keys` on purpose: "what this process minted" and "what we read off a process we did not
# start" are different facts, and a single dict would lose the distinction the moment anyone
# needed it.
_keys: dict[str, str] = {}

#: Keys read back from a live daemon THIS PROCESS DID NOT START. Never minted, never persisted,
#: and dropped the moment a read comes back empty so a stale one cannot survive a daemon swap.
_adopted: dict[str, str] = {}

#: What `_gate_request` passes instead of a key. THE GATE IS NEVER GIVEN THE REAL ONE — not
#: redacted afterwards, never handed over in the first place, which is the only version of that
#: property a future edit cannot quietly undo. Locked by test_zap_proxy_safety.
GATE_KEY_PLACEHOLDER = "<not-yet-minted>"


def mint_api_key() -> str:
    """A fresh API key. 32 hex chars from `secrets` — never `random`, never derived from the port."""
    return secrets.token_hex(16)


def _key_slot(container: str, port: int) -> str:
    return f"{container}:{port}"


#: Read a running ZAP daemon's port and API key out of its OWN argv, inside the container.
#:
#: THE `api[.]key=` IS NOT A TYPO — it is the `[z]aproxy` lesson applied to a `grep` instead of a
#: `pkill`. This command's own cmdline contains the pattern text, so an unbracketed `api.key=`
#: would match the probe itself and hand back a fragment of this string as a credential. The
#: value is stripped with `${K#*=}` for the same reason and not `${K#api.key=}`, which the test
#: caught on its first run: the obvious spelling reintroduces the literal the guard removed.
#:
#: It also skips the `sh -c` wrapper for free, and that is the OTHER half of the same lesson. The
#: wrapper's whole command is a SINGLE argv element, so splitting on NULs leaves it as one line
#: beginning `zaproxy …`, which `^api[.]key=` cannot match; only the real JVM, whose settings are
#: separate argv entries, does. Build #14 was bitten by `-f` seeing the wrapper instead of the
#: JVM; here the same structural difference is what makes the match precise.
_DAEMON_PROBE = (
    'for f in /proc/[0-9]*/cmdline; do '
    'L=$(tr "\\0" "\\n" < "$f" 2>/dev/null) || continue; '
    'K=$(printf "%s\\n" "$L" | grep -m1 -e "^api[.]key=") || continue; '
    'P=$(printf "%s\\n" "$L" | grep -A1 -x -e "-port" | tail -1); '
    'printf "%s %s\\n" "$P" "${K#*=}"; break; done'
)


def observed_daemon(container: str) -> tuple[int, str] | None:
    """``(port, api_key)`` of a ZAP daemon ACTUALLY RUNNING in ``container``, else ``None``.

    IMPURE — it runs `docker exec`. Deliberately kept out of :func:`clash_refusal`, which is pure
    and hermetically tested; that function takes this as an argument instead. A test that reached
    for Docker inside a pure check is precisely what passed locally and failed in CI twice.
    """
    argv = ["docker", "exec", container, "sh", "-c", _DAEMON_PROBE]
    try:
        # Bytes + explicit decode for the same reason as `_api_get`: never let the ambient
        # locale codec decide whether this function works.
        out = subprocess.run(argv, capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    parts = (out.stdout or b"").decode("utf-8", "replace").strip().split()
    if len(parts) != 2 or not parts[0].isdigit():
        return None
    return int(parts[0]), parts[1]


def api_key_for(container: str, port: int) -> str:
    """The key for that daemon: minted by this process, or READ BACK from the daemon itself.

    Returns "" only when there is genuinely no daemon to talk to — which is the distinction the
    old version could not make, because "we lost the key" and "there is nothing there" both came
    out as "" and then as an empty API response and then as `[]`.
    """
    slot = _key_slot(container, port)
    with _lock:
        known = _keys.get(slot) or _adopted.get(slot, "")
    if known:
        return known
    found = observed_daemon(container)
    # The port is checked, not assumed: adopting a key from a daemon on a DIFFERENT port would
    # send a valid-looking secret to whatever else is listening on the one we were asked about.
    if found is None or found[0] != port:
        return ""
    with _lock:
        _adopted[slot] = found[1]
    return found[1]


def forget_adopted(container: str, port: int) -> None:
    """Drop a recovered key. Called when a read comes back empty, so a key adopted from a daemon
    that has since been replaced cannot keep being sent to its successor."""
    with _lock:
        _adopted.pop(_key_slot(container, port), None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
class ProxyStartRequest(BaseModel):
    """Start the recording proxy in a sandbox."""

    port: int = Field(DEFAULT_PROXY_PORT, ge=1024, le=65535)
    engagement_id: str | None = Field(
        None,
        description="Engagement to attribute against. OMIT for LAB mode — unlike a pivot "
        "listener, this runs in whichever sandbox you are using, so lab mode is coherent and "
        "its isolation gate is about the very container the proxy occupies.",
    )
    publish: bool = Field(
        False,
        description="Bind the daemon to every interface INSIDE its container so a published "
        "host port can reach it. Required for a real browser on this machine to use the proxy, "
        "and ENGAGEMENT-ONLY: the lab network is `internal: true`, so a published port there "
        "has no route in the first place. Publishing the HOST port is a separate, explicit step "
        "through the exposure profile — this flag alone exposes nothing.",
    )
    # THE GATE FIELDS. Both default False, so a client that omits them is REFUSED rather than
    # allowed — a default of True would mean an omitted field silently grants exactly what the
    # field was added to require.
    approved: bool = Field(
        False, description="Explicit human approval for starting this proxy. Never defaulted true."
    )
    dangerous_ack: bool = Field(
        False,
        description="The explicit red-confirm. A recording proxy holds full request bodies — "
        "credentials, session tokens and payloads in cleartext — so this is always required.",
    )


class Proxy(BaseModel):
    """One live (or starting) recording proxy."""

    id: str
    container: str
    port: int
    status: str = Field(
        description="starting | listening | down — OBSERVED after the settle window, never "
        "assigned at spawn time. 'listening' means the port was confirmed bound inside the "
        "container; 'starting' means the process is up but the bind is unconfirmed."
    )
    liveness: str = Field("", description="What was actually observed about the process/port.")
    captured: int = 0
    started_at: str
    engagement_id: str | None = None
    #: The address it bound INSIDE the container. Reported, never assigned from the request alone
    #: — the panel has to be able to say which posture is actually running.
    bind_host: str = PROXY_HOST
    published: bool = Field(
        False,
        description="Bound wide inside its container so a published host port can reach it. "
        "This does NOT mean a host port exists — that is the exposure profile's job.",
    )
    #: NEVER the key itself. The panel needs to know a key is in force; it never needs the value,
    #: and a model field is exactly the thing that ends up in a log line or a report.
    api_key_enforced: bool = True
    #: NAMES of the WAF-bypass headers ZAP is actually holding for this proxy, READ BACK from
    #: `replacer/view/rules` rather than echoed from what was sent. Same rule as `api_key_enforced`
    #: one line up and as `browser_id` on the spider: the value is a credential and never appears
    #: in a model, and what is reported is what the daemon holds rather than what we asked for.
    bypass_headers: list[str] = Field(default_factory=list)


class CapturedHeader(BaseModel):
    name: str
    value: str


class CapturedRequest(BaseModel):
    method: str = "GET"
    url: str = ""
    headers: list[CapturedHeader] = Field(default_factory=list)
    #: RAW. Redaction happens in report.py and nowhere else — spec §6.
    body: str = ""


class CapturedResponse(BaseModel):
    status: int | None = None
    headers: list[CapturedHeader] = Field(default_factory=list)
    body: str = ""
    size_bytes: int = 0
    time_ms: int = 0


class CapturedExchange(BaseModel):
    """One recorded request/response pair.

    *** DELIBERATELY NOT `repeater.RepeaterExchange`, THOUGH THE SHAPE MATCHES. ***
    The first version of this module imported those models, and `test_repeater.py` refused it:
    the repeater is HUMAN-ONLY and its lock bans *any* import of the module, not just
    ``repeater.send`` — because a module that can import it is one line from calling it.

    The tempting fix was to add ``cockpit/proxy.py`` to that allow-list. That is the exact
    anti-pattern build #5 was about: widening a safety allow-list so new code fits, rather than
    working within it. The field NAMES match the repeater's on purpose, so the existing panel
    renders a captured exchange with no translation layer and a "replay in repeater" action can
    hand one straight over — the operator gets the reuse without the coupling.
    """

    id: str
    request: CapturedRequest
    response: CapturedResponse
    sent_at: str = ""
    container: str = ""


class ProxyRefused(RuntimeError):
    """The proxy could not start / the request was invalid. NOTHING ran.

    Carries the GATE that refused it so the route can map a safety refusal (403) apart from an
    availability problem (409), rather than collapsing both into one status.
    """

    def __init__(self, reason: str, gate: str = "unavailable",
                 dangerous_flags: list[str] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.gate = gate
        self.dangerous_flags = dangerous_flags or []


# --------------------------------------------------------------------------- #
# the gate — approval + the heuristic red-confirm, before anything spawns
# --------------------------------------------------------------------------- #
def container_for(req: "ProxyStartRequest | ScanStartRequest | SpiderStartRequest") -> str:
    """Engagement runs use the engage sandbox; everything else the isolated lab one.

    Getting this wrong is not cosmetic: a real-target proxy in the egress-less lab box would
    capture nothing, and a lab proxy in the fully-open box would have reach it must not have.

    Shared by the proxy and the scanner deliberately: a scan drives the daemon that a start put
    in a particular container, so the two must agree on which one that is or the scan would talk
    to a port in the wrong box (and, in the lab case, to a box with reach the gate never scoped).
    """
    return config.ENGAGE_SANDBOX_CONTAINER if req.engagement_id else config.SANDBOX_CONTAINER


def bind_host_for(req: ProxyStartRequest) -> str:
    """The address the daemon binds INSIDE its container. One derivation, both callers.

    ``127.0.0.1`` unless the operator asked to publish. A container process on loopback cannot be
    reached through `docker -p` at all — the mapping forwards to the container's bridge
    interface, where nothing is listening — so a published proxy that stayed loopback-bound would
    be silently inert, which is the worst of both worlds: the port is open on the host and the
    feature still does not work.
    """
    return PUBLISHED_PROXY_HOST if req.publish else PROXY_HOST


def server_argv_for(req: ProxyStartRequest, *, api_key: str) -> list[str]:
    """The daemon argv this request will run. THE SINGLE DERIVATION.

    Both the gate and :func:`start_proxy` come through here, for the same reason the WinRM path
    funnels through one join: classifying a DIFFERENT argv than the one that executes reproduces
    Critical 2 in a new place. A test asserts the two are equal.

    *** ``api_key`` IS A REQUIRED ARGUMENT AND THE GATE IS NEVER GIVEN A REAL ONE. ***
    :func:`_gate_request` passes :data:`GATE_KEY_PLACEHOLDER`. That is not ceremony — the gate's
    output is an ExecRequest, and an ExecRequest is the thing this codebase RECORDS, reports and
    feeds to the model. Redacting a secret after handing it over depends on the redactor being
    correct forever; never handing it over cannot regress. Redaction still exists as the second
    layer (``secretargs`` knows ``api.key``), and both are asserted.

    *** ``-config api.disablekey=false`` IS STATED EVEN THOUGH FALSE IS THE DEFAULT. ***
    ZAP persists ``-config`` values into ``$HOME/.ZAP/config.xml``, so "the default" is whatever
    the last run wrote — and the last run was HackPit itself, which used to write
    ``disablekey=true`` on every start. Stating it explicitly is what makes the lock a property
    of this argv rather than of the container's history. See the block on :data:`_keys`.

    *** WHAT ``publish`` WIDENS, AND WHAT PAYS FOR IT. ***
    For a published proxy the bind moves to every interface inside the container AND the API's
    own address filter has to allow a non-loopback caller: a request arriving through a published
    port reaches ZAP from the docker bridge gateway, not from 127.0.0.1, and ZAP's default
    ``api.addrs`` would refuse it. Both widenings are real. What pays for them is that the key is
    ENFORCED on views and actions alike (measured), so what becomes reachable is an HTTP PROXY —
    which is the entire point of the feature — while scan control still refuses everyone who
    cannot present a secret only this process holds.
    """
    argv = [
        "zaproxy", "-daemon",
        "-host", bind_host_for(req),
        "-port", str(req.port),
        "-config", "api.disablekey=false",
        "-config", f"api.key={api_key}",
        # *** THE AJAX SPIDER DOES NOT WORK WITHOUT THIS, AND IT FAILS SILENTLY. ***
        # ZAP's `webdriverlinux` add-on bundles its own chromedriver, built for Chrome 151, and
        # PREFERS it to the system one. Kali ships Chromium 150, so Selenium refuses the session
        # with "This version of ChromeDriver only supports Chrome version 151" — while the API
        # still answers `{"Result":"OK"}` and the crawl reports zero results. Measured; found by
        # the proof, invisible to every hermetic test.
        #
        # Stated on EVERY start, including lab starts, for the reason the whole build turns on:
        # ZAP persists `-config` values, so an unstated key inherits whatever a previous run
        # wrote. The Dockerfile compares the driver's major version against the browser's, so a
        # future image whose packages drift apart fails the build instead of failing here.
        "-config", f"selenium.chromeDriver={SPIDER_DRIVER_PATH}",
    ]
    if req.publish:
        # Address filter, NOT authentication — the key above is the authentication. Without this
        # ZAP answers "API not available from this address" to a correctly-keyed request that
        # arrived through the published port, which reads as a broken feature rather than as a
        # control doing its job.
        argv += [
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
        ]
    return argv


def recorded_argv_for(req: ProxyStartRequest, *, api_key: str) -> list[str]:
    """The daemon argv as it may be WRITTEN DOWN — key redacted, everything else intact.

    The second layer behind "the gate is never given the key". Anything that persists, renders or
    prompts with this argv uses this function; ``secretargs`` masks the ``api.key`` value and
    deliberately leaves ``api.disablekey=false`` visible, because that token is the evidence the
    lock was on and redacting it would destroy the audit trail it exists to provide.
    """
    from . import secretargs

    argv = server_argv_for(req, api_key=api_key)
    return [argv[0], *secretargs.redact_argv(argv[0], argv[1:])]


def kill_pattern_for(port: int) -> list[str]:
    """The ``pkill -f`` pattern that matches the RUNNING process, joined by lifecycle.kill.

    *** THE SPAWNED ARGV IS NOT THE RUNNING ARGV, AND THIS IS WHY. ***
    ``zaproxy`` is a wrapper script that exec's the JVM, so the process actually on the box is::

        java -Xmx2738m -jar /usr/share/zaproxy/zap-2.17.0.jar -daemon -host 127.0.0.1 -port 8090

    The literal string "zaproxy -daemon" never appears in that command line. Passing
    :func:`server_argv_for` to ``pkill -f`` therefore matched NOTHING and the daemon survived
    every stop — found by the proof's teardown check, not by any unit test, because a hermetic
    test has no process to fail to kill.

    The pattern matches on the install path and the PORT, so it is version-agnostic (no
    ``zap-2.17.0.jar`` to rot) and cannot reap a proxy running on a different port.

    *** THE ``[z]`` IS LOad-BEARING, NOT A TYPO. ***
    ``docker exec <c> pkill -f <pattern>`` runs pkill INSIDE the container, so the pattern is
    part of pkill's own command line and ``-f`` matches full command lines — a plain
    ``zaproxy...`` pattern matches the killer as well as the daemon, and pkill SIGTERMs itself.
    Observed directly: the probe shell exited 143 having killed nothing useful. ``[z]aproxy``
    matches the literal text "zaproxy" in the JVM's argv while the killer's own argv contains
    "[z]aproxy", which does not.
    """
    return [rf"[z]aproxy.*-daemon.*-port {int(port)}\b"]


def _gate_request(req: ProxyStartRequest):
    """The ExecRequest the real gates run against.

    Surface: the daemon BINARY, the engagement, and — in LAB mode only — the lab target.

    THE REAL ARGV IS NOT THE SURFACE, and that is deliberate in both directions:

    * ``-host 127.0.0.1`` must NOT go in. The scope extractor reads any dotted token as a
      hostname, so passing it makes the gate refuse the operator's OWN SOCKET as an out-of-scope
      host — a refusal that teaches nothing and trains a workaround. tunnels.py keeps ``-laddr``
      out of its surface for exactly this reason, and this module's first test run reproduced it.

    * THE LAB TARGET must go in, in lab mode. A listener names no target, and lab mode refuses a
      target-less command ("the command must reference the lab") — a LOCKED invariant that
      test_cockpit.py guards and that this build does not touch. Declaring the lab is not a
      workaround around that rule; it is a true statement of scope. :func:`container_for` puts a
      lab proxy in the isolated sandbox, which sits on an ``internal: true`` network with no
      route off the bridge, so the lab target IS everything this listener can ever reach.
      (Decision 2026-08-03, Zaid; the alternatives were engagement-only — which would push
      practice traffic into the fully-open sandbox — and relaxing the locked rule for everyone.)

    In ENGAGEMENT mode the surface stays empty, as tunnels does: engagement mode already permits
    a target-less command, and the engagement's own scope governs what any run may reach.

    Nothing is weakened by the omission of the flags: the danger verdict comes from the BINARY
    plus ``-daemon`` (see ``allowlist._TOOL_ATTACK_FLAGS``), and the port is a bind on a
    container we already own rather than anything network-facing.
    """
    from .models import ExecRequest

    # THE PLACEHOLDER, NOT A KEY. What comes back from here is an ExecRequest, and an ExecRequest
    # is what gets recorded, reported and put in front of the model. See :func:`server_argv_for`.
    argv = server_argv_for(req, api_key=GATE_KEY_PLACEHOLDER)
    # ``-daemon`` IS IN THE SURFACE, and it has to be. The danger verdict for this binary is
    # argument-based (allowlist._TOOL_ATTACK_FLAGS: `-quickurl` attacks, `-daemon` records), so a
    # surface carrying only the binary name would make the red-confirm unfirable and
    # ``dangerous_ack`` decorative — gate-audit finding I2's exact shape. The surface therefore
    # carries the flag that DETERMINES DANGER while still omitting the bind address that would
    # make the scope extractor refuse our own socket.
    surface: list[str] = ["-daemon"]
    if not req.engagement_id:
        surface.append(config.LAB_TARGET_HOST)
    return ExecRequest(
        command=argv[0],
        args=surface,
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def publish_refusal(req: ProxyStartRequest) -> "ProxyRefused | None":
    """Refuse a publish that cannot mean what it says. PURE — spawns nothing.

    ENGAGEMENT ONLY, and by physics before preference. The lab sandbox sits on
    ``hackpit-isolated``, which is ``internal: true``: Docker attaches no gateway, so a published
    host port there has no route to the container and ``exposure.py`` refuses that container
    outright anyway ("exposure and lab isolation are mutually exclusive by construction"). What a
    published lab proxy WOULD do is bind the ZAP API to every interface inside the isolated
    network, where the lab target itself lives — a real widening buying literally nothing.

    Checked BEFORE the executor gates on purpose. This is not a safety verdict about a coherent
    request; it is a request that does not describe a reachable state, and refusing it at
    ``approval`` or ``danger`` would tell the operator to tick a box that cannot help.
    """
    if not req.publish:
        return None
    if not req.engagement_id:
        return ProxyRefused(
            "publish is engagement-only. The lab sandbox runs on an `internal: true` network "
            "with no gateway, so a published port has no route to it — binding wide there would "
            "expose the ZAP API inside the isolated network and still not be reachable from this "
            "machine. Start a lab proxy without publish, or enter an engagement.",
            gate="publish",
        )
    return None


def validate_start(req: ProxyStartRequest):
    """The gate verdict for starting this proxy, spawning nothing. PURE.

    NO ENGAGEMENT PRECONDITION, and that is a deliberate divergence from tunnels.py rather than
    an omission. A pivot listener lives in the engage sandbox, so tunnels refuses lab mode rather
    than make the operator satisfy an isolation gate about a container the listener is not in —
    its docstring calls that "firing a gate on an unrelated condition".

    That reasoning INVERTS here. This proxy runs in whichever sandbox the operator is using, so
    in lab mode the isolation gate is asking about the very container the proxy occupies: the
    relevant condition, not an unrelated one. Requiring an engagement would also lock the proxy
    out of the lab, which is where most of its practice value is.
    """
    from . import executor

    return executor.validate_request(_gate_request(req))


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #
def _container_running(name: str) -> bool:
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return name in out.stdout.split()


def _api_get(container: str, port: int, path: str, timeout: int = 10) -> str:
    """Read one of this module's fixed URLs, via ``docker exec``. NEVER a socket from the backend.

    ``path`` is only ever one of the module constants above; no caller passes a computed value.

    *** THE KEY GOES IN A HEADER, NOT THE QUERY STRING. *** ZAP accepts ``?apikey=`` too, and
    that spelling would put the secret into ZAP's OWN history — the proxy records what passes
    through it, this module's whole purpose is to read that history back, and a report is
    rendered from it. A header keeps the credential out of the artefact the feature produces.
    It also keeps it off the `docker exec` argv's URL, which `ps` on the host can read.

    Always dials 127.0.0.1: this runs INSIDE the container, so loopback reaches the daemon
    whichever address it bound. A published daemon is reachable both ways; an unpublished one is
    reachable only this way, and that asymmetry is the isolation property.
    """
    url = f"http://{PROXY_HOST}:{port}{path}"
    argv = ["docker", "exec", container, "curl", "-s", "--max-time", str(timeout)]
    key = api_key_for(container, port)
    if key:
        argv += ["-H", f"X-ZAP-API-Key: {key}"]
    argv.append(url)
    # *** BYTES, THEN AN EXPLICIT DECODE — NOT `text=True` (build #17). ***
    # `text=True` decodes with the AMBIENT LOCALE codec, which on this Windows host is cp1252.
    # What comes back here is CAPTURED RESPONSE BODIES from arbitrary sites, so a single byte
    # outside that codepage raises UnicodeDecodeError inside subprocess's own reader thread and
    # `out.stdout` lands as None. Reading 200 real messages from a live capture did exactly
    # that. The failure was invisible for as long as it has existed because `history()` catches
    # the downstream TypeError and returns `[]` — this module's recurring silent empty, one
    # layer below the one build #17 came here to fix, and it would have made a real capture look
    # like no capture on every Windows operator's machine.
    try:
        out = subprocess.run(argv, capture_output=True, timeout=timeout + 5)
    except (OSError, subprocess.SubprocessError):
        return ""
    body = (out.stdout or b"").decode("utf-8", "replace")
    # ZAP answers a keyless or wrong-keyed call with an EMPTY BODY, which is also what a dead
    # daemon looks like. Either way an ADOPTED key is now suspect, so it is dropped and the next
    # call re-reads the daemon's argv. Self-healing across a daemon swap, and it costs one extra
    # `docker exec` only on a path that is already returning nothing.
    if not body.strip() and key:
        forget_adopted(container, port)
    return body


def _api_post(container: str, port: int, path: str, fields: dict[str, str],
              timeout: int = 15) -> str:
    """Call one ZAP ACTION with its parameters in a POST BODY, delivered on STDIN.

    *** THIS EXISTS FOR ONE REASON: A BYPASS HEADER'S VALUE IS A CREDENTIAL. ***
    :func:`_api_get` already keeps the API key off the URL by putting it in a header, and its
    docstring says why — the proxy records what passes through it and a report is rendered from
    that history. The replacer rule's ``replacement`` is a SECOND secret, and ZAP's action API
    takes it as a parameter. On a GET it would land in ZAP's own history AND on the
    ``docker exec … curl … <url>`` argv, which ``ps`` on this host can read.

    ZAP accepts every action over POST with a form-encoded body, and ``curl --data-binary @-``
    reads that body from stdin — so the value never touches an argv, a shell or a URL. Same trick
    as build #13 part 3's OOB signature, applied to a different secret. What remains on the argv
    is the API key header, which is the residual build #15 already wrote down and accepted.

    ``-i`` on ``docker exec`` is load-bearing: without it the container's curl gets a closed
    stdin, reads an empty body, and ZAP answers a cheerful ``{"Result":"OK"}`` for a rule with no
    match string. Another OK that is not a result.
    """
    url = f"http://{PROXY_HOST}:{port}{path}"
    body = "&".join(f"{quote_plus(k)}={quote_plus(str(v))}" for k, v in fields.items())
    argv = ["docker", "exec", "-i", container, "curl", "-s", "--max-time", str(timeout),
            "-X", "POST", "--data-binary", "@-",
            "-H", "Content-Type: application/x-www-form-urlencoded"]
    key = api_key_for(container, port)
    if key:
        argv += ["-H", f"X-ZAP-API-Key: {key}"]
    argv.append(url)
    try:
        out = subprocess.run(argv, capture_output=True, timeout=timeout + 5,
                             input=body.encode("utf-8"))
    except (OSError, subprocess.SubprocessError):
        return ""
    # Bytes then an explicit decode, for the same reason as :func:`_api_get` — never let the
    # ambient locale codec decide whether this function works.
    answer = (out.stdout or b"").decode("utf-8", "replace")
    if not answer.strip() and key:
        forget_adopted(container, port)
    return answer


def _post_first_that_answers(container: str, port: int, paths: tuple[str, ...],
                             fields: dict[str, str], timeout: int = 15) -> str:
    """POST to each candidate path until one answers with parseable JSON. "" if none did.

    For the action names that were RENAMED across add-on versions (see the replacer constants).
    An unknown path answers with ZAP's `no_implementor` error or an empty body; either way the
    next spelling is tried. The caller still reads the state back — this only decides which URL
    to speak, never whether it worked.
    """
    for path in paths:
        answer = _api_post(container, port, path, fields, timeout=timeout)
        if not answer.strip():
            continue
        code = str(_json(answer).get("code", ""))
        if code in ("no_implementor", "bad_action", "illegal_parameter"):
            continue
        return answer
    return ""


def _wait_ready(container: str, port: int) -> bool:
    """Poll the version endpoint until the JVM answers.

    Polling beats sleeping a fixed time in both directions: a loaded host is slower than the ~7s
    measured, and a fast one should not be punished for it.
    """
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if '"version"' in _api_get(container, port, _VIEW_VERSION, timeout=3):
            return True
        time.sleep(1)
    return False


def clash_refusal(
    container: str, port: int, observed_port: int | None = None
) -> ProxyRefused | None:
    """The refusal a new proxy in ``container`` would earn from one already there. PURE.

    *** IT USED TO PROTECT AGAINST A STATE IT COULD NOT OBSERVE (build #17). *** The check read
    only ``_models``, which is in-process, so after a backend restart it saw no daemon and would
    happily let ``start_proxy`` spawn a second one — which dies instantly on the home-directory
    lock described below, while ``lifecycle.observe()`` finds the port bound BY THE OLD DAEMON
    and reports the new proxy `up`, holding a key the listening process will never accept. Every
    read after that returns empty. The one function whose entire job is to prevent that failure
    was blind to the only state that produces it.

    ``observed_port`` is what a ZAP daemon is ACTUALLY listening on in that container, from
    :func:`observed_daemon`. It is injected rather than looked up here so this stays pure and
    hermetically testable — running Docker inside this function is the mistake its own history
    records, and CI has no Docker.

    *** ONE PROXY PER CONTAINER, NOT PER PORT — AND THE REASON IS ZAP'S, NOT OURS. ***

    ZAP takes an exclusive lock on its HOME DIRECTORY (``$HOME/.ZAP``), not on its port, so a
    second daemon in the same container dies at startup with "The home directory is already in
    use" whatever port it was given. This check was port-scoped until build #14 part 3's proof
    hit it: a leftover daemon on 8092 killed a fresh one on 8093, and the only evidence was a
    line in the JVM's log inside the container.

    Nothing was UNSAFE about the old behaviour — status is observed, so the dead proxy reported
    itself down rather than lying. It was unexplainable, which is its own kind of defect: the
    operator saw a proxy that would not start, and no reason anywhere in the UI.

    Split out of :func:`start_proxy` so it can be tested WITHOUT Docker. The first version of its
    test drove the whole of ``start_proxy`` and passed locally and failed in CI, where there is
    no Docker and the isolation gate refuses first — a test that silently depended on the
    developer's stack being up. A hermetic suite has to stay hermetic.
    """
    with _lock:
        clash = next(
            (p for p in _models.values() if p.container == container and p.status != "down"),
            None,
        )
    if clash is None:
        # No model — but a daemon can be there without one, and that is the case this function
        # was blind to. Reported as ORPHANED rather than as an ordinary clash, because the fix
        # differs: there is no proxy in the UI to press stop on.
        if observed_port is not None:
            return ProxyRefused(
                f"a ZAP daemon is already running in {container} on :{observed_port}, started "
                "by something other than this backend process (a restart loses the record, not "
                "the daemon). ZAP locks its HOME DIRECTORY rather than its port, so a second "
                "daemon here would die at startup while the port stayed bound by the first — "
                "stop the running one before starting a new proxy",
                gate="limit",
            )
        return None
    return ProxyRefused(
        f"a proxy is already live on {clash.container}:{clash.port} — stop it first"
        + ("" if clash.port == port else
           ". ZAP locks its home directory rather than its port, so a second daemon on "
           f":{port} in the same container would fail to start"),
        gate="limit",
    )


def start_proxy(req: ProxyStartRequest) -> Proxy:
    """Start the recording proxy in the sandbox. GATED — nothing spawns on a refusal."""
    from . import lifecycle

    incoherent = publish_refusal(req)
    if incoherent is not None:
        raise incoherent

    rejected = validate_start(req)
    if rejected is not None:
        raise ProxyRefused(rejected.reason, gate=rejected.gate,
                           dangerous_flags=list(rejected.dangerous_flags))

    container = container_for(req)
    if not _container_running(container):
        raise ProxyRefused(
            f"sandbox '{container}' is not running — bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d)"
        )

    pid = f"zapproxy-{container}-{req.port}"
    # OBSERVED, not assumed: `_models` cannot see a daemon this process did not start.
    seen = observed_daemon(container)
    clash = clash_refusal(container, req.port, observed_port=seen[0] if seen else None)
    if clash is not None:
        raise clash

    # Minted here and nowhere else, AFTER every gate has passed: a refused start must not leave a
    # key behind for a slot that has no daemon, or the next reader would send a stale secret to
    # whatever does answer on that port.
    key = mint_api_key()
    with _lock:
        _keys[_key_slot(container, req.port)] = key

    argv = server_argv_for(req, api_key=key)
    # interactive=False: a daemon needs no stdin, so it gets DEVNULL and proc.stdin is None.
    watched = lifecycle.spawn_watched(
        lifecycle.exec_argv(container, argv, interactive=False), interactive=False
    )
    ready = _wait_ready(container, req.port)
    live = lifecycle.observe(
        watched, container=container, port=req.port, proto="tcp", settle=SETTLE_SECONDS
    )

    detail = live.detail
    if not ready and live.status != "down":
        detail = (detail + " — the API did not answer within the ready window").strip()

    # THE BYPASS HEADER, INSTALLED ON THE DAEMON THAT WILL CARRY IT (build #18 item 1). A fresh
    # daemon in a container that ran a PREVIOUS engagement inherits that engagement's replacer
    # rules out of `$HOME/.ZAP` — so this runs even when the engagement holds no headers, and in
    # that case it CLEARS. It is not allowed to fail the start: a proxy that came up is worth
    # having, and `bypass_headers` reports what ZAP actually holds so a silent install failure
    # shows as an empty list next to an engagement that has one.
    installed: list[str] = []
    if ready:
        try:
            installed = list(
                sync_bypass_headers(container, req.port, req.engagement_id).get("installed") or []
            )
        except Exception as exc:  # noqa: BLE001 - warn and continue; never refuse the start
            detail = (detail + f" — bypass headers were not installed ({exc})").strip()

    model = Proxy(
        id=pid, container=container, port=req.port,
        status=live.status, liveness=detail,
        captured=captured_count(container, req.port) if ready else 0,
        started_at=_now(), engagement_id=req.engagement_id,
        bind_host=bind_host_for(req), published=req.publish, api_key_enforced=True,
        bypass_headers=installed,
    )
    with _lock:
        _models[pid] = model
        _watched[pid] = watched
    return model


def stop_proxy(pid: str) -> Proxy:
    """Stop a running proxy.

    NOT GATED, deliberately. Stopping a listener REMOVES capability; a gate that can refuse to
    stop one is a gate that makes the system less safe. Same position tunnels.py takes.
    """
    with _lock:
        model = _models.get(pid)
        watched = _watched.get(pid)
    if model is None:
        raise ProxyRefused(f"no proxy with id {pid!r}", gate="notfound")

    # THE BYPASS HEADER DIES WITH THE DAEMON — and it has to be removed BEFORE the kill, because
    # afterwards there is no API to remove it through, while ZAP's persisted config.xml keeps the
    # rule for whatever starts next. A credential surviving into an engagement it was not issued
    # for is the failure this ordering exists to prevent.
    # The same applies to an auth CONTEXT, which carries a stored credential in its user.
    try:
        clear_bypass_headers(model.container, model.port)
        clear_auth_contexts(model.container, model.port)
    except Exception:  # noqa: BLE001 - a failed cleanup must still stop the daemon
        pass

    if watched is not None:
        try:
            watched.kill(container=model.container, server_argv=kill_pattern_for(model.port))
        except Exception:  # noqa: BLE001 - a failed teardown must still mark it down
            pass

    stopped = model.model_copy(update={"status": "down", "liveness": "stopped by the operator",
                                       "bypass_headers": []})
    with _lock:
        _models[pid] = stopped
        _watched.pop(pid, None)
        # The key dies with the daemon. Keeping it would mean a later start on the same
        # container:port inherits a secret the new process was never given, and every read
        # against it would fail for a reason nothing in the UI could explain. A RECOVERED key
        # is dropped for the same reason and in the same breath — it was read off the process
        # this call just killed.
        _keys.pop(_key_slot(model.container, model.port), None)
        _adopted.pop(_key_slot(model.container, model.port), None)
    return stopped


def list_proxies() -> list[Proxy]:
    with _lock:
        return list(_models.values())


def status() -> dict[str, Any]:
    """Availability of both sandboxes + the live count — drives the UI banner."""
    with _lock:
        live = [p for p in _models.values() if p.status != "down"]
    return {
        "lab_sandbox": config.SANDBOX_CONTAINER,
        "lab_running": _container_running(config.SANDBOX_CONTAINER),
        "engage_sandbox": config.ENGAGE_SANDBOX_CONTAINER,
        "engage_running": _container_running(config.ENGAGE_SANDBOX_CONTAINER),
        "live": len(live),
        "default_port": DEFAULT_PROXY_PORT,
    }


# --------------------------------------------------------------------------- #
# THE WAF-BYPASS HEADER (build #18 item 1)
#
# A program that invites testing and then buys an edge that refuses it issues researchers a
# header that skips the WAF. Build #17 measured why this is the highest-value line in the build:
# 36 of 39 scanner requests came back `403 AkamaiGHost` with an "Access Denied" body. Those
# payloads never reached the application, so the zero findings were not evidence about the
# application at all.
#
# *** ZAP'S REPLACER IS THE SINGLE POINT, AND THAT IS THE WHOLE DESIGN. ***
# Every request that leaves through this proxy passes the Replacer add-on: the operator's own
# browser, the AJAX spider's browser, the active scanner's payloads, and any sandbox tool run
# with `proxy: true`. One rule covers all four. The alternative — threading a header through
# each caller — would need four correct implementations and would silently miss the fifth.
#
# *** ZAP PERSISTS ITS CONFIGURATION, SO A RULE OUTLIVES THE ENGAGEMENT THAT SET IT. ***
# This module's own history says it in one line: "a daemon that persists its configuration makes
# every measurement conditional on what a previous run wrote". A bypass header left installed
# would keep being sent to whatever the NEXT engagement points this proxy at — a credential
# leaking to a third party by nothing worse than forgetting. So:
#
#   * every install starts by REMOVING every hackpit rule, then adds the current ones,
#   * :func:`stop_proxy` clears them,
#   * exiting an engagement clears them (router),
#   * and what is reported is what ZAP HOLDS, never what we sent.
#
# The rules carry a fixed description prefix so this module can tell its own rules from any a
# human added in ZAP's UI, and it removes only its own.
# --------------------------------------------------------------------------- #
BYPASS_RULE_PREFIX = "hackpit-bypass:"

#: ZAP's match type for "set this request header" — the name goes in ``matchString`` and the
#: value in ``replacement``. NOT ``REQ_HEADER_STR``, which substitutes a substring anywhere in
#: the header block and would rewrite an unrelated header that happened to contain the name.
BYPASS_MATCH_TYPE = "REQ_HEADER"


class ReplacerRule(BaseModel):
    """One replacer rule AS ZAP HOLDS IT — with the replacement VALUE deliberately absent.

    ``replacement_set`` says whether ZAP holds a non-empty value; the value itself is a
    credential and this model is what the route returns to the browser. Reporting the value back
    would undo the entire point of putting it on stdin in the first place.
    """

    description: str = ""
    match_type: str = ""
    match_string: str = Field(
        "", description="For a REQ_HEADER rule this is the HEADER NAME — not a secret."
    )
    enabled: bool = False
    replacement_set: bool = Field(
        False, description="ZAP holds a non-empty replacement. The value is NEVER reported."
    )
    hackpit_managed: bool = Field(
        False, description="This rule carries HackPit's description prefix, so HackPit installed "
        "it and HackPit will remove it. Rules a human added in ZAP's own UI are left alone."
    )


def bypass_rule_description(header_name: str) -> str:
    """The rule description HackPit uses for one header. Lower-cased: header names are."""
    return f"{BYPASS_RULE_PREFIX}{(header_name or '').strip().lower()}"


def _rule_from(obj: Any) -> ReplacerRule | None:
    """One row of ``replacer/view/rules`` -> a :class:`ReplacerRule`. Never raises.

    ZAP has spelled these keys differently across add-on versions (``matchType`` vs
    ``matchtype``, ``enabled`` as a bool or as the string "true"), so each is read defensively.
    A row that carries no description at all is dropped, because a rule this module cannot
    identify is a rule it must not remove.
    """
    if not isinstance(obj, dict):
        return None
    def _pick(*names: str) -> Any:
        for n in names:
            if n in obj:
                return obj[n]
        return None
    description = str(_pick("description", "Description") or "").strip()
    if not description:
        return None
    enabled_raw = _pick("enabled", "Enabled")
    replacement = str(_pick("replacement", "Replacement") or "")
    return ReplacerRule(
        description=description,
        match_type=str(_pick("matchType", "matchtype", "MatchType") or ""),
        match_string=str(_pick("matchString", "matchstring", "MatchString") or ""),
        enabled=str(enabled_raw).strip().lower() in ("true", "1", "yes"),
        replacement_set=bool(replacement),
        hackpit_managed=description.lower().startswith(BYPASS_RULE_PREFIX),
    )


def observed_replacer_rules(container: str, port: int) -> list[ReplacerRule]:
    """Every replacer rule ZAP is holding right now. READ-ONLY. Values never come back.

    This is the arbiter for item 1, not the ``{"Result":"OK"}`` from the add call. The lesson is
    written twice already in this file — ``setOptionBrowserId`` answered OK for a browser it
    could not use, and the ``-daemon`` red-confirm described traffic it did not send.
    """
    rows = _json(_api_get(container, port, _VIEW_REPLACER_RULES)).get("rules")
    if not isinstance(rows, list):
        return []
    out = [_rule_from(r) for r in rows]
    return [r for r in out if r is not None]


def clear_bypass_headers(container: str, port: int) -> list[str]:
    """Remove every rule HackPit installed. Returns the descriptions ZAP no longer holds.

    ONLY HackPit's own rules, identified by the description prefix. A rule a human added in ZAP's
    UI is somebody else's decision, and a cleanup that removed it would be this module reaching
    outside what it owns.

    The return value is computed from a READ-BACK, so a remove that answered OK and did nothing
    reports as still-present rather than as removed.
    """
    before = [r.description for r in observed_replacer_rules(container, port) if r.hackpit_managed]
    for description in before:
        _post_first_that_answers(container, port, _ACTION_REPLACER_REMOVE,
                                 {"description": description})
    after = {r.description for r in observed_replacer_rules(container, port) if r.hackpit_managed}
    return [d for d in before if d not in after]


def install_bypass_headers(container: str, port: int,
                           headers: list[tuple[str, str]]) -> list[ReplacerRule]:
    """Install the bypass headers on this daemon. Returns THE RULES ZAP HOLDS AFTERWARDS.

    ``headers`` is ``[(name, value), …]`` and the values are credentials — they go out through
    :func:`_api_post`, i.e. on stdin, and are never returned, logged or rendered.

    Clears first, then adds, then reads back. Clearing first is what makes this idempotent AND
    what stops an amended header from being sent alongside the one it replaced: ZAP keys a rule
    on its description, so re-adding the same description on some add-on versions appends a
    second rule rather than replacing the first.
    """
    clear_bypass_headers(container, port)
    for name, value in headers or []:
        clean = (name or "").strip()
        if not clean or not (value or "").strip():
            # An empty value would make the rule STRIP the header rather than set it. Skipped
            # here as well as refused at the engagement, because this function is also reachable
            # from the proof script with hand-built input.
            continue
        _post_first_that_answers(container, port, _ACTION_REPLACER_ADD, {
            "description": bypass_rule_description(clean),
            "enabled": "true",
            "matchType": BYPASS_MATCH_TYPE,
            "matchString": clean,
            "matchRegex": "false",
            "replacement": value,
            # No `initiators` and no `url`: an empty initiators list means EVERY initiator —
            # proxied browser traffic, the spider's browser and the active scanner alike — which
            # is the property item 1 is actually asking for. Naming a subset here would silently
            # exclude whichever one was forgotten.
            "initiators": "",
        })
    return [r for r in observed_replacer_rules(container, port) if r.hackpit_managed]


def sync_bypass_headers(container: str, port: int, engagement_id: str | None) -> dict[str, Any]:
    """Make this daemon hold exactly the bypass headers of ``engagement_id`` — and say what it holds.

    With no engagement (lab mode, or an engagement that was exited) this CLEARS and holds none.
    That direction is deliberate: the failure mode worth preventing is a credential surviving into
    a session it was not issued for, not a missing header, which is visible the moment a request
    comes back 403.

    Returns ``{"installed": [names], "cleared": [descriptions], "rules": [ReplacerRule]}`` —
    every field derived from a read-back of ZAP, and no field carrying a value.
    """
    from . import engagement as engagement_mod

    wanted: list[tuple[str, str]] = []
    if engagement_id:
        try:
            wanted = engagement_mod.bypass_headers(engagement_id)
        except Exception:  # noqa: BLE001 - a header lookup must never break a proxy start
            wanted = []
    if not wanted:
        cleared = clear_bypass_headers(container, port)
        held = [r for r in observed_replacer_rules(container, port) if r.hackpit_managed]
        return {"installed": [], "cleared": cleared, "rules": held}
    held = install_bypass_headers(container, port, wanted)
    return {
        "installed": [r.match_string for r in held],
        "cleared": [],
        "rules": held,
    }


# --------------------------------------------------------------------------- #
# history — READ-ONLY and UNGATED
# --------------------------------------------------------------------------- #
def _first_line(raw: Any) -> str:
    return str(raw or "").replace("\r\n", "\n").split("\n", 1)[0].strip()


def _headers_from(raw: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in str(raw or "").replace("\r\n", "\n").split("\n")[1:]:
        if not line.strip() or ":" not in line:
            continue
        name, _, value = line.partition(":")
        out.append((name.strip(), value.strip()))
    return out


def parse_message(obj: Any, container: str):
    """One ZAP message -> a RepeaterExchange. NEVER raises; returns None if unusable.

    MEASURED shape (ZAP 2.17.0): ``id, requestHeader, requestBody, responseHeader, responseBody,
    rtt, timestamp, type, tags, note, cookieParams``. ``requestHeader``'s first line is
    ``METHOD URL HTTP/x``; ``responseHeader``'s is ``HTTP/x STATUS REASON``.

    A MALFORMED RESPONSE LINE DOES NOT DISCARD THE RECORD. ZAP logs exchanges that never
    completed (the fixture carries a real one reading ``HTTP/1.0 0``), and the request half is
    still worth having — so the status becomes None and everything else survives.

    Returns a :class:`CapturedExchange` — same field names as the repeater's model, but a local
    class, because the repeater is human-only and its lock bans importing it. See that class.
    """
    try:
        if not isinstance(obj, dict):
            return None
        parts = _first_line(obj.get("requestHeader")).split()
        if len(parts) < 2 or not parts[1].startswith("http"):
            return None
        method, url = parts[0], parts[1]

        status = None
        resp_parts = _first_line(obj.get("responseHeader")).split()
        if len(resp_parts) >= 2 and resp_parts[1].isdigit():
            code = int(resp_parts[1])
            # ZAP writes "HTTP/1.0 0" for an exchange that never got a response.
            status = code if 100 <= code <= 599 else None

        try:
            rtt = int(str(obj.get("rtt") or "0"))
        except (TypeError, ValueError):
            rtt = 0

        body = str(obj.get("responseBody") or "")
        mid = str(obj.get("id", ""))
        return CapturedExchange(
            id=f"zap-{mid}",
            request=CapturedRequest(
                method=method, url=url,
                headers=[CapturedHeader(name=n, value=v)
                         for n, v in _headers_from(obj.get("requestHeader"))],
                # RAW, deliberately. Redaction happens in report.py and nowhere else — spec §6.
                body=str(obj.get("requestBody") or ""),
            ),
            response=CapturedResponse(
                status=status,
                headers=[CapturedHeader(name=n, value=v)
                         for n, v in _headers_from(obj.get("responseHeader"))],
                body=body, size_bytes=len(body), time_ms=rtt,
            ),
            sent_at=str(obj.get("timestamp") or ""),
            container=container,
        )
    except Exception:  # noqa: BLE001 - a parser must never break a completed run
        return None


def endpoints_from(exchanges, session_id: str, run_id: str | None = None):
    """Captured requests -> Endpoint records. Existing model, no schema change."""
    from urllib.parse import parse_qs, urlparse

    from state.models import Endpoint

    out = []
    for ex in exchanges:
        if ex is None or not ex.request.url.startswith("http"):
            continue
        out.append(Endpoint(
            session_id=session_id, url=ex.request.url, method=ex.request.method,
            status=ex.response.status,
            params=sorted(parse_qs(urlparse(ex.request.url).query).keys()),
            source_run_id=run_id,
        ))
    return out


def captured_count(container: str, port: int) -> int:
    raw = _api_get(container, port, _VIEW_COUNT)
    try:
        return int(json.loads(raw).get("numberOfMessages", 0))
    except (ValueError, AttributeError, TypeError):
        return 0


def history(container: str, port: int, start: int = 0, count: int = 50):
    """RECENT captured exchanges — the NEWEST window, which is not what this used to return.

    READ-ONLY and UNGATED. A panel that refreshes cannot demand approval per refresh, and
    ``lifecycle.port_is_bound()`` sets the precedent by running ``ss`` the same way. See the
    note on the URL constants: this path reaching ZAP means reaching it unapproved, so it issues
    only the two fixed view URLs.

    *** IT SAID "RECENT" AND RETURNED THE OLDEST (build #17). *** ZAP's ``start`` counts from the
    BEGINNING of history, and this passed the caller's ``start`` straight through — defaulting to
    0. Measured on a daemon holding 1,296 exchanges: ``start=0`` returned requests to
    ``example.com`` from hours earlier, while the traffic the operator was actually looking at
    sat at the tail. The `:proxy` captured-traffic panel passes no ``start`` at all, so it has
    always shown *the first 50 requests that daemon ever recorded*, permanently, however long
    the engagement ran.

    **The knock-on is the serious half.** ``session_health`` reads ``history(count=200)`` to
    decide whether a scan's traffic has started coming back login-shaped — build #16's answer to
    a silent wrong answer. Judging the OLDEST 200 exchanges, it was looking at the moment the
    session was freshly established, so it could not detect a session expiring mid-scan by
    construction. It reported ``ok`` throughout build #17's live scan for that reason, not
    because it had checked.

    ``start`` is now an offset BACK from the newest, so paging still works and ``start=0`` means
    "the latest window". Order within the window stays chronological — a traffic log reads that
    way, and reversing it would change what every existing caller sees for no stated need.
    """
    total = captured_count(container, port)
    end = max(0, total - int(start))
    begin = max(0, end - int(count))
    count = end - begin
    if count <= 0:
        return []
    raw = _api_get(container, port, f"{_VIEW_MSGS}?start={begin}&count={count}")
    try:
        msgs = json.loads(raw).get("messages") or []
    except (ValueError, AttributeError, TypeError):
        return []
    parsed = [parse_message(m, container) for m in msgs]
    return [e for e in parsed if e is not None]


# --------------------------------------------------------------------------- #
# THE SCANNER (build #14 part 3) — GATED start, OBSERVED status, UNGATED stop
#
# What this adds over part 1's `zaproxy -cmd -quickurl <url>`: an aim. `-quickurl` spiders the
# site and attacks whatever the crawl found, so an endpoint reached only by USING the app —
# `/rest/products/search?q=` behind a login, an API route nothing links to, the exact request a
# ffuf run just made — is not in its reach. Those are precisely what the proxy already recorded.
# MEASURED 2026-08-04: one captured endpoint, 376 attack requests, one live High SQL injection.
# --------------------------------------------------------------------------- #
#: ZAP's own words for how bad an alert is -> the severity vocabulary state.models.Finding uses.
#: NOT reusable from parsers._ZAP_RISK, which maps the REPORT's numeric `riskcode` ("0".."3").
#: The API says `risk: "High"`. Two shapes, two maps; see :func:`alerts_from` and spec §2.3.
_RISK_TO_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


# --------------------------------------------------------------------------- #
# AUTHENTICATED-SCAN SESSION EXPIRY — turning a silent wrong answer into a loud one
#
# Build #15's AJAX spider crawls behind a login by inheriting a session the human established
# by hand in a real browser. It added NO ZAP context, no session-management configuration and
# no authentication handling — verified — which is fine, and is not what this is.
#
# THE PROBLEM IS WHAT HAPPENS WHEN THAT SESSION EXPIRES MID-SCAN. The active scanner does not
# stop. It keeps firing payloads at what are now login redirects, finds nothing in them, and
# reports **zero findings** — which is indistinguishable from "the application is secure".
# That is the worst failure shape this project recognises: not a crash, not an error, but a
# confident and wrong answer nobody has a reason to doubt.
#
# THIS IS THE CHEAP HONEST VERSION, on purpose. It does not re-authenticate, maintain a
# session, or build a ZAP context — all of which are a separate decision. It only NOTICES
# that scan traffic has started coming back login-shaped, and says so. Converting a silent
# failure into a visible one is the whole goal; fixing the failure is a different build.
# --------------------------------------------------------------------------- #
#: Path fragments that mean "you are being sent to a login". Matched on the redirect TARGET.
_LOGIN_PATHS = (
    "/login", "/signin", "/sign-in", "/log-in", "/auth", "/sso", "/session/new",
    "/account/login", "/users/sign_in", "/oauth", "/saml", "/adfs", "/idp",
)
#: Markers of a login FORM in a response body. Deliberately narrow: a password input is hard
#: to produce by accident, while the word "login" appears in half the nav bars on the web.
_LOGIN_BODY_MARKERS = (
    'type="password"', "type='password'", 'name="password"', "name='password'",
    'id="password"', "j_security_check", 'name="username" ', "__requestverificationtoken",
)
#: Below this many sampled responses there is nothing to judge. A verdict drawn from four
#: requests would be a guess wearing a percentage.
_SESSION_MIN_SAMPLE = 10
#: What share of sampled responses has to look login-shaped before we say so.
_SESSION_SUSPECT_SHARE = 0.30
#: ...and the share of IDENTICAL responses that means the app collapsed to one shape.
_SESSION_UNIFORM_SHARE = 0.90


def _is_login_redirect(exchange: "CapturedExchange") -> bool:
    status = exchange.response.status or 0
    if status not in (301, 302, 303, 307, 308):
        return False
    for h in exchange.response.headers:
        if h.name.lower() == "location":
            target = (h.value or "").lower()
            return any(p in target for p in _LOGIN_PATHS)
    return False


def _has_login_form(exchange: "CapturedExchange") -> bool:
    if (exchange.response.status or 0) != 200:
        return False
    body = (exchange.response.body or "").lower()
    return any(m in body for m in _LOGIN_BODY_MARKERS)


def session_health(exchanges: list["CapturedExchange"]) -> dict[str, Any]:
    """Does this scan traffic still look authenticated? PURE — reads, decides nothing else.

    Three independent signals, because a session can end in three different shapes:
      * a redirect to a login path,
      * a 200 that is really the login page,
      * a wall of 401/403.
    Plus a fourth that catches the ones those miss: a COLLAPSE to a single response shape.
    An application answering 90% of a varied scan with the same status and near-identical
    body length has stopped distinguishing between the requests, which is what a login wall
    looks like when it renders a friendly page instead of redirecting.

    Verdicts are ``ok`` | ``suspect`` | ``unknown``, and ``unknown`` is used freely. With too
    few responses to judge, saying so is the honest answer; "ok" on a sample of four would
    re-create the false confidence this exists to remove.
    """
    sampled = [e for e in exchanges if (e.response.status or 0) > 0]
    total = len(sampled)
    if total < _SESSION_MIN_SAMPLE:
        return {
            "verdict": "unknown",
            "reasons": [
                f"only {total} response(s) to look at — too few to judge whether the "
                "session is still live"
            ],
            "sampled": total, "login_redirects": 0, "login_bodies": 0,
            "auth_rejections": 0, "uniform_share": 0.0,
        }

    redirects = sum(1 for e in sampled if _is_login_redirect(e))
    bodies = sum(1 for e in sampled if _has_login_form(e))
    rejections = sum(1 for e in sampled if (e.response.status or 0) in (401, 403))

    shapes: dict[tuple[int, int], int] = {}
    for e in sampled:
        # Bucket by status + body size rounded to 100 bytes: a login page rendered for many
        # different URLs varies by a few bytes, not by kilobytes.
        key = (e.response.status or 0, (e.response.size_bytes or len(e.response.body or "")) // 100)
        shapes[key] = shapes.get(key, 0) + 1
    top_shape, top_count = max(shapes.items(), key=lambda kv: kv[1])
    uniform_share = top_count / total

    reasons: list[str] = []
    login_share = (redirects + bodies) / total
    if login_share >= _SESSION_SUSPECT_SHARE:
        parts = []
        if redirects:
            parts.append(f"{redirects} redirected to a login path")
        if bodies:
            parts.append(f"{bodies} returned a login form")
        reasons.append(
            f"{int(login_share * 100)}% of {total} responses were login-shaped ("
            + ", ".join(parts) + ")"
        )
    if rejections / total >= _SESSION_SUSPECT_SHARE:
        reasons.append(
            f"{rejections} of {total} responses were 401/403 — the credential is being refused"
        )
    if uniform_share >= _SESSION_UNIFORM_SHARE:
        reasons.append(
            f"{int(uniform_share * 100)}% of responses collapsed to one shape (HTTP "
            f"{top_shape[0]}, ~{top_shape[1] * 100} bytes) — the app stopped distinguishing "
            "between the requests, which is what a login wall looks like"
        )

    return {
        "verdict": "suspect" if reasons else "ok",
        "reasons": reasons,
        "sampled": total,
        "login_redirects": redirects,
        "login_bodies": bodies,
        "auth_rejections": rejections,
        "uniform_share": round(uniform_share, 2),
    }


# --------------------------------------------------------------------------- #
# SCAN POLICY (build #18 item 3) — fewer requests, and the ones that could apply
#
# Build #17's measurement: 39 attack requests at one endpoint, 36 refused `403 AkamaiGHost`,
# roughly three requests a minute through a tarpitting edge. A large share of them came from
# checks that could not have found anything — a Shellshock probe against a Next.js storefront
# costs a request, earns a WAF hit, and has nowhere to land.
#
# So a policy here is A LIST OF CHECKS TO SWITCH OFF, plus the strength and threshold, and each
# entry carries WHY. The reasons are what make this reviewable: "disabled because the target is
# not a C server" is a claim someone can disagree with; a bare id list is not.
#
# *** IT IS APPLIED FROM A KNOWN BASELINE ON EVERY SCAN, AND NEVER RESET AFTERWARDS. ***
# Two facts force that shape, and both are already written down in this file:
#   1. ZAP PERSISTS ITS CONFIGURATION. A policy set for one scan is still set for the next one
#      and for the next ENGAGEMENT, so reading "what is enabled" tells you what a previous run
#      wrote. Every apply therefore starts with `enableAllScanners` and states strength and
#      threshold explicitly, exactly as `api.disablekey=false` is stated even though false is
#      ZAP's own default.
#   2. A SCAN IS ASYNCHRONOUS. `start_scan` returns as soon as ZAP accepts it, so a "reset when
#      finished" would either race the running scan or need a watcher that outlives the request.
#      Resetting at the START of the next scan achieves the same property with no race.
#
# The consequence is stated rather than buried: BETWEEN scans, the daemon holds the last policy
# applied. Anything that reads scanner state outside a scan start is reading history, and
# :func:`observed_scan_policy` is there so it reads it from ZAP rather than from our hopes.
# --------------------------------------------------------------------------- #
#: ZAP's five scanner CATEGORIES (`org.parosproxy.paros.core.scanner.Category`). Strength and
#: threshold are set per category, so setting them "globally" means setting all five.
_POLICY_CATEGORY_IDS = (0, 1, 2, 3, 4)

DEFAULT_SCAN_POLICY = "default"


class ScanPolicy(BaseModel):
    """A named active-scan policy. Data only — applying it is :func:`apply_scan_policy`."""

    name: str
    description: str
    attack_strength: str = Field(
        "MEDIUM", description="LOW | MEDIUM | HIGH | INSANE — how many payloads each rule sends."
    )
    alert_threshold: str = Field(
        "MEDIUM", description="OFF | LOW | MEDIUM | HIGH — how sure a rule must be to report."
    )
    disabled_scanners: dict[int, str] = Field(
        default_factory=dict,
        description="ZAP plugin id -> WHY it is off for this policy. A bare id list would be "
        "unreviewable; the reason is the part a human can disagree with.",
    )


#: THE TWO POLICIES. `default` is ZAP's own behaviour stated explicitly rather than inherited,
#: which is what makes it a usable CONTROL for the measurement item 3 asks for: same endpoint,
#: same everything, one variable — the disabled set.
SCAN_POLICIES: dict[str, ScanPolicy] = {
    DEFAULT_SCAN_POLICY: ScanPolicy(
        name=DEFAULT_SCAN_POLICY,
        description="Every active-scan rule ZAP ships, at medium strength. The widest reach and "
        "the most requests. This is ZAP's own default behaviour, stated explicitly so that what "
        "runs is a property of this policy rather than of whatever the last scan wrote.",
        attack_strength="MEDIUM",
        alert_threshold="MEDIUM",
        disabled_scanners={},
    ),
    "targeted-web": ScanPolicy(
        name="targeted-web",
        description="For a modern JavaScript web application or JSON API behind a CDN. Switches "
        "off the rules that are locked to a platform the target is not running — they cannot "
        "find anything, and each one costs requests through an edge that is already pacing us to "
        "about three a minute.",
        attack_strength="MEDIUM",
        alert_threshold="MEDIUM",
        disabled_scanners={
            30001: "Buffer Overflow — a memory-safety probe against a C server. Node/JVM/.NET "
                   "runtimes do not have the failure this looks for.",
            30002: "Format String Error — same family, same reason.",
            30003: "Integer Overflow Error — same family, same reason.",
            10048: "Remote Code Execution (Shell Shock) — needs a CGI handler that shells out to "
                   "bash. This is the check whose payload build #17 caught being 403'd.",
            40009: "Server Side Include — Apache/nginx SSI directives.",
            40028: "ELMAH Information Leak — an ASP.NET error-logging module.",
            40032: ".htaccess Information Leak — an Apache configuration file.",
            10045: "Source Code Disclosure /WEB-INF — a Java servlet-container layout.",
            7: "Remote File Inclusion — needs PHP with remote URL includes enabled.",
        },
    ),
}


def scan_policy_for(name: str) -> ScanPolicy:
    """The named policy, or the default. AN UNKNOWN NAME IS NOT AN ERROR — it is a default.

    Deliberately not a refusal. A typo'd policy name should cost the operator a wider scan they
    can see reported back (`Scan.scan_policy` says which policy actually ran), not a 403 that
    reads like a safety verdict. Nothing here decides whether a scan may happen.
    """
    return SCAN_POLICIES.get((name or "").strip() or DEFAULT_SCAN_POLICY,
                             SCAN_POLICIES[DEFAULT_SCAN_POLICY])


class ObservedPolicy(BaseModel):
    """What ZAP HOLDS after a policy was applied. Read back, never echoed.

    ``disabled_ids`` is the intersection of "we asked for this off" and "ZAP reports it off", so
    a plugin id that does not exist in this ZAP build shows up as *requested but not held* rather
    than being silently counted as a success.
    """

    requested: str = ""
    attack_strength: list[str] = Field(
        default_factory=list, description="Strength per category, AS ZAP REPORTS IT."
    )
    alert_threshold: list[str] = Field(default_factory=list)
    disabled_ids: list[int] = Field(
        default_factory=list, description="Requested AND confirmed disabled by a read-back."
    )
    not_held: list[int] = Field(
        default_factory=list,
        description="Requested off, but ZAP does not report them disabled — usually a plugin id "
        "this ZAP build does not have. Reported rather than swallowed.",
    )
    scanners_seen: int = Field(0, description="How many scan rules the read-back could see. 0 "
                              "means the read FAILED, not that ZAP has no rules.")


def observed_scan_policy(container: str, port: int,
                         requested: str = "") -> ObservedPolicy:
    """What the daemon's active-scan configuration actually is. READ-ONLY.

    ``scanners_seen == 0`` is the honest report of a FAILED read — this module's recurring
    silent-empty, named in the model rather than left for a caller to misread as "nothing is
    disabled".
    """
    wanted = set(scan_policy_for(requested).disabled_scanners) if requested else set()

    rows = _json(_api_get(container, port, _VIEW_SCANNERS)).get("scanners")
    disabled: set[int] = set()
    seen = 0
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            seen += 1
            if str(row.get("enabled", "")).strip().lower() in ("false", "0", "no"):
                disabled.add(_int(row.get("id")))

    strengths: list[str] = []
    thresholds: list[str] = []
    prows = _json(_api_get(container, port, _VIEW_SCAN_POLICIES)).get("policies")
    if isinstance(prows, list):
        for row in prows:
            if not isinstance(row, dict):
                continue
            strengths.append(str(row.get("attackStrength") or row.get("attackstrength") or ""))
            thresholds.append(str(row.get("alertThreshold") or row.get("alertthreshold") or ""))

    return ObservedPolicy(
        requested=requested or DEFAULT_SCAN_POLICY,
        attack_strength=sorted({s for s in strengths if s}),
        alert_threshold=sorted({t for t in thresholds if t}),
        disabled_ids=sorted(wanted & disabled) if wanted else sorted(disabled),
        not_held=sorted(wanted - disabled),
        scanners_seen=seen,
    )


def apply_scan_policy(container: str, port: int, name: str) -> ObservedPolicy:
    """Put ``name``'s policy on the daemon, FROM A KNOWN BASELINE, and read it back.

    Order matters and is the point: enable everything first, THEN disable this policy's set. A
    disable-only apply would inherit whatever the previous scan switched off and call it this
    policy — the same class of mistake as measuring `api.key` against a config a previous run
    wrote.

    Never raises and never refuses. A policy that would not apply leaves a wider scan, which is
    a worse measurement and not a safety event; the returned :class:`ObservedPolicy` says so.
    """
    policy = scan_policy_for(name)
    try:
        _api_get(container, port, _ACTION_ENABLE_ALL_SCANNERS)
        for category in _POLICY_CATEGORY_IDS:
            _api_get(container, port,
                     f"{_ACTION_POLICY_STRENGTH}?id={category}"
                     f"&attackStrength={quote_plus(policy.attack_strength)}")
            _api_get(container, port,
                     f"{_ACTION_POLICY_THRESHOLD}?id={category}"
                     f"&alertThreshold={quote_plus(policy.alert_threshold)}")
        if policy.disabled_scanners:
            ids = ",".join(str(i) for i in sorted(policy.disabled_scanners))
            _api_get(container, port, f"{_ACTION_DISABLE_SCANNERS}?ids={quote_plus(ids)}")
    except Exception:  # noqa: BLE001 - the read-back below is what the caller is told
        pass
    return observed_scan_policy(container, port, requested=policy.name)


class ScanStartRequest(BaseModel):
    """Start an ACTIVE SCAN against one URL the proxy already captured."""

    target_url: str = Field(
        description="The URL to attack. It must already be in ZAP's Sites tree — i.e. something "
        "the proxy recorded. ZAP itself answers 'url_not_found' otherwise (measured), which is "
        "why this feature can only ever aim at traffic that already passed through the proxy."
    )
    port: int = Field(DEFAULT_PROXY_PORT, ge=1024, le=65535)
    recurse: bool = Field(
        False,
        description="Also attack everything below this URL in the tree. Same host either way — "
        "a subtree is same-origin — so this changes how MUCH attack traffic runs, not where it "
        "goes. The approved surface declares `-quickurl`, which means spider-then-scan, so it "
        "already describes more aggression than recursing over an existing tree.",
    )
    scan_policy: str = Field(
        DEFAULT_SCAN_POLICY,
        description="Named policy: 'default' (every rule ZAP ships) or 'targeted-web' (the "
        "platform-locked rules switched off). An UNKNOWN NAME FALLS BACK TO THE DEFAULT rather "
        "than refusing — the policy chooses how many requests to send, and nothing about it is a "
        "safety verdict. What actually ran comes back on the Scan as `policy_observed`.",
    )
    engagement_id: str | None = Field(
        None, description="Engagement to attribute against. OMIT for LAB mode."
    )
    # THE GATE FIELDS. Both default False so an omitted field is REFUSED, never granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False,
        description="The explicit red-confirm. This sends real SQLi/XSS/command-injection "
        "payloads at every parameter of the target — 376 requests against a single endpoint in "
        "the measurement. Always required.",
    )

    @field_validator("target_url")
    @classmethod
    def _must_be_http(cls, v: str) -> str:
        """Refuse anything that is not an http(s) URL, before any gate runs.

        Not defence in depth for its own sake: the gate surface is ``-quickurl <target>`` and the
        scope extractor reads a HOST out of it. A ``file://`` or bare string has no host, so it
        would reach the target gate as a target-less command and be refused for a confusing
        reason — or, in engagement mode where target-less commands are permitted, be refused by
        nothing here at all and only bounce off ZAP. Refusing the shape up front means the
        surface the gate sees always contains a real host.
        """
        v = (v or "").strip()
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("target_url must be an http:// or https:// URL")
        return v


class Scan(BaseModel):
    """One active scan. Every count here is READ BACK FROM ZAP, never assigned at launch."""

    id: str
    container: str
    port: int
    target_url: str = ""
    recurse: bool = False
    state: str = Field(
        "", description="ZAP's own word: RUNNING | PAUSED | FINISHED | STOPPED. Observed."
    )
    progress: int = 0
    requests: int = Field(0, description="Attack requests ZAP has sent for this scan.")
    alerts: int = 0
    started_at: str = ""
    engagement_id: str | None = None
    #: The policy NAME that was requested for this scan, and what ZAP actually held after it was
    #: applied. Both blank/None for a scan this backend process did not start — ZAP does not
    #: report how a scan was configured, and inventing it would be worse than admitting we do not
    #: know. See :func:`observed_scans`.
    scan_policy: str = ""
    policy_observed: ObservedPolicy | None = None
    #: NAMES of the WAF-bypass headers in force when this scan started, read back from ZAP.
    #: This is what makes a 403 share interpretable: "36 of 39 refused" means one thing with the
    #: program's bypass header on and something else entirely without it.
    bypass_headers: list[str] = Field(default_factory=list)
    #: The ZAP context this scan ran inside, and what tier of authentication it had. Blank/0 when
    #: none was configured — which is the pre-build-#18 behaviour and is a perfectly ordinary
    #: scan, not an error.
    context_name: str = ""
    auth_tier: int = Field(0, description="0 none | 2 context+session | 3 form auth + re-login.")


class ScanAlert(BaseModel):
    """One alert as the API reports it.

    *** NOT the shape `state/parsers.py::parse_zap` reads, and that is the trap of this build. ***
    That parser handles the `-quickurl` REPORT: nested under `site[].alerts[]`, severity in
    `riskcode` ("0".."3"), plugin in `pluginid`, the URL down in `instances[].uri`. The API
    returns a FLAT list with `risk: "High"`, `pluginId`, and `url` on the alert itself. Feeding an
    API response to `parse_zap` returns ZERO findings silently — `_zap_report()` requires a `site`
    key — which is part 1's headline trap (a parser matched against a string nobody measured)
    wearing new clothes. A test asserts the two are NOT interchangeable so this cannot be
    "simplified" into one function by someone who has not measured both.
    """

    id: str = ""
    name: str = ""
    risk: str = ""
    confidence: str = ""
    url: str = ""
    method: str = "GET"
    param: str = ""
    evidence: str = ""
    attack: str = ""
    plugin_id: str = ""
    cwe_id: str = ""
    description: str = ""
    solution: str = ""


# --------------------------------------------------------------------------- #
# the gate — the same four gates, given an honest surface
# --------------------------------------------------------------------------- #
def scan_target_for(req: ScanStartRequest) -> str:
    """*** THE SINGLE DERIVATION OF WHAT GETS ATTACKED. ***

    Part 2's lock was "the gated argv is the spawned argv". **That lock cannot be restated here**,
    because the gate classifies an ARGV and what executes is a URL — asserting string equality
    between the two would be theatre. The property underneath it still holds and is what matters:
    *the thing the gate scoped is the thing that gets attacked*.

    So both sides come through this one function: :func:`_gate_scan_request` puts its output in
    the surface the scope extractor reads, and :func:`scan_url_for` percent-encodes the SAME
    output into ZAP's ``url=`` parameter. A test asserts the host the gate scoped is the host the
    API attacks, for a target carrying a port, a path and a query string.
    """
    return req.target_url.strip()


def scan_argv_for(req: ScanStartRequest) -> list[str]:
    """The command this scan is EQUIVALENT TO, which is what the human approves.

    ``-quickurl`` is defined in ``allowlist._TOOL_ATTACK_FLAGS`` as "spider THEN ACTIVE SCAN —
    real SQLi/XSS/command-injection payloads at every parameter it discovered". An
    ``ascan/action/scan`` is that attack MINUS the spider, aimed at a tree the proxy already
    built. So the declared command describes strictly MORE than what runs.

    That direction is the whole argument. Declaring more aggression than you perform is safe;
    declaring less is the Critical 2 defect. This surface therefore needs none of the omissions
    the DAEMON surface needed (:func:`_gate_request` drops ``-host 127.0.0.1`` so the scope
    extractor does not refuse our own socket) — there is no bind address in it, so the whole argv
    goes to the gate exactly as written.
    """
    return ["zaproxy", "-quickurl", scan_target_for(req)]


#: ``ascan/action/scan`` attacks as an anonymous client. ``scanAsUser`` attacks as a CONFIGURED
#: USER of a context, which is what makes Tier 3's automatic re-login reachable — ZAP can only
#: re-authenticate if it knows who to re-authenticate as.
_ACTION_SCAN_AS_USER = "/JSON/ascan/action/scanAsUser/"


def scan_url_for(req: ScanStartRequest, context_id: str = "", user_id: str = "") -> str:
    """The API path+query that launches the scan.

    *** THE CONTEXT AND USER ARE PARAMETERS, NOT LOOKUPS, AND THAT IS DELIBERATE. ***
    This function is PURE and is one half of "the thing the gate scoped is the thing that gets
    attacked" — a lock that a `docker exec` inside here would break, in exactly the way
    `clash_refusal` records having been broken. :func:`start_scan` resolves the ids and passes
    them in; every existing caller passes neither and gets the pre-build-#18 URL unchanged.

    With a user, the endpoint becomes ``scanAsUser``: ZAP then knows which account to
    re-authenticate as when the logged-out indicator matches mid-scan. Without one it stays
    ``scan``, with the context attached when there is a context — the scanner still runs inside
    the context's session management, it just has no identity to re-establish.

    *** WHY THE TARGET IS PERCENT-ENCODED, AND WHY THAT IS A SAFETY CONTROL ***

    The operator-supplied target is interpolated into a URL that carries THE SCAN'S OWN
    PARAMETERS. A target containing ``&recurse=true`` would append to ZAP's parameter list and
    turn recursion on — the human approves one scan and a broader one runs. That is Critical 2
    expressed in a query string rather than an argv, and nothing about a text field stops a ``&``.

    ``quote(safe="")`` encodes ``&``, ``=``, ``?`` and ``#``, so the target cannot escape its own
    parameter into ZAP's parser. A test asserts a target carrying ``&recurse=true`` does not
    enable recursion, with a control proving the parameter can still be set legitimately.

    (Shell injection is a separate and already-closed question: :func:`_api_get` hands argv to
    ``subprocess.run`` as a LIST with no shell, as part 2 established.)

    ``inScopeOnly=false`` because HackPit does not configure ZAP CONTEXTS — with none defined,
    ZAP considers nothing in scope and the parameter would refuse every scan. Scope is enforced
    where it belongs, at HackPit's own target gate (:func:`validate_scan`), which reads the real
    host out of the surface. Do not "tighten" this to true without first defining contexts; it
    would not add a control, it would remove the feature.
    """
    target = quote(scan_target_for(req), safe="")
    recurse = "true" if req.recurse else "false"
    if user_id and context_id:
        return (
            f"{_ACTION_SCAN_AS_USER}?url={target}&recurse={recurse}"
            f"&contextId={quote(str(context_id), safe='')}"
            f"&userId={quote(str(user_id), safe='')}"
        )
    tail = f"&contextId={quote(str(context_id), safe='')}" if context_id else ""
    return (
        f"{_ACTION_SCAN}?url={target}"
        f"&recurse={recurse}"
        f"&inScopeOnly=false{tail}"
    )


def _gate_scan_request(req: ScanStartRequest):
    """The ExecRequest the real gates run against. The FULL equivalent argv, nothing omitted."""
    from .models import ExecRequest

    argv = scan_argv_for(req)
    return ExecRequest(
        command=argv[0],
        args=argv[1:],
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate_scan(req: ScanStartRequest):
    """The gate verdict for this scan, attacking nothing. PURE.

    All four lab gates run, in the executor's order and unchanged. MEASURED against the real
    validator (spec §2.4): an unapproved scan is refused at ``approval``; one without the
    red-confirm at ``danger`` ("active web scan"); and a target outside the lab at ``target``
    ("'example.com' is not the lab") — so the existing scope extractor reads the host out of a
    full URL with a port and a query string, and no new gate is needed or added.
    """
    from . import executor

    return executor.validate_request(_gate_scan_request(req))


# --------------------------------------------------------------------------- #
# scan lifecycle
# --------------------------------------------------------------------------- #
_scans: dict[str, Scan] = {}


def _scan_key(container: str, port: int, scan_id: str) -> str:
    return f"{container}:{port}:{scan_id}"


def _json(raw: str) -> dict[str, Any]:
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return obj if isinstance(obj, dict) else {}


def observed_scans(container: str, port: int) -> list[Scan]:
    """Every scan ZAP knows about, as ZAP reports it. OBSERVED — nothing here is remembered.

    MEASURED row shape: ``{"reqCount","alertCount","progress","newAlertCount","id","state"}``.
    ``target_url`` and ``recurse`` are not in it — ZAP does not report what a scan was aimed at —
    so those are merged back in from :data:`_scans` when this process is the one that started it,
    and left empty when it is not. Empty is the honest answer after a backend restart; inventing
    a target would be worse than admitting we no longer know it.
    """
    return scans_snapshot(container, port)[0]


def scans_snapshot(container: str, port: int) -> tuple[list[Scan], bool]:
    """``(scans, read_ok)`` — the same read, with the FAILURE told apart from the ZERO.

    *** BUILD #18 ITEM 8. THIS ONE FAILS OPEN ON A BOUND, WHICH IS WHY IT IS FIXED. ***
    :func:`observed_scans` answered ``[]`` for both "ZAP knows of no scan" and "the read
    failed". :func:`start_scan` uses that answer to enforce ONE SCAN AT A TIME — a bound on
    concurrent ATTACK TRAFFIC against a live production target. So an unreadable daemon made
    the bound grant rather than refuse.

    It is the same defect build #17 fixed one function away, in ``clash_refusal``: a check
    protecting against a state it could not observe. The fix is the same shape — observe, and
    tell "there is nothing" apart from "we cannot see".
    """
    body = _json(_api_get(container, port, _VIEW_SCANS))
    rows = body.get("scans")
    if not isinstance(rows, list):
        return [], False
    out: list[Scan] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        sid = str(row.get("id", ""))
        if not sid:
            continue
        remembered = _scans.get(_scan_key(container, port, sid))
        out.append(Scan(
            id=sid, container=container, port=port,
            target_url=remembered.target_url if remembered else "",
            recurse=remembered.recurse if remembered else False,
            state=str(row.get("state") or ""),
            progress=_int(row.get("progress")),
            requests=_int(row.get("reqCount")),
            alerts=_int(row.get("alertCount")),
            started_at=remembered.started_at if remembered else "",
            engagement_id=remembered.engagement_id if remembered else None,
            # Same rule as `target_url` two lines up: ZAP does not report what a scan was
            # CONFIGURED with, so these are merged back in when this process started the scan and
            # left blank when it did not. Blank is the honest answer after a backend restart; the
            # dangerous alternative is a panel confidently claiming a bypass header was in force
            # for a scan it knows nothing about.
            scan_policy=remembered.scan_policy if remembered else "",
            policy_observed=remembered.policy_observed if remembered else None,
            bypass_headers=list(remembered.bypass_headers) if remembered else [],
            context_name=remembered.context_name if remembered else "",
            auth_tier=remembered.auth_tier if remembered else 0,
        ))
    return out, True


def _int(raw: Any) -> int:
    try:
        return int(str(raw or "0"))
    except (TypeError, ValueError):
        return 0


def is_running(scan: Scan) -> bool:
    """A scan that could still send attack traffic — i.e. one that must block a second scan.

    ``PAUSED`` counts as running. What is being bounded is CONCURRENT attack traffic, and a
    paused scan can be resumed at any moment, so treating it as finished would let a second scan
    start and then have the first one wake up underneath it.

    ``FINISHED`` and ``STOPPED`` never block, whatever ``progress`` says — a scan stopped at 40%
    is over, and refusing new work because of it would make :func:`stop_scan` a trap.

    The ``progress < 100`` clause exists for the converse: ZAP reports state and progress
    independently, so a row that has reached 100% but not yet flipped its state must not block.
    """
    return scan.state.upper() in {"RUNNING", "PAUSED"} and scan.progress < 100


def start_scan(req: ScanStartRequest) -> Scan:
    """Start an active scan. GATED — nothing is attacked on a refusal.

    Order is the point: validate, then check the world, then act. The gate runs FIRST and against
    the equivalent argv, so a refusal happens before ZAP is contacted at all.
    """
    rejected = validate_scan(req)
    if rejected is not None:
        raise ProxyRefused(rejected.reason, gate=rejected.gate,
                           dangerous_flags=list(rejected.dangerous_flags))

    container = container_for(req)
    if not _container_running(container):
        raise ProxyRefused(
            f"sandbox '{container}' is not running — bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d)"
        )

    # ONE SCAN AT A TIME, decided by OBSERVATION rather than by a local flag. A second concurrent
    # scan doubles the attack traffic against a target the operator approved once; a backend dict
    # would lose that fact across a restart, while ZAP always knows. Same principle as
    # lifecycle.observe: status is observed, never assigned.
    known, read_ok = scans_snapshot(container, req.port)
    live = [s for s in known if is_running(s)]
    if live:
        raise ProxyRefused(
            f"a scan is already running on {container}:{req.port} "
            f"(id {live[0].id}, {live[0].progress}%, {live[0].requests} requests sent) — "
            "stop it first, or wait for it to finish",
            gate="limit",
        )
    if not read_ok:
        # *** NOT A NEW PROHIBITION — THE EXISTING BOUND, FIRING FOR THE REASON IT WAS WRITTEN.
        # The refusal above already exists and its gate is already `limit`. What changed is that
        # an unreadable daemon used to make it GRANT: `[]` came back and read as "no scan is
        # running". This is `clash_refusal`'s defect one function away, and doubling concurrent
        # attack traffic against a live production storefront is the harm the bound exists for.
        # It also costs nothing real: a daemon whose scan list will not read is a daemon whose
        # scan START would fail one call later, with a worse message.
        raise ProxyRefused(
            f"could not read the scan list from {container}:{req.port}, so whether a scan is "
            "already running is UNKNOWN — and starting a second one would double the attack "
            "traffic against this target. Is the proxy up on that port? (a backend restart "
            "loses the API key; the reader recovers it from the daemon's own argv, so an "
            "unreadable daemon usually means it is gone)",
            gate="limit",
        )

    # *** THE POLICY AND THE BYPASS HEADER, APPLIED FROM A KNOWN BASELINE, EVERY SCAN. ***
    # Both are ZAP configuration and ZAP PERSISTS ITS CONFIGURATION, so "what is set" is whatever
    # the last run wrote unless it is stated explicitly — the lesson `api.disablekey=false` is
    # passed for. Applying at start (rather than resetting at the end) is also the only version
    # that can work: a scan is asynchronous, so a reset after `start_scan` returns would land in
    # the middle of the scan it was meant to follow.
    #
    # Neither is allowed to refuse the scan. A scan with the default policy is a worse scan, not
    # an unsafe one, and a scan without the bypass header is exactly what build #17 already ran.
    # What both DO is report what ZAP holds, so "the header was on" is never assumed.
    header_names: list[str] = []
    try:
        header_names = list(
            sync_bypass_headers(container, req.port, req.engagement_id).get("installed") or []
        )
    except Exception:  # noqa: BLE001 - warn-and-continue; the readback below is the truth
        header_names = []
    policy = apply_scan_policy(container, req.port, req.scan_policy)

    # SCAN INSIDE THE CONTEXT, when one exists for this target (build #18 item 6). The context is
    # LOOKED UP rather than requested: the operator configured it against a target, and asking
    # them to name it again on every scan is a second place for the two to disagree. A target
    # with no context scans exactly as it did before, which is what makes this additive.
    ctx = observed_auth_context(container, req.port, context_name_for(scan_target_for(req)))
    raw = _api_get(
        container, req.port,
        scan_url_for(req, context_id=ctx.context_id, user_id=ctx.user_id),
        timeout=30,
    )
    body = _json(raw)

    if not body:
        raise ProxyRefused(
            f"the ZAP API on {container}:{req.port} did not answer — is the recording proxy "
            f"running on that port? (raw: {raw[:200]!r})"
        )
    if "code" in body:
        code = str(body.get("code"))
        if code == "url_not_found":
            raise ProxyRefused(
                f"ZAP has never seen {scan_target_for(req)} — the active scanner can only attack "
                "URLs already in its Sites tree. Proxy a request to it first (run a tool with "
                "proxy: true, or check the history panel for the exact URL that was captured).",
                gate="notfound",
            )
        raise ProxyRefused(f"ZAP refused the scan: {code} — {body.get('message', '')}")

    sid = str(body.get("scan", "")).strip()
    if not sid:
        raise ProxyRefused(f"ZAP returned no scan id: {raw[:200]!r}")

    model = Scan(
        id=sid, container=container, port=req.port,
        target_url=scan_target_for(req), recurse=req.recurse,
        state="RUNNING", progress=0, requests=0, alerts=0,
        started_at=_now(), engagement_id=req.engagement_id,
        scan_policy=req.scan_policy or DEFAULT_SCAN_POLICY,
        policy_observed=policy, bypass_headers=header_names,
        context_name=ctx.context_name if ctx.context_id else "",
        auth_tier=ctx.tier,
    )
    with _lock:
        _scans[_scan_key(container, req.port, sid)] = model
    # and immediately replace the assumed state with an observed one, so a scan that died on
    # arrival is never reported as RUNNING just because we launched it.
    return scan_status(container, req.port, sid) or model


def scan_status(container: str, port: int, scan_id: str) -> Scan | None:
    """One scan as ZAP currently reports it. READ-ONLY, UNGATED — a progress bar polls."""
    for scan in observed_scans(container, port):
        if scan.id == str(scan_id):
            return scan
    return None


def stop_scan(container: str, port: int, scan_id: str) -> Scan | None:
    """Stop an in-flight scan.

    NOT GATED, deliberately, and this is the strongest case in the codebase for that position:
    an active scan is sending hundreds of attack requests per endpoint right now, so this is the
    panic button. A gate that can refuse to press it is a gate that makes the system less safe —
    the same position tunnels.py and :func:`stop_proxy` take. It is the ONE action URL this
    module issues without approval, and the constant block says so.
    """
    _api_get(container, port, f"{_ACTION_STOP}?scanId={quote_plus(str(scan_id))}", timeout=20)
    return scan_status(container, port, scan_id)


# --------------------------------------------------------------------------- #
# alerts — READ-ONLY and UNGATED
# --------------------------------------------------------------------------- #
def parse_alert(obj: Any) -> ScanAlert | None:
    """One API alert -> :class:`ScanAlert`. NEVER raises; returns None if unusable.

    Tolerant on purpose, for the same reason :func:`parse_message` is: a parser must never break
    a run that already happened. An alert with a name is worth keeping even if every other field
    is missing, so only a missing name discards it.
    """
    try:
        if not isinstance(obj, dict):
            return None
        name = str(obj.get("name") or obj.get("alert") or "").strip()
        if not name:
            return None
        return ScanAlert(
            id=str(obj.get("id", "")),
            name=name,
            risk=str(obj.get("risk") or ""),
            confidence=str(obj.get("confidence") or ""),
            url=str(obj.get("url") or ""),
            method=str(obj.get("method") or "GET").upper(),
            param=str(obj.get("param") or ""),
            evidence=str(obj.get("evidence") or "")[:2000],
            attack=str(obj.get("attack") or "")[:2000],
            plugin_id=str(obj.get("pluginId") or obj.get("pluginid") or ""),
            cwe_id=str(obj.get("cweid") or ""),
            description=str(obj.get("description") or "")[:4000],
            solution=str(obj.get("solution") or "")[:4000],
        )
    except Exception:  # noqa: BLE001 - a parser must never break a completed scan
        return None


def scan_alerts(container: str, port: int, base_url: str = "",
                start: int = 0, count: int = 50) -> list[ScanAlert]:
    """Alerts ZAP is holding. READ-ONLY and UNGATED, like :func:`history`.

    NOT SCAN-SCOPED, and the caller should know it: ``core/view/alerts`` returns everything ZAP
    has, INCLUDING passive-scan alerts raised merely by traffic passing through the proxy (the
    committed fixture's Cross-Domain Misconfiguration came from ``sourceid: 3``, the passive
    scanner, with no active scan involved). Alerts also SURVIVE ``removeAllScans`` — both
    measured. ``base_url`` narrows by site, which is the only scoping the API offers.
    """
    alerts, _ = alerts_snapshot(container, port, base_url=base_url, start=start, count=count)
    return alerts


def alerts_snapshot(container: str, port: int, base_url: str = "",
                    start: int = 0, count: int = 50) -> tuple[list[ScanAlert], bool]:
    """``(alerts, read_ok)`` — THE SAME READ, WITH THE FAILURE TOLD APART FROM THE ZERO.

    *** BUILD #18 ITEM 8, AND THIS IS THE ONE WITH TEETH. ***
    :func:`scan_alerts` returns ``[]`` both when ZAP holds no alerts and when the read failed —
    a wrong key, a dead daemon, bytes that would not decode, a `docker exec` that errored. Its
    caller `POST /proxy/alerts/ingest` then writes "0 findings ingested" into engagement state,
    and a REPORT is rendered from that state. That is a confident zero travelling all the way to
    a deliverable, which is the exact failure shape build #17 found three of.

    ``read_ok`` is False when ZAP did not answer with a JSON object carrying an ``alerts`` key.
    An empty list WITH ``read_ok`` True is a real, trustworthy zero.
    """
    query = f"?start={int(start)}&count={int(count)}"
    if base_url:
        query += f"&baseurl={quote_plus(base_url)}"
    body = _json(_api_get(container, port, _VIEW_ALERTS + query, timeout=20))
    rows = body.get("alerts")
    if not isinstance(rows, list):
        return [], False
    parsed = [parse_alert(a) for a in rows]
    return [a for a in parsed if a is not None], True


def findings_from(alerts, session_id: str, run_id: str | None = None):
    """Alerts -> Finding records. Existing model, no schema change.

    The severity map is :data:`_RISK_TO_SEVERITY` and NOT ``parsers._ZAP_RISK`` — see
    :class:`ScanAlert` for why those are two different vocabularies over the same concept.
    ``reference`` is the plugin id in the same ``pluginid:NNNNN`` spelling ``parse_zap`` writes,
    so an alert found by BOTH paths fingerprints to one finding instead of two.
    """
    from state.models import Finding

    out = []
    for a in alerts:
        if a is None or not a.name.strip():
            continue
        out.append(Finding(
            session_id=session_id,
            title=a.name,
            severity=_RISK_TO_SEVERITY.get(a.risk.strip().lower(), "info"),
            target=a.url,
            tool="zap",
            reference=f"pluginid:{a.plugin_id}" if a.plugin_id else "",
            evidence=(a.evidence or a.attack)[:2000],
            source_run_id=run_id,
        ))
    return out


def alert_endpoints_from(alerts, session_id: str, run_id: str | None = None):
    """Alerts -> Endpoint records: the parameter ZAP attacked is the one worth remembering."""
    from urllib.parse import parse_qs, urlparse

    from state.models import Endpoint

    out = []
    for a in alerts:
        if a is None or not a.url.startswith("http"):
            continue
        params = sorted(parse_qs(urlparse(a.url).query).keys())
        if a.param and a.param not in params:
            params = sorted([*params, a.param])
        out.append(Endpoint(
            session_id=session_id, url=a.url, method=a.method or "GET",
            params=params, source_run_id=run_id,
        ))
    return out


# --------------------------------------------------------------------------- #
# THE AJAX SPIDER (build #15 part 2) — GATED start, OBSERVED status, UNGATED stop
#
# WHY ZAP'S CRAWLER AND NOT OUR OWN HEADLESS BROWSER, and the reason exists only because part 1
# landed first: manual browsing through the published proxy establishes an AUTHENTICATED SESSION
# INSIDE ZAP, and the AJAX spider runs through that same ZAP — so it inherits those cookies and
# crawls the logged-in application. A separate headless Chromium would start cold and need
# scripted authentication per target, an auth-automation problem this build would then own
# forever. Log in once by hand, let the spider expand from there, let part 3's scanner attack
# what both produced. Three stages, one pipeline, no glue code.
#
# *** AN OK IS NOT A RESULT. *** `setOptionBrowserId` DOES NOT VALIDATE: it accepted
# `not-a-browser` and answered `{"Result":"OK"}` (measured 2026-08-04). The image ships Chromium
# but no Firefox, while ZAP's configured default is `firefox-headless` — so the one thing that
# must never be trusted here is a successful-looking response to the call that sets the browser.
# :func:`start_spider` therefore reads the value BACK and, more importantly, the proof asserts a
# browser actually launched and messages were captured. Same family as part 1's "an exit code is
# not a result".
# --------------------------------------------------------------------------- #
#: The image has Chromium (150.0.7871.124) and NO Firefox, so ZAP's own default of
#: `firefox-headless` would fail at crawl time rather than at set time.
#:
#: *** HEADED, NOT HEADLESS — AND THE REASON IS MEASURED, NOT PREFERRED (build #17). ***
#: Build #15 shipped `chrome-headless` and the crawl was refused outright by the Akamai-fronted
#: assets that motivated the whole feature. Build #17's diagnostic found the discriminator, and
#: it is NOT the `HeadlessChrome` token everyone suspected:
#:
#:     headed Chromium      sec-ch-ua present   ->  31x 200
#:     headless, stock UA   sec-ch-ua ABSENT    ->  504
#:     headless, SPOOFED UA sec-ch-ua ABSENT    ->  504
#:
#: Headless Chromium sends no Client Hints at all, and `--user-agent` does not add them — so
#: overriding the UA changes what the client CLAIMS and leaves untouched the header set a real
#: browser EMITS. The dishonest route is not merely disallowed here, it does not work. A headed
#: browser under a virtual display sends the real header set because it IS the real browser,
#: which is the whole premise of build #15 stated as a measurement.
#:
#: This needs a display, so the image installs `xvfb` and the daemon runs under `Xvfb :99`.
#: NOT trusted: `setOptionBrowserId` answers `{"Result":"OK"}` for values it cannot use, so
#: :func:`start_spider` reads this back and refuses a mismatch.
SPIDER_BROWSER_ID = "chrome"

#: The virtual display the headed browser draws into. `:99` by convention; nothing else in the
#: container uses a display, so there is no clash to arbitrate.
SPIDER_DISPLAY = ":99"

#: ZAP's own defaults are depth 10 / 60 minutes. These are lower on purpose: they are what the
#: human approves, and a crawl the operator did not expect to still be clicking an hour later is
#: the thing this bounds.
DEFAULT_CRAWL_DEPTH = 5
DEFAULT_CRAWL_MINUTES = 10


class SpiderStartRequest(BaseModel):
    """Crawl a target with a REAL BROWSER, through the session the proxy already holds."""

    target_url: str = Field(
        description="Where the crawl starts. The browser drives from here and follows what it "
        "finds, so this is a starting point rather than a boundary — the depth and duration "
        "below are the boundary."
    )
    port: int = Field(DEFAULT_PROXY_PORT, ge=1024, le=65535)
    # *** IN THE APPROVED SURFACE, NOT JUST IN THE REQUEST. ***
    # Same reason `-autorun` was excluded from the catalog in part 1: a crawler that decides its
    # own depth means the command the human approved has stopped describing what runs.
    max_depth: int = Field(
        DEFAULT_CRAWL_DEPTH, ge=1, le=10,
        description="How deep the browser follows links. Appears in the approved command.",
    )
    max_duration_minutes: int = Field(
        DEFAULT_CRAWL_MINUTES, ge=1, le=60,
        description="Wall-clock ceiling on the crawl. Appears in the approved command.",
    )
    engagement_id: str | None = Field(
        None, description="Engagement to attribute against. OMIT for LAB mode."
    )
    # THE GATE FIELDS. Both default False so an omitted field is REFUSED, never granted.
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False,
        description="The explicit red-confirm — earned for a DIFFERENT reason than the active "
        "scanner's. This sends no injection payloads. It drives a real browser that CLICKS "
        "every control it finds, which on a production site can submit a form, empty a basket, "
        "trigger an email or place an order. Always required.",
    )

    @field_validator("target_url")
    @classmethod
    def _must_be_http(cls, v: str) -> str:
        """Refuse anything that is not an http(s) URL, before any gate runs.

        Same reasoning as :class:`ScanStartRequest`: the gate surface carries this URL and the
        scope extractor reads a HOST out of it, so a shape with no host would reach the target
        gate as a target-less command and be refused for a confusing reason. Refusing the shape
        up front means the surface the gate sees always contains a real host.
        """
        v = (v or "").strip()
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("target_url must be an http:// or https:// URL")
        return v


class Spider(BaseModel):
    """One browser-driven crawl. Every field here is READ BACK FROM ZAP, never assigned."""

    container: str
    port: int
    target_url: str = ""
    state: str = Field(
        "", description="ZAP's own word: running | stopped. OBSERVED, never assumed."
    )
    results: int = Field(0, description="URLs the crawl has found so far.")
    captured: int = Field(0, description="Messages in ZAP's history — proof a browser ran.")
    browser_id: str = Field(
        "", description="READ BACK from ZAP. setOptionBrowserId does not validate, so the value "
        "we sent proves nothing and only the value ZAP reports is worth reporting."
    )
    max_depth: int = 0
    max_duration_minutes: int = 0
    started_at: str = ""
    engagement_id: str | None = None


# --------------------------------------------------------------------------- #
# the gate — the same four gates, given an honest surface
# --------------------------------------------------------------------------- #
def spider_target_for(req: SpiderStartRequest) -> str:
    """*** THE SINGLE DERIVATION OF WHAT GETS CRAWLED. ***

    Part 3's lock, restated for this action: the gate classifies an ARGV and what executes is a
    URL, so string equality between them would be theatre — but *the thing the gate scoped is the
    thing that gets hit* still holds, and that is the property worth locking. Both sides come
    through here: :func:`_gate_spider_request` puts this output in the surface the scope
    extractor reads, and :func:`spider_url_for` percent-encodes the SAME output into ZAP's
    ``url=`` parameter.
    """
    return req.target_url.strip()


def spider_argv_for(req: SpiderStartRequest) -> list[str]:
    """The command this crawl is EQUIVALENT TO, which is what the human approves.

    ``-ajaxspider`` IS A DECLARED MARKER, NOT A REAL ZAP FLAG, and that is recorded in
    ``allowlist._ATTACK_FLAG_IS_REAL`` so a second one cannot arrive unnoticed. ZAP drives this
    over its API and ships no command-line switch for it, exactly as ``ascan/action/scan`` has
    none — part 3 established that the gate classifies an equivalent command.

    ``-zapit`` is deliberately ABSENT even though the spec first proposed it. Once the marker
    carries the danger verdict and the URL carries the scope, adding ``-zapit`` would make the
    declared command claim two crawl modes at once — and it would collide with
    ``test_zap_safety``'s lock that a plain ``-zapit`` recon run must NOT demand a red-confirm.

    Depth and duration are in the surface because they are the bounds. A crawler that decides its
    own is a command that has stopped describing what runs.
    """
    return [
        "zaproxy", "-ajaxspider", spider_target_for(req),
        "-maxdepth", str(req.max_depth),
        "-maxduration", str(req.max_duration_minutes),
    ]


def spider_url_for(req: SpiderStartRequest) -> str:
    """The API path+query that launches the crawl.

    Percent-encoded for the reason part 3 wrote down: the operator-supplied target is
    interpolated into a URL carrying THE CRAWL'S OWN PARAMETERS, so a target containing
    ``&subtreeOnly=false`` would append to ZAP's parameter list and silently change the approved
    crawl's shape. ``quote(safe="")`` encodes ``&``, ``=``, ``?`` and ``#`` so the target cannot
    escape its own parameter. That is Critical 2 in a query string, and a text field does not
    stop a ``&``.

    ``inScope=false`` for the same reason ``inScopeOnly=false`` is set on the scanner: HackPit
    does not configure ZAP CONTEXTS, so with none defined ZAP considers nothing in scope and the
    parameter would refuse every crawl. Scope is enforced at HackPit's own target gate
    (:func:`validate_spider`), which reads the real host out of the surface.
    """
    target = quote(spider_target_for(req), safe="")
    return f"{_ACTION_SPIDER_SCAN}?url={target}&inScope=false&subtreeOnly=false"


def _gate_spider_request(req: SpiderStartRequest):
    """The ExecRequest the real gates run against. The FULL equivalent argv, nothing omitted."""
    from .models import ExecRequest

    argv = spider_argv_for(req)
    return ExecRequest(
        command=argv[0],
        args=argv[1:],
        approved=req.approved,
        dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id,
    )


def validate_spider(req: SpiderStartRequest):
    """The gate verdict for this crawl, crawling nothing. PURE.

    All four gates run, in the executor's order and unchanged: an unapproved crawl is refused at
    ``approval``; one without the red-confirm at ``danger``; a target outside the lab at
    ``target``. No new gate is needed or added — the existing scope extractor reads the host out
    of a full URL with a port and a query string.
    """
    from . import executor

    return executor.validate_request(_gate_spider_request(req))


# --------------------------------------------------------------------------- #
# spider lifecycle
# --------------------------------------------------------------------------- #
_spiders: dict[str, Spider] = {}


def _spider_view(container: str, port: int, path: str, key: str, timeout: int = 15) -> str:
    """One ajaxSpider view, unwrapped to its scalar. "" when the API did not answer."""
    raw = _api_get(container, port, path, timeout=timeout)
    value = _json(raw).get(key)
    return "" if value is None else str(value)


def observed_spider(container: str, port: int) -> Spider:
    """What ZAP says the crawl is doing right now. OBSERVED — nothing here is remembered.

    ``browser_id`` is READ BACK rather than echoed from :data:`SPIDER_BROWSER_ID`, because
    ``setOptionBrowserId`` accepted ``not-a-browser`` with ``{"Result":"OK"}``. Reporting what we
    sent would report a wish.
    """
    remembered = _spiders.get(_key_slot(container, port))
    return Spider(
        container=container, port=port,
        target_url=remembered.target_url if remembered else "",
        state=_spider_view(container, port, _VIEW_SPIDER_STATUS, "status"),
        results=_int(_spider_view(container, port, _VIEW_SPIDER_RESULTS, "numberOfResults")),
        captured=captured_count(container, port),
        browser_id=_spider_view(container, port, _VIEW_SPIDER_BROWSER, "optionBrowserId"),
        max_depth=remembered.max_depth if remembered else 0,
        max_duration_minutes=remembered.max_duration_minutes if remembered else 0,
        started_at=remembered.started_at if remembered else "",
        engagement_id=remembered.engagement_id if remembered else None,
    )


def spider_is_running(spider: Spider) -> bool:
    """ZAP reports ``running`` / ``stopped`` for the AJAX spider — no progress percentage."""
    return spider.state.strip().lower() == "running"


def display_is_up(container: str) -> bool:
    """Is the virtual display running? OBSERVED — `pgrep -x Xvfb`, never `-f`.

    `-x` matches the process NAME. A `-f` pattern here would be a claim about every argv in the
    container, and this repo has now been bitten by that in both directions: `[z]aproxy` matched
    too little because the wrapper exec'd the JVM, and `[c]hrome` matched too much and killed the
    ZAP daemon because an unrelated fix put "chromedriver" on its command line.
    """
    argv = ["docker", "exec", container, "pgrep", "-x", "Xvfb"]
    try:
        return subprocess.run(argv, capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def ensure_display(container: str) -> bool:
    """Bring up ``Xvfb`` for the headed crawl browser, and REPORT whether it is actually there.

    Returns the OBSERVED state, not "we ran the start command" — starting Xvfb and assuming it
    worked is the same shape as `setOptionBrowserId` answering OK for a browser it cannot use.
    """
    if display_is_up(container):
        return True
    subprocess.run(
        ["docker", "exec", "-d", container, "Xvfb", SPIDER_DISPLAY,
         "-screen", "0", "1280x1024x24"],
        capture_output=True, timeout=30, check=False,
    )
    for _ in range(20):
        if display_is_up(container):
            return True
        time.sleep(0.5)
    return False


def start_spider(req: SpiderStartRequest) -> Spider:
    """Start a browser-driven crawl. GATED — no browser launches on a refusal.

    Order is the point, and it is part 3's: validate, then check the world, then act. The gate
    runs FIRST and against the equivalent argv, so a refusal happens before ZAP is contacted.
    """
    rejected = validate_spider(req)
    if rejected is not None:
        raise ProxyRefused(rejected.reason, gate=rejected.gate,
                           dangerous_flags=list(rejected.dangerous_flags))

    container = container_for(req)
    if not _container_running(container):
        raise ProxyRefused(
            f"sandbox '{container}' is not running — bring the stack up "
            "(docker compose -f docker/docker-compose.yml up -d)"
        )

    # ONE CRAWL AT A TIME, decided by OBSERVATION. ZAP runs a single AJAX spider per session, so
    # a second start would either be refused by ZAP or silently replace the first — and either
    # way the operator would be watching a crawl they did not approve the shape of.
    live = observed_spider(container, req.port)
    if spider_is_running(live):
        raise ProxyRefused(
            f"a browser crawl is already running on {container}:{req.port} "
            f"({live.results} URLs found so far) — stop it first, or wait for it to finish",
            gate="limit",
        )

    # *** THE DISPLAY, BEFORE THE CRAWL — a headed browser with nowhere to draw does not start.
    # It fails inside ZAP's own log, and the symptom is `{"Result":"OK"}` followed by zero URLs,
    # which is the identical symptom of the two defects build #15 spent a day on. Refusing here
    # turns the third instance of that symptom into a sentence the operator can read.
    if not ensure_display(container):
        raise ProxyRefused(
            f"no virtual display in {container}: Xvfb {SPIDER_DISPLAY} did not come up, so the "
            f"headed crawl browser ({SPIDER_BROWSER_ID!r}) would die at launch and the crawl "
            "would report OK and find nothing. Is `xvfb` installed in this image? If Xvfb is "
            "present but refuses to exec, strip its file capabilities (`setcap -r`) — "
            "no-new-privileges makes the kernel refuse a setcap'd binary.",
            gate="display",
        )

    # THE BYPASS HEADER REACHES THE CRAWL BROWSER TOO, and it has to: the AJAX spider's Chromium
    # goes out through this same ZAP, so a replacer rule is the one place that covers browsing,
    # crawling and scanning without three implementations. Warn-and-continue — a crawl without
    # the header is exactly the crawl build #15 ran.
    try:
        sync_bypass_headers(container, req.port, req.engagement_id)
    except Exception:  # noqa: BLE001 - never refuse a crawl over a header
        pass

    # The approved bounds, applied BEFORE the crawl starts. These are action URLs and they are
    # reached only here, after validate_spider returned None — see the constant block.
    _api_get(container, req.port,
             f"{_ACTION_SPIDER_BROWSER}?String={quote_plus(SPIDER_BROWSER_ID)}")
    _api_get(container, req.port, f"{_ACTION_SPIDER_DEPTH}?Integer={int(req.max_depth)}")
    _api_get(container, req.port,
             f"{_ACTION_SPIDER_DURATION}?Integer={int(req.max_duration_minutes)}")

    # *** AN OK IS NOT A RESULT — CHECK WHAT ZAP HOLDS, NOT WHAT IT ANSWERED. ***
    # setOptionBrowserId returns {"Result":"OK"} for `not-a-browser` (measured), so the only
    # thing worth reading is the value back out. A wrong browser id fails at CRAWL time with a
    # driver error buried in ZAP's log, which is a far worse place to discover it.
    configured = _spider_view(container, req.port, _VIEW_SPIDER_BROWSER, "optionBrowserId")
    if configured and configured != SPIDER_BROWSER_ID:
        raise ProxyRefused(
            f"ZAP reports browser {configured!r} after being set to {SPIDER_BROWSER_ID!r} — the "
            "crawl would launch the wrong browser (or none). The image ships Chromium and no "
            "Firefox, so a `firefox-headless` value here means the option did not take.",
            gate="browser",
        )

    raw = _api_get(container, req.port, spider_url_for(req), timeout=30)
    body = _json(raw)
    if not body:
        raise ProxyRefused(
            f"the ZAP API on {container}:{req.port} did not answer — is the recording proxy "
            f"running on that port? (raw: {raw[:200]!r})"
        )
    if str(body.get("Result", "")).upper() != "OK":
        raise ProxyRefused(
            f"ZAP refused the crawl: {body.get('code') or body}"
            f" — {body.get('message', '')}".rstrip(" —")
        )

    model = Spider(
        container=container, port=req.port, target_url=spider_target_for(req),
        state="running", max_depth=req.max_depth,
        max_duration_minutes=req.max_duration_minutes,
        browser_id=configured or SPIDER_BROWSER_ID,
        started_at=_now(), engagement_id=req.engagement_id,
    )
    with _lock:
        _spiders[_key_slot(container, req.port)] = model
    # and immediately replace the assumed state with an observed one, so a crawl whose browser
    # died on arrival is never reported as running just because we launched it.
    return observed_spider(container, req.port)


def stop_spider(container: str, port: int) -> Spider:
    """Stop an in-flight crawl.

    NOT GATED, for the reason :func:`stop_scan` and :func:`stop_proxy` are not: stopping removes
    capability, and a gate that can refuse to press the panic button makes the system less safe.
    It matters as much here as for the scanner — what is running is a real browser clicking real
    controls on a production site.
    """
    _api_get(container, port, _ACTION_SPIDER_STOP, timeout=20)
    return observed_spider(container, port)


# --------------------------------------------------------------------------- #
# AUTHENTICATED SCANNING (build #18 items 6 and 7)
#
# *** THE HARD PART ALREADY EXISTED, AND NAMING IT IS HALF THE DESIGN. ***
# Build #15 published the proxy so a real browser could use it. A human logging in by hand
# through that proxy puts a LIVE SESSION inside ZAP — cookies and all. What was missing was
# never the session; it was telling ZAP's scanner what the session MEANS.
#
# TIER 2 — a Context, cookie-based session management, and logged-in/out indicators.
#   Needs NO CREDENTIALS AT ALL. The human has already logged in; this describes the result so
#   the scanner scans inside it and so ZAP's own view of "am I still authenticated" exists.
#   This is also what finally makes build #16's session-expiry detector mean something: build
#   #17 found it was reading the OLDEST 200 exchanges and therefore could not fire.
#
# TIER 3 — form-based authentication with stored credentials and automatic re-login.
#   *** THE TRAP, STATED SO IT IS ENTERED WITH EYES OPEN. *** Build #15 declined this
#   deliberately, on the grounds that per-target auth scripting is a problem the codebase would
#   then own forever. Zaid took the decision to own it (2026-08-05). The defence is to stay
#   DECLARATIVE — a login URL, a request body with two ZAP placeholders, two indicator regexes —
#   and to refuse to grow a scripting language. If a target needs JavaScript to log in, the
#   answer is Tier 2 and a human's browser, not a script engine in here.
#
# *** THE PASSWORD NEVER TOUCHES AN ARGV, A URL OR A RECORD. ***
# It is resolved SERVER-SIDE out of the state credential vault, by the same
# {session_id, kind, principal, domain} reference the Windows profile path already uses, and it
# reaches ZAP through :func:`_api_post` — i.e. on stdin. No request model in this module has a
# password field, so there is no field for one to leak out of.
#
# *** ZAP PERSISTS CONTEXTS AND USERS, TOO. *** Same trap as the replacer rule and the scan
# policy, third instance in one build. A context named for one engagement's host survives into
# the next, and a USER carries a credential. So contexts carry a HackPit prefix, applying one
# removes and rebuilds it rather than editing in place, and :func:`clear_auth_contexts` runs on
# proxy stop next to the bypass headers.
# --------------------------------------------------------------------------- #
CONTEXT_NAME_PREFIX = "hackpit-"

#: ZAP's own method names. Spelled out rather than inlined so a future ZAP rename is one edit.
SESSION_METHOD_COOKIE = "cookieBasedSessionManagement"
AUTH_METHOD_FORM = "formBasedAuthentication"

#: ZAP substitutes these two tokens in ``loginRequestData`` with the user's credentials. They are
#: ZAP's spelling, not ours, and getting them wrong produces a login POST that literally sends
#: the string "{%username%}" — a request that succeeds, authenticates nothing, and leaves the
#: scanner running unauthenticated while every indicator says it failed.
ZAP_USERNAME_TOKEN = "{%username%}"
ZAP_PASSWORD_TOKEN = "{%password%}"


def context_name_for(target_url: str) -> str:
    """The context name HackPit uses for a target. Derived from the HOST, prefixed, lower-cased.

    Prefixed so :func:`clear_auth_contexts` can tell HackPit's contexts from any a human made in
    ZAP's UI and remove only its own — the same ownership rule as the replacer rules.
    """
    from urllib.parse import urlparse

    host = (urlparse((target_url or "").strip()).hostname or "").lower()
    return f"{CONTEXT_NAME_PREFIX}{host or 'target'}"


def context_regex_for(target_url: str) -> str:
    """The ``includeInContext`` regex covering the target's whole origin.

    ``\\Q…\\E`` quotes the literal so a host containing a dot — which is every host — cannot have
    that dot read as "any character" and pull an unrelated domain into the context. That is the
    same class of bug as the percent-encoding on the scan URL: a field the operator typed being
    read as syntax by the thing downstream.
    """
    from urllib.parse import urlparse

    parsed = urlparse((target_url or "").strip())
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return rf"\Q{origin}\E.*"


class CredentialRef(BaseModel):
    """Which stored credential to log in with. NO SECRET FIELD, deliberately.

    Identical shape to the Windows-profile path's ``from_credential``, and for the identical
    reason: the secret is resolved server-side out of the vault, so it never has to be sent to a
    browser and back, and there is no field on any model for it to be logged from.
    """

    session_id: str = Field(..., description="Engagement session whose vault holds the credential.")
    kind: str = Field("password", description="Credential kind as captured, e.g. 'password'.")
    principal: str = Field(..., description="The account name.")
    domain: str = Field("", description="Domain, if the capture had one.")


class AuthContextRequest(BaseModel):
    """Describe an authenticated context to ZAP. Tier 2 by default; Tier 3 when ``login_url`` is set.

    NOT GATED, and the constant block says why: this configures how OUR OWN next request is
    shaped and emits nothing at the target. The traffic it describes is emitted by ``start_scan``
    (gated), the spider (gated) or a human's browser (the human).
    """

    target_url: str = Field(..., description="Any URL on the site. Its ORIGIN becomes the context.")
    port: int = Field(DEFAULT_PROXY_PORT, ge=1024, le=65535)
    engagement_id: str | None = Field(
        None, description="Engagement to attribute against. OMIT for LAB mode."
    )
    logged_in_regex: str = Field(
        "", description="A regex matching something only a LOGGED-IN response contains — a "
        "logout link, an account menu. Optional but strongly worth setting: without it ZAP has "
        "no way to tell an authenticated response from a login page."
    )
    logged_out_regex: str = Field(
        "", description="A regex matching something only a LOGGED-OUT response contains — the "
        "login form's action, a 'sign in' control. This is what triggers Tier 3's re-login."
    )
    # --- TIER 3 ONLY. All three absent = Tier 2, which needs no credentials whatsoever. ---
    login_url: str = Field(
        "", description="Where the login form POSTs. Setting this switches on Tier 3."
    )
    login_body: str = Field(
        "", description="The login POST body with ZAP's own placeholders, e.g. "
        "'username={%username%}&password={%password%}'. DECLARATIVE ONLY — this is a form body, "
        "not a script, and it is deliberately the whole of the login language."
    )
    credential: CredentialRef | None = Field(
        None, description="Which vault credential to log in as. The secret is resolved "
        "server-side and reaches ZAP on stdin; it is never in this model."
    )

    @field_validator("target_url")
    @classmethod
    def _must_be_http(cls, v: str) -> str:
        v = (v or "").strip()
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("target_url must be an http:// or https:// URL")
        return v


class AuthContext(BaseModel):
    """An authenticated context AS ZAP HOLDS IT. Every field read back, none echoed."""

    container: str = ""
    port: int = 0
    context_id: str = ""
    context_name: str = ""
    included: list[str] = Field(default_factory=list, description="Include regexes ZAP holds.")
    session_method: str = ""
    auth_method: str = ""
    logged_in_regex: str = ""
    logged_out_regex: str = ""
    user_id: str = ""
    user_name: str = Field(
        "", description="The ACCOUNT NAME the context logs in as. A username is not a secret and "
        "an operator needs to see which account a scan ran as; the password has no field here."
    )
    tier: int = Field(
        0, description="2 = context + session management, no credentials. 3 = plus form-based "
        "authentication with a stored credential and automatic re-login. 0 = nothing configured."
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Things that did not take. WARN AND CONTINUE: a context missing its "
        "logged-out indicator is a weaker scan, not a refusal, and saying so beats refusing.",
    )


def observed_auth_context(container: str, port: int, context_name: str) -> AuthContext:
    """What ZAP holds for this context. READ-ONLY. ``context_id == ""`` means it does not exist.

    The arbiter for items 6 and 7, in the same sense ``observed_replacer_rules`` is item 1's:
    every one of these setters answers ``{"Result":"OK"}``, and this module has measured an OK
    that meant nothing twice already.
    """
    raw = _json(_api_get(container, port, f"{_VIEW_CONTEXT}?contextName={quote_plus(context_name)}"))
    body = raw.get("context")
    if not isinstance(body, dict):
        return AuthContext(container=container, port=port, context_name=context_name)

    ctx_id = str(body.get("id", "")).strip()
    included = body.get("includeRegexs") or body.get("includedRegexs") or []
    users = _json(_api_get(container, port,
                           f"{_VIEW_USERS}?contextId={quote_plus(ctx_id)}")).get("usersList")
    user_id = user_name = ""
    if isinstance(users, list) and users:
        first = users[0] if isinstance(users[0], dict) else {}
        user_id = str(first.get("id", "")).strip()
        user_name = str(first.get("name", "")).strip()

    def _scalar(path: str, key: str) -> str:
        answer = _json(_api_get(container, port, f"{path}?contextId={quote_plus(ctx_id)}"))
        value = answer.get(key)
        if isinstance(value, dict):
            return str(value.get("methodName") or value.get("className") or "")
        return "" if value is None else str(value)

    session_method = _scalar(_VIEW_SESSION_METHOD, "methodName") or _scalar(
        _VIEW_SESSION_METHOD, "getSessionManagementMethod")
    auth_method = _scalar(_VIEW_AUTH_METHOD, "methodName") or _scalar(
        _VIEW_AUTH_METHOD, "getAuthenticationMethod")

    tier = 0
    if ctx_id:
        tier = 3 if (user_id and "form" in auth_method.lower()) else 2
    return AuthContext(
        container=container, port=port, context_id=ctx_id, context_name=context_name,
        included=[str(r) for r in included] if isinstance(included, list) else [],
        session_method=session_method, auth_method=auth_method,
        logged_in_regex=_scalar(_VIEW_LOGGED_IN, "logged_in_regex")
        or _scalar(_VIEW_LOGGED_IN, "getLoggedInIndicator"),
        logged_out_regex=_scalar(_VIEW_LOGGED_OUT, "logged_out_regex")
        or _scalar(_VIEW_LOGGED_OUT, "getLoggedOutIndicator"),
        user_id=user_id, user_name=user_name, tier=tier,
    )


def list_auth_contexts(container: str, port: int) -> list[str]:
    """Every context name ZAP holds. READ-ONLY."""
    names = _json(_api_get(container, port, _VIEW_CONTEXTS)).get("contextList")
    if isinstance(names, str):
        # Some ZAP builds answer with a bracketed string rather than a JSON list. Parsed rather
        # than dropped, because dropping it would report "no contexts" for a daemon holding some
        # — the silent empty this build spent an item hunting.
        names = [n.strip() for n in names.strip("[]").split(",") if n.strip()]
    return [str(n) for n in names] if isinstance(names, list) else []


def clear_auth_contexts(container: str, port: int) -> list[str]:
    """Remove every context HackPit created. Returns the names ZAP no longer holds.

    Removing a context removes its users, so this also takes the stored credential out of the
    daemon. Called from :func:`stop_proxy` for the reason the replacer clear is: ZAP persists,
    and a context carrying a credential must not survive into the next engagement.
    """
    before = [n for n in list_auth_contexts(container, port)
              if n.lower().startswith(CONTEXT_NAME_PREFIX)]
    for name in before:
        _api_get(container, port, f"{_ACTION_REMOVE_CONTEXT}?contextName={quote_plus(name)}")
    after = set(list_auth_contexts(container, port))
    return [n for n in before if n not in after]


def _resolve_login_secret(ref: CredentialRef) -> tuple[str, str]:
    """``(username, secret)`` out of the state vault. The one place a login secret is read.

    Raises ProxyRefused if the credential is not there — which is a NOT-FOUND, not a safety
    verdict: the operator named a credential that does not exist, and silently scanning
    unauthenticated instead would be the confident-wrong-answer failure this module exists to
    stop producing.
    """
    from state import store as state_store

    creds = state_store.load(ref.session_id).credentials
    match = next(
        (c for c in creds
         if c.kind.lower() == ref.kind.strip().lower()
         and c.principal.lower() == ref.principal.strip().lower()
         and (c.domain or "").lower() == (ref.domain or "").strip().lower()),
        None,
    )
    if match is None:
        raise ProxyRefused(
            f"no credential {ref.principal!r} (kind {ref.kind!r}) in session {ref.session_id!r} — "
            "capture it into the vault first. Scanning unauthenticated instead would report "
            "zero findings from a login page, which reads exactly like a secure application.",
            gate="notfound",
        )
    return match.principal, match.secret or ""


def apply_auth_context(req: AuthContextRequest, container: str) -> AuthContext:
    """Build (or rebuild) the context on the daemon and READ IT BACK.

    Rebuilds rather than edits: ZAP persists contexts, so an existing one may already carry an
    include regex, a session method or a USER from a previous engagement, and editing in place
    would leave whichever of those this call does not set. Remove-then-create makes the result a
    property of this request instead of a property of the daemon's history.

    WARN AND CONTINUE throughout. A missing indicator, an auth method that would not take, a
    session method ZAP spelled differently — each lands in ``warnings`` and the context is still
    returned. The one thing that refuses is a named credential that is not in the vault, and that
    is a not-found rather than a gate.
    """
    name = context_name_for(req.target_url)
    warnings: list[str] = []

    _api_get(container, req.port, f"{_ACTION_REMOVE_CONTEXT}?contextName={quote_plus(name)}")
    created = _json(_api_get(container, req.port,
                             f"{_ACTION_NEW_CONTEXT}?contextName={quote_plus(name)}"))
    ctx_id = str(created.get("contextId", "")).strip()
    if not ctx_id:
        # Fall through to the read-back anyway: `newContext` on some builds answers only
        # {"Result":"OK"} and the id has to come from the context view. Never assume the failure.
        ctx_id = observed_auth_context(container, req.port, name).context_id
    if not ctx_id:
        raise ProxyRefused(
            f"ZAP did not create a context for {name!r} — is the recording proxy running on "
            f"{container}:{req.port}?",
            gate="notfound",
        )

    _api_get(container, req.port,
             f"{_ACTION_INCLUDE_IN_CONTEXT}?contextName={quote_plus(name)}"
             f"&regex={quote_plus(context_regex_for(req.target_url))}")
    _api_get(container, req.port,
             f"{_ACTION_SET_SESSION_METHOD}?contextId={quote_plus(ctx_id)}"
             f"&methodName={quote_plus(SESSION_METHOD_COOKIE)}&methodConfigParams=")

    for regex, action, label in (
        (req.logged_in_regex, _ACTION_SET_LOGGED_IN, "loggedInIndicatorRegex"),
        (req.logged_out_regex, _ACTION_SET_LOGGED_OUT, "loggedOutIndicatorRegex"),
    ):
        if not regex.strip():
            continue
        # POST, not GET: an indicator regex is not a secret, but it is arbitrary operator text
        # with `&` and `#` in it as often as not, and the same escaping argument that percent-
        # encodes the scan target applies — a regex containing `&` on a query string would set
        # half a regex and silently add a parameter.
        _api_post(container, req.port, action,
                  {"contextId": ctx_id, label: regex.strip()})

    tier = 2
    if req.login_url.strip():
        tier = 3
        if ZAP_PASSWORD_TOKEN not in req.login_body:
            warnings.append(
                f"the login body does not contain {ZAP_PASSWORD_TOKEN} — ZAP substitutes that "
                "exact token with the credential, so without it the login POST sends no password "
                "and the scan runs unauthenticated while every indicator says the login failed"
            )
        if not req.logged_out_regex.strip():
            warnings.append(
                "no logged-out indicator was set, so ZAP has no trigger for automatic re-login — "
                "Tier 3 will authenticate once and never notice the session ending"
            )
        _api_post(container, req.port, _ACTION_SET_AUTH_METHOD, {
            "contextId": ctx_id,
            "authMethodName": AUTH_METHOD_FORM,
            "authMethodConfigParams":
                f"loginUrl={req.login_url.strip()}&loginRequestData={req.login_body}",
        })
        if req.credential is not None:
            username, secret = _resolve_login_secret(req.credential)
            made = _json(_api_post(container, req.port, _ACTION_NEW_USER,
                                   {"contextId": ctx_id, "name": username}))
            user_id = str(made.get("userId", "")).strip()
            if not user_id:
                user_id = observed_auth_context(container, req.port, name).user_id
            if user_id:
                # *** THE SECRET GOES ON STDIN AND NOWHERE ELSE. *** _api_post, not _api_get —
                # a GET would put the password in ZAP's own recorded history, on the `docker exec`
                # argv that `ps` can read, and into the artefact a report is rendered from.
                _api_post(container, req.port, _ACTION_SET_USER_CREDS, {
                    "contextId": ctx_id, "userId": user_id,
                    "authCredentialsConfigParams": f"username={username}&password={secret}",
                })
                _api_get(container, req.port,
                         f"{_ACTION_SET_USER_ENABLED}?contextId={quote_plus(ctx_id)}"
                         f"&userId={quote_plus(user_id)}&enabled=true")
            else:
                warnings.append(
                    "ZAP created no user for this context, so the stored credential was NOT "
                    "installed and the scan would run unauthenticated"
                )
        else:
            warnings.append(
                "Tier 3 was requested (a login URL was given) but no credential was named, so "
                "there is no account to log in as — this is a Tier 2 context with a login form "
                "described but never submitted"
            )

    held = observed_auth_context(container, req.port, name)
    if held.tier and held.tier < tier:
        warnings.append(
            f"tier {tier} was requested but ZAP holds a tier-{held.tier} context — the "
            "authentication method or the user did not take"
        )
    return held.model_copy(update={"warnings": warnings})
