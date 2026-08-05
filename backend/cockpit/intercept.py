"""Request interception — hold a request in flight, read it, change it, forward or drop it.

*** THIS IS A SURFACING JOB, NOT A PROXY-BUILDING JOB. *** ZAP already implements breaking
inside the container HackPit already drives; this module exposes it. Nothing here parses TLS,
holds a socket or forwards a byte — every verb is one call to a ZAP API that was MEASURED to
work before a line of this was written (build #19 item 1; `docs/proof/build19_break_api.py`).

*** IT IS HUMAN-IN-THE-LOOP BY CONSTRUCTION, SO IT ADDS NO GATE. ***
A request is held, a HUMAN reads it, a HUMAN edits it, a HUMAN presses forward. There is no
approval to bypass because the operator pressing the button IS the approval — the same argument
`:kali` and the repeater already make, and for the same reason. Interception also strictly
REDUCES what reaches the target: with breaking on, nothing goes anywhere until a person says so.
A gate on a feature whose default action is "stop the traffic" would be ceremony.

WHAT THE MEASUREMENT ACTUALLY SAID — and every one of these is a trap this module is shaped
around, because guessing any of them would have produced a confident wrong answer:

1. **`brk` IS NOT IN THE INSTALLED ADD-ON LIST AND THE API IS THERE ANYWAY.**
   `autoupdate/view/installedAddons` returns 48 add-ons and none of them is the Break add-on;
   `break/view/isBreakAll` answers regardless, because `BreakAPI` ships in ZAP core. An add-on
   inventory is not an API surface, and a go/no-go taken off that list would have said NO to a
   feature that works.

2. *** `http-all` IS THE ONLY `type` THE ACTION ACCEPTS. ***
   `http-request`, `http-response` and `http-sender` — all three of which read like obvious
   values and two of which name views that DO exist — every one answers `illegal_parameter`.
   Measured, after a first pass of this module's own docstring claimed `http-request` "answers
   OK and holds nothing"; the proof script disagreed and the proof script was right. So
   :data:`BREAK_TYPE` is a constant rather than a request field, and it is one for the simplest
   possible reason: there is nothing else to choose. (The value is case-insensitive — `HTTP-ALL`
   is accepted too — which is worth nothing except as evidence the comparison is `equalsIgnoreCase`
   against a closed set.)

3. *** `continue` TURNS BREAKING OFF. `step` AND `drop` LEAVE IT ON. ***
   Measured directly: `isBreakAll` reads `true` while a request is held, and `false` immediately
   after `continue` — while `step` and `drop` leave it `true`. That is ZAP's break-panel
   semantics (Continue means "let everything go", Step means "let this one go"), and it is not a
   detail: an operator who forwards a request expecting to catch the next one will catch nothing,
   and the global "breaking is on" banner will correctly vanish underneath them. :func:`release`
   reads the state back afterwards precisely so the UI shows what actually happened rather than
   what was intended.

4. **`isBreakRequest` IS A SETTING, NOT A STATE.** It reads `true` whenever breaking is switched
   on, whether or not anything is held. A UI wired to it would report "a request is waiting"
   forever. The ONLY signal that something is held is a non-empty `break/view/httpMessage`.

5. *** A `drop` ISSUED WHEN NOTHING IS HELD PERMANENTLY WEDGES THE BREAK MANAGER. ***
   THE WORST ONE, AND THE PROOF SCRIPT FOUND IT BY DOING IT. After one stray
   `break/action/drop/` against a daemon holding nothing, that daemon still HOLDS requests —
   `isBreakAll` reads true, the origin never sees the request, the client blocks — but
   `break/view/httpMessage` returns `""` forever and `setHttpMessage` therefore never applies.
   Interception silently becomes a way to freeze your own browser with no way to read or release
   anything except `panic`.

   Established as a single-variable experiment on a FRESH daemon, twice in each direction: with
   the stray drop, 23 passed / 4 failed; with the one line removed, 27 passed / 0 failed. It is
   not degradation over time — a brand-new daemon wedges on the first stray drop — and it is not
   a read-side problem, because a reader INSIDE the container sees the same empty string.

   So every drop in this module is GUARDED BY A READ-BACK, and that guard is load-bearing rather
   than defensive: :func:`release` will not send `drop` unless something is actually held, and
   :func:`panic` drops only when `before.held` says there is something to drop. This is NOT a
   prohibition on the operator — pressing drop with nothing held was never a meaningful action —
   it is refusing to send an API call that breaks the daemon.

6. **THE HELD MESSAGE MUST BE POLLED, NOT READ ONCE.** A single read a fixed few seconds after
   firing a request came back empty in runs where the request was demonstrably held. Polling
   every 250ms found it at ~0.0s once the hold had registered. The UI polls at 2s for the same
   reason, and nothing here treats one empty read as "nothing is held" — only as "not held YET".

4. **`setHttpMessage` NEEDS A HELD MESSAGE AND SAYS SO CONFUSINGLY.** With nothing held it
   answers `does_not_exist`, which reads like "that action does not exist". It is distinguishable
   from a genuinely absent action, which answers `bad_action` — and the enumeration in item 1
   depended on telling those two apart.

5. **THE VIEW/ACTION INDEX PAGES ARE A 200 OF HTML.** `/JSON/break/view/` returns ZAP's welcome
   page, and `core/view/apiSummary` is `bad_view` in 2.17.0. There is no machine-readable index
   to enumerate from; the surface was established by probing names and reading the error CODE.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from . import proxy as proxy_mod

# --------------------------------------------------------------------------- #
# the API surface, as MEASURED on ZAP 2.17.0 (2026-08-05). See the module docstring.
# --------------------------------------------------------------------------- #
_VIEW_IS_BREAK_ALL = "/JSON/break/view/isBreakAll/"
_VIEW_IS_BREAK_REQUEST = "/JSON/break/view/isBreakRequest/"
_VIEW_IS_BREAK_RESPONSE = "/JSON/break/view/isBreakResponse/"
_VIEW_HTTP_MESSAGE = "/JSON/break/view/httpMessage/"

_ACTION_BREAK = "/JSON/break/action/break/"
_ACTION_CONTINUE = "/JSON/break/action/continue/"
_ACTION_STEP = "/JSON/break/action/step/"
_ACTION_DROP = "/JSON/break/action/drop/"
_ACTION_SET_MESSAGE = "/JSON/break/action/setHttpMessage/"

#: *** THE ONLY VALUE THE ACTION ACCEPTS. NOT A PARAMETER. ***
#: See trap 2: `http-request`, `http-response` and `http-sender` all answer `illegal_parameter`.
BREAK_TYPE = "http-all"

#: Release verbs, and WHAT EACH ONE LEAVES BREAKING IN — measured, not read off the docs.
#: This mapping exists so the UI can tell the operator, before they press, that forwarding with
#: `continue` also stops breaking. See trap 3.
RELEASE_LEAVES_BREAKING_ON = {"continue": False, "step": True, "drop": True}


class InterceptState(BaseModel):
    """What breaking is doing right now, READ BACK FROM ZAP on every call.

    Nothing here is remembered between calls. ZAP persists its configuration across scans and
    across ENGAGEMENTS — this repo has been bitten by that four times — so a cached "breaking is
    off" would be a claim about what we last wrote, not about what the daemon is doing.
    """

    container: str
    port: int
    breaking: bool = Field(False, description="Is break-all on? ZAP's own `isBreakAll`.")
    held: bool = Field(
        False,
        description="Is a request actually WAITING? Derived from httpMessage being non-empty, "
        "NEVER from isBreakRequest — that is a setting and reads true with nothing held.",
    )
    message: str = Field(
        "", description="The held request, raw, exactly as ZAP hands it over. Empty when none."
    )
    #: Reported so the UI can show them and nobody re-learns trap 3 the hard way.
    break_on_request: bool = False
    break_on_response: bool = False
    read_ok: bool = Field(
        True,
        description="False means the daemon did not answer readably — which is a different fact "
        "from 'breaking is off', and the UI must not draw the two the same way.",
    )
    detail: str = ""


def _view_bool(container: str, port: int, path: str, key: str) -> tuple[bool, bool]:
    """``(value, read_ok)``. An unreadable view is NOT False — build #18 item 8's whole lesson."""
    body = proxy_mod._json(proxy_mod._api_get(container, port, path))
    if key not in body:
        return False, False
    return str(body.get(key, "")).strip().lower() == "true", True


def observed(container: str, port: int) -> InterceptState:
    """The live state. READ-ONLY and UNGATED — a panel polls this while breaking is on."""
    state = InterceptState(container=container, port=port)
    breaking, ok_all = _view_bool(container, port, _VIEW_IS_BREAK_ALL, "isBreakAll")
    state.breaking = breaking
    on_req, ok_req = _view_bool(container, port, _VIEW_IS_BREAK_REQUEST, "isBreakRequest")
    on_res, _ = _view_bool(container, port, _VIEW_IS_BREAK_RESPONSE, "isBreakResponse")
    state.break_on_request, state.break_on_response = on_req, on_res

    body = proxy_mod._json(proxy_mod._api_get(container, port, _VIEW_HTTP_MESSAGE))
    if "httpMessage" not in body:
        state.read_ok = False
        state.detail = (
            "the daemon did not answer break/view/httpMessage readably — this is NOT 'nothing is "
            "held'. Check the proxy is up and the API key is right before trusting the panel."
        )
        return state
    state.message = str(body.get("httpMessage") or "")
    state.held = bool(state.message)
    state.read_ok = ok_all and ok_req
    if not state.read_ok:
        state.detail = "breaking state partially unreadable — the held message was read, the "\
                       "switches were not"
    return state


def set_breaking(container: str, port: int, on: bool) -> InterceptState:
    """Turn breaking on or off, then READ THE STATE BACK. Ungated in BOTH directions.

    On is ungated because holding traffic reduces what reaches the target. Off is ungated for the
    reason every stop in this codebase is ungated — and it matters more here than anywhere else,
    because while breaking is on the operator's BROWSER IS FROZEN. A gate that could refuse to
    turn it off would look exactly like the target having gone down.

    The verdict is the read-back, never the `{"Result":"OK"}`: trap 2 in the module docstring is
    an OK from this very endpoint for a setting that did nothing.
    """
    proxy_mod._api_get(
        container, port,
        f"{_ACTION_BREAK}?type={BREAK_TYPE}&state={'true' if on else 'false'}&scope=",
    )
    return observed(container, port)


def replace_intercepted_message(container: str, port: int, payload: Any) -> InterceptState:
    """Route-facing wrapper: takes the request model, calls :func:`replace_held`.

    Split so the module keeps a plain string signature that a test and a proof script can call
    without constructing a router model — the same reason `shape_request` is pure.
    """
    return replace_held(container, port,
                        getattr(payload, "http_header", ""), getattr(payload, "http_body", ""))


def replace_held(container: str, port: int, raw_header: str, raw_body: str = "") -> InterceptState:
    """Replace the HELD request with these bytes, then read it back. Nothing is forwarded.

    *** THE READ-BACK IS THE VERDICT, AND HERE IT IS LOAD-BEARING TWICE. ***
    With nothing held, ZAP answers `does_not_exist` — which this returns as an ordinary state
    with `held` False and a `detail` saying so, rather than raising. An operator whose request
    timed out while they were editing has not done anything wrong.

    The header and body go over as a FORM BODY ON STDIN, never in the URL, for build #18's
    reason: `_api_get` puts its query string into ZAP's own recorded history AND onto the
    `docker exec … curl …` argv that `ps` on this host can read. A held request routinely carries
    a session cookie and an Authorization header, so an edited request in an argv is a credential
    on the process table.
    """
    proxy_mod._api_post(container, port, _ACTION_SET_MESSAGE,
                        {"httpHeader": raw_header, "httpBody": raw_body})
    state = observed(container, port)
    if not state.held:
        state.detail = (
            "nothing is held any more, so the replacement was not applied — the request was "
            "forwarded or timed out while it was being edited. Nothing was sent on your behalf."
        )
    return state


def release(container: str, port: int, verb: str) -> InterceptState:
    """Let the held request go. Ungated.

    *** THE THREE VERBS DIFFER IN WHAT THEY LEAVE BREAKING IN, AND THAT IS MEASURED. ***

      ``continue``  forwards it AND TURNS BREAKING OFF. `isBreakAll` reads false afterwards.
      ``step``      forwards it and leaves breaking on, so the next request is held too.
      ``drop``      bins it and leaves breaking on.

    That is ZAP's break-panel semantics and it surprises people, so the state is read back and
    ``detail`` says what happened rather than what was asked for. `continue` and `step` were both
    measured forwarding the REPLACED bytes to the origin, which is the property the feature turns
    on; `drop` was measured never reaching the origin at all.

    AN UNKNOWN VERB IS REPORTED, NOT REFUSED-WITH-A-RAISE: the state comes back with a detail
    saying which verbs exist and nothing was released. Refusing loudly here would be a
    prohibition on a typo.
    """
    paths = {"continue": _ACTION_CONTINUE, "drop": _ACTION_DROP, "step": _ACTION_STEP}
    name = (verb or "").strip().lower()
    path = paths.get(name)
    if path is None:
        state = observed(container, port)
        state.detail = (
            f"{verb!r} is not a release verb — use continue (forward, and breaking stops), drop "
            "(bin it, breaking continues) or step (forward, breaking continues). Nothing was "
            "released; the request is still held."
        )
        return state

    # *** THE DROP GUARD. SEE TRAP 5 — THIS IS NOT DEFENSIVENESS, IT IS THE FIX. ***
    # A `drop` with nothing held wedges the daemon's break manager for good: it keeps holding
    # requests and never lets anyone read one again. So the state is read FIRST and the call is
    # not made. Nothing is refused to the operator here — dropping nothing was never an action —
    # and the state comes back with a detail saying why the button did nothing.
    if name == "drop":
        current = observed(container, port)
        if not current.held:
            current.detail = (
                "nothing is held, so no drop was sent. That is deliberate: a drop with nothing "
                "held permanently stops this daemon from ever showing a held request again "
                "(measured). Breaking is left exactly as it was."
            )
            return current

    proxy_mod._api_get(container, port, path)
    state = observed(container, port)
    if name == "continue" and not state.breaking:
        state.detail = (
            "forwarded — and ZAP's `continue` also TURNED BREAKING OFF, so the next request will "
            "not be held. Use `step` to forward one and keep breaking."
        )
    return state


def panic(container: str, port: int) -> dict[str, Any]:
    """DROP WHATEVER IS HELD AND TURN BREAKING OFF, in that order. The one-click way out.

    *** THE ORDER IS THE WHOLE FUNCTION. *** Turning breaking off first leaves the already-held
    request still held with no UI reachable to release it — measured during item 1, where a
    control request issued after `state=false` timed out at 15s because a stale message from the
    previous round was still sitting in front of it. Dropping first and switching off second is
    the sequence that actually restores traffic, and the read-back proves it did.

    *** AND THE `if before.held` IS NOT AN OPTIMISATION. SEE TRAP 5. ***
    A drop sent with nothing held wedges the break manager permanently. This function is the one
    most likely to be pressed when nothing is held — it is the "I think the target is down"
    button — so an unguarded drop here would break interception for the rest of the daemon's life
    at exactly the moment the operator was most confused.

    DROP, not forward, because this is the button an operator presses when they have forgotten
    breaking was on and think the target has gone down. Sending a request they have stopped
    paying attention to is the wrong default; a dropped request is one refresh away from being
    retried.
    """
    before = observed(container, port)
    dropped = False
    if before.held:
        proxy_mod._api_get(container, port, _ACTION_DROP)
        dropped = True
    after = set_breaking(container, port, False)
    return {
        "dropped_held_request": dropped,
        "was_breaking": before.breaking,
        "state": after,
        "detail": (
            "breaking is off and traffic is flowing again"
            if after.read_ok and not after.breaking
            else "breaking could not be confirmed off — read the state again before trusting it"
        ),
    }
