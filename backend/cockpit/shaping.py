"""Payload shaping — encode, vary and pollute a payload so a signature does not match it.

*** WHY THIS IS IN THE REPEATER AND NOT IN THE ACTIVE SCANNER. ***

Build #18 item 4 asked for payload-level WAF bypass and asked, first, for an honest answer about
where it can actually be built. That answer is: **the scanner cannot, the repeater can**, and the
reason is a property of ZAP rather than a preference of ours.

ZAP's active scanner generates its payloads INSIDE each scan rule, in Java, at scan time. What
its API exposes is which RULES run (``ascan/action/disableScanners``), how HARD they try
(``setPolicyAttackStrength``) and which INPUT VECTORS they fill (query, POST body, headers,
cookies). None of those is a payload transform. The two things that come closest are both
narrower than they look:

  * **The Custom Payloads add-on** replaces the payload LISTS of the handful of rules that opt
    into it — it swaps ``' OR 1=1--`` for a different string. It cannot apply an encoding to what
    a rule already generated, and most injection rules do not participate at all.
  * **The Replacer add-on** — which build #18 item 1 uses for the bypass header — rewrites
    HEADERS and fixed strings on the way out. Pointing it at payload bytes would mean writing a
    regex that matches every payload every rule might emit, which is not a thing that exists.

So a "shape the scanner's payloads" knob would have been a fake knob: a switch in the UI, a field
in the model, and nothing different on the wire. This module builds it where it does work — the
REPEATER, which is operator-driven, sends one request at a time, and is exactly the surface a
human uses when they already know which parameter to attack and are watching a WAF refuse them.

*** IT IS AN OPTION, NOT A GATE. *** No confirm, no acknowledgement, no refusal if unset. The
repeater is human-only by construction (see repeater.py rule #3) and a human clicking Send is the
approval; shaping changes the bytes of a request that human already composed. Legitimate on a
safe-harbour program, and the decision to build it was taken explicitly (Zaid, 2026-08-05).

*** THE MARKER IS EXPLICIT, BECAUSE GUESSING WHAT THE PAYLOAD IS WOULD BE WORSE. ***
Shaping applies only between ``[[`` and ``]]``. A transform applied to a whole URL would encode
the scheme, the host and the parameter names as well and produce a request that goes nowhere; one
applied by guessing which parameter "looks like" a payload would be wrong silently. The operator
marks the span, the markers are stripped, and what is sent is stated back to them.

Every function here is PURE. Nothing in this module opens a socket, spawns a process or reads a
file.
"""

from __future__ import annotations

from urllib.parse import quote, urlparse, urlunparse

#: The span markers. ASCII on purpose — the console this project is driven from is cp1252, and a
#: marker outside that codepage would raise UnicodeEncodeError in every verification script that
#: printed a shaped request back (a trap already paid for twice in this repo).
SHAPE_OPEN = "[["
SHAPE_CLOSE = "]]"


def _url_encode(value: str) -> str:
    """Percent-encode EVERYTHING, including characters a URL would normally leave alone.

    ``safe=""`` is the point. ``quote`` leaves ``/``, ``:`` and ``~`` untouched by default, and
    those are exactly the characters a path-traversal or SSRF signature keys on.
    """
    return quote(value, safe="")


def _double_url_encode(value: str) -> str:
    """Encode, then encode the percent signs again.

    Aimed at the two-layer decode: an edge decodes once, sees harmless text, and passes it to an
    application framework that decodes a second time.
    """
    return _url_encode(_url_encode(value))


def _case_vary(value: str) -> str:
    """Alternate the case of every letter — ``select`` becomes ``sElEcT``.

    Against a signature that lower-cases before matching this does nothing, which is worth saying
    plainly: it is a probe for a case-sensitive rule, not a general bypass.
    """
    out = []
    upper = False
    for ch in value:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)


def _sql_comment(value: str) -> str:
    """Replace runs of whitespace with an inline SQL comment ``/**/``.

    A SQL parser treats ``/**/`` as whitespace; a signature looking for ``UNION SELECT`` with a
    space in it does not.
    """
    out: list[str] = []
    run = False
    for ch in value:
        if ch.isspace():
            run = True
            continue
        if run:
            out.append("/**/")
            run = False
        out.append(ch)
    if run:
        out.append("/**/")
    return "".join(out)


def _whitespace_tab(value: str) -> str:
    """Swap spaces for horizontal tabs. The same idea as ``sql-comment``, one layer simpler, and
    it survives places a comment does not (a shell command line, an XPath expression)."""
    return value.replace(" ", "\t")


def _plus_space(value: str) -> str:
    """Spaces to ``+``. Only meaningful in a query string or a form body, where ``+`` decodes
    back to a space — in a path or a JSON body it is a literal plus and changes the payload."""
    return value.replace(" ", "+")


#: name -> (function, one-line description). ORDERED, because the order they are applied in is
#: the operator's choice and the UI lists them in a stable order.
VALUE_TRANSFORMS: dict[str, tuple] = {
    "url-encode": (_url_encode, "Percent-encode every character, including / : and ~."),
    "double-url-encode": (_double_url_encode, "Percent-encode twice — for a two-layer decode."),
    "case-vary": (_case_vary, "Alternate letter case. A probe for a case-sensitive rule."),
    "sql-comment": (_sql_comment, "Whitespace becomes /**/, which SQL reads as a space."),
    "whitespace-tab": (_whitespace_tab, "Spaces become tabs."),
    "plus-space": (_plus_space, "Spaces become '+' (query strings and form bodies only)."),
}

#: Shapes that change the REQUEST rather than the payload span. Handled by the caller, not here,
#: because they need the whole request — but named here so one list documents the vocabulary.
REQUEST_TRANSFORMS: dict[str, str] = {
    "param-pollution": "Duplicate every query parameter, shaped value last. Which copy a server "
                       "reads varies by stack, and an edge and an origin often disagree.",
    "chunked": "Send the body with Transfer-Encoding: chunked rather than a Content-Length.",
}


def known_shapes() -> dict[str, str]:
    """Every shape name -> its description. For the UI and for an error message that lists them."""
    out = {name: desc for name, (_, desc) in VALUE_TRANSFORMS.items()}
    out.update(REQUEST_TRANSFORMS)
    return out


def has_marker(text: str) -> bool:
    """Is there a shaping span in this text? Used to WARN, never to refuse."""
    return SHAPE_OPEN in (text or "") and SHAPE_CLOSE in (text or "")


def strip_markers(text: str) -> str:
    """The text with markers removed and nothing else changed — what an UNSHAPED send transmits.

    This is what makes a marked request safe to send with no shapes selected: the markers are
    annotation, so they never reach the wire either way. It is also the CONTROL half of every
    measurement — shaped vs unshaped has to differ in the shaping and in nothing else.
    """
    return (text or "").replace(SHAPE_OPEN, "").replace(SHAPE_CLOSE, "")


def apply_shapes(text: str, shapes: list[str]) -> tuple[str, list[str]]:
    """Apply ``shapes`` to every ``[[…]]`` span in ``text``. Returns (shaped, unknown_shape_names).

    An UNKNOWN SHAPE NAME IS RETURNED, NOT RAISED. The caller warns and sends the rest — a typo
    in one transform name should not throw away a request the operator composed, and a refusal
    here would be a prohibition this build is not allowed to add. What it must not do is pretend:
    the unknown names come back so the caller can say which ones did nothing.

    Transforms compose in the order given, so ``["sql-comment", "url-encode"]`` comments first and
    then encodes the comment — which is usually what is wanted, and is never guessed at here.
    """
    src = text or ""
    unknown = [s for s in shapes if s not in VALUE_TRANSFORMS and s not in REQUEST_TRANSFORMS]
    value_shapes = [s for s in shapes if s in VALUE_TRANSFORMS]
    if not value_shapes:
        return strip_markers(src), unknown

    out: list[str] = []
    rest = src
    while True:
        start = rest.find(SHAPE_OPEN)
        if start == -1:
            out.append(rest)
            break
        end = rest.find(SHAPE_CLOSE, start + len(SHAPE_OPEN))
        if end == -1:
            # An opening marker with no close is not a span. Left ALONE rather than shaped to the
            # end of the string, which would silently encode the rest of the request.
            out.append(rest)
            break
        out.append(rest[:start])
        span = rest[start + len(SHAPE_OPEN):end]
        for name in value_shapes:
            span = VALUE_TRANSFORMS[name][0](span)
        out.append(span)
        rest = rest[end + len(SHAPE_CLOSE):]
    return "".join(out), unknown


def pollute_query(url: str) -> str:
    """Duplicate every query parameter, original first and the value as-given second.

    HTTP parameter pollution as a bypass rests on a disagreement: an edge that inspects the FIRST
    value of a repeated parameter in front of an origin that reads the LAST (or the other way
    round) means one of them never sees the payload. Which way a given stack goes is a fact about
    that stack, so this duplicates and lets the response say.

    A URL with no query string comes back UNCHANGED — there is nothing to duplicate, and
    inventing a parameter would change what the operator asked to send.
    """
    parsed = urlparse(url or "")
    if not parsed.query:
        return url or ""
    # parse_qsl would drop a valueless parameter (`?debug`) and re-order nothing else usefully,
    # so the pairs are split by hand: what goes back on the wire has to be what was typed.
    pairs: list[tuple[str, str]] = []
    for chunk in parsed.query.split("&"):
        if not chunk:
            continue
        name, sep, value = chunk.partition("=")
        pairs.append((name, value if sep else ""))
    doubled: list[str] = []
    for name, value in pairs:
        doubled.append(f"{name}={value}")
    for name, value in pairs:
        doubled.append(f"{name}={value}")
    return urlunparse(parsed._replace(query="&".join(doubled)))


__all__ = [
    "REQUEST_TRANSFORMS", "SHAPE_CLOSE", "SHAPE_OPEN", "VALUE_TRANSFORMS",
    "apply_shapes", "has_marker", "known_shapes", "pollute_query", "strip_markers",
]
