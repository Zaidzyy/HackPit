"""ZAP proxy gating locks.  Run:  python test_zap_proxy_safety.py

THE INVARIANT: a proxy start passes the real executor gates, and the argv the gate classified is
the argv that gets spawned.
"""

from __future__ import annotations

from cockpit import proxy


#: A fixed stand-in so argv assertions are deterministic. The real key is minted per start.
KEY = "0123456789abcdef0123456789abcdef"


def _req(**kw):
    base = dict(approved=True, dangerous_ack=True, engagement_id=None)
    base.update(kw)
    return proxy.ProxyStartRequest(**base)


def _argv(**kw) -> list[str]:
    return proxy.server_argv_for(_req(**kw), api_key=KEY)


def test_an_unapproved_start_is_refused_with_a_control() -> None:
    """approved=False must refuse. The control is in THIS test: the same request WITH approval
    must reach a different gate, or the check is passing for the wrong reason."""
    rejected = proxy.validate_start(_req(approved=False))
    assert rejected is not None, "an unapproved proxy start was NOT refused"
    assert rejected.gate == "approval", f"refused at {rejected.gate!r}, expected 'approval'"

    # control: approval satisfied -> the approval gate no longer fires
    other = proxy.validate_start(_req(approved=True))
    if other is not None:
        assert other.gate != "approval", (
            "the approval gate still fires with approved=True — it is not reading the field"
        )
    print("  an unapproved start is refused at the approval gate, control holds: PASS")


def test_the_red_confirm_is_required() -> None:
    """A proxy holds full request bodies — credentials and session tokens in cleartext.

    This is the check that forced task 1a: part 1's _TOOL_ATTACK_FLAGS keys on `-quickurl`,
    which the DAEMON argv does not carry, so without adding `-daemon` the danger gate would
    never fire here and `dangerous_ack` would be decorative. That is gate-audit finding I2's
    shape — a gate field that exists and is never enforced.
    """
    rejected = proxy.validate_start(_req(dangerous_ack=False))
    assert rejected is not None, "a proxy start with no red-confirm was NOT refused"
    assert rejected.gate == "danger", (
        f"refused at {rejected.gate!r}, expected 'danger' — if this says 'approval' the danger "
        "heuristic is not flagging the daemon argv at all"
    )
    print("  a start without the red-confirm is refused at the danger gate: PASS")


def test_the_gated_argv_is_the_spawned_argv() -> None:
    """*** CRITICAL 2. *** Classifying a different string than the one that runs reproduces the
    bug in a new place. One derivation, asserted — the same lock tunnels.py carries."""
    import inspect

    req = _req()
    argv = proxy.server_argv_for(req, api_key=KEY)
    gated = proxy._gate_request(req)
    assert gated.command == argv[0], (
        f"the gate classifies {gated.command!r} but the spawn runs {argv[0]!r}"
    )

    # and the spawn path must DERIVE from server_argv_for rather than rebuilding the argv
    src = inspect.getsource(proxy.start_proxy)
    assert "server_argv_for" in src, (
        "start_proxy does not call server_argv_for — it is building its own argv, which is "
        "exactly how the gated string and the executed string drift apart"
    )
    print("  the gated argv and the spawned argv come from one derivation: PASS")


def test_the_daemon_binds_loopback_unless_publish_was_asked_for() -> None:
    """THE ISOLATION PROPERTY, now with exactly one way out of it.

    `-host 127.0.0.1` is what keeps the API unreachable from the host, and it stays the DEFAULT.
    Build #15 adds a single opt-in — `publish=True` — because a container process on loopback
    cannot be reached through a published port at all. The lock therefore moves from "this
    constant never changes" to "it changes only when the operator asked, and never in lab mode".
    """
    joined = " ".join(_argv())
    assert "-host 127.0.0.1" in joined, f"the DEFAULT daemon does not bind loopback: {joined}"
    for bad in ("0.0.0.0", "api.addrs.addr.name=.*"):
        assert bad not in joined, f"an unpublished argv opens the API beyond loopback: {bad!r}"

    # the one way out, and it has to actually work or the feature is inert
    published = " ".join(_argv(publish=True, engagement_id="e1"))
    assert "-host 0.0.0.0" in published, (
        "a published proxy still binds loopback INSIDE the container — `docker -p` forwards to "
        "the bridge interface, so nothing would be listening there and the port would be open "
        "on the host while the feature silently did not work"
    )
    assert "api.addrs.addr.regex=true" in published, (
        "a published proxy does not widen api.addrs — a correctly-keyed request arriving through "
        "the published port comes from the bridge gateway, not 127.0.0.1, and ZAP would refuse it"
    )
    print("  loopback by default; 0.0.0.0 only when publish was asked for: PASS")


def test_publishing_is_engagement_only() -> None:
    """The lab network is `internal: true` — a published port there has no route.

    Refused BEFORE the executor gates, because this is not a safety verdict about a coherent
    request; it is a request that cannot describe a reachable state. Control in the same test:
    the identical request WITH an engagement is not refused here.
    """
    refused = proxy.publish_refusal(_req(publish=True, engagement_id=None))
    assert refused is not None, "a published LAB proxy was not refused"
    assert refused.gate == "publish", f"refused at {refused.gate!r}"

    assert proxy.publish_refusal(_req(publish=True, engagement_id="e1")) is None, (
        "control failed — an engagement publish is refused too, so the check fires on everything"
    )
    assert proxy.publish_refusal(_req(publish=False)) is None, (
        "control failed — an ordinary unpublished start is refused"
    )
    print("  publish is engagement-only, both controls hold: PASS")


def test_the_api_key_is_enforced_and_never_reaches_a_record() -> None:
    """*** THE SINGLE EASIEST WAY FOR THIS BUILD TO LEAK A CREDENTIAL. ***

    Closed twice over, because one of the two cannot regress:
      1. the GATE IS NEVER GIVEN A REAL KEY — an ExecRequest is the thing this codebase records,
         reports and puts in the model's prompt, so the key is not handed over in the first place
      2. and if it ever were, `secretargs` masks the `api.key` VALUE while deliberately leaving
         `api.disablekey=false` visible, because that token is the evidence the lock was on
    """
    argv = _argv()
    joined = " ".join(argv)
    assert "api.disablekey=false" in joined, (
        "the daemon does not state disablekey=false. ZAP PERSISTS -config values into "
        "$HOME/.ZAP/config.xml, so an unstated flag inherits whatever the last run wrote — which "
        "is how the original 'api.key enforces nothing' finding came to be wrong"
    )
    assert f"api.key={KEY}" in joined, "the daemon does not set an API key at all"

    # 1. the gate never sees it
    gated = " ".join(proxy._gate_request(_req()).args)
    assert KEY not in gated, f"THE KEY IS IN THE GATE SURFACE — it will be recorded: {gated!r}"
    assert proxy.GATE_KEY_PLACEHOLDER not in gated, (
        "the placeholder leaked into the surface — the surface should carry no key token at all"
    )

    # 2. and the recorded form is redacted, with the audit token intact
    recorded = " ".join(proxy.recorded_argv_for(_req(), api_key=KEY))
    assert KEY not in recorded, f"the recorded argv contains the API key: {recorded!r}"
    assert "api.key=<redacted>" in recorded, f"the key was not redacted, just dropped: {recorded!r}"
    assert "api.disablekey=false" in recorded, (
        "redaction ate `api.disablekey=false` — that token is the EVIDENCE the lock was on, and "
        "masking it destroys the audit trail redaction exists to protect (the `nmap -p 445` rule)"
    )

    # POSITIVE CONTROL: the check can fail. A tool with no registered secret keeps its value, so
    # a redaction rule that silently stopped matching would show up here as an unmasked key.
    from cockpit import secretargs

    unknown = secretargs.redact_argv("some-unknown-binary", ["-config", f"api.key={KEY}"])
    assert KEY in " ".join(unknown), (
        "control failed — redaction fires on tools it has no rule for, so the assertions above "
        "would pass even if the zaproxy rule were removed"
    )
    print("  key enforced, absent from the gate surface, redacted in the record: PASS")


def test_the_key_is_different_on_two_consecutive_starts() -> None:
    """Random per start, so nothing long-lived exists to leak."""
    keys = {proxy.mint_api_key() for _ in range(8)}
    assert len(keys) == 8, f"mint_api_key repeats itself: {keys}"
    assert all(len(k) >= 32 for k in keys), f"a key is too short to be worth having: {keys}"
    print("  every minted key is fresh and long: PASS")


def test_both_modes_are_reachable() -> None:
    """Deliberate divergence from tunnels.py, which refuses lab mode. The proxy runs in WHICHEVER
    sandbox the operator is in, so lab mode's isolation gate is the relevant condition, not an
    unrelated one — see spec §5. Neither mode may be refused for LACKING the other's
    precondition."""
    lab = proxy.validate_start(_req(engagement_id=None))
    if lab is not None:
        assert lab.gate != "engagement", (
            "lab mode is refused for having no engagement id — that is tunnels.py's rule, and "
            "it inverts here: the proxy runs in the container the lab isolation gate is about"
        )
    print("  lab mode is not refused for lacking an engagement id: PASS")


def test_the_lab_surface_declares_the_lab_and_nothing_else() -> None:
    """*** THE DECISION THAT MADE LAB MODE POSSIBLE (2026-08-03, Zaid). ***

    A listener names no target, and lab mode refuses a target-less command — a LOCKED invariant
    this build does not touch. So the lab gate surface declares the lab, which is a true
    statement of scope: container_for() puts a lab proxy in the isolated sandbox, whose
    `internal: true` network has no route off the bridge, so the lab target IS everything it can
    reach.

    Two things must hold or the declaration stops being true:
      * the surface names the lab and NOTHING else — no second host smuggled in
      * engagement mode does NOT get the lab declared, because there the engagement's own scope
        governs and the proxy is in the fully-open sandbox where the claim would be false
    """
    from cockpit import config

    lab_surface = proxy._gate_request(_req(engagement_id=None)).args
    lab_hosts = [a for a in lab_surface if not a.startswith("-")]
    assert lab_hosts == [config.LAB_TARGET_HOST], (
        f"the lab surface declares hosts {lab_hosts!r} — it must be exactly the lab target. "
        "Anything more is a host this listener cannot actually reach, so the declaration would "
        "stop being true; anything less is refused by the locked target-less rule."
    )
    assert "-daemon" in lab_surface, (
        f"the surface {lab_surface!r} drops -daemon — the danger verdict for this binary is "
        "argument-based, so without it the red-confirm cannot fire and dangerous_ack is "
        "decorative (gate-audit finding I2's shape)"
    )

    eng_surface = proxy._gate_request(_req(engagement_id="e1")).args
    eng_hosts = [a for a in eng_surface if not a.startswith("-")]
    assert eng_hosts == [], (
        f"engagement mode declares hosts {eng_hosts!r} — the lab claim is FALSE there (the "
        "engage sandbox is fully open), and engagement mode already permits a target-less command"
    )
    assert "-daemon" in eng_surface, "engagement mode drops -daemon — the red-confirm cannot fire"

    # and the claim must stay true: the real argv must not carry some other host
    argv = " ".join(_argv())
    assert config.LAB_TARGET_HOST not in argv, (
        "the daemon argv now names the lab target — if the argv ever gains a real target, the "
        "gate surface must be derived from it rather than declared"
    )
    print("  lab declares exactly the lab; engagement declares nothing: PASS")


def test_the_daemon_gets_no_stdin_writer() -> None:
    """A daemon needs no stdin, so it is spawned interactive=False and proc.stdin is None.
    lifecycle's own lock covers the mechanism; this asserts THIS caller opted out — the C2
    console binaries need a held-open stdin and a daemon must not inherit that by copy-paste."""
    import inspect

    src = inspect.getsource(proxy.start_proxy)
    assert "interactive=False" in src, (
        "start_proxy does not spawn with interactive=False — a daemon needs no stdin, and an "
        "interactive spawn would hand it a pipe nobody should hold"
    )
    assert "interactive=True" not in src, f"start_proxy spawns interactively somewhere: {src[:200]}"
    print("  the daemon is spawned with no stdin writer: PASS")


def test_a_refused_start_spawns_nothing() -> None:
    """*** NOTHING RUNS ON A REFUSAL. *** The gate must be checked BEFORE any spawn call.
    Source-level, because the alternative is spawning a real daemon in a unit test."""
    import inspect

    src = inspect.getsource(proxy.start_proxy)
    gate_at = src.find("validate_start")
    spawn_at = src.find("spawn_watched")
    assert gate_at != -1, "start_proxy never calls validate_start"
    assert spawn_at != -1, "start_proxy never calls spawn_watched"
    assert gate_at < spawn_at, (
        "start_proxy spawns before it gates — a refused start would leave a live daemon"
    )
    print("  the gate is checked before anything spawns: PASS")


def test_stopping_is_not_gated() -> None:
    """Stopping a listener REMOVES capability. A gate that can refuse to stop one is a gate that
    makes the system less safe — the position tunnels.py takes, restated here so a later 'for
    consistency' edit has to argue with it."""
    import inspect

    src = inspect.getsource(proxy.stop_proxy)
    assert "validate_start" not in src and "validate_request" not in src, (
        "stop_proxy runs a gate — refusing to stop a running proxy leaves capability up that "
        "the operator asked to remove"
    )
    print("  stopping is not gated: PASS")


def test_the_proxy_flag_is_per_tool_and_never_silent() -> None:
    """Each tool spells its proxy flag differently, and a tool we do not know is run UNCHANGED
    with the note SAYING SO — silently dropping the flag would hand the operator a run they
    believe was captured and was not."""
    from cockpit import executor

    args, note = executor.apply_proxy("curl", ["http://x"], 8090)
    assert args[:2] == ["-x", "http://127.0.0.1:8090"], args
    assert "http://x" in args, "the original args were dropped"
    assert note and "not captured" not in note.lower(), note

    args, _ = executor.apply_proxy("nuclei", ["-u", "http://x"], 8090)
    assert args[:2] == ["-proxy", "http://127.0.0.1:8090"], args

    args, _ = executor.apply_proxy("sqlmap", ["-u", "http://x"], 8090)
    assert args[0] == "--proxy=http://127.0.0.1:8090", args

    # normalisation: a path-prefixed spelling must still be recognised
    args, _ = executor.apply_proxy("/usr/bin/curl", ["http://x"], 8090)
    assert args[0] == "-x", f"a path-prefixed binary lost its proxy flag: {args}"

    # THE HONEST CASE
    unknown_args, unknown_note = executor.apply_proxy("someunknowntool", ["-a"], 8090)
    assert unknown_args == ["-a"], f"an unknown tool's args were rewritten: {unknown_args}"
    assert "not captured" in unknown_note.lower(), (
        f"an unknown tool was left unproxied with no warning: {unknown_note!r}"
    )
    print("  per-tool proxy flags, path-normalised, unknown tool left alone and reported: PASS")


def test_the_rewrite_cancels_a_prevalidated_verdict() -> None:
    """*** CRITICAL 2, WEARING A NEW HAT. ***

    A caller that validated the ORIGINAL request holds a verdict about a DIFFERENT command line
    than the one about to run. iter_run therefore discards `prevalidated` whenever the rewrite
    actually changed the argv, and re-validates what will execute.
    """
    import inspect

    src = inspect.getsource(proxy_executor().iter_run)
    rewrite_at = src.find("apply_proxy_to_request")
    validate_at = src.find("validate_request(request)")
    assert rewrite_at != -1, "iter_run does not apply the proxy rewrite at all"
    assert validate_at != -1, "iter_run does not validate"
    assert rewrite_at < validate_at, (
        "iter_run validates BEFORE rewriting the argv — the gate would classify a command line "
        "different from the one that runs"
    )
    assert "prevalidated = False" in src, (
        "the rewrite does not cancel a prevalidated verdict — a router that validated the "
        "original request would let the rewritten one through ungated"
    )
    print("  the rewrite precedes validation and cancels a stale verdict: PASS")


def proxy_executor():
    from cockpit import executor
    return executor


def test_a_request_that_did_not_ask_is_untouched() -> None:
    """proxy=False must be byte-identical to before this feature existed."""
    from cockpit.models import ExecRequest

    req = ExecRequest(command="curl", args=["http://x"], approved=True)
    out, note = proxy_executor().apply_proxy_to_request(req)
    assert out is req and note == "", f"a non-proxy request was altered: {out.args!r} {note!r}"

    # and an unknown tool WITH proxy=True is also untouched, so `prevalidated` survives
    unknown = ExecRequest(command="someunknowntool", args=["-a"], approved=True, proxy=True)
    out2, note2 = proxy_executor().apply_proxy_to_request(unknown)
    assert out2 is unknown and note2 == "", (
        "an unrewritten request reported a change, which would needlessly discard a "
        f"prevalidated verdict: {note2!r}"
    )
    print("  proxy=False and unknown-tool requests are returned untouched: PASS")


# --------------------------------------------------------------------------- #
# THE AJAX SPIDER (build #15 part 2)
# --------------------------------------------------------------------------- #
def _spider(**kw):
    base = dict(target_url="http://hackpit-lab-target:3000/", approved=True, dangerous_ack=True)
    base.update(kw)
    return proxy.SpiderStartRequest(**base)


def test_every_crawl_gate_fires_each_with_a_control() -> None:
    """All four gates, in the executor's order, against the real validator.

    Each case carries its control in the SAME test: a heuristic stuck on always-refuse would
    otherwise satisfy every assertion here and look correct.

    *** THE CONTROL SAYS "NOT REFUSED AT **THIS** GATE", NEVER "NOT REFUSED". ***
    CI caught the first version of this test doing exactly what build #14 part 3's locks were
    already rewritten to stop doing. `assert clean is None` passed locally and failed on the
    runner, because the LAB gate order is target -> approval -> danger -> **sandbox**, and with
    no Docker in CI the isolation gate refuses last:
        gate='sandbox' — "hackpit-kali-sandbox is not running"
    So the assertion was silently depending on the developer's stack being up, which is the
    opposite of hermetic. A control must exclude the gate under test and nothing else.
    """
    clean = proxy.validate_spider(_spider())
    if clean is not None:
        assert clean.gate == "sandbox", (
            f"a fully approved in-scope crawl was refused at {clean.gate!r}: {clean.reason}"
        )

    unapproved = proxy.validate_spider(_spider(approved=False))
    assert unapproved is not None and unapproved.gate == "approval", unapproved

    unconfirmed = proxy.validate_spider(_spider(dangerous_ack=False))
    assert unconfirmed is not None and unconfirmed.gate == "danger", (
        f"refused at {unconfirmed.gate if unconfirmed else None!r}, expected 'danger'. If this "
        "says None, the -ajaxspider marker is not in allowlist._TOOL_ATTACK_FLAGS and "
        "dangerous_ack is decorative — gate-audit finding I2's shape."
    )

    off_scope = proxy.validate_spider(_spider(target_url="http://example.com/"))
    assert off_scope is not None and off_scope.gate == "target", off_scope
    print("  crawl gates: approval / danger / target all fire, controls hold: PASS")


def test_the_crawl_confirm_states_the_BROWSER_hazard_not_the_scanner_s() -> None:  # noqa: N802
    """*** THE WHOLE REASON THIS ACTION GOT ITS OWN REASON STRING. ***

    The active scanner earns its confirm by sending injection payloads. A crawl earns one because
    it drives a real browser that clicks things. If the operator reads the scanner's sentence
    here, the confirm is describing traffic that is not being sent — and a red-confirm whose
    stated reason is false is what teaches people the text is noise.
    """
    rejected = proxy.validate_spider(_spider(dangerous_ack=False))
    assert rejected is not None
    flags = " ".join(rejected.dangerous_flags).lower()
    assert "browser" in flags and "click" in flags, (
        f"the crawl's red-confirm does not mention the browser hazard: {flags!r}"
    )
    assert "injection payload" not in flags, (
        f"the crawl claims it sends injection payloads. It sends none: {flags!r}"
    )
    print("  the crawl's confirm states the browser hazard, not the scanner's: PASS")


def test_the_scoped_host_is_the_crawled_host() -> None:
    """*** PART 3's LOCK, RESTATED FOR THIS ACTION. ***

    The gate classifies an ARGV; what executes is a URL. String equality between them would be
    theatre, so the property locked is the one underneath: the host the gate scoped is the host
    the browser is pointed at. Exercised with a port, a path and a query string, because that is
    where a naive split falls over.
    """
    from urllib.parse import unquote, urlparse

    target = "http://hackpit-lab-target:3000/rest/products/search?q=a&b=c"
    req = _spider(target_url=target)

    surface = " ".join(proxy._gate_spider_request(req).args)
    assert target in surface, f"the gate surface does not carry the real target: {surface!r}"

    url = proxy.spider_url_for(req)
    sent = unquote(url.split("url=", 1)[1].split("&", 1)[0])
    assert sent == target, f"the API is aimed at {sent!r} but the gate scoped {target!r}"
    assert urlparse(sent).hostname == urlparse(target).hostname
    print("  the scoped host is the crawled host, through port/path/query: PASS")


def test_a_target_cannot_smuggle_a_crawl_parameter() -> None:
    """*** CRITICAL 2 IN A QUERY STRING. *** Part 3's defect class, in this action's parameters.

    The target is interpolated into a URL that carries THE CRAWL'S OWN parameters, so a `&` in
    the target would append to ZAP's parameter list and change the shape of the approved crawl.
    Nothing about a text field stops a `&`.
    """
    sneaky = proxy.spider_url_for(
        _spider(target_url="http://hackpit-lab-target:3000/?x=1&subtreeOnly=true"))
    assert "subtreeOnly=false" in sneaky, f"the crawl's own parameter was overridden: {sneaky}"
    assert sneaky.count("subtreeOnly=") == 1, (
        f"the target smuggled a second subtreeOnly parameter into the query: {sneaky}"
    )
    assert "&inScope=false" in sneaky, f"the target displaced inScope: {sneaky}"

    # CONTROL: the encoding is not simply mangling everything — a legitimate query survives and
    # round-trips, so this cannot pass by breaking the feature.
    from urllib.parse import unquote

    plain = proxy.spider_url_for(_spider(target_url="http://hackpit-lab-target:3000/a?q=1"))
    assert unquote(plain.split("url=", 1)[1].split("&", 1)[0]) == \
        "http://hackpit-lab-target:3000/a?q=1", plain
    print("  a target carrying '&' cannot set a crawl parameter, control holds: PASS")


def test_depth_and_duration_are_in_the_approved_surface() -> None:
    """A crawler that decides its own bounds is a command that stopped describing what runs.

    Same reason `-autorun` is excluded from the ZAP catalog entry: the human approved a shape,
    and the shape has to include the numbers that decide how far it goes.
    """
    surface = proxy.spider_argv_for(_spider(max_depth=3, max_duration_minutes=7))
    joined = " ".join(surface)
    assert "-maxdepth 3" in joined, f"depth is not in the approved surface: {joined}"
    assert "-maxduration 7" in joined, f"duration is not in the approved surface: {joined}"

    # and they track the request rather than being pinned to the defaults
    other = " ".join(proxy.spider_argv_for(_spider(max_depth=9, max_duration_minutes=45)))
    assert "-maxdepth 9" in other and "-maxduration 45" in other, other
    print("  crawl depth and duration appear in the gated surface: PASS")


def test_the_crawl_surface_does_not_claim_two_modes() -> None:
    """`-zapit` stays OUT, and this is the lock that keeps it out.

    The spec first proposed `zaproxy -zapit <target>` as the surface. Once `-ajaxspider` carries
    the danger verdict and the URL carries the scope, adding `-zapit` would make the declared
    command claim two crawl modes at once — and it would collide head-on with test_zap_safety's
    lock that a plain `-zapit` recon run must NOT demand a red-confirm.
    """
    argv = proxy.spider_argv_for(_spider())
    assert "-ajaxspider" in argv, f"the marker that carries the danger verdict is gone: {argv}"
    assert "-zapit" not in argv, (
        "the crawl surface declares -zapit as well. Two modes in one declared command, and "
        "-zapit is locked as a NON-dangerous recon flag by test_zap_safety.py"
    )
    assert "-quickurl" not in argv, (
        "the crawl surface borrows the SCANNER's flag — the confirm would then tell the operator "
        "injection payloads are being sent, which is false for a crawl"
    )
    print("  the crawl declares -ajaxspider only, never -zapit or -quickurl: PASS")


def test_stopping_a_crawl_is_not_gated() -> None:
    """A real browser is clicking real controls on a live site. The stop must never be refusable."""
    import inspect

    src = inspect.getsource(proxy.stop_spider)
    assert "validate_spider" not in src and "validate_request" not in src, (
        "stop_spider runs a gate — a browser is mid-crawl on a production site and this is the "
        "panic button"
    )
    print("  stopping a crawl is not gated: PASS")


def test_a_refused_crawl_launches_no_browser() -> None:
    """The gate must be checked BEFORE any API call, including the option-setting ones."""
    import inspect

    src = inspect.getsource(proxy.start_spider)
    gate_at = src.find("validate_spider")
    act_at = min(i for i in (src.find("_ACTION_SPIDER_BROWSER"), src.find("spider_url_for"))
                 if i != -1)
    assert gate_at != -1, "start_spider never calls validate_spider"
    assert gate_at < act_at, (
        "start_spider contacts ZAP before it gates — a refused crawl would still have changed "
        "the browser id or launched Chromium"
    )
    print("  a refused crawl contacts ZAP not at all: PASS")


def test_the_browser_id_is_read_back_not_trusted() -> None:
    """*** AN OK IS NOT A RESULT. ***

    `setOptionBrowserId` accepted `not-a-browser` and answered `{"Result":"OK"}` (measured).
    The image ships Chromium and no Firefox while ZAP's default is `firefox-headless`, so
    trusting the OK means discovering the failure later, in a driver stack trace inside ZAP's log.
    """
    import inspect

    src = inspect.getsource(proxy.start_spider)
    assert "_VIEW_SPIDER_BROWSER" in src, (
        "start_spider never reads the browser id back — it trusts setOptionBrowserId's OK, and "
        "that call returns OK for values ZAP cannot use"
    )
    assert 'gate="browser"' in src, "a mismatched browser id does not refuse"
    assert proxy.SPIDER_BROWSER_ID == "chrome-headless", (
        f"the browser id is {proxy.SPIDER_BROWSER_ID!r} — the image has Chromium and NO Firefox"
    )

    # observed_spider must report ZAP's value, never the constant we hoped for.
    #
    # AST, NOT A SUBSTRING — build #8's recorded lesson, and it fired here on the first run: the
    # function's own DOCSTRING says "rather than echoed from SPIDER_BROWSER_ID", and a text scan
    # failed the test for explaining itself. A scan that a comment can trip is a scan that gets
    # silenced by rewording rather than by fixing the code.
    import ast
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(proxy.observed_spider)))
    referenced = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert "SPIDER_BROWSER_ID" not in referenced, (
        "observed_spider references the id we SET rather than reporting the one ZAP holds — "
        "that reports a wish, which is the failure mode this build's measurement warned about"
    )
    print("  the browser id is read back from ZAP and a mismatch refuses: PASS")


def test_the_container_follows_the_mode() -> None:
    """Lab runs in the isolated sandbox; an engagement run in the open one. Picking the wrong
    container would either put a real-target proxy in the egress-less box (it would capture
    nothing) or put a lab proxy in the fully-open one (it would have reach it must not have)."""
    from cockpit import config

    assert proxy.container_for(_req(engagement_id=None)) == config.SANDBOX_CONTAINER
    assert proxy.container_for(_req(engagement_id="e1")) == config.ENGAGE_SANDBOX_CONTAINER
    print("  lab -> isolated sandbox, engagement -> engage sandbox: PASS")


def test_a_recovered_key_is_never_sent_to_a_different_port() -> None:
    """Build #17's defect, and the one way its fix could be WORSE than the defect.

    A daemon states its API key in its own argv, and that is how a restarted backend recovers it.
    But `observed_daemon` reports ONE daemon per container, so adopting its key without checking
    the port would send a live secret to whatever else happens to be listening on the port we
    were actually asked about. Hermetic: the observation is stubbed, no Docker.
    """
    real = proxy.observed_daemon
    try:
        proxy.observed_daemon = lambda container: (8090, KEY)  # type: ignore[assignment]
        proxy._adopted.clear()
        assert proxy.api_key_for("c", 8090) == KEY, "the key was not recovered at all"
        proxy._adopted.clear()
        assert proxy.api_key_for("c", 9999) == "", (
            "a key read off the daemon on :8090 was handed to a caller asking about :9999"
        )
        assert not proxy._adopted, "a mismatched port still cached a key"

        # and no daemon at all must stay "" — the honest answer, not a stale one
        proxy.observed_daemon = lambda container: None  # type: ignore[assignment]
        proxy._adopted.clear()
        assert proxy.api_key_for("c", 8090) == ""
    finally:
        proxy.observed_daemon = real  # type: ignore[assignment]
        proxy._adopted.clear()
    print("  a recovered key is bound to the port it was read from: PASS")


def test_the_daemon_probe_cannot_match_itself() -> None:
    """The `[z]aproxy` lesson, statically enforced on a grep instead of a pkill.

    The probe's own command line is visible in /proc while it runs. An unbracketed `api.key=`
    would match the probe itself and return a fragment of this module's source as a credential.
    `pkill -f` has now been wrong in BOTH directions in this repo; this locks the shape.
    """
    assert "api.key=" not in proxy._DAEMON_PROBE, (
        "the daemon probe contains a literal 'api.key=' and will match its own /proc entry"
    )
    assert "api[.]key=" in proxy._DAEMON_PROBE, (
        "the bracketed self-match guard is gone from the daemon probe"
    )
    # The guard has to survive the VALUE extraction too. `${K#api.key=}` is the obvious way to
    # strip the prefix and it puts the literal straight back; the first run of this test caught
    # exactly that, which is the only reason the property is written down rather than assumed.
    assert "${K#*=}" in proxy._DAEMON_PROBE, (
        "the probe strips the prefix by naming it, reintroducing the literal the guard removed"
    )
    print("  the daemon probe cannot match its own command line: PASS")


def test_the_api_reader_survives_bytes_the_local_codec_cannot_decode() -> None:
    """A capture is arbitrary bytes from arbitrary sites; the reader must not depend on the
    operator's locale.

    `text=True` decodes with the AMBIENT codec — cp1252 on a Windows host — so one byte outside
    that codepage raised UnicodeDecodeError in subprocess's reader thread and left `stdout` as
    None. It was invisible because `history()` catches the downstream error and returns `[]`:
    a real capture read as no capture, on every Windows machine, for as long as the code existed.
    Found only when build #17's key recovery let a read reach real bodies for the first time.
    """
    import subprocess as sp

    real = proxy.subprocess.run
    seen: dict = {}

    def fake(argv, **kw):
        seen.update(kw)
        # 0x8f is undefined in cp1252 and is not valid UTF-8 either — the exact shape that broke
        return sp.CompletedProcess(argv, 0, stdout=b'{"v":"\x8f\xff ok"}', stderr=b"")

    try:
        proxy.subprocess.run = fake  # type: ignore[assignment]
        got = proxy._api_get("c", 8090, "/JSON/core/view/version/")
        assert isinstance(got, str), f"the reader returned {type(got).__name__}, not str"
        assert "ok" in got, f"the readable part of the body was lost: {got!r}"
        assert seen.get("text") is not True, (
            "_api_get is decoding with the ambient locale codec again — a capture containing "
            "one byte outside it will read as no capture"
        )

        # and stdout=None (what the decode failure actually produced) must not raise
        proxy.subprocess.run = lambda argv, **kw: sp.CompletedProcess(  # type: ignore[assignment]
            argv, 0, stdout=None, stderr=b"")
        assert proxy._api_get("c", 8090, "/JSON/core/view/version/") == ""
    finally:
        proxy.subprocess.run = real  # type: ignore[assignment]
    print("  the API reader survives bytes the local codec cannot decode: PASS")


def test_history_reads_the_NEWEST_window_not_the_oldest() -> None:
    """"Recent captured exchanges" must actually be recent.

    ZAP's `start` counts from the beginning of history, and this used to pass the caller's
    `start` through unchanged — defaulting to 0. Measured on a daemon holding 1,296 exchanges,
    `start=0` returned requests from hours earlier while the traffic under inspection sat at the
    tail. The `:proxy` panel passes no `start`, so it showed the first 50 requests that daemon
    ever recorded, permanently.

    THE KNOCK-ON IS WHY THIS IS A SAFETY TEST AND NOT A UI ONE: `session_health` reads
    `history(count=200)` to notice a scan's traffic coming back login-shaped. Judging the OLDEST
    200 exchanges it was looking at the moment the session was established, so it could never
    detect a session expiring mid-scan — build #16's guard against a silent wrong answer,
    silently unable to fire.
    """
    asked: dict = {}

    def fake_api_get(container, port, path, timeout=10):
        asked["path"] = path
        return '{"messages": []}'

    real_get, real_count = proxy._api_get, proxy.captured_count
    try:
        proxy.captured_count = lambda c, p: 1000  # type: ignore[assignment]
        proxy._api_get = fake_api_get  # type: ignore[assignment]

        proxy.history("c", 8090, start=0, count=50)
        assert "start=950" in asked["path"] and "count=50" in asked["path"], (
            f"history(count=50) asked ZAP for {asked['path']!r} — that is the OLDEST window, "
            "so the panel shows the first requests ever captured and session_health judges the "
            "moment the session began"
        )

        # paging still works, one window further back
        proxy.history("c", 8090, start=50, count=50)
        assert "start=900" in asked["path"], asked["path"]

        # and a history shorter than the window must not ask for a negative start
        proxy.captured_count = lambda c, p: 10  # type: ignore[assignment]
        proxy.history("c", 8090, start=0, count=50)
        assert "start=0" in asked["path"] and "count=10" in asked["path"], asked["path"]

        # asking past the end returns nothing rather than wrapping round to the oldest
        assert proxy.history("c", 8090, start=999, count=50) == []
    finally:
        proxy._api_get, proxy.captured_count = real_get, real_count  # type: ignore[assignment]
    print("  history returns the NEWEST window, and pages backwards from it: PASS")


def test_an_orphaned_daemon_blocks_a_new_proxy_and_says_why() -> None:
    """clash_refusal used to protect against a state it could not observe.

    `_models` is in-process, so after a backend restart the check saw nothing and would let a
    second daemon spawn — which dies on ZAP's home-directory lock while the port stays bound by
    the first. PURE, so the observation is injected: this is exactly the function whose test
    once reached for Docker, passed locally and failed in CI.
    """
    with proxy._lock:
        proxy._models.clear()
    # unchanged behaviour: nothing known, nothing observed -> no refusal
    assert proxy.clash_refusal("c", 8090) is None
    assert proxy.clash_refusal("c", 8090, observed_port=None) is None

    refused = proxy.clash_refusal("c", 8090, observed_port=8090)
    assert refused is not None, (
        "a daemon is running in the container and a second start was still permitted"
    )
    assert refused.gate == "limit", refused.gate
    reason = refused.reason.lower()
    assert "home directory" in reason, (
        "the refusal does not state ZAP's actual reason, so the operator sees a proxy that "
        f"will not start and no explanation: {refused.reason!r}"
    )
    assert "restart" in reason or "other than this backend" in reason, (
        f"the refusal does not say WHY there is no proxy to stop in the UI: {refused.reason!r}"
    )
    # the gated start must actually observe, or the argument above is decorative
    import inspect

    src = inspect.getsource(proxy.start_proxy)
    assert "observed_daemon" in src and "observed_port" in src, (
        "start_proxy no longer passes an observation to clash_refusal — the check is blind again"
    )
    print("  an orphaned daemon is refused, with ZAP's reason and the restart context: PASS")


if __name__ == "__main__":
    test_a_recovered_key_is_never_sent_to_a_different_port()
    test_the_daemon_probe_cannot_match_itself()
    test_the_api_reader_survives_bytes_the_local_codec_cannot_decode()
    test_history_reads_the_NEWEST_window_not_the_oldest()
    test_an_orphaned_daemon_blocks_a_new_proxy_and_says_why()
    test_an_unapproved_start_is_refused_with_a_control()
    test_the_red_confirm_is_required()
    test_the_gated_argv_is_the_spawned_argv()
    test_the_daemon_binds_loopback_unless_publish_was_asked_for()
    test_publishing_is_engagement_only()
    test_the_api_key_is_enforced_and_never_reaches_a_record()
    test_the_key_is_different_on_two_consecutive_starts()
    test_both_modes_are_reachable()
    test_the_lab_surface_declares_the_lab_and_nothing_else()
    test_the_daemon_gets_no_stdin_writer()
    test_a_refused_start_spawns_nothing()
    test_stopping_is_not_gated()
    test_the_proxy_flag_is_per_tool_and_never_silent()
    test_the_rewrite_cancels_a_prevalidated_verdict()
    test_a_request_that_did_not_ask_is_untouched()
    test_every_crawl_gate_fires_each_with_a_control()
    test_the_crawl_confirm_states_the_BROWSER_hazard_not_the_scanner_s()
    test_the_scoped_host_is_the_crawled_host()
    test_a_target_cannot_smuggle_a_crawl_parameter()
    test_depth_and_duration_are_in_the_approved_surface()
    test_the_crawl_surface_does_not_claim_two_modes()
    test_stopping_a_crawl_is_not_gated()
    test_a_refused_crawl_launches_no_browser()
    test_the_browser_id_is_read_back_not_trusted()
    test_the_container_follows_the_mode()
    print("ALL ZAP proxy gating locks pass")
