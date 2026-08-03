"""ZAP proxy gating locks.  Run:  python test_zap_proxy_safety.py

THE INVARIANT: a proxy start passes the real executor gates, and the argv the gate classified is
the argv that gets spawned.
"""

from __future__ import annotations

from cockpit import proxy


def _req(**kw):
    base = dict(approved=True, dangerous_ack=True, engagement_id=None)
    base.update(kw)
    return proxy.ProxyStartRequest(**base)


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
    argv = proxy.server_argv_for(req)
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


def test_the_daemon_binds_loopback_only() -> None:
    """THE ISOLATION PROPERTY. `-host 127.0.0.1` is what keeps the API unreachable from the host.
    A change to 0.0.0.0 would publish nothing by itself, but it removes the last thing standing
    between a published port and an ungated control channel."""
    argv = proxy.server_argv_for(_req())
    joined = " ".join(argv)
    assert "-host 127.0.0.1" in joined, f"the daemon does not bind loopback: {joined}"
    for bad in ("0.0.0.0", "api.addrs.addr.name=.*"):
        assert bad not in joined, f"the argv opens the API beyond loopback: {bad!r} in {joined}"
    print("  the daemon binds 127.0.0.1 only: PASS")


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
    argv = " ".join(proxy.server_argv_for(_req()))
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


def test_the_container_follows_the_mode() -> None:
    """Lab runs in the isolated sandbox; an engagement run in the open one. Picking the wrong
    container would either put a real-target proxy in the egress-less box (it would capture
    nothing) or put a lab proxy in the fully-open one (it would have reach it must not have)."""
    from cockpit import config

    assert proxy.container_for(_req(engagement_id=None)) == config.SANDBOX_CONTAINER
    assert proxy.container_for(_req(engagement_id="e1")) == config.ENGAGE_SANDBOX_CONTAINER
    print("  lab -> isolated sandbox, engagement -> engage sandbox: PASS")


if __name__ == "__main__":
    test_an_unapproved_start_is_refused_with_a_control()
    test_the_red_confirm_is_required()
    test_the_gated_argv_is_the_spawned_argv()
    test_the_daemon_binds_loopback_only()
    test_both_modes_are_reachable()
    test_the_lab_surface_declares_the_lab_and_nothing_else()
    test_the_daemon_gets_no_stdin_writer()
    test_a_refused_start_spawns_nothing()
    test_stopping_is_not_gated()
    test_the_container_follows_the_mode()
    print("ALL ZAP proxy gating locks pass")
