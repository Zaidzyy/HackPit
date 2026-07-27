"""One hermetic shim for the three listener lifecycles, so they cannot drift apart.

``cockpit/sliver.py``, ``cockpit/tunnels.py`` and ``cockpit/obfuscation.py`` all spawn their
server through ``cockpit.lifecycle``. Before build #7 each suite faked its OWN module's
``subprocess.Popen``, which meant three slightly different fakes pinning three slightly
different ideas of what a start does — exactly the drift that let ``status="listening"`` be
asserted by all three while being false in two of them.

This shim fakes the ONE place the spawn now lives, and it fakes it in a way that keeps the real
code under test: ``lifecycle.spawn_watched``, ``lifecycle.observe``, the status derivation and
every refusal path still run for real. Only three things are replaced —

    lifecycle.subprocess.Popen  -> a fake process (captures argv, controllable liveness)
    lifecycle.port_is_bound     -> a canned probe verdict (no docker, no `ss`)
    lifecycle.SETTLE_SECONDS    -> 0, so a suite does not sleep 3s per start

— and each is a knob a test can turn to prove the guard can fail: ``alive=False`` reproduces the
dead-console bug, ``bound=False``/``None`` reproduces an unconfirmed bind.
"""

from __future__ import annotations

import types

from cockpit import lifecycle


class FakeListenerSpawn:
    """Context manager: hermetic ``lifecycle`` spawn + probe, with the outcome under test control.

    ``alive``  — does the spawned process survive the settle window? False reproduces the
                 console-binary-dies-on-EOF defect this build fixed.
    ``bound``  — what the port probe reports: True / False / None (probe could not run).
    ``exit_code`` — what a dead process exited with.
    """

    def __init__(self, *, alive: bool = True, bound: bool | None = True, exit_code: int = 0):
        self.alive = alive
        self.bound = bound
        self.exit_code = exit_code
        self.argv: list[str] | None = None
        self.child_stdin = None
        self.killed = False
        # Every spawn, not just the last: a test that asserts "this call spawned nothing extra"
        # needs the count, and one that asserts on the argv needs the most recent.
        self.spawns: list[list[str]] = []
        self.procs: list = []
        # Every `docker exec … pkill` a stop issued to reap the container-side server.
        self.reaped: list[list[str]] = []
        self._orig: tuple = ()

    def __enter__(self) -> "FakeListenerSpawn":
        self._orig = (lifecycle.subprocess.Popen, lifecycle.port_is_bound,
                      lifecycle.SETTLE_SECONDS, lifecycle.subprocess.run)

        spy = self

        def fake_popen(argv, **kwargs):
            spy.argv = list(argv)
            spy.spawns.append(list(argv))
            spy.child_stdin = kwargs.get("stdin")

            def _kill():
                spy.killed = True

            proc = types.SimpleNamespace(
                # A real Popen given a raw fd for stdin exposes stdin=None; the fake must too,
                # or the "no writer object exists" assertion would be testing the fake.
                stdin=None, stdout=None, stderr=None,
                poll=lambda: None if spy.alive else spy.exit_code,
                kill=_kill,
            )
            spy.procs.append(proc)
            return proc

        # WHAT subprocess.run WAS WHEN WE ARRIVED, and why this delegates instead of replacing.
        # `lifecycle.subprocess` and `sliver.subprocess` are THE SAME MODULE OBJECT, so assigning
        # `lifecycle.subprocess.run` replaces it for every module in the process — including a
        # suite's own fake that was installed moments earlier. Blanket-replacing it swallowed the
        # Sliver implant build's `subprocess.run` and made `run_argv` None, which read as "the
        # build never ran". So this intercepts ONLY the reap and hands everything else back.
        prior_run = lifecycle.subprocess.run

        def fake_run(argv, **kwargs):
            # A stop reaps the server INSIDE the container (`docker exec … pkill -f <argv>`),
            # because killing the `docker exec` client does not stop what it started. Recorded
            # rather than swallowed so a test can assert the reap happened AND that it targeted
            # this listener's own argv instead of every process of the same kind.
            if "pkill" in list(argv):
                spy.reaped.append(list(argv))
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            return prior_run(argv, **kwargs)

        lifecycle.subprocess.Popen = fake_popen
        lifecycle.subprocess.run = fake_run
        lifecycle.port_is_bound = lambda container, port, proto: spy.bound
        lifecycle.SETTLE_SECONDS = 0.0
        return self

    def __exit__(self, *exc):
        (lifecycle.subprocess.Popen, lifecycle.port_is_bound, lifecycle.SETTLE_SECONDS,
         lifecycle.subprocess.run) = self._orig
        return False

    @property
    def reap_patterns(self) -> list[str]:
        """The `pkill -f <pattern>` patterns a stop used — one per reaped listener."""
        return [a[-1] for a in self.reaped if "pkill" in a]

    # -- convenience assertions the suites share -------------------------------------- #
    @property
    def spawned(self) -> bool:
        """Did anything actually spawn? A refused start must leave this False."""
        return self.argv is not None

    def container_argv(self) -> list[str]:
        """The tokens after the `docker exec [-i] <container>` prefix."""
        argv = list(self.argv or [])
        i = 3 if len(argv) > 2 and argv[2] == "-i" else 2
        return argv[i + 1:]

    @property
    def interactive(self) -> bool:
        """Was the container process given a forwarded stdin (`docker exec -i`)?"""
        return bool(self.argv) and self.argv[2:3] == ["-i"]
