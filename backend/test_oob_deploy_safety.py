"""Build #13 part 3 — SAFETY invariants for the canary deploy (spec §3.5, §4).

Shipping `oob/server.py` to a VPS and starting it is a THIRD remote-execution transport, after
docker exec and WinRM. Part 2 of this same build already made the mistake this file exists to
prevent: `deliver` grew its own WinRM call, reached around the gated execution point, and a
whole-tree guard caught it. Joining that guard's allow-list would have been the wrong fix, and
the right one — move the capability to the executor — is what is locked here.

Four invariants, each with a positive control (backend/AGENTS.md §3):

  1. **THE DEPLOY TAKES NO DESTINATION.** Not a defaulted host, not an optional one, not a
     target object. Asserted over the AST of the real signature, because this is the entire
     containment argument: there is no way to EXPRESS "deploy somewhere else", so no request
     field, no agent proposal and no future refactor can redirect it. A comment claiming this
     would be worth nothing; the parameter list is the claim.

  2. **NOTHING REACHES IT BUT THE EXECUTOR AND ITS ROUTE.** No orchestrator, no agent, no loop,
     no reasoning module. Same whole-tree scan the `:kali`, tunnel, Sliver and WinRM locks use.

  3. **APPROVAL IS THE GATE, AND A REFUSAL SENDS NOTHING.** This starts a listener on the
     public internet. A refusal that had already shipped the file would be a refusal in name.

  4. **THE READ SECRET NEVER TOUCHES AN ARGV OR A RECORD.** It travels on stdin into a 0700
     file, because a command line is world-readable in `ps` on a multi-user box — and the
     returned record is serialised straight to the browser.

Hermetic: the ssh transport is stubbed, so not one connection is attempted.

Run: python test_oob_deploy_safety.py
"""

from __future__ import annotations

import ast
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from test_support import scans  # noqa: E402

from cockpit import executor  # noqa: E402
from oob import config as oob_config  # noqa: E402

# SCRATCH STORE — see test_oob_poll.py for why. This file in particular SAVES a canary pointed
# at a documentation-range address; doing that to the real store would silently repoint a live
# canary's deploy target.
_SCRATCH = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
oob_config.DB_PATH = Path(_SCRATCH.name) / "oob-test.db"

BACKEND = Path(__file__).resolve().parent
EXECUTOR_PATH = BACKEND / "cockpit" / "executor.py"

HOST = "203.0.113.10"
ZONE = "oob.example.net"
SECRET = "canary-read-secret-0123456789"

# Only these two may reach the deploy. The executor DEFINES it (it is the gated execution
# point); the canary's own route CALLS it and passes nothing but the approval flag.
_ALLOWED = {"cockpit/executor.py", "oob/router.py"}
_PATTERNS = [r"\bdeploy_oob_canary\b", r"\b_ssh_argv\b"]
_AST_TARGETS = ["deploy_oob_canary"]


def _configured() -> None:
    oob_config.init_db()
    oob_config.save(zone=ZONE, host=HOST, read_secret=SECRET, ssh_key_path="/home/op/.ssh/id_ed25519")


def _capture() -> tuple[list[dict], callable]:
    """Replace the ssh transport with a recorder. Returns (calls, restore)."""
    calls: list[dict] = []
    original = executor._ssh

    def _fake(target, remote_command, stdin=b""):
        calls.append({
            "argv": executor._ssh_argv(target, remote_command),
            "remote_command": remote_command,
            "stdin": stdin,
        })
        return {"exit_code": 0, "stdout": "ok", "stderr": ""}

    executor._ssh = _fake  # type: ignore[assignment]
    return calls, (lambda: setattr(executor, "_ssh", original))


# --------------------------------------------------------------------------- #
# 1. the deploy takes no destination
# --------------------------------------------------------------------------- #
def _params(tree: ast.AST, name: str) -> list[str]:
    fn = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name),
        None,
    )
    assert fn is not None, f"{name}() not found — the lock below would be vacuous"
    a = fn.args
    names = [p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return names


_DESTINATION_WORDS = (
    "host", "addr", "ip", "url", "user", "port", "key", "target", "dest", "server",
    "path", "file", "script", "content", "payload", "zone",
)


def test_the_deploy_signature_carries_no_destination() -> None:
    """THE containment claim, asserted on the parameter list rather than on a docstring."""
    tree = ast.parse(EXECUTOR_PATH.read_text(encoding="utf-8"))
    params = _params(tree, "deploy_oob_canary")
    assert params == ["approved", "restart"], (
        f"deploy_oob_canary{tuple(params)} — it must take an approval and a restart flag and "
        f"NOTHING else; anything addressable here is a request field one refactor later"
    )
    offending = [p for p in params if any(w in p.lower() for w in _DESTINATION_WORDS)]
    assert not offending, f"deploy_oob_canary takes destination-shaped parameters: {offending}"

    # The other half: the resolver it uses takes no arguments either, so there is nowhere in
    # the chain to express a different destination.
    config_tree = ast.parse((BACKEND / "oob" / "config.py").read_text(encoding="utf-8"))
    assert _params(config_tree, "deploy_target") == [], (
        "oob.config.deploy_target() grew a parameter — the destination is addressable again"
    )

    # POSITIVE CONTROL — the same predicate must flag a planted destination parameter.
    planted = ast.parse("def deploy_oob_canary(*, approved, host='1.2.3.4'):\n    pass\n")
    planted_params = _params(planted, "deploy_oob_canary")
    assert [p for p in planted_params if any(w in p.lower() for w in _DESTINATION_WORDS)], (
        "the signature check cannot fail — it would pass on a deploy that takes a host"
    )
    print("  deploy_oob_canary(approved, restart) takes no destination; resolver takes none: PASS")


# --------------------------------------------------------------------------- #
# 2. nothing reaches it but the executor and its route
# --------------------------------------------------------------------------- #
def test_no_agent_orchestrator_or_loop_can_reach_the_deploy() -> None:
    result = scans.scan_source_tree(
        patterns=_PATTERNS, allowed=_ALLOWED, ast_targets=_AST_TARGETS,
    )
    scans.assert_clean(
        result,
        what="the canary deploy (a remote-execution path) is reachable from a non-gated module",
        must_have_scanned=[
            "orchestrator.py", "adgraph/orchestrator.py", "cockpit/session.py",
            "reasoning/specialists.py", "reasoning/frontier.py", "evasion/engine.py",
            "cockpit/router.py", "cockpit/kali.py", "chat.py",
        ],
        min_checked=60,
    )
    print(f"  {len(result.checked)} modules scanned; only {sorted(_ALLOWED)} reach the "
          "deploy: PASS")


def test_the_deploy_scan_can_fail() -> None:
    """Plant the violation in a literal orchestrator module the old narrow globs never opened."""
    scans.assert_catches_a_planted_violation(
        plant="from cockpit.executor import deploy_oob_canary",
        patterns=_PATTERNS, allowed=_ALLOWED, ast_targets=_AST_TARGETS,
    )
    print("  a planted deploy import in adgraph/orchestrator.py is CAUGHT: PASS")


# --------------------------------------------------------------------------- #
# 3. approval is the gate, and a refusal sends nothing
# --------------------------------------------------------------------------- #
def test_an_unapproved_deploy_is_refused_and_sends_nothing() -> None:
    """A refusal that had already shipped the file would be a refusal in name only."""
    _configured()
    calls, restore = _capture()
    try:
        try:
            executor.deploy_oob_canary(approved=False)
        except executor.OOBDeployRefused as exc:
            assert exc.gate == "approval", exc.gate
        else:
            raise AssertionError("an unapproved deploy was allowed to run")
        assert calls == [], f"{len(calls)} remote command(s) were sent by a REFUSED deploy"
    finally:
        restore()
    oob_config.clear()
    print("  an unapproved deploy is refused at the approval gate and sends nothing: PASS")


def test_a_deploy_with_no_canary_configured_is_refused() -> None:
    oob_config.init_db()
    oob_config.clear()
    calls, restore = _capture()
    try:
        try:
            executor.deploy_oob_canary(approved=True)
        except executor.OOBDeployRefused as exc:
            assert exc.gate == "oob", exc.gate
        else:
            raise AssertionError("a deploy ran with no canary configured")
        assert calls == [], "an unconfigured deploy still sent something"
    finally:
        restore()
    print("  a deploy with no configured canary is refused and sends nothing: PASS")


def test_an_approved_deploy_goes_only_to_the_stored_host() -> None:
    _configured()
    calls, restore = _capture()
    try:
        result = executor.deploy_oob_canary(approved=True)
    finally:
        restore()

    assert result["ok"] is True, result
    assert len(calls) == 3, [c["remote_command"][:40] for c in calls]
    for call in calls:
        argv = call["argv"]
        assert argv[0] == "ssh", argv
        assert f"root@{HOST}" in argv, f"the deploy did not address the stored host: {argv}"
        # Nothing else host-shaped may appear anywhere in the argv.
        for element in argv:
            assert "@" not in element or element == f"root@{HOST}", element
    oob_config.clear()
    print(f"  all {len(calls)} deploy steps address root@{HOST} — the stored host: PASS")


# --------------------------------------------------------------------------- #
# 4. the secret never touches an argv or a record
# --------------------------------------------------------------------------- #
def test_the_read_secret_never_appears_in_an_argv_or_the_returned_record() -> None:
    """`ps` is world-readable on a multi-user box, and the record is serialised to the browser."""
    _configured()
    calls, restore = _capture()
    try:
        result = executor.deploy_oob_canary(approved=True)
    finally:
        restore()

    for call in calls:
        assert SECRET not in " ".join(call["argv"]), (
            f"the read secret is on the ssh command line: {call['argv']}"
        )
        assert SECRET not in call["remote_command"], (
            f"the read secret is in the remote command, visible in `ps` on the VPS: "
            f"{call['remote_command']}"
        )
    # It IS sent — on stdin, into a 0700 file. A test that only checked absence would pass on
    # a deploy that never shipped the secret at all, which would leave a canary that refuses
    # to start.
    carried = [c for c in calls if SECRET in c["stdin"].decode("utf-8", "replace")]
    assert len(carried) == 1, (
        f"{len(carried)} steps carry the secret on stdin; exactly one (the launcher) must"
    )
    assert "chmod 0700" in carried[0]["remote_command"], (
        f"the file holding the secret is not written 0700: {carried[0]['remote_command']}"
    )
    assert SECRET not in str(result), "the returned record carries the read secret"
    assert result["target"]["host"] == HOST, result["target"]
    oob_config.clear()
    print("  the secret rides stdin into a 0700 file — never an argv, never the record: PASS")


# --------------------------------------------------------------------------- #
# nothing unvalidated reaches the remote shell
# --------------------------------------------------------------------------- #
def test_the_config_refuses_values_that_could_break_out_of_the_remote_command() -> None:
    """The remote side runs the command through `sh` — that is what SSH does.

    Every value interpolated into it comes from the config store, so the store is where the
    character allow-list has to hold. Checked with the shapes that would actually break out.
    """
    oob_config.init_db()
    hostile_hosts = [
        "1.2.3.4; rm -rf /", "$(curl evil)", "`id`", "a b", "host\nnewline", "a'b", 'a"b',
        "a|b", "a&b", "a>b",
    ]
    for host in hostile_hosts:
        try:
            oob_config.save(zone=ZONE, host=host, read_secret=SECRET)
        except oob_config.ConfigError:
            continue
        oob_config.clear()
        raise AssertionError(f"the config store accepted host={host!r}")

    hostile_zones = ["a b.net", "x;y.net", "single", "$(id).net", "a`b`.net", ""]
    for zone in hostile_zones:
        try:
            oob_config.save(zone=zone, host=HOST, read_secret=SECRET)
        except oob_config.ConfigError:
            continue
        oob_config.clear()
        raise AssertionError(f"the config store accepted zone={zone!r}")

    for key_path in ("/k;rm -rf /", "/k`id`", "/k$(id)", "/k|x", "/k&x"):
        try:
            oob_config.save(zone=ZONE, host=HOST, read_secret=SECRET, ssh_key_path=key_path)
        except oob_config.ConfigError:
            continue
        oob_config.clear()
        raise AssertionError(f"the config store accepted ssh_key_path={key_path!r}")

    # ...and a trivially short secret is refused here too, matching the deployable's own floor,
    # so it fails when it is typed rather than on the first deploy.
    try:
        oob_config.save(zone=ZONE, host=HOST, read_secret="short")
    except oob_config.ConfigError:
        pass
    else:
        oob_config.clear()
        raise AssertionError("a 5-character read secret was accepted for an internet-facing API")

    oob_config.clear()
    print(f"  {len(hostile_hosts)} hostile hosts, {len(hostile_zones)} zones, 5 key paths and "
          "a weak secret all refused: PASS")


def test_every_interpolated_value_reaches_the_remote_command_quoted() -> None:
    """A belt-and-suspenders over the allow-list above: even a value that somehow got stored
    is single-quoted at the point of use, so it is one shell word."""
    _configured()
    calls, restore = _capture()
    try:
        executor.deploy_oob_canary(approved=True)
    finally:
        restore()
    for call in calls:
        assert f"'{oob_config.REMOTE_DIR}'" in call["remote_command"], call["remote_command"]
    launcher = next(c for c in calls if SECRET in c["stdin"].decode())
    script = launcher["stdin"].decode()
    for value in (SECRET, ZONE, HOST, oob_config.REMOTE_DIR):
        assert f"'{value}'" in script, f"{value!r} is unquoted in the launcher:\n{script}"
    oob_config.clear()
    print("  every interpolated value is single-quoted in the remote command and launcher: PASS")


if __name__ == "__main__":
    print("== OOB canary deploy SAFETY invariants (spec §3.5, §4) ==")
    test_the_deploy_signature_carries_no_destination()
    test_no_agent_orchestrator_or_loop_can_reach_the_deploy()
    test_the_deploy_scan_can_fail()
    test_an_unapproved_deploy_is_refused_and_sends_nothing()
    test_a_deploy_with_no_canary_configured_is_refused()
    test_an_approved_deploy_goes_only_to_the_stored_host()
    test_the_read_secret_never_appears_in_an_argv_or_the_returned_record()
    test_the_config_refuses_values_that_could_break_out_of_the_remote_command()
    test_every_interpolated_value_reaches_the_remote_command_quoted()
    print("ALL OOB deploy safety invariants hold")
