"""Proof-harness HONESTY lock — an unfilled offensive slot can never become a fake pass.

The four build #10 C2/AD proof scripts (docker/proof/c2_0{1..4}_*.sh) deliberately ship with
their offensive commands UNFILLED. Each holds them in a `[[PASTE]]` shell variable the
operator fills by hand; the harness writes that variable to a scratch file and hands the
driver a FILE PATH, so no offensive string ever lives in the repo. While a slot is empty the
proof must report **NOT-RUN** — never PASS, never silently nothing.

That is the single claim the whole build #10 proof story rests on. Every proof result Zaid
reads is only worth something if "not demonstrated" is distinguishable from "demonstrated
fine", and the failure mode is silent in both directions: a harness that scored an empty
paste as PASS would look exactly like a harness that worked. So it is locked here rather
than trusted.

This test caught a real one. c2_01's two slots and c2_04's DCSync slot did not ship empty —
they held a self-referential shell fragment (`echo $(cat …| grep …| cut …)`) left over from
an earlier placeholder sweep. That text is not a comment, so `_read_paste` returned it as
LIVE content, the empty-guard never fired, and the driver would have sent it to the domain
controller as PowerShell and scored the exit code as a genuine attempt. An unfilled proof
was one WinRM round-trip away from reporting FAIL-or-PASS instead of NOT-RUN. Locked below
by test_shipped_slots_are_unfilled.

Four independent angles, because each alone has a blind spot:

  1. READER      — `_read_paste` treats empty / whitespace / comment-only as unfilled.
  2. BEHAVIOUR   — driving the real subcommands with an empty paste emits NOTRUN, emits no
                   PASS, and never reaches the WinRM transport at all.
  3. STRUCTURE   — every `_read_paste` call site in the driver is followed by an empty-guard
                   that reports NOTRUN and returns. Catches a NEW slot added without a guard.
  4. SHIPPED     — the slots in the four scripts as committed really are unfilled.

Hermetic: no VM, no network, no pywinrm, no Docker. The transport is monkeypatched with a
tripwire, so "nothing executed" is asserted rather than assumed. Run: python test_proof_honesty.py
"""
from __future__ import annotations

import ast
import io
import re
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
PROOF = BACKEND.parent / "docker" / "proof"
DRIVER_PATH = PROOF / "c2_winrm_driver.py"

sys.path.insert(0, str(PROOF))
import c2_winrm_driver as D  # noqa: E402

# The scripts whose slots must be unfilled, and the slot variables in each.
SHIPPED_SLOTS = {
    "c2_01_dc_prereq_stage.sh": ["IODINE_STAGE_CMD", "TAP_INSTALL_CMD"],
    "c2_02_iodine_tunnel.sh": ["IODINE_CLIENT_CMD"],
    "c2_03_sliver_beacon.sh": ["IODINE_CLIENT_CMD", "SLIVER_IMPLANT_GEN", "SLIVER_IMPLANT_RUN"],
    "c2_04_dcsync_defender_excl.sh": ["DCSYNC_CMD"],
}


def _write(text: str) -> str:
    """Write paste content to a scratch file exactly the way c2_lib.sh's paste_file does."""
    fh = tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8")
    fh.write(text)
    fh.close()
    return fh.name


# --------------------------------------------------------------------------- #
# 1. THE READER: what counts as "unfilled".
# --------------------------------------------------------------------------- #


def test_reader_treats_placeholders_as_unfilled() -> None:
    """Empty / whitespace / comment-only content reads back falsy — i.e. NOT filled."""
    unfilled = {
        "empty file": "",
        "whitespace only": "   \n\t\n  \n",
        "a single comment": "# [[PASTE: the thing you have to fill in]]\n",
        "the real template block": (
            "\n"
            "# [[PASTE: the exact command that materialises the client binary on the DC at\n"
            "#          C:\\hackpit\\iodine\\iodine.exe. MUST be idempotent.]]\n"
        ),
        "comments with blank lines between": "\n# one\n\n#   two\n\n\n#\tthree\n\n",
        "indented comments": "    # leading whitespace then a comment\n\t# and a tabbed one\n",
    }
    for label, text in unfilled.items():
        got = D._read_paste(_write(text))
        assert got == "", f"{label!r} must read as UNFILLED, got {got!r}"

    # ...and a genuinely filled slot must still read through, or the guard would block real use.
    filled = D._read_paste(_write("# explain\nGet-Item C:\\hackpit\\note.txt\n"))
    assert filled == "Get-Item C:\\hackpit\\note.txt", filled

    # A filled slot keeps its live lines and drops only the commentary around them.
    mixed = D._read_paste(_write("# why\nGet-Date\n\n# more\nGet-Location\n"))
    assert mixed == "Get-Date\nGet-Location", mixed
    print("  an empty / whitespace / comment-only slot reads as UNFILLED: PASS")


# --------------------------------------------------------------------------- #
# 2. BEHAVIOUR: the real subcommands, driven with an empty slot.
# --------------------------------------------------------------------------- #


class _Tripwire:
    """Replaces the WinRM transport. Firing it at all is the failure."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __call__(self, *a, **kw):
        self.calls.append((a, kw))
        raise AssertionError(
            "the harness reached the WinRM transport with an UNFILLED paste — "
            "an empty slot must stop before anything is sent to the DC"
        )


def _drive(fn, *args) -> str:
    """Run a driver subcommand with the transport tripwired; return its RESULT protocol output."""
    trip = _Tripwire()
    orig_gated, orig_secret = D._winrm_gated, D.winprofiles.get_secret
    D._winrm_gated = trip
    D.winprofiles.get_secret = lambda _pid: ""
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            fn(*args)
        out = buf.getvalue()
    finally:
        D._winrm_gated, D.winprofiles.get_secret = orig_gated, orig_secret
    assert not trip.calls, "nothing may be sent to the DC for an unfilled paste"
    return out


def test_empty_slot_reports_notrun_and_never_passes() -> None:
    """The behaviour that matters: NOTRUN out, no PASS, and the DC never touched."""
    for label, fn, args in [
        ("winrm-run", D.cmd_winrm_run, ("win-test", "sess", "1", "stage.iodine")),
        ("winrm-probe", D.cmd_winrm_probe, ("win-test", "sess", "probe.tap")),
        ("dcsync", D.cmd_winrm_dcsync, ("win-test", "sess")),
    ]:
        for content in ("", "   \n", "# [[PASTE: fill me in]]\n"):
            out = _drive(fn, *args, _write(content))
            results = [l for l in out.splitlines() if l.startswith("RESULT ")]
            assert results, f"{label} must REPORT an unfilled slot, printed nothing: {out!r}"
            assert all(" NOTRUN " in r for r in results), (
                f"{label} with an unfilled slot must report only NOTRUN, got: {results}"
            )
            assert " PASS " not in out and " FAIL " not in out, (
                f"{label} scored an unfilled slot as PASS/FAIL — that is a fake result: {out!r}"
            )
    print("  an unfilled slot reports NOTRUN, never PASS, and never reaches the DC: PASS")


# --------------------------------------------------------------------------- #
# 3. STRUCTURE: every slot reader is guarded. Catches a NEW slot added unguarded.
# --------------------------------------------------------------------------- #


def _guard_reports_notrun_and_returns(node: ast.If, var: str) -> bool:
    """True if `node` is `if not <var>:` whose body reports NOTRUN and returns."""
    test = node.test
    if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)):
        return False
    if not (isinstance(test.operand, ast.Name) and test.operand.id == var):
        return False
    says_notrun = any(
        isinstance(n, ast.Constant) and n.value == "NOTRUN" for n in ast.walk(node)
    )
    returns = any(isinstance(n, (ast.Return, ast.Raise)) for n in ast.walk(node))
    return says_notrun and returns


def test_every_slot_reader_is_guarded() -> None:
    """Structural lock: no `x = _read_paste(...)` without an immediate NOTRUN empty-guard.

    The behavioural test above only covers the slots that exist today. This one fails when a
    FIFTH paste point is added to the driver without a guard — which is exactly how an
    unfilled proof would quietly regain the ability to fake a pass.
    """
    tree = ast.parse(DRIVER_PATH.read_text(encoding="utf-8"))
    found = 0
    for parent in ast.walk(tree):
        body = getattr(parent, "body", None)
        if not isinstance(body, list):
            continue
        for i, stmt in enumerate(body):
            if not (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)):
                continue
            fn = stmt.value.func
            if not (isinstance(fn, ast.Name) and fn.id == "_read_paste"):
                continue
            assert len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name), (
                f"line {stmt.lineno}: a _read_paste result must land in a plain name so the "
                f"guard below can be verified"
            )
            var = stmt.targets[0].id
            nxt = body[i + 1] if i + 1 < len(body) else None
            assert isinstance(nxt, ast.If) and _guard_reports_notrun_and_returns(nxt, var), (
                f"{DRIVER_PATH.name}:{stmt.lineno}: `{var} = _read_paste(...)` is not "
                f"immediately followed by `if not {var}:` reporting NOTRUN and returning. An "
                f"unguarded slot lets an UNFILLED proof run something and be scored."
            )
            found += 1
    assert found >= 4, f"expected the driver's paste points to be found, saw {found}"
    print(f"  all {found} driver slot-readers are followed by a NOTRUN empty-guard: PASS")


# --------------------------------------------------------------------------- #
# 4. SHIPPED: the committed scripts really are unfilled.
# --------------------------------------------------------------------------- #


def _slot_value(script: str, var: str) -> str:
    """Extract a single-quoted shell slot's literal value, concatenating adjacent quoted runs.

    Shell concatenates quoted and unquoted fragments into one word, so `A='x'y'z'` is `xyz`.
    Reproducing that is the point: the c2_01/c2_04 regression hid in exactly that seam — the
    live text sat OUTSIDE the first pair of quotes, where a naive `'([^']*)'` match would not
    have seen it and this test would have passed while the harness stayed broken.
    """
    m = re.search(rf"^{re.escape(var)}=(.*?)(?:\n(?=[A-Z#\n])|\Z)", script, re.M | re.S)
    assert m, f"slot {var} not found"
    raw, out, i = m.group(1), [], 0
    while i < len(raw):
        ch = raw[i]
        if ch in "'\"":
            end = raw.find(ch, i + 1)
            end = len(raw) if end == -1 else end
            out.append(raw[i + 1 : end])
            i = end + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def test_shipped_slots_are_unfilled() -> None:
    """The four committed proof scripts hold NO offensive command — every slot reads unfilled.

    This is the check that failed before the fix: c2_01's and c2_04's slots opened with a live
    `echo $(cat … | grep … | cut …)` fragment, so the harness saw them as FILLED.
    """
    for name, slots in SHIPPED_SLOTS.items():
        script = (PROOF / name).read_text(encoding="utf-8")
        for var in slots:
            value = _slot_value(script, var)
            got = D._read_paste(_write(value))
            assert got == "", (
                f"{name}:{var} is NOT unfilled — the harness would treat this as a real "
                f"command and score it. Live content: {got[:160]!r}"
            )
    total = sum(len(v) for v in SHIPPED_SLOTS.values())
    print(f"  all {total} shipped [[PASTE]] slots across 4 proof scripts are UNFILLED: PASS")


def test_the_unfilled_check_can_fail() -> None:
    """Control: the shipped-slot check must actually catch a filled slot.

    Every assertion above reports "all clear" both when it is working and when it is broken.
    Feeding it the exact fragment that used to ship proves it discriminates.
    """
    regression = "echo $(cat docker/proof/c2_01_dc_prereq_stage.sh | grep '^x=' | cut -d '=' -f 2)"
    for planted in (regression, "Get-Item C:\\x", "# lead\nStart-Process x.exe"):
        assert D._read_paste(_write(planted)) != "", (
            f"the reader called {planted!r} unfilled — this check cannot detect a filled slot"
        )
    # And the shell-fragment parser must see live text that sits OUTSIDE the first quote pair.
    fake = "DCSYNC_CMD='" + regression + "\n# [[PASTE: instructions]]\n'\n"
    assert D._read_paste(_write(_slot_value(fake, "DCSYNC_CMD"))) != "", (
        "the slot parser missed live text outside the first quoted run — the exact shape of "
        "the c2_01/c2_04 regression"
    )
    print("  control: a filled/regressed slot IS detected (the checks can fail): PASS")


if __name__ == "__main__":
    test_reader_treats_placeholders_as_unfilled()
    test_empty_slot_reports_notrun_and_never_passes()
    test_every_slot_reader_is_guarded()
    test_shipped_slots_are_unfilled()
    test_the_unfilled_check_can_fail()
    print("ALL proof-harness honesty tests pass")
