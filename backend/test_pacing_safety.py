"""SAFETY + HONESTY invariants for RUN PACING (D3).

Pacing adds a tool's own rate/delay flag so a real bug-bounty program does not ban your IP
mid-engagement. It is an ARGUMENT REWRITE on an already-gated request — the same shape as the
recording proxy's flag injection and as tunnels.wrap_command — and it must stay that shape:

  1. IT GRANTS NOTHING. A paced command clears exactly the same gates as an unpaced one, and
     the REWRITTEN argv is what gets classified. A paced command is quieter, not safer.
  2. ENGAGEMENT MODE ONLY. Lab runs are byte-identical to before this feature existed.
  3. IT NEVER LIES ABOUT WHETHER IT WORKED. This is the invariant with teeth. A tool with no
     known throttle flag, a tool that already carries its own rate, a lab run, a WinRM run —
     each runs UNPACED, and each says so before any output arrives. An operator who believes
     a run was paced and was not is the exact person this feature exists to protect, and
     silently dropping the flag would hand them that run.
  4. THE UNITS ARE CONVERTED, NOT PASSED THROUGH. Tools spell throttling three incompatible
     ways. Handing "4" to a flag that means SECONDS OF DELAY when the operator asked for 4
     requests per second would slow a scan 16x — or, reversed, hammer a target at 1000x the
     requested rate while reporting success.

Every flag asserted here was read out of the tool's own --help inside hackpit/kali-sandbox on
2026-08-04. Hermetic: no Docker, no network. Run:  python test_pacing_safety.py
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import executor as E  # noqa: E402
from cockpit.models import ExecRequest  # noqa: E402

# The lab target the target-lock permits, so a gate refusal in these tests is never just
# "wrong host". Matches the value the other cockpit tests use.
_LAB = "hackpit-lab-target"


# --------------------------------------------------------------------------- #
# 1. pacing grants nothing — every gate still fires on the REWRITTEN argv
# --------------------------------------------------------------------------- #
def test_a_paced_command_still_clears_every_gate() -> None:
    unapproved = E.validate_request(
        ExecRequest(command="ffuf", args=["-u", f"http://{_LAB}/FUZZ"], approved=False, pace=4)
    )
    assert unapproved is not None and unapproved.gate in ("approval", "sandbox"), (
        f"a paced command skipped approval — got {getattr(unapproved, 'gate', None)}"
    )

    off_target = E.validate_request(
        ExecRequest(command="nmap", args=["-sV", "scanme.nmap.org"], approved=True, pace=4)
    )
    assert off_target is not None and off_target.gate == "target", (
        "a paced command pointed off-target must still be refused at the target gate — "
        f"got {getattr(off_target, 'gate', None)}"
    )

    # the danger gate reads the argv, and pacing only ever ADDS to it
    dangerous = E.validate_request(
        ExecRequest(
            command="sqlmap",
            args=["-u", f"http://{_LAB}/x", "--os-shell"],
            approved=True,
            pace=4,
        )
    )
    assert dangerous is not None and dangerous.gate == "danger", (
        "a paced dangerous command must still be refused at the danger gate — "
        f"got {getattr(dangerous, 'gate', None)}"
    )
    print("  a paced command still faces approval, target and danger: PASS")


def test_the_pace_rewrite_cancels_a_prevalidated_verdict() -> None:
    """*** CRITICAL 2, WEARING THE SAME HAT AS THE PROXY REWRITE. ***

    A caller that validated the ORIGINAL request holds a verdict about a DIFFERENT command
    line than the one about to run.
    """
    src = inspect.getsource(E.iter_run)
    rewrite_at = src.find("apply_pace_to_request")
    validate_at = src.find("validate_request(request)")
    assert rewrite_at != -1, "iter_run never applies the pace rewrite"
    assert validate_at != -1, "iter_run does not validate"
    assert rewrite_at < validate_at, (
        "iter_run validates BEFORE adding the pace flag — the gate would classify a command "
        "line different from the one that runs"
    )
    assert "if pace_note:" in src and "prevalidated = False" in src, (
        "the pace rewrite does not cancel a prevalidated verdict"
    )
    print("  the pace rewrite precedes validation and cancels a stale verdict: PASS")


# --------------------------------------------------------------------------- #
# 2. engagement mode only — the lab is byte-identical to before
# --------------------------------------------------------------------------- #
def test_pacing_is_engagement_mode_only() -> None:
    args = ["-u", f"http://{_LAB}/FUZZ"]

    lab = ExecRequest(command="ffuf", args=args, approved=True, pace=4)
    out, note = E.apply_pace_to_request(lab)
    assert out is lab and note == "", f"a LAB run was paced: {out.args!r}"

    win = ExecRequest(
        command="Get-Process", args=[], approved=True, pace=4, windows_profile_id="w1"
    )
    out_w, note_w = E.apply_pace_to_request(win)
    assert out_w is win and note_w == "", "a WinRM run was rewritten — it has no argv to rewrite"

    # ...and the request that did not ask is untouched in every mode
    plain = ExecRequest(command="ffuf", args=args, approved=True, engagement_id="e1")
    out_p, note_p = E.apply_pace_to_request(plain)
    assert out_p is plain and note_p == "", "a request with no pace was altered"

    eng = ExecRequest(command="ffuf", args=args, approved=True, pace=4, engagement_id="e1")
    out_e, note_e = E.apply_pace_to_request(eng)
    assert out_e is not eng and out_e.args[:2] == ["-rate", "4"], out_e.args
    assert note_e, "an engagement run was paced but reported nothing"
    print("  paced in engagement mode; lab, WinRM and unasked runs untouched: PASS")


# --------------------------------------------------------------------------- #
# 3. it never lies about whether it worked
# --------------------------------------------------------------------------- #
def test_an_unpaceable_run_says_so() -> None:
    """THE HONESTY INVARIANT. Every path that does NOT pace must announce it."""
    # a tool with no known throttle flag
    unchanged, note = E.apply_pace("curl", ["http://x"], 4)
    assert unchanged == ["http://x"], f"an unknown tool's argv was altered: {unchanged!r}"
    assert "NOT paced" in note, note

    # a tool the operator already throttled themselves — we defer, and say we deferred
    kept, note2 = E.apply_pace("ffuf", ["-rate", "500", "-u", "http://x"], 4)
    assert kept == ["-rate", "500", "-u", "http://x"], kept
    assert "already sets its own rate" in note2 and "NOT re-paced" in note2, note2
    # the glued spelling counts as already-set too
    _, note3 = E.apply_pace("sqlmap", ["--delay=2", "-u", "http://x"], 4)
    assert "already sets its own rate" in note3, note3

    # and each of those reaches the OPERATOR, not just the return value
    def notes_for(**kw) -> list[str]:
        return E.run_notes(ExecRequest(approved=True, pace=4, **kw))

    lab = notes_for(command="ffuf", args=["-u", "http://x"])
    assert any("engagement mode only" in n and "NOT paced" in n for n in lab), lab

    win = notes_for(command="Get-Process", args=[], windows_profile_id="w1")
    assert any("not available over WinRM" in n and "NOT paced" in n for n in win), win

    unknown = notes_for(command="curl", args=["http://x"], engagement_id="e1")
    assert any("no known throttle flag" in n for n in unknown), unknown

    # a run that WAS paced says that too, with the flag it used
    paced = notes_for(command="ffuf", args=["-u", "http://x"], engagement_id="e1")
    assert any("paced to ~4/s" in n and "-rate 4" in n for n in paced), paced

    # POSITIVE CONTROL — run_notes must be silent when nothing was asked for, or a
    # "not paced" line would appear on every ordinary run and stop being read.
    quiet = E.run_notes(ExecRequest(command="ffuf", args=["-u", "http://x"], approved=True))
    assert quiet == [], quiet
    print("  every unpaced path announces itself; an unasked run stays silent: PASS")


def test_the_note_reaches_the_start_event() -> None:
    """A note nobody sees is not honesty. It has to be ON the wire, before the output."""
    src = inspect.getsource(E.iter_run)
    notes_at = src.find("notes = run_notes(request)")
    start_at = src.find('"type": "start"')
    assert notes_at != -1, "iter_run never computes the operator notes"
    assert start_at != -1 and notes_at < start_at, "the notes are computed after the start event"
    assert '"notes": notes' in src, (
        "the start event does not carry the notes — the operator would never be told that "
        "their run went unpaced"
    )
    print("  the notes ride the start event, before any output: PASS")


# --------------------------------------------------------------------------- #
# 4. the units are converted, not passed through
# --------------------------------------------------------------------------- #
def test_the_rate_is_converted_into_each_tools_own_unit() -> None:
    """4 requests/second is `-rate 4` to ffuf and `--delay 0.25` to sqlmap. Passing the
    literal 4 to sqlmap would mean a 4-SECOND wait — a 16x slowdown reported as success.
    Reversed, a delay handed to a rate flag would run 1000x faster than asked."""
    cases = {
        # rate-per-second tools take the number as-is
        "ffuf": (["-rate", "4"], "rps"),
        "nuclei": (["-rate-limit", "4"], "rps"),
        "feroxbuster": (["--rate-limit", "4"], "rps"),
        "nmap": (["--max-rate", "4"], "pps"),
        "naabu": (["-rate", "4"], "pps"),
        "masscan": (["--rate=4"], "pps"),
        # delay tools get the INVERSE, in their own unit
        "sqlmap": (["--delay=0.25"], "seconds"),
        "dirsearch": (["--delay=0.25"], "seconds"),
        "wfuzz": (["-s", "0.25"], "seconds"),
        "arjun": (["-d", "0.25"], "seconds"),
        "wpscan": (["--throttle", "250"], "milliseconds"),
        "dalfox": (["--delay", "250"], "milliseconds"),
    }
    for tool, (expected, unit) in cases.items():
        got, _ = E.apply_pace(tool, ["-u", "http://x"], 4)
        assert got[: len(expected)] == expected, (
            f"{tool} ({unit}) got {got[: len(expected)]!r}, expected {expected!r}"
        )

    # gobuster wants a Go duration STRING, not a bare number
    go, _ = E.apply_pace("gobuster", ["dir", "-u", "http://x"], 4)
    assert "250ms" in go, go

    # 1/s is the slowest sensible ask and must not round to zero delay
    slow, _ = E.apply_pace("wpscan", ["--url", "http://x"], 1)
    assert slow[:2] == ["--throttle", "1000"], slow
    # a very fast ask must not produce a zero-millisecond wait either
    fast, _ = E.apply_pace("wpscan", ["--url", "http://x"], 10000)
    assert int(fast[1]) >= 1, fast
    print(f"  all {len(cases)} verified flags converted into their own unit: PASS")


def test_a_subcommand_tools_flag_lands_where_it_parses() -> None:
    """MEASURED against the real image: `gobuster --delay 250ms dir …` exits with "flag
    provided but not defined" and does nothing. The flag has to follow the subcommand.

    The same rule fixes the proxy rewrite, which shipped with this bug — asking to capture a
    gobuster run broke the run. One placement helper serves both, so the next tool with
    subcommands cannot be right in one rewrite and wrong in the other."""
    paced, _ = E.apply_pace("gobuster", ["dir", "-u", "http://x"], 4)
    assert paced[0] == "dir" and paced[1:3] == ["--delay", "250ms"], paced

    proxied, _ = E.apply_proxy("gobuster", ["dir", "-u", "http://x"], 8090)
    assert proxied[0] == "dir" and proxied[1] == "--proxy", proxied

    # a flat tool is still prefixed, exactly as before
    flat, _ = E.apply_proxy("curl", ["http://x"], 8090)
    assert flat[:2] == ["-x", "http://127.0.0.1:8090"], flat

    # no subcommand given -> nothing is invented on the operator's behalf
    bare, _ = E.apply_pace("gobuster", ["-h"], 4)
    assert bare[:2] == ["--delay", "250ms"], bare
    print("  a subcommand tool's flag follows its subcommand, in BOTH rewrites: PASS")


def test_every_paced_tool_has_an_already_set_guard() -> None:
    """A tool we know how to pace but cannot tell is ALREADY paced would silently get two
    contradictory rate flags — resolved differently by each tool, invisibly to the operator."""
    missing = sorted(set(E._PACE_FLAGS) - set(E._PACE_ALREADY_SET))
    assert not missing, f"these paced tools have no already-set guard: {missing}"
    for tool, (flag, _joiner, _unit) in E._PACE_FLAGS.items():
        assert flag in E._PACE_ALREADY_SET[tool], (
            f"{tool}: the flag we ADD ({flag}) is not in its own already-set list, so pacing "
            "a command we already paced would add it twice"
        )
    print(f"  all {len(E._PACE_FLAGS)} paced tools guard against a double rate flag: PASS")


if __name__ == "__main__":
    test_a_paced_command_still_clears_every_gate()
    test_the_pace_rewrite_cancels_a_prevalidated_verdict()
    test_pacing_is_engagement_mode_only()
    test_an_unpaceable_run_says_so()
    test_the_note_reaches_the_start_event()
    test_the_rate_is_converted_into_each_tools_own_unit()
    test_a_subcommand_tools_flag_lands_where_it_parses()
    test_every_paced_tool_has_an_already_set_guard()
    print("ALL pacing safety invariants hold")
