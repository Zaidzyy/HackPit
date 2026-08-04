"""WinRM CLIXML PROGRESS-RECORD FILTERING (D7).

PowerShell's stderr over WinRM is not text. It is a CLIXML document — a serialised object
stream — and every progress bar PowerShell would have drawn on a console arrives inside it
as an `<Obj S="progress">` record. Build #9's live-fire run against a real `corp.local`
domain controller is where this surfaced: commands that succeeded returned `rc=0` alongside
a wall of markup, so **every clean run read as a failing one**.

The fix strips progress records. The whole risk of the fix is that it strips something else,
which would convert a cosmetic annoyance into a silent failure — a strictly worse bug. So
the tests that matter here are the negative ones:

  * A GENUINE ERROR STILL SURFACES, in the same document as the progress noise.
  * Warning / Verbose / Debug streams survive — they are real output, not progress.
  * A document that cannot be parsed is returned VERBATIM, never swallowed.
  * Plain, non-CLIXML stderr is untouched.

Every sample below is the real wire format: the `#< CLIXML` header, the PowerShell 2004/04
namespace, and `_x000D__x000A_` escapes for the newlines PowerShell cannot put in XML text.

Hermetic — no network, no Windows box. Run:  python test_winrm_clixml.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cockpit import winrm_transport as W  # noqa: E402

_NS = 'xmlns="http://schemas.microsoft.com/powershell/2004/04"'


def _progress(activity: str = "Preparing modules for first use.") -> str:
    """One PROGRESS record, in the shape PowerShell actually emits."""
    return (
        '<Obj S="progress" RefId="0"><TN RefId="0">'
        "<T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN>"
        '<MS><I64 N="SourceId">1</I64><PR N="Record">'
        f"<AV>{activity}</AV><AI>0</AI><Nil N=\"ParentActivityId\"/><PI>-1</PI>"
        '<PC>-1</PC><T N="Type">Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj>'
    )


def _doc(*inner: str) -> str:
    return f"#< CLIXML\r\n<Objs Version=\"1.1.0.1\" {_NS}>{''.join(inner)}</Objs>"


def test_progress_records_are_removed() -> None:
    """The reported symptom: rc=0 and a wall of markup."""
    noisy = _doc(*[_progress(f"step {i}") for i in range(40)])
    out, dropped = W.clean_stderr(noisy)
    assert dropped == 40, dropped
    assert out == "", f"a purely-progress stderr must come back empty, got {out!r}"
    assert "CLIXML" not in out and "<Obj" not in out, out
    print("  40 progress records collapse to an empty stderr: PASS")


def test_a_genuine_error_still_surfaces() -> None:
    """*** THE TRAP. *** The filter runs on the same document that carries the real error.

    If this ever regresses, a failing AD command reports rc!=0 with an EMPTY stderr, and the
    operator has no idea why it failed — worse than the noise this replaced.
    """
    err = (
        '<S S="Error">Get-ADUser : Cannot find an object with identity: '
        "'nosuchuser'_x000D__x000A_</S>"
    )
    doc = _doc(_progress(), err, _progress("more noise"))
    out, dropped = W.clean_stderr(doc)
    assert dropped == 2, dropped
    assert "Get-ADUser" in out and "nosuchuser" in out, (
        f"THE REAL ERROR WAS SWALLOWED BY THE PROGRESS FILTER: {out!r}"
    )
    assert "<Obj" not in out and "Preparing modules" not in out, out
    # the _xNNNN_ escapes are decoded back into real characters, not left as literals
    assert "_x000D_" not in out and "_x000A_" not in out, out
    print("  a real error survives a document full of progress records: PASS")


def test_error_only_documents_are_unchanged_in_substance() -> None:
    """No progress at all → nothing dropped, the error still comes through."""
    doc = _doc('<S S="Error">Access is denied._x000D__x000A_</S>')
    out, dropped = W.clean_stderr(doc)
    assert dropped == 0, dropped
    assert out.strip() == "Access is denied.", repr(out)
    print("  an error-only document loses nothing: PASS")


def test_other_streams_are_not_progress() -> None:
    """Warning / Verbose / Debug are real output. Only PROGRESS is noise."""
    doc = _doc(
        _progress(),
        '<S S="Warning">WARNING: the module is deprecated_x000D__x000A_</S>',
        '<S S="Verbose">VERBOSE: connecting to DC01_x000D__x000A_</S>',
        '<S S="Debug">DEBUG: using NTLM_x000D__x000A_</S>',
    )
    out, dropped = W.clean_stderr(doc)
    assert dropped == 1, dropped
    for expected in ("deprecated", "connecting to DC01", "using NTLM"):
        assert expected in out, f"{expected!r} was dropped — only progress may be: {out!r}"
    print("  warning, verbose and debug streams all survive: PASS")


def test_unparseable_clixml_is_returned_verbatim() -> None:
    """FAIL-OPEN. A document we do not understand is handed back whole.

    Showing markup is a nuisance. Deleting an error nobody can now read is a silent failure,
    and this codebase treats a silent wrong answer as the worse outcome every time.
    """
    broken = '#< CLIXML\r\n<Objs Version="1.1.0.1"><S S="Error">truncated mid-docum'
    out, dropped = W.clean_stderr(broken)
    assert dropped == 0, dropped
    assert "truncated mid-docum" in out, (
        f"an unparseable document was swallowed instead of passed through: {out!r}"
    )
    print("  an unparseable CLIXML document is passed through, not swallowed: PASS")


def test_plain_stderr_is_untouched() -> None:
    """Transport errors and ordinary text never go near the parser."""
    for plain in (
        "[winrm] timed out after 60s",
        "WinRM run failed against 10.0.0.5:5985 — auth rejected",
        "",
    ):
        out, dropped = W.clean_stderr(plain)
        assert out == plain and dropped == 0, (out, dropped)
    print("  plain non-CLIXML stderr passes through byte-for-byte: PASS")


def test_several_concatenated_documents() -> None:
    """PowerShell writes one document per flush; a long run returns several, concatenated."""
    doc = _doc(_progress()) + "\r\n" + _doc('<S S="Error">boom_x000D__x000A_</S>')
    out, dropped = W.clean_stderr(doc)
    assert dropped == 1, dropped
    assert out.strip() == "boom", repr(out)
    print("  concatenated CLIXML documents are each handled: PASS")


def test_the_result_keeps_the_raw_and_reports_the_count() -> None:
    """Nothing is destroyed: the raw stderr stays on the result, and the count is reported
    so "quiet because it was filtered" is distinguishable from "quiet because it was quiet".
    But the raw markup does NOT ride the wire — keeping it off the screen is the point."""
    raw = _doc(_progress(), '<S S="Error">real problem_x000D__x000A_</S>')
    cleaned, dropped = W.clean_stderr(raw)
    r = W.WinRMResult(
        exit_code=1, stdout="", stderr=cleaned, stderr_raw=raw, progress_records_dropped=dropped
    )
    assert r.stderr_raw == raw, "the raw stderr was not preserved on the result"
    d = r.to_dict()
    assert d["progress_records_dropped"] == 1, d
    assert "real problem" in d["stderr"], d
    assert "stderr_raw" not in d and "CLIXML" not in d["stderr"], (
        "the raw CLIXML wall reached the response — that is the bug, not the fix"
    )
    print("  raw kept on the result, count reported, markup kept off the wire: PASS")


def test_the_transport_filters_at_the_single_build_point() -> None:
    """Filtering must happen where the WinRMResult is BUILT, not at a display layer — or the
    persisted run record keeps the markup and every future consumer has to remember."""
    import inspect

    src = inspect.getsource(W._send)
    assert "clean_stderr(" in src, (
        "_send does not filter — the run record and the event stream would keep the markup"
    )
    assert "stderr_raw=raw_stderr" in src, "_send discards the raw stderr instead of keeping it"
    print("  the transport filters where the result is built: PASS")


if __name__ == "__main__":
    test_progress_records_are_removed()
    test_a_genuine_error_still_surfaces()
    test_error_only_documents_are_unchanged_in_substance()
    test_other_streams_are_not_progress()
    test_unparseable_clixml_is_returned_verbatim()
    test_plain_stderr_is_untouched()
    test_several_concatenated_documents()
    test_the_result_keeps_the_raw_and_reports_the_count()
    test_the_transport_filters_at_the_single_build_point()
    print("ALL WinRM CLIXML filtering tests pass")
