"""The WinRM execution transport — the AD-native way HackPit drives a Windows box.

This is the piece that swaps ``docker exec`` for a WinRM call. Model A (docs/WINDOWS-
EXECUTION.md): HackPit does NOT own the VM. The operator runs a Windows/AD VM in VMware
themselves; this module opens a WinRM session to it, runs ONE PowerShell command string on
the box, and captures the output. Rubeus, PowerView, Mimikatz, PowerShell/.NET all run ON
the Windows host — HackPit is only the driver.

It is a TRANSPORT, not a gate. Every WinRM run has already cleared the executor's gates
(target-lock to the profile host → per-command human approval → danger-heuristic red
confirm) before anything here is called. Swapping the transport changes nothing about the
safety model — that is the whole point of Model A.

HERMETIC BY CONSTRUCTION
------------------------
``pywinrm`` is imported LAZILY, inside :func:`_send`, so the safety suite runs with no
third-party WinRM dependency and no network. Tests exercise the executor's Windows path by
monkeypatching :func:`_send` (or :func:`run`) with a fake transport — exactly how test_kali
fakes ``subprocess.run``.

The hermetic suite is therefore not the whole story, and the rest of it is no longer pending:
the live path was VERIFIED against a real Windows/AD box in build #9 (2026-07-31), with a
round trip reaching a real ``corp.local`` domain controller and returning
``corp\\administrator`` (``backend/livefire.log`` line 21). That run is also where this
transport's real-world edges surfaced — stderr arriving as CLIXML, and impacket needing the
DC's address rather than its FQDN — neither of which any amount of mocking would have shown.

AUTH. NTLM/Negotiate, so a LOCAL Windows account authenticates over plain HTTP:5985 without
enabling Basic auth. Two credential kinds:
  * ``password``   — cleartext password over NTLM.
  * ``ntlm-hash``  — pass-the-hash: the NT hash is used directly (no password). The hash is
    presented in the ``LM:NT`` form pyspnego recognises as a hash rather than a passphrase.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from xml.etree import ElementTree

# The all-zero LM hash — the standard "no LM" filler pass-the-hash tools prepend so the
# credential is a well-formed ``LM:NT`` pair.
_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


class WinRMError(RuntimeError):
    """A transport-level failure (unreachable host, auth rejected, WinRM not enabled)."""


@dataclass(frozen=True)
class WinRMResult:
    """The outcome of one remote command."""

    exit_code: int | None
    stdout: str
    stderr: str
    #: stderr exactly as the box sent it, before the CLIXML progress records were stripped.
    #: Kept so nothing is destroyed by the filter, and deliberately NOT in ``to_dict`` — it
    #: is the wall of markup the filter exists to keep off the operator's screen.
    stderr_raw: str = ""
    #: How many PowerShell PROGRESS records were dropped from stderr. Reported rather than
    #: hidden: an operator who sees "0 progress records" and still has noise knows the
    #: filter is not the reason, and one who sees 40 knows what happened to them.
    progress_records_dropped: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "progress_records_dropped": self.progress_records_dropped,
        }


# --------------------------------------------------------------------------- #
# CLIXML — why a successful AD command looks like a failing one (D7)
#
# `run_ps` runs the command through powershell.exe, whose stderr is not text but a CLIXML
# document: a PowerShell object stream serialised as XML, prefixed with the literal line
# `#< CLIXML`. Every progress bar PowerShell would have drawn on a console — "Preparing
# modules for first use", the percent-complete ticks of any cmdlet that reports progress —
# is serialised into it as an <Obj S="progress"> record. So a command that succeeded
# perfectly returns rc=0 with hundreds of lines of markup on stderr, and every clean run in
# build #9's live-fire session read as a failing one.
#
# WHAT IS DROPPED, AND ONLY THAT: progress records. The Error, Warning, Verbose and Debug
# streams are real output and are kept, unescaped back into text. If anything about the
# document cannot be parsed the ORIGINAL text is returned untouched — a filter that swallows
# an error it did not understand would turn a cosmetic annoyance into a silent failure,
# which is a strictly worse bug than the one being fixed.
# --------------------------------------------------------------------------- #
_CLIXML_HEADER = "#< CLIXML"
_PS_NS = "{http://schemas.microsoft.com/powershell/2004/04}"
#: PowerShell escapes characters it cannot put in XML text as _xNNNN_ (CR is _x000D_).
_XML_ESCAPE_RE = re.compile(r"_x([0-9A-Fa-f]{4})_")


def _unescape(text: str) -> str:
    return _XML_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text or "")


def clean_stderr(text: str) -> tuple[str, int]:
    """Strip PowerShell PROGRESS records from a CLIXML stderr blob.

    Returns ``(stderr, progress_records_dropped)``. Plain (non-CLIXML) stderr is returned
    unchanged with a count of 0, so a transport error string or an ordinary message passes
    straight through.

    FAIL-OPEN BY DESIGN. Any parse failure returns the input verbatim. The cost of that is
    the operator seeing the markup they saw before; the cost of the alternative is a real
    error being deleted because its document had a shape this function did not expect.
    """
    if not text or _CLIXML_HEADER not in text:
        return text or "", 0

    kept: list[str] = []
    dropped = 0
    # A single stderr may carry several CLIXML documents concatenated — one per write.
    chunks = text.split(_CLIXML_HEADER)
    for chunk in chunks:
        body = chunk.strip()
        if not body:
            continue
        try:
            root = ElementTree.fromstring(body)
        except ElementTree.ParseError:
            # Not parseable — hand it back exactly as it arrived rather than guess.
            kept.append(chunk.strip("\r\n"))
            continue
        for node in root:
            tag = node.tag.replace(_PS_NS, "")
            stream = (node.get("S") or "").lower()
            # THE ONLY THING THIS FUNCTION REMOVES.
            if tag == "Obj" and stream == "progress":
                dropped += 1
                continue
            if tag == "S":
                piece = _unescape(node.text or "")
                if piece.strip():
                    kept.append(piece)
                continue
            # Anything else (an Obj that is not progress, an unknown element) is real
            # output of some kind. Keep its text rather than silently discard it.
            piece = _unescape("".join(node.itertext()))
            if piece.strip():
                kept.append(piece)

    out = "".join(kept)
    # Trailing CR/LF from the last record only — internal newlines are the error's own.
    return out.rstrip("\r\n"), dropped


def _endpoint(host: str, port: int) -> str:
    return f"http://{host}:{port}/wsman"


def _credential(profile: dict[str, Any]) -> str:
    """The value handed to pywinrm as the 'password', per the profile's auth kind.

    For a password profile it is the password verbatim. For a pass-the-hash profile it is
    the NT hash in ``LM:NT`` form, which pyspnego (pywinrm's NTLM backend) treats as a hash
    credential rather than a passphrase — so the plaintext password is never needed.
    """
    secret = profile.get("secret") or ""
    if (profile.get("auth_kind") or "password") == "ntlm-hash":
        nt = secret.strip()
        # Accept either a bare NT hash or an already-formed LM:NT pair.
        return nt if ":" in nt else f"{_EMPTY_LM}:{nt}"
    return secret


def _send(profile: dict[str, Any], command: str, timeout: int) -> WinRMResult:
    """Open a WinRM session to the profile host and run ONE PowerShell command string.

    Lazy-imports pywinrm so the hermetic suite never needs it. TESTS MONKEYPATCH THIS (or
    :func:`run`) with a fake, so the executor's Windows path is exercised without a network
    or the dependency installed.
    """
    try:
        import winrm  # noqa: PLC0415 — deliberately lazy; keeps the suite hermetic
    except ModuleNotFoundError as exc:  # pragma: no cover - only on a box without pywinrm
        raise WinRMError(
            "pywinrm is not installed — `pip install pywinrm` to drive a Windows target "
            "(the hermetic test suite does not need it)"
        ) from exc

    host = profile["host"]
    port = int(profile.get("port") or 5985)
    username = profile["username"]
    domain = (profile.get("domain") or "").strip()
    # pywinrm wants DOMAIN\\user (or user for a local account) as the username.
    winrm_user = f"{domain}\\{username}" if domain else username

    session = winrm.Session(
        _endpoint(host, port),
        auth=(winrm_user, _credential(profile)),
        transport="ntlm",              # NTLM/Negotiate — local accounts over HTTP, no Basic
        server_cert_validation="ignore",
        operation_timeout_sec=max(1, int(timeout) - 5) if timeout else 55,
        read_timeout_sec=max(2, int(timeout)) if timeout else 60,
    )
    try:
        result = session.run_ps(command)  # runs the command as a PowerShell script
    except Exception as exc:  # pragma: no cover - network/auth failures need a live box
        raise WinRMError(f"WinRM run failed against {host}:{port} — {exc}") from exc
    raw_stderr = _decode(result.std_err)
    # Filter HERE, at the one place a WinRM result is built, so the events, the persisted
    # RunRecord and anything else downstream all see the same cleaned stderr. Doing it at a
    # display layer would leave the run record full of markup and put the burden on every
    # future consumer to remember.
    stderr, dropped = clean_stderr(raw_stderr)
    return WinRMResult(
        exit_code=result.status_code,
        stdout=_decode(result.std_out),
        stderr=stderr,
        stderr_raw=raw_stderr,
        progress_records_dropped=dropped,
    )


def _decode(blob: Any) -> str:
    if isinstance(blob, bytes):
        return blob.decode("utf-8", "replace")
    return str(blob or "")


def run(profile: dict[str, Any], command: str, timeout: int) -> WinRMResult:
    """Run ONE command on the profile's Windows host over WinRM. Thin wrapper over _send
    so callers (and tests) have a single stable entry point."""
    return _send(profile, command, timeout)
