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
fakes ``subprocess.run``. The live path against a real VM is verified separately, once the
operator's VM is up (deferred, like AD-live execution and tunnels were).

AUTH. NTLM/Negotiate, so a LOCAL Windows account authenticates over plain HTTP:5985 without
enabling Basic auth. Two credential kinds:
  * ``password``   — cleartext password over NTLM.
  * ``ntlm-hash``  — pass-the-hash: the NT hash is used directly (no password). The hash is
    presented in the ``LM:NT`` form pyspnego recognises as a hash rather than a passphrase.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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

    def to_dict(self) -> dict[str, Any]:
        return {"exit_code": self.exit_code, "stdout": self.stdout, "stderr": self.stderr}


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
    return WinRMResult(
        exit_code=result.status_code,
        stdout=_decode(result.std_out),
        stderr=_decode(result.std_err),
    )


def _decode(blob: Any) -> str:
    if isinstance(blob, bytes):
        return blob.decode("utf-8", "replace")
    return str(blob or "")


def run(profile: dict[str, Any], command: str, timeout: int) -> WinRMResult:
    """Run ONE command on the profile's Windows host over WinRM. Thin wrapper over _send
    so callers (and tests) have a single stable entry point."""
    return _send(profile, command, timeout)
