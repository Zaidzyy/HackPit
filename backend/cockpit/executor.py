"""The exec layer — validated, approved, target-locked `docker exec` into the sandbox.

Wired in M1.3, permitted only because the M1.2 isolation proof passed. Every run must
clear four independent gates, in order:
    1. allowlist   — command is on the safe set, args are metachar-free + rule-valid
    2. target lock — the lab is explicitly targeted and NO non-lab host appears
    3. approval    — request.approved is True (per-command human approval)
    4. isolation   — the running sandbox is attached only to internal networks
Only then is the command run, argv-style (never through a shell), with a hard timeout.
"""

from __future__ import annotations

import queue
import re
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, NamedTuple

from state import ingest as state_ingest

from . import (
    allowlist, config, engagement, loot, runstore, secretargs, winprofiles, winrm_transport,
)
from .models import EngagementRecord, ExecRejected, ExecRequest, RunRecord
from .sandbox import SandboxError, assert_isolation_proven

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# A plausible TLD: letters only, 2-24 chars. This is the POSITIVE test for "the last label
# of a dotted token looks like a real domain suffix" (com, org, io, local, internal). It is
# what separates a host from the two things that used to false-trip the target-lock:
#   * versions / list names — `directory-list-2.3-medium`, `scan.1.2`, `raft-2.3` — whose
#     last label has a digit or hyphen, so it is NOT an alphabetic TLD, so NOT a host;
#   * filenames — `words.txt`, `config.yaml` — whose last label IS alphabetic, handled by
#     the file-extension exclusion below.
_TLD_RE = re.compile(r"^[a-z]{2,24}$")

# File extensions that are alphabetic (so they pass _TLD_RE) but name a FILE operand, not a
# host — a wordlist, output file, config. Only the ALPHABETIC entries are load-bearing now
# (a `.7z` or `.mp3` already fails _TLD_RE), but the fuller list is kept for clarity.
# Non-load-bearing overall (isolation / human-approval is the real bound), so imperfect is fine.
_FILE_EXTS = frozenset({
    "txt", "json", "xml", "csv", "html", "htm", "js", "py", "conf", "cfg", "ini", "list",
    "lst", "dic", "gz", "zip", "tar", "log", "md", "yaml", "yml", "php", "asp", "aspx",
    "bak", "pem", "key", "crt", "db", "sqlite", "pdf", "png", "jpg", "gif", "svg", "css",
})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _looks_like_host(token: str) -> bool:
    """True if a token is addressing *something* (URL, dotted host, IP, host:port).

    Recognises a host POSITIVELY rather than assuming every dotted token is one. A dotted
    token is a host only if its last label is a plausible alphabetic TLD (``evil.com``,
    ``dc01.corp.local``) and is not a file extension (``words.txt``). This stops the whole
    class of false rejections the old assume-host-unless-known-extension logic produced —
    ``directory-list-2.3-medium``, ``--user-agent Mozilla/5.0``, ``-oA scan.1.2``, version
    strings — which read as out-of-scope hosts and blocked legitimate, human-approved
    commands. Best-effort DiD, not the real bound (isolation / human-approval is); a scheme'd
    URL always wins, and under-detecting an exotic host (punycode) fails toward allowing a
    command the human already approved, which is the safe direction here.
    """
    if "://" in token:
        return True
    host = _host_of(token) or ""
    if not host:
        return False
    if _IPV4.match(host):
        return True
    if "." not in host:
        return False
    last = host.rsplit(".", 1)[-1].lower()
    if not _TLD_RE.match(last):
        return False                    # 2.3, 3-medium, scan.1.2 — a version/list, not a host
    return last not in _FILE_EXTS       # words.txt / config.yaml — a file operand, not a host


def _host_of(token: str) -> str | None:
    """Extract a bare host from a token that may be a URL or host[:port]."""
    t = token.strip()
    if not t or t.startswith("-"):
        return None
    if "://" in t:
        t = t.split("://", 1)[1]
    for sep in ("/", "?", "#"):
        if sep in t:
            t = t.split(sep, 1)[0]
    if "@" in t:
        t = t.split("@", 1)[1]
    if ":" in t:
        t = t.split(":", 1)[0]
    return t or None


def _engagement_aliases(target: str) -> frozenset[str]:
    """The accepted target-lock aliases for an engagement's named target: the raw string
    (a host or URL) plus its bare host form, so both ``scanme.nmap.org`` and
    ``http://scanme.nmap.org/`` resolve to the same locked target."""
    aliases = {target}
    host = _host_of(target)
    if host:
        aliases.add(host)
    return frozenset(aliases)


def _engagement_lock(eng: EngagementRecord) -> tuple[frozenset[str], Any, str]:
    """(allowed aliases, in_scope matcher, label) for an engagement's SCOPE-AWARE target-lock.

    The allowed set is the named target's aliases plus the LIVE allowed set (the scope's exact
    hosts + every in-scope host recon has revealed). The matcher additionally accepts anything
    the PROGRAM SCOPE covers — a subdomain under a ``*.wildcard``, an IP inside a CIDR — so the
    loop can pivot within the authorized scope without re-entering mode. Exclusions always win
    (they are part of the matcher). Falls back to the single named target if the scope can't be
    resolved — fail-closed, never wider.
    """
    aliases = set(_engagement_aliases(eng.target))
    aliases.update(h for h in eng.allowed_hosts if h)
    try:
        matcher = engagement.resolved_scope(eng)
        return frozenset(aliases), matcher.in_scope, (eng.scope or eng.target)
    except Exception:  # pragma: no cover - defensive: a broken scope narrows, never widens
        return frozenset(aliases), None, eng.target


def check_target_lock(
    args: list[str],
    command: str | None = None,
    allowed: frozenset[str] | None = None,
    label: str | None = None,
    in_scope: Any = None,
) -> tuple[bool, str]:
    """BEST-EFFORT target-lock: every host-shaped token in args must be an allowed target.

    ``allowed`` defaults to the lab aliases (LAB mode — messages + behaviour unchanged); in
    ENGAGEMENT mode it is the engagement's live allowed set, ``in_scope`` is the PROGRAM SCOPE
    matcher (so any in-scope host passes, not just one exact host) and ``label`` names the scope
    in the reason. This is cheap defense-in-depth (it catches e.g. ``nmap evil.com``), NOT a
    load-bearing control: args can be an arbitrary command whose real target is invisible to any
    argv inspection (``python -c "...connect to X..."``, ``curl @file``, a host inside a base64
    blob). In LAB mode ISOLATION is the actual bound; in ENGAGEMENT mode there is no isolation
    floor and Wall A is down, so HUMAN APPROVAL of every command is the actual bound and this
    lock is an aid to the human, not a guarantee. ``command`` is for signature compatibility.

    A token is an allowed/in-scope target, another host (→ reject), or a non-host operand
    (→ ignore).

    TARGET-LESS COMMANDS split by mode. In LAB a command must still reference the lab —
    isolation is the real bound there and the rule is part of the locked lab invariant. In
    ENGAGEMENT a command that names no host at all is ALLOWED: the hosts of ``nmap -iL
    targets.txt`` live in the file, so refusing it protected nothing (this lock cannot see
    into files either way) while blocking a legitimate, human-approved command. Refusing
    where the check has no information is friction without safety.
    """
    is_lab = allowed is None and in_scope is None
    allow = allowed if allowed is not None else config.LAB_TARGET_ALIASES
    found = False
    for token in allowlist.extract_hostish(args):
        if token in allow:
            found = True
            continue
        if _looks_like_host(token):
            host = _host_of(token)
            if host in allow or (in_scope is not None and in_scope(token)):
                found = True
            elif is_lab:
                return False, f"target '{host}' is not the lab — only the lab is allowed"
            else:
                return False, f"target '{host}' is not in the engagement scope '{label}'"
        # else: bare non-host operand → ignore
    if not found and is_lab:
        return False, "no lab target specified — the command must reference the lab"
    return True, ""


def _resolved_target(
    command: str,
    args: list[str],
    allowed: frozenset[str] | None = None,
    default: str | None = None,
    in_scope: Any = None,
) -> str:
    """The host this command targets (for the record/UI), among the allowed/in-scope hosts."""
    allow = allowed if allowed is not None else config.LAB_TARGET_ALIASES
    for token in allowlist.extract_hostish(args):
        host = _host_of(token)
        if token in allow or host in allow:
            return host or (default or config.LAB_TARGET_HOST)
        if in_scope is not None and _looks_like_host(token) and in_scope(token):
            return host or (default or config.LAB_TARGET_HOST)
    return default or config.LAB_TARGET_HOST


def _engagement_for(request: ExecRequest) -> EngagementRecord | None:
    """The ACTIVE engagement this request runs under, or None (→ lab mode). An engagement_id
    that is set but not active resolves to None; the caller treats that as a hard refusal."""
    if not request.engagement_id:
        return None
    return engagement.get_active(request.engagement_id)


def validate_request(request: ExecRequest) -> ExecRejected | None:
    """Run the mode's gates in order, returning an ExecRejected on the first failure.

    MODE SPLIT (the whole risk model): if ``engagement_id`` names an ACTIVE, explicitly-entered
    engagement, the request runs against a REAL target with NO isolation floor and is gated by
    :func:`_validate_engagement`. Otherwise it is LAB mode, gated by :func:`_validate_lab` —
    entirely unchanged. An ``engagement_id`` that doesn't resolve is refused (never silently
    downgraded to lab), so engagement mode can only be reached by explicitly entering it.
    """
    if request.windows_profile_id:
        return _validate_windows(request)
    if request.engagement_id:
        eng = _engagement_for(request)
        if eng is None:
            return ExecRejected(
                reason="engagement mode is not active for this id — enter engagement mode first "
                "(POST /cockpit/engagement/enter); an unknown or exited engagement cannot run",
                gate="engagement",
            )
        return _validate_engagement(request, eng)
    return _validate_lab(request)


def _validate_lab(request: ExecRequest) -> ExecRejected | None:
    """LAB mode gates (UNCHANGED): best-effort target-lock (lab) → human approval → heuristic
    danger red-confirm → ISOLATION (the real lab containment: an egress-less sandbox)."""
    ok, reason = check_target_lock(request.args, request.command)
    if not ok:
        return ExecRejected(reason=reason, gate="target")

    if not request.approved:
        return ExecRejected(
            reason="command not approved — set approved=true to run", gate="approval"
        )

    # Danger gate: a command the HEURISTIC flags as dangerous (interpreter, reverse shell,
    # framework…) needs an EXPLICIT second confirm (dangerous_ack) on top of approval — so
    # arbitrary code / a shell can't be approved by accident, incl. an agent-proposed one.
    # NEVER blocks outright; requires the confirm. Over-inclusive assist — human is the gate.
    # Called DIRECTLY, not through danger_reasons_for_mode(): that dispatcher reaches
    # join_ps_command() on its windows branch, and test_winrm_safety asserts — statically, over
    # the call graph — that the LAB validator can never reach the PowerShell derivation. Routing
    # this through the dispatcher would make that control vacuous even though mode="lab" never
    # takes the branch at runtime. Same function either way.
    dangerous = allowlist.dangerous_command_heuristic(request.command, request.args)
    if dangerous and not request.dangerous_ack:
        return _danger_rejection(dangerous)

    try:
        assert_isolation_proven()
    except SandboxError as exc:
        return ExecRejected(reason=str(exc), gate="sandbox")

    return None


def _validate_engagement(request: ExecRequest, eng: EngagementRecord) -> ExecRejected | None:
    """ENGAGEMENT mode gates (REAL target, NO isolation floor, WALL A DOWN). Order:
        target-lock (the engagement's PROGRAM SCOPE) → NEVER-AUTO-RUN human approval →
        heuristic danger red-confirm.

    There is NO isolation gate and NO Wall-A gate here — the sandbox is FULLY OPEN (internet +
    LAN + host + metadata) on purpose. Nothing bounds WHERE it can reach. The ONLY bound is the
    per-command human approval below (there is no batch/approve-all path) plus the heuristic
    red-confirm — a conscious human on every single command. That guard now protects real
    targets AND the operator's own machine; it must hold every command, every time.
    """
    allowed, in_scope, label = _engagement_lock(eng)
    ok, reason = check_target_lock(
        request.args, request.command, allowed=allowed, label=label, in_scope=in_scope
    )

    # NEVER-AUTO-RUN: on a real target every single command needs an INDIVIDUAL human approval.
    # No batch, no approve-all, no autonomy. This is the load-bearing bound (Wall A is down) —
    # checked FIRST so it can never be skipped. Enforce hard.
    if not request.approved:
        return ExecRejected(
            reason="engagement mode: every command needs an individual human approval "
            "(approved=true) — never hands-off / no batch approval on a real target",
            gate="approval",
        )

    # TARGET-LOCK IS A HANDRAIL, NOT A WALL (accepted policy 2026-08-04: the target lock is a
    # handrail, per-command human approval is the wall — see docs/hackpit-scope-model). An
    # out-of-scope target does NOT dead-reject; it WARNS and refuses at the 'scope' gate until
    # the operator ticks the explicit scope_override (mirroring the dangerous-command red-confirm),
    # then runs — so going off the declared program scope stays a conscious act, never a reflex,
    # but the operator is never dead-ended. The lab and Windows target-locks stay HARD (isolated /
    # structurally-fixed hosts — different, contained models).
    if not ok and not request.scope_override:
        return _scope_rejection(reason)

    # Direct, for the same call-graph reason as _validate_lab above.
    dangerous = allowlist.dangerous_command_heuristic(request.command, request.args)
    if dangerous and not request.dangerous_ack:
        return _danger_rejection(dangerous)

    return None


def _validate_windows(request: ExecRequest) -> ExecRejected | None:
    """WINDOWS mode gates (a PowerShell command run on a Windows box over WinRM).

    A NEW EXECUTION TRANSPORT behind the SAME gate discipline (docs/WINDOWS-EXECUTION.md).
    Order:
        windows (the named profile exists) → target (the profile HOST is the lock; if an
        engagement is also named, its scope must additionally permit that host) →
        NEVER-AUTO-RUN human approval → heuristic danger red-confirm.

    There is NO isolation gate — the target is a real external box, exactly like engagement
    mode. The target-lock is STRUCTURAL: a Windows run reaches only the profile's host,
    resolved server-side from ``windows_profile_id`` (never a host in the request), so a
    command can never run against a box the operator did not pick. That is the same
    containment shape :kali gets from its hardcoded container.
    """
    profile = winprofiles.get_profile(request.windows_profile_id or "")
    if profile is None:
        return ExecRejected(
            reason="no such Windows target profile — create one (POST /cockpit/windows/profiles) "
            "or pick an existing one; a Windows run is locked to a saved profile's host",
            gate="windows",
        )

    # Belt-and-suspenders: if an engagement is ALSO named, the profile host must be inside
    # that engagement's authorized scope. This never widens anything — it only adds a second
    # check on top of the structural profile-host lock.
    if request.engagement_id:
        eng = _engagement_for(request)
        if eng is None:
            return ExecRejected(
                reason="engagement is not active for this id — cannot scope a Windows run to it",
                gate="engagement",
            )
        allowed, in_scope, label = _engagement_lock(eng)
        host = profile["host"]
        in_allowed = host in allowed
        in_matcher = bool(in_scope and in_scope(host))
        if not (in_allowed or in_matcher):
            return ExecRejected(
                reason=f"Windows target host '{host}' is not in the engagement scope '{label}'",
                gate="target",
            )

    # NEVER-AUTO-RUN: every command on a real Windows box needs an INDIVIDUAL human approval.
    # No batch, no approve-all, no autonomy — the orchestrator may PROPOSE a WinRM command but
    # can never fire one (regression-locked in test_winrm_safety.py).
    if not request.approved:
        return ExecRejected(
            reason="windows mode: every command needs an individual human approval "
            "(approved=true) — the orchestrator proposes, it never auto-runs a WinRM command",
            gate="approval",
        )

    dangerous = windows_danger_reasons(request.command, list(request.args))
    if dangerous and not request.dangerous_ack:
        return _danger_rejection(dangerous)
    return None


def join_ps_command(command: str, args: list[Any]) -> str:
    """The ONE PowerShell script a Windows run produces — command + args, rejoined.

    THE SINGLE DERIVATION, and the reason it is a function. This string is what the Windows
    transport executes, so it is also what the danger gate must classify. When those were built
    in two places the gate read ``argv[0]`` while the transport ran a whole script, and
    ``Write-Host go ; Invoke-Mimikatz`` was silent. Scanning a DIFFERENT string than the one
    that runs would reproduce that bug somewhere new, so every caller comes through here and
    test_winrm_safety asserts — on the source, transitively — that they still do.

    Takes ``(command, args)`` rather than a request because the AD orchestrator needs the same
    verdict for its advisory pre-check and is forbidden from constructing an ``ExecRequest``
    (a proposer that can build one is one line away from firing it — locked in
    test_adorch_safety.py).
    """
    return " ".join([str(command), *[str(a) for a in args]]).strip()


def build_ps_command(request: ExecRequest) -> str:
    """The PowerShell script for a request. Credentials live in the profile, never in the
    command, so nothing secret can leak into the command line, the record or the transcript."""
    return join_ps_command(request.command, list(request.args))


def windows_danger_reasons(command: str, args: list[Any]) -> list[str]:
    """Every reason a WinRM invocation must demand the red-confirm (empty if none).

    The UNION of two classifiers, and additive by construction — it can only ever ADD reasons
    to what the docker-path heuristic already returned, so no command flagged before this
    change is unflagged after it:

      * :func:`allowlist.dangerous_command_heuristic` on ``(command, args)`` — keeps the
        argv-shaped verdicts (eval flags, per-tool exec flags) that read the argument STRUCTURE;
      * :func:`allowlist.dangerous_script_heuristic` on the joined script — catches everything
        the first-token view could not see, because on this transport the whole string is a
        PowerShell program.

    Shared by the executor's gate and by the AD orchestrator's advisory pre-check, so the panel
    never promises a confirm the gate would not actually require, or stays quiet where it would.
    """
    reasons = list(allowlist.dangerous_command_heuristic(command, list(args)))
    for reason in allowlist.dangerous_script_heuristic(join_ps_command(command, list(args))):
        if reason not in reasons:
            reasons.append(reason)
    return reasons


def danger_reasons_for_mode(mode: str, command: str, args: list[Any]) -> list[str]:
    """Every reason THIS MODE's danger gate must demand the red-confirm (empty if none).

    THE MODE DISPATCH, in one place, for :func:`iter_run`'s belt-and-suspenders re-check on the
    prevalidated path — which knows only the resolved ``mode`` string, not which ``_validate_*``
    branch a request would have taken.

    WHY THE VALIDATORS DO NOT CALL THIS. They call their classifier directly and deliberately.
    This dispatcher reaches :func:`join_ps_command` through its windows branch, and
    test_winrm_safety asserts over the STATIC call graph that ``_validate_lab`` can never reach
    the PowerShell derivation — that assertion is the positive control proving the reachability
    check can fail at all. Wiring the docker-path validators through here would satisfy the
    type checker and quietly empty that control, even though ``mode="lab"`` never takes the
    windows branch at runtime. The classifier each side ends up calling is identical either
    way; only the call graph differs, and the call graph is what the control reads.

    The mode split is load-bearing, not cosmetic:
      * ``windows``        — the whole joined string is a PowerShell PROGRAM, so it needs
        :func:`windows_danger_reasons` (argv heuristic UNION whole-script heuristic). Reading
        only ``argv[0]`` here is Critical 2 from the 2026-07-27 gate audit: the gate saw
        ``Write-Host`` and the transport ran ``Write-Host go ; Invoke-Mimikatz``.
      * ``lab`` / ``engagement`` — argv-style docker exec, so the argument STRUCTURE is what
        matters and :func:`allowlist.dangerous_command_heuristic` is the right classifier.
    """
    if mode == "windows":
        return windows_danger_reasons(command, list(args))
    return list(allowlist.dangerous_command_heuristic(command, list(args)))


def _danger_rejection(reasons: list[str]) -> ExecRejected:
    """The ONE danger-gate rejection payload, so every path words it identically."""
    return ExecRejected(
        reason="this command is flagged dangerous — confirm to run: " + "; ".join(reasons),
        gate="danger",
        dangerous_flags=reasons,
    )


def _scope_rejection(reason: str) -> ExecRejected:
    """Engagement OFF-SCOPE rejection — a WARNING that becomes runnable with ``scope_override``,
    NOT a dead wall. Mirrors :func:`_danger_rejection`: the SAME command, re-approved with the
    override ticked, runs. The engagement target-lock is a handrail (accepted policy: per-command
    human approval is the only bound); this keeps going off-scope a conscious act, never a
    reflex, without ever dead-ending the operator."""
    return ExecRejected(
        reason="OFF SCOPE (handrail, not a wall) — " + reason + ". Tick 'override scope' and "
        "re-approve to run it anyway; you are asserting you are authorized for this host.",
        gate="scope",
    )


def engagement_offscope_reason(request: ExecRequest) -> str | None:
    """The off-scope warning for an engagement command, or None (in scope, or lab/Windows mode).
    Read-only: it only reports whether the target is outside the program scope, so the run can be
    annotated with a loud note when it proceeds under an override."""
    if request.windows_profile_id or not request.engagement_id:
        return None
    eng = _engagement_for(request)
    if eng is None:
        return None
    allowed, in_scope, label = _engagement_lock(eng)
    ok, reason = check_target_lock(
        request.args, request.command, allowed=allowed, label=label, in_scope=in_scope
    )
    return None if ok else reason


class EngagementInactive(RuntimeError):
    """The request names an engagement that is no longer active — nothing may run.

    Raised by :func:`resolve_mode` so a run can NEVER silently fall back to LAB mode
    against an id that was meant for a real target.
    """


class WindowsProfileUnavailable(RuntimeError):
    """The request names a Windows profile that no longer exists — nothing may run.

    Raised by :func:`resolve_mode` so a Windows run can never fall through to a different
    transport when its profile has been deleted mid-flight.
    """


class ResolvedMode(NamedTuple):
    """Which transport a request runs through, and what it is pointed at."""

    mode: str  # "lab" | "engagement" | "windows"
    container: str  # the sandbox container (lab/engagement) or a winrm:// marker (windows)
    target: str  # the resolved target, for the record/UI
    engagement: EngagementRecord | None
    windows_profile: dict[str, Any] | None = None  # the FULL profile (incl. secret) for WinRM


def resolve_mode(request: ExecRequest) -> ResolvedMode:
    """The SINGLE SOURCE OF TRUTH for which container a mode execs into.

    Shared by :func:`iter_run` (one-shot commands) and the live-session manager
    (cockpit/session.py), so a long-lived session can never bind to a different sandbox
    than a one-shot command would in the same mode. LAB → the isolated, egress-less
    sandbox; ENGAGEMENT → the fully-open engagement sandbox.

    Raises :class:`EngagementInactive` when ``engagement_id`` is set but no longer
    active. Pure: it only reads the engagement record and resolves names — it never
    executes anything, so calling it before a gate re-check is safe.
    """
    # WINDOWS mode: the transport is WinRM against the profile's host (resolved server-side
    # from the id). The host is the locked target; the container slot carries a winrm:// marker
    # only for display — the WinRM path never builds a docker argv.
    if request.windows_profile_id:
        profile = winprofiles.get_profile(request.windows_profile_id)
        if profile is None:
            raise WindowsProfileUnavailable(
                "the Windows target profile is no longer available — refusing to run"
            )
        return ResolvedMode(
            mode="windows",
            container=f"winrm://{profile['host']}:{profile['port']}",
            target=profile["host"],
            engagement=_engagement_for(request),
            windows_profile=profile,
        )

    eng = _engagement_for(request)
    if request.engagement_id and eng is None:
        raise EngagementInactive("engagement is no longer active — refusing to run")
    if eng is not None:
        allowed, in_scope, _label = _engagement_lock(eng)
        return ResolvedMode(
            mode="engagement",
            container=config.ENGAGE_SANDBOX_CONTAINER,
            target=_resolved_target(
                request.command,
                request.args,
                allowed=allowed,
                default=eng.target,
                in_scope=in_scope,
            ),
            engagement=eng,
        )
    return ResolvedMode(
        mode="lab",
        container=config.SANDBOX_CONTAINER,
        target=_resolved_target(request.command, request.args),
        engagement=None,
    )


def _danger_recheck(mode: str, request: ExecRequest) -> dict[str, Any] | None:
    """The rejected EVENT a flagged-but-unacked command earns inside :func:`iter_run`, or None.

    Mirrors the approval re-checks around it, and reuses :func:`danger_reasons_for_mode` so the
    verdict is byte-identical to the one :func:`validate_request` reached for the same request.
    """
    dangerous = danger_reasons_for_mode(mode, request.command, request.args)
    if not dangerous or request.dangerous_ack:
        return None
    return {
        "type": "rejected",
        "gate": "danger",
        "reason": "this command is flagged dangerous — confirm to run: " + "; ".join(dangerous),
        "dangerous_flags": dangerous,
    }


#: How each tool spells "send your traffic through this proxy". Keyed on the NORMALISED binary
#: name (allowlist._tool_name), because the spelling is not guessable and getting it wrong is
#: worse than not offering it: the run would silently bypass the proxy while the operator
#: believed it was captured. Only tools whose flag was verified against their own help output are
#: listed; everything else falls through to the honest "not captured" path.
_PROXY_FLAGS: dict[str, tuple[str, str]] = {
    # name          -> (flag, joiner)   joiner "" = separate argv token, "=" = glued
    "curl": ("-x", ""),
    "ffuf": ("-x", ""),
    "nuclei": ("-proxy", ""),
    "katana": ("-proxy", ""),
    # MEASURED 2026-08-04, against the real image: /usr/bin/httpx in hackpit/kali-sandbox is
    # the PYTHON httpx CLI ("Usage: httpx [OPTIONS] URL"), whose proxy flag is `--proxy`.
    # ProjectDiscovery's httpx — the one `-http-proxy` belongs to — installs as
    # `httpx-toolkit`. The two were mapped to the same flag, so asking to capture an `httpx`
    # run produced `httpx -http-proxy …`, which that CLI rejects outright. Same defect class
    # as "Kali ships no zap-baseline.py": the map named a flag for a tool that isn't there.
    "httpx": ("--proxy", ""),
    "httpx-toolkit": ("-http-proxy", ""),
    "sqlmap": ("--proxy", "="),
    "feroxbuster": ("--proxy", ""),
    "gobuster": ("--proxy", ""),
    "wpscan": ("--proxy", ""),
}


#: Tools whose flags belong AFTER a leading subcommand. Prepending to argv is right for the
#: flat tools and wrong for these, and wrong here is not subtle — MEASURED against the real
#: image on 2026-08-04, `gobuster --proxy http://… dir -u …` exits with "flag provided but
#: not defined: -proxy" and does nothing at all. That is the SHIPPING behaviour of the proxy
#: flag today: asking to capture a gobuster run breaks the run. Pacing would have reproduced
#: the bug exactly, so the placement rule lives here, once, and both rewrites use it.
_SUBCOMMAND_TOOLS = frozenset({"gobuster", "amass"})


def _place_flag(tool: str, args: list[str], prefix: list[str]) -> list[str]:
    """Insert a tool's own flag where that tool will actually parse it. PURE.

    After the leading subcommand for the tools that take one — recognised as a first argument
    that is not itself a flag, so a caller who already passed `dir` gets it right and one who
    passed none is left where they were rather than having a subcommand invented for them.
    """
    if tool in _SUBCOMMAND_TOOLS and args and not args[0].startswith("-"):
        return [args[0], *prefix, *args[1:]]
    return [*prefix, *args]


def _mask_proxy_url(url: str) -> str:
    """A proxy URL safe to show and RECORD — its ``user:pass@`` userinfo stripped. PURE.

    A pool URL can carry credentials; the honesty note and any run record built from it must
    not. Same rule that keeps the bypass-header VALUE and AD passwords out of persisted records.
    """
    if "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]
    return f"{scheme}://{rest}"


def _proxy_rewrite(command: str, args: list[str], url: str) -> tuple[list[str], bool]:
    """Inject a tool's own proxy flag pointing at ``url``. Returns ``(args, rewritten)``. PURE.

    The shared core under both :func:`apply_proxy` (INBOUND capture, loopback) and
    :func:`apply_egress` (OUTBOUND source-IP control, an external proxy). A proxy flag is a
    proxy flag to every tool — only the URL and the honesty note differ, so the injection lives
    once and the two public helpers format their own message. ``rewritten`` is False (and args
    are returned unchanged) exactly when the tool has no known proxy flag, so each caller can
    tell the honest "went direct" case and word it for its own purpose.
    """
    from .allowlist import _tool_name

    tool = _tool_name(command)
    entry = _PROXY_FLAGS.get(tool)
    if entry is None:
        return list(args), False
    flag, joiner = entry
    prefix = [f"{flag}={url}"] if joiner == "=" else [flag, url]
    return _place_flag(tool, list(args), prefix), True


def apply_proxy(command: str, args: list[str], port: int) -> tuple[list[str], str]:
    """Point one tool at the recording proxy. Returns ``(args, note)``. PURE.

    An ARGUMENT REWRITE on a request that still passes every gate — the same shape as
    ``tunnels.wrap_command``, which "adds a prefix; it introduces NO new execution capability and
    no new gate".

    A TOOL WITH NO KNOWN FLAG IS RETURNED UNCHANGED AND THE NOTE SAYS SO. Silently dropping the
    flag would hand the operator a run they believe was captured and was not, which is worse
    than not offering the option — the same honesty the lifecycle module applies to a listener
    whose bind it could not confirm.
    """
    url = f"http://127.0.0.1:{int(port)}"
    new_args, rewritten = _proxy_rewrite(command, args, url)
    if not rewritten:
        return new_args, (
            f"{command} has no known proxy flag — this run was NOT captured, it went direct"
        )
    return new_args, f"{command} routed through the recording proxy on {url}"


def apply_egress(command: str, args: list[str], url: str) -> tuple[list[str], str]:
    """Route one tool's OUTBOUND traffic through an external egress proxy. Returns ``(args, note)``. PURE.

    Same argv-rewrite shape as :func:`apply_proxy`; the difference is intent and destination —
    egress points at a controllable/rotating source-IP proxy (``url`` from the engagement's
    pool) so a single WAF ban does not strand the engagement, not at the loopback recorder.

    A TOOL WITH NO KNOWN PROXY FLAG IS RETURNED UNCHANGED AND THE NOTE SAYS SO PLAINLY: its
    traffic left from the sandbox's own IP, uncontrolled. That is the whole point of saying it —
    an operator who believes every run rode the rotating pool, while ``curl``/``python`` and any
    unmapped binary went direct, is exactly how the real IP leaks and gets banned. Container-
    level routing (proxychains in the engage sandbox) is the belt that covers those; this flag is
    the suspenders for the tools that speak proxy natively.
    """
    new_args, rewritten = _proxy_rewrite(command, args, url)
    if not rewritten:
        return new_args, (
            f"{command} has no known proxy flag — this run did NOT use the egress proxy, it "
            "went direct from the sandbox IP"
        )
    return new_args, f"{command} egressing via {_mask_proxy_url(url)}"


#: How each tool spells "add this request header". Same shape/rules as :data:`_PROXY_FLAGS`,
#: keyed on the NORMALISED binary name. Used to PIN an identifying header (many bug-bounty
#: programs REQUIRE you identify your traffic and PROHIBIT blind anonymisers) while the egress
#: IP rotates underneath. A tool with no header flag takes the honest no-op path — the header
#: was not added and the note says so, rather than pretending the run was attributable.
_HEADER_FLAGS: dict[str, tuple[str, str]] = {
    # name -> (flag, joiner)
    "curl": ("-H", ""),
    "ffuf": ("-H", ""),
    "nuclei": ("-H", ""),
    "katana": ("-H", ""),
    "httpx": ("-H", ""),
    "httpx-toolkit": ("-H", ""),
    "sqlmap": ("--header", "="),
    "feroxbuster": ("-H", ""),
    "wpscan": ("--headers", ""),
}


def apply_identify_header(command: str, args: list[str], header: str) -> tuple[list[str], str]:
    """Pin an identifying ``"Name: value"`` request header on one tool. Returns ``(args, note)``. PURE.

    The attribution half of egress: it says "this traffic is me" so a rotating source IP stays
    within a program's rules. Same honesty contract as the proxy rewrites — a tool with no known
    header flag is returned UNCHANGED and the note says the run went out UN-attributed, because
    an operator who thinks every run carried their identifying header when some did not is one
    program-rule violation away from a ban or worse.
    """
    from .allowlist import _tool_name

    header = header.strip()
    if not header:
        return list(args), ""
    tool = _tool_name(command)
    entry = _HEADER_FLAGS.get(tool)
    if entry is None:
        return list(args), (
            f"{command} has no known header flag — the identify header was NOT added; this run "
            "went out un-attributed"
        )
    flag, joiner = entry
    prefix = [f"{flag}={header}"] if joiner == "=" else [flag, header]
    return _place_flag(tool, list(args), prefix), f"{command} tagged with identify header ({header.split(':', 1)[0]})"


#: How each tool spells "go slower". Same shape as :data:`_PROXY_FLAGS` — keyed on the
#: NORMALISED binary name — with one extra element it cannot do without: a UNIT. A proxy URL
#: is a proxy URL to every tool, but throttling is spelled three incompatible ways (requests
#: per second, packets per second, or a delay BETWEEN requests), so the operator's single
#: number has to be converted per tool. Getting that conversion backwards would be worse than
#: not offering pacing at all: an operator asking for 2 req/s and silently getting a 2-second
#: delay interpreted as a rate would hammer the target while believing they were being polite.
#:
#: EVERY FLAG BELOW WAS READ OUT OF THE TOOL'S OWN `--help` INSIDE hackpit/kali-sandbox on
#: 2026-08-04, not recalled. Three candidates were REMOVED by that check rather than guessed
#: at, and they now take the honest no-flag path:
#:   * amass   — un-probeable in the sandbox (sudo vs no-new-privileges; see the image traps)
#:   * httpx   — the image's /usr/bin/httpx is the python CLI, which has no rate flag at all
#:               (its ProjectDiscovery namesake is httpx-toolkit, which does and is listed)
#:   * curl    — issues one request; there is nothing to pace, and --limit-rate is BANDWIDTH
#:
#: unit: "rps" requests/sec · "pps" packets/sec · "delay_s" seconds between requests
#:       "delay_ms" milliseconds between requests · "delay_go" a Go duration string ("200ms")
_PACE_FLAGS: dict[str, tuple[str, str, str]] = {
    # name          -> (flag, joiner, unit)   joiner "" = separate argv token, "=" = glued
    "ffuf": ("-rate", "", "rps"),
    "nuclei": ("-rate-limit", "", "rps"),
    "katana": ("-rate-limit", "", "rps"),
    "httpx-toolkit": ("-rate-limit", "", "rps"),
    "subfinder": ("-rate-limit", "", "rps"),
    "dnsx": ("-rate-limit", "", "rps"),
    "feroxbuster": ("--rate-limit", "", "rps"),
    # PACKETS per second, not requests. A port scanner's knob is the only pacing it has, and
    # it is the one that gets you rate-limited by a WAF or noticed by a NIDS.
    "nmap": ("--max-rate", "", "pps"),
    "masscan": ("--rate", "=", "pps"),
    "naabu": ("-rate", "", "pps"),
    # delay-between-requests tools — the operator's rate is INVERTED into a wait
    "sqlmap": ("--delay", "=", "delay_s"),
    "dirsearch": ("--delay", "=", "delay_s"),
    "wfuzz": ("-s", "", "delay_s"),
    "arjun": ("-d", "", "delay_s"),
    "wpscan": ("--throttle", "", "delay_ms"),
    "dalfox": ("--delay", "", "delay_ms"),
    "gobuster": ("--delay", "", "delay_go"),
}

#: Spellings that mean "the operator already set this tool's rate themselves". Checked before
#: adding anything: two rate flags on one command line is a contradiction the tool resolves
#: silently and differently per tool, which would leave the operator believing a pace applied
#: when their own value won. We defer to what they typed and say we did.
_PACE_ALREADY_SET: dict[str, tuple[str, ...]] = {
    "ffuf": ("-rate", "-p"),
    "nuclei": ("-rate-limit", "-rl", "-rate-limit-minute", "-rlm"),
    "katana": ("-rate-limit", "-rl", "-delay", "-rd"),
    "httpx-toolkit": ("-rate-limit", "-rl"),
    "subfinder": ("-rate-limit", "-rl"),
    "dnsx": ("-rate-limit", "-rl"),
    "feroxbuster": ("--rate-limit",),
    "nmap": ("--max-rate", "--min-rate"),
    "masscan": ("--rate", "--max-rate"),
    "naabu": ("-rate",),
    "sqlmap": ("--delay",),
    "dirsearch": ("--delay",),
    "wfuzz": ("-s",),
    "arjun": ("-d",),
    "wpscan": ("--throttle",),
    "dalfox": ("--delay",),
    "gobuster": ("--delay", "-d"),
}


def _pace_value(rate: int, unit: str) -> str:
    """The operator's requests-per-second expressed in one tool's own unit."""
    rate = max(1, int(rate))
    if unit in ("rps", "pps"):
        return str(rate)
    if unit == "delay_s":
        # 1 req/s -> 1s, 4 req/s -> 0.25s. Trimmed so a whole number reads as "1", not "1.0".
        secs = round(1.0 / rate, 3)
        return str(int(secs)) if secs == int(secs) else str(secs)
    ms = max(1, round(1000.0 / rate))
    return f"{ms}ms" if unit == "delay_go" else str(ms)


def apply_pace(command: str, args: list[str], rate: int) -> tuple[list[str], str]:
    """Throttle one tool to ``rate`` requests per second. Returns ``(args, note)``. PURE.

    The same ARGUMENT REWRITE shape as :func:`apply_proxy`, on a request that still passes
    every gate. Nothing here is a safety control — a paced command is not a safer command,
    it is a quieter one, and every gate still applies to the rewritten argv exactly as before.

    A TOOL WITH NO KNOWN THROTTLE FLAG IS RETURNED UNCHANGED AND THE NOTE SAYS SO. This is
    the whole point: a run the operator believes was paced and was not is how a program bans
    your IP mid-engagement, and it is worse than being told plainly that this tool will go
    full speed. Same rule the proxy flag follows for capture.

    A tool that ALREADY carries its own rate flag is likewise left alone and says so, rather
    than being handed a second, contradictory one.
    """
    from .allowlist import _tool_name

    tool = _tool_name(command)
    entry = _PACE_FLAGS.get(tool)
    if entry is None:
        return list(args), (
            f"{command} has no known throttle flag — this run was NOT paced, it went at "
            "full speed"
        )
    existing = _PACE_ALREADY_SET.get(tool, ())
    for a in args:
        head = a.split("=", 1)[0]
        if head in existing:
            return list(args), (
                f"{command} already sets its own rate ({head}) — left as you typed it, NOT "
                f"re-paced to {rate}/s"
            )
    flag, joiner, unit = entry
    value = _pace_value(rate, unit)
    prefix = [f"{flag}={value}"] if joiner == "=" else [flag, value]
    how = (
        f"{flag} {value}" if unit in ("rps", "pps") else f"{flag} {value} between requests"
    )
    return _place_flag(tool, list(args), prefix), f"{command} paced to ~{rate}/s ({how})"


def apply_pace_to_request(request: ExecRequest) -> tuple[ExecRequest, str]:
    """Apply :func:`apply_pace` to a request, if it asked for it. Returns (request, note).

    ENGAGEMENT MODE ONLY, deliberately. Pacing exists to keep a REAL program from banning
    you; the lab target is a container on an isolated network with nobody to annoy, and
    slowing lab runs down would be a behaviour change to the mode this build keeps
    byte-identical. Windows/WinRM is excluded too: that transport sends a PowerShell string,
    not an argv, so there is no flag to add.

    Returns the request UNCHANGED (and an empty note) whenever nothing was rewritten — same
    contract as :func:`apply_proxy_to_request`, so the caller can tell "nothing happened"
    from "rewritten" and only discard a prevalidated verdict in the second case. The honest
    "not paced" message for the operator is produced by :func:`run_notes`, which reports it
    whether or not the argv changed.
    """
    if not getattr(request, "pace", None):
        return request, ""
    if request.windows_profile_id or not request.engagement_id:
        return request, ""
    new_args, note = apply_pace(request.command, list(request.args), int(request.pace))
    if new_args == list(request.args):
        return request, ""
    return request.model_copy(update={"args": new_args}), note


def run_notes(request: ExecRequest) -> list[str]:
    """What the operator needs told about how this run was rewritten, before it runs. PURE.

    Separate from the two ``*_to_request`` helpers because their return value answers a
    different question — "did the argv change?", which is what decides whether a prevalidated
    verdict survives. The cases that matter most here are exactly the ones where the argv did
    NOT change: the tool has no proxy flag, the tool has no throttle flag, pacing was asked
    for in lab mode. Those produce an empty change-note by design, and reporting them is the
    difference between an honest run and one the operator misreads.
    """
    notes: list[str] = []
    if getattr(request, "proxy", False):
        from . import proxy as proxy_mod

        _, note = apply_proxy(request.command, list(request.args), proxy_mod.DEFAULT_PROXY_PORT)
        notes.append(note)
    rate = getattr(request, "pace", None)
    if rate:
        if request.windows_profile_id:
            notes.append(
                "pacing is not available over WinRM — that transport sends a PowerShell "
                "string, not a command line with flags; this run was NOT paced"
            )
        elif not request.engagement_id:
            notes.append(
                "pacing applies in engagement mode only — this is a LAB run against the "
                "isolated target and was NOT paced"
            )
        else:
            _, note = apply_pace(request.command, list(request.args), int(rate))
            notes.append(note)
    if getattr(request, "egress", False):
        # The honest no-op cases only — each is determinable WITHOUT advancing rotation, so the
        # "egressing via <ip>" note (the one case that IS rewritten) is left to
        # apply_egress_to_request, which picks the URL exactly once. Reporting them here is the
        # difference between an operator who knows this run left from the real IP and one who
        # believes the pool covered it.
        if request.windows_profile_id:
            notes.append(
                "egress control is not available over WinRM — that transport sends a PowerShell "
                "string, not a command line with flags; this run was NOT routed through the pool"
            )
        elif not request.engagement_id:
            notes.append(
                "egress control applies in engagement mode only — this is a LAB run against the "
                "isolated target and went direct"
            )
        elif getattr(request, "proxy", False):
            notes.append(
                "egress not applied — this run already routes through the recording proxy; "
                "stacking a second proxy flag would be a contradiction the tool resolves silently"
            )
        else:
            from . import engagement as engagement_mod
            from .allowlist import _tool_name

            if engagement_mod.egress_pool_size(request.engagement_id) == 0:
                notes.append(
                    "no egress pool is configured for this engagement — this run went direct "
                    "from the sandbox IP"
                )
            elif _tool_name(request.command) not in _PROXY_FLAGS:
                notes.append(
                    f"{request.command} has no known proxy flag — this run did NOT use the "
                    "egress proxy, it went direct from the sandbox IP"
                )
    return notes


def apply_proxy_to_request(request: ExecRequest) -> tuple[ExecRequest, str]:
    """Apply :func:`apply_proxy` to a request, if it asked for it. Returns (request, note).

    Returns the request UNCHANGED (and an empty note) when ``proxy`` is off or the tool has no
    known flag, so the caller can tell "nothing happened" from "rewritten" and only discard a
    prevalidated verdict in the second case.
    """
    if not getattr(request, "proxy", False):
        return request, ""
    from . import proxy as proxy_mod

    new_args, note = apply_proxy(request.command, list(request.args), proxy_mod.DEFAULT_PROXY_PORT)
    if new_args == list(request.args):
        return request, ""
    return request.model_copy(update={"args": new_args}), note


def apply_egress_to_request(request: ExecRequest) -> tuple[ExecRequest, str]:
    """Route this run through the engagement's egress pool, if it asked and one is usable.

    ENGAGEMENT MODE ONLY, like pacing and for the same reason: egress control exists to keep a
    REAL program from banning your one source IP; a lab run is an isolated container with no IP
    to protect, and WinRM sends a PowerShell string with no argv flag to add. Picks ONE pool URL
    (advancing rotation once) and injects the tool's proxy flag, then pins the engagement's
    identify header if one is set. Skipped when the recording proxy is already in play — two
    proxy flags on one command line is a contradiction the tool resolves silently.

    Returns the request UNCHANGED (empty note) whenever nothing was rewritten — same contract as
    the sibling helpers, so the caller only discards a prevalidated verdict when the argv changed.
    The honest "no pool / no flag / lab / captured instead" messages are produced by
    :func:`run_notes`, which needs no rotation pick to word them.
    """
    if not getattr(request, "egress", False):
        return request, ""
    if request.windows_profile_id or not request.engagement_id:
        return request, ""
    if getattr(request, "proxy", False):  # recording proxy wins; don't stack a second proxy flag
        return request, ""
    from . import egress as egress_mod
    from . import engagement as engagement_mod

    url = egress_mod.pick(request.engagement_id)
    if url is None:
        return request, ""
    new_args, _ = apply_egress(request.command, list(request.args), url)
    _, header = engagement_mod.egress_config(request.engagement_id)
    if header:
        new_args, _ = apply_identify_header(request.command, new_args, header)
    if new_args == list(request.args):
        return request, ""
    return request.model_copy(update={"args": new_args}), (
        f"{request.command} egressing via {_mask_proxy_url(url)}"
    )


def _timeout_verdict(idle: float, total: float, idle_limit: int, ceiling: int) -> str:
    """Whether (and why) a streaming run should be killed. Pure, so the watchdog POLICY is
    testable without a subprocess.

    A command that is actively producing output is "properly running" and must NOT be killed —
    so the per-run timeout is an IDLE window (time with NO output), not a wall-clock cap: a scan
    that keeps printing resets it every line and runs to completion. A separate absolute
    ``ceiling`` still reaps a runaway that streams forever. Neither is a safety property — the
    safety gates are target-lock, approval and danger-confirm, none of which a timeout touches.

    Returns ``"idle"`` (silent too long — looks stuck), ``"ceiling"`` (absolute cap hit), or
    ``""`` (keep running).
    """
    if idle >= idle_limit:
        return "idle"
    if total >= ceiling:
        return "ceiling"
    return ""


def iter_run(request: ExecRequest, prevalidated: bool = False) -> Iterator[dict[str, Any]]:
    """Validate then stream a run as events.

    Yields dict events: {type: start|stdout|stderr|exit|rejected|error, ...}. The full
    output is accumulated and persisted as a RunRecord when the process finishes. The
    caller (router) formats events for transport (SSE). Validation happens first, so a
    rejected request yields exactly one {type: rejected} event and nothing runs.

    ``prevalidated=True`` skips the full gate chain when the caller (router) already ran
    validate_request to decide the HTTP status. It does NOT skip everything: the engagement
    liveness check, the per-mode APPROVAL re-check and the per-mode DANGER re-check all run
    regardless, so the two gates that are the sole floor on a real target cannot be lost by a
    caller that forgets to validate first. Regression-locked in test_prevalidated_gates.py.
    """
    # THE PROXY REWRITE HAPPENS FIRST, AND IT CANCELS `prevalidated`.
    # Pointing a tool at the recording proxy changes the argv. A caller that validated the
    # ORIGINAL request has a verdict about a DIFFERENT command line than the one about to run —
    # which is Critical 2 wearing a new hat. So when the rewrite actually changes something, the
    # earlier verdict is discarded and the REWRITTEN request is validated here. Adding an
    # argument can only ever make the danger classifier fire MORE, never less, so re-validating
    # is strictly safe; skipping it would not be.
    #
    # THE PACE REWRITE rides the same rails, for the same reason: it adds an argument, so the
    # argv the gates classify must be the argv that runs. Both notes are computed from the
    # ORIGINAL request first, because the messages that matter — "no proxy flag", "no throttle
    # flag", "lab run, not paced" — are precisely the ones where nothing was rewritten.
    notes = run_notes(request)
    # A run that proceeds OFF the declared program scope (scope_override ticked) is annotated
    # loudly, so the transcript and the record show it went outside scope — never silent.
    _off_scope = engagement_offscope_reason(request)
    if _off_scope and request.scope_override:
        notes.append(f"⚠ RAN OFF SCOPE (override): {_off_scope}")
    request, proxy_note = apply_proxy_to_request(request)
    if proxy_note:
        prevalidated = False
    request, pace_note = apply_pace_to_request(request)
    if pace_note:
        prevalidated = False
    # THE EGRESS REWRITE rides the same rails: it adds the tool's proxy flag (and maybe an
    # identify header), so the argv the gates classify must be the argv that runs. Adding an
    # argument can only make the danger classifier fire MORE, never less, so re-validating the
    # rewritten request is strictly safe.
    request, egress_note = apply_egress_to_request(request)
    if egress_note:
        prevalidated = False

    if not prevalidated:
        rejected = validate_request(request)
        if rejected is not None:
            yield {"type": "rejected", "gate": rejected.gate, "reason": rejected.reason}
            return

    # Route by mode. An engagement_id that is set but no longer active is refused here too
    # (even when prevalidated), so a run can NEVER fall back to lab against a real-target id.
    try:
        resolved = resolve_mode(request)
    except EngagementInactive as exc:
        yield {"type": "rejected", "gate": "engagement", "reason": str(exc)}
        return
    except WindowsProfileUnavailable as exc:
        yield {"type": "rejected", "gate": "windows", "reason": str(exc)}
        return
    mode, container, target, eng = (
        resolved.mode, resolved.container, resolved.target, resolved.engagement
    )

    # WINDOWS mode: a PowerShell command run on a real Windows box over WinRM. Belt-and-
    # suspenders approval re-check (like engagement) — never-auto-run is the sole floor on a
    # real target, so its enforcement must not depend on every caller running validate first.
    if mode == "windows":
        if not request.approved:
            yield {
                "type": "rejected",
                "gate": "approval",
                "reason": "windows mode: every command needs an individual human approval "
                "(approved=true) — the orchestrator proposes, it never auto-runs a WinRM command",
            }
            return
        rejected = _danger_recheck(resolved.mode, request)
        if rejected is not None:
            yield rejected
            return
        yield from _run_windows(request, resolved)
        return

    if eng is not None:
        # Belt-and-suspenders (ENGAGEMENT ONLY): with Wall A down, per-command human
        # approval is the SOLE floor on a real target, so its enforcement must not depend
        # solely on every future caller remembering to run validate_request first. Re-check
        # approval here even in the prevalidated path. This is a pure no-op for valid flows —
        # the router runs validate_request (which rejects an unapproved engagement at the
        # approval gate) before it ever sets prevalidated=True. The LAB path is deliberately
        # left behaviourally unchanged.
        if not request.approved:
            yield {
                "type": "rejected",
                "gate": "approval",
                "reason": "engagement mode: every command needs an individual human approval "
                "(approved=true) — never hands-off / no batch approval on a real target",
            }
            return

    # Belt-and-suspenders DANGER re-check (ALL THREE MODES — build #7). Same reasoning as the
    # approval re-checks above, applied to the other gate that a prevalidated caller could
    # skip. Nothing was exposed when this was added — the one prevalidated=True caller
    # (cockpit/router.py) validates first — but the asymmetry was a trap for the SECOND
    # caller: approval was re-checked here and danger was not, so a future caller that
    # prevalidated a dangerous command would have run it with no red-confirm. Additive by
    # construction: it can only ever ADD a rejection, and only for a command the same
    # classifier validate_request uses already flags.
    rejected = _danger_recheck(mode, request)
    if rejected is not None:
        yield rejected
        return

    run_id = uuid.uuid4().hex[:12]
    started_at = _now()
    # Wall-clock start, kept so the state ingest can tell which loot files THIS run wrote.
    # Loot directories persist across runs; without this, an old scan's XML would be
    # re-attributed to whatever ran last and the source_run_id would be a lie.
    started_epoch = time.time()
    # Working directory: engagement runs land in their own loot directory so `-oA scan`
    # writes somewhere durable. LAB runs get None -> no -w flag -> argv byte-identical to
    # what it was before loot existed. See cockpit/loot.py for why the lab is excluded.
    workdir = loot.workdir_for(mode, eng.engagement_id if eng is not None else None)
    timeout_seconds = config.clamp_timeout(request.timeout_seconds)
    argv = ["docker", "exec", *loot.exec_flags(workdir), container, request.command, *request.args]

    yield {
        "type": "start",
        "run_id": run_id,
        "command": request.command,
        "args": request.args,
        "target": target,
        "mode": mode,
        "started_at": started_at,
        "timeout_seconds": timeout_seconds,
        "workdir": workdir,
        # How this run was rewritten, in the operator's words — INCLUDING the cases where it
        # was not. "curl has no known throttle flag — this run was NOT paced" has to arrive
        # before the output does, or the operator reads a full-speed run as a paced one.
        "notes": notes,
    }

    out_buf: list[str] = []
    err_buf: list[str] = []
    exit_code: int | None = None
    events: "queue.Queue[dict[str, Any]]" = queue.Queue()

    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        yield {"type": "error", "reason": "docker CLI not found on PATH"}
        return

    # Last time this run produced ANY output. The watchdog treats a run that keeps printing as
    # "properly running" and never kills it — only silence past the idle window is "stuck".
    last_activity = {"t": time.monotonic()}

    def _pump(stream, kind: str, buf: list[str]) -> None:
        for line in iter(stream.readline, ""):
            last_activity["t"] = time.monotonic()
            buf.append(line)
            events.put({"type": kind, "line": line.rstrip("\n")})
        stream.close()

    threads = [
        threading.Thread(target=_pump, args=(proc.stdout, "stdout", out_buf), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, "stderr", err_buf), daemon=True),
    ]
    for t in threads:
        t.start()

    # IDLE timeout, not wall-clock (build 2026-08-14): a command actively producing output is
    # "properly running" and is never killed — `timeout_seconds` is the max time with NO output
    # before it looks stuck. A separate absolute ceiling (MAX_TIMEOUT_SECONDS) still reaps a
    # runaway that streams forever. The timeout is a resource bound, never a safety property.
    timed_out = {"v": ""}  # "" | "idle" | "ceiling"
    ceiling = max(timeout_seconds, config.MAX_TIMEOUT_SECONDS)
    start_mono = time.monotonic()

    def _watchdog() -> None:
        while proc.poll() is None:
            now = time.monotonic()
            verdict = _timeout_verdict(
                now - last_activity["t"], now - start_mono, timeout_seconds, ceiling
            )
            if verdict:
                timed_out["v"] = verdict
                proc.kill()
                return
            time.sleep(1.0)

    wd = threading.Thread(target=_watchdog, daemon=True)
    wd.start()

    # Drain events until the process exits and both pumps finish.
    while True:
        try:
            ev = events.get(timeout=0.2)
            yield ev
        except queue.Empty:
            if proc.poll() is not None and not any(t.is_alive() for t in threads):
                break

    # flush any last events
    while not events.empty():
        yield events.get_nowait()

    exit_code = proc.poll()
    finished_at = _now()
    if timed_out["v"] == "idle":
        yield {
            "type": "error",
            "reason": (
                f"no output for {timeout_seconds}s — looked stuck, killed. "
                "A command that keeps producing output is never timed out."
            ),
        }
    elif timed_out["v"] == "ceiling":
        yield {
            "type": "error",
            "reason": f"hit the {ceiling}s absolute ceiling (HACKPIT_MAX_TIMEOUT) and was killed",
        }

    record = RunRecord(
        run_id=run_id,
        command=request.command,
        # A credentialed Linux tool (bloodhound-python, netexec, impacket-*) carries its secret
        # as an argv token — the only interface it has. The EXECUTED argv above is untouched;
        # what gets PERSISTED is redacted, because the stored record is what the audit trail,
        # the rendered report and the LLM proposer context all read back. See secretargs.py.
        args=secretargs.redact_argv(request.command, request.args),
        target=target,
        approved=request.approved,
        mode=mode,
        exit_code=exit_code,
        stdout="".join(out_buf),
        stderr="".join(err_buf),
        started_at=started_at,
        finished_at=finished_at,
        session_id=request.session_id,
        step_id=request.step_id,
    )
    try:
        runstore.save_run(record)
    except Exception as exc:  # persistence must never crash the stream
        yield {"type": "error", "reason": f"run recorded in-memory only: {exc}"}

    # STATE INGEST: turn this finished run into structured state — hosts, services,
    # endpoints, credentials, findings — from its stdout AND from any file it just wrote
    # into its loot directory (that is how `nmap -oA` gets picked up). Additive enrichment,
    # never a gate: the command has already run and a failure here must not surface as a
    # run failure. The ingest layer executes nothing.
    if request.session_id:
        try:
            counts = state_ingest.ingest_run(
                session_id=request.session_id,
                run_id=run_id,
                command=request.command,
                stdout=record.stdout,
                # target + full command line let the proof/local.txt flag capture attribute a
                # flag to the right host (the flag file sits in the args, e.g. `cat proof.txt`).
                target=record.target or "",
                command_line=" ".join([request.command, *request.args]),
                loot_dir=Path(loot.host_dir(eng.engagement_id)) if eng is not None else None,
                started_at_epoch=started_epoch,
            )
            if any(counts.values()):
                yield {"type": "state", "run_id": run_id, "added": counts}
        except Exception as exc:  # pragma: no cover - never load-bearing
            yield {"type": "error", "reason": f"state ingest skipped: {exc}"}

    # RECON-DRIVEN EXPANSION (engagement only): mine this run's output for hosts and sort them
    # by the engagement's PROGRAM SCOPE. In-scope hosts join the live allowed set (so the loop
    # can pivot to them); out-of-scope hosts are surfaced read-only and never added. This
    # approves NOTHING — every command against a discovered host still needs its own individual
    # human approval. Best-effort: a failure here can never affect the run that already ran.
    if eng is not None:
        try:
            found = engagement.record_discoveries(
                eng, record.stdout + record.stderr, run_id=run_id
            )
            if found["added"] or found["out_of_scope"]:
                yield {
                    "type": "discovered",
                    "run_id": run_id,
                    "in_scope": found["added"],
                    "out_of_scope": found["out_of_scope"],
                    "truncated": found["truncated"],
                }
        except Exception as exc:  # pragma: no cover - never load-bearing
            yield {"type": "error", "reason": f"scope expansion skipped: {exc}"}

    yield {"type": "exit", "run_id": run_id, "code": exit_code, "finished_at": finished_at}


def _run_windows(request: ExecRequest, resolved: "ResolvedMode") -> Iterator[dict[str, Any]]:
    """Run ONE PowerShell command on a Windows target over WinRM, streaming events.

    Same event shape and same finalisation (record → state ingest → recon expansion) as the
    docker path — only the transport differs. WinRM is request/response rather than a live
    line stream, so the whole command runs on a worker thread (bounded by a wall-clock
    timeout) and its captured stdout/stderr are emitted line-by-line once it returns.

    The gates already ran (validate_request → _validate_windows) and approval was re-checked
    by the caller. The target is the profile HOST, resolved server-side — this function is
    handed the profile, it never reads a host from the request.
    """
    profile = resolved.windows_profile or {}
    eng = resolved.engagement
    target = resolved.target
    # One PowerShell command STRING (fork #2), derived by the SAME function the danger gate
    # classified — see build_ps_command() for why that sharing is the actual fix.
    ps_command = build_ps_command(request)

    run_id = uuid.uuid4().hex[:12]
    started_at = _now()
    started_epoch = time.time()
    timeout_seconds = config.clamp_timeout(request.timeout_seconds)

    yield {
        "type": "start",
        "run_id": run_id,
        "command": request.command,
        "args": request.args,
        "target": target,
        "mode": "windows",
        "transport": "winrm",
        "container": resolved.container,  # winrm://host:port — display only
        "started_at": started_at,
        "timeout_seconds": timeout_seconds,
        "workdir": None,
    }

    box: dict[str, Any] = {"result": None, "error": None}

    def _worker() -> None:
        try:
            box["result"] = winrm_transport.run(profile, ps_command, timeout_seconds)
        except winrm_transport.WinRMError as exc:
            box["error"] = str(exc)
        except Exception as exc:  # pragma: no cover - defensive, transport is isolated
            box["error"] = f"WinRM transport error: {exc}"

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()
    worker.join(timeout=timeout_seconds + 5)  # +5: the transport has its own read timeout

    stdout = ""
    stderr = ""
    exit_code: int | None = None
    finished_at = _now()

    if worker.is_alive():
        yield {"type": "error", "reason": f"timed out after {timeout_seconds}s"}
        stderr = f"[winrm] timed out after {timeout_seconds}s"
    elif box["error"] is not None:
        yield {"type": "error", "reason": box["error"]}
        stderr = str(box["error"])
    else:
        result = box["result"]
        stdout = result.stdout if result else ""
        stderr = result.stderr if result else ""
        exit_code = result.exit_code if result else None
        for line in stdout.splitlines():
            yield {"type": "stdout", "line": line}
        for line in stderr.splitlines():
            yield {"type": "stderr", "line": line}

    record = RunRecord(
        run_id=run_id,
        command=request.command,
        # Uniform with the docker path. A Windows run has no secret in its argv by construction
        # (the credential is resolved server-side from the profile), so this is a no-op there —
        # but it must not be the ONE record path that skips the redaction.
        args=secretargs.redact_argv(request.command, request.args),
        target=target,
        approved=request.approved,
        mode="windows",
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        started_at=started_at,
        finished_at=finished_at,
        session_id=request.session_id,
        step_id=request.step_id,
    )
    try:
        runstore.save_run(record)
    except Exception as exc:  # persistence must never crash the stream
        yield {"type": "error", "reason": f"run recorded in-memory only: {exc}"}

    # STATE INGEST — turn the remote command's stdout into structured state (hosts, creds,
    # findings, proof flags). No loot directory: WinRM output comes back as text, not files.
    if request.session_id:
        try:
            counts = state_ingest.ingest_run(
                session_id=request.session_id,
                run_id=run_id,
                command=request.command,
                stdout=record.stdout,
                target=record.target or "",
                command_line=ps_command,
                loot_dir=None,
                started_at_epoch=started_epoch,
            )
            if any(counts.values()):
                yield {"type": "state", "run_id": run_id, "added": counts}
        except Exception as exc:  # pragma: no cover - never load-bearing
            yield {"type": "error", "reason": f"state ingest skipped: {exc}"}

    # RECON-DRIVEN EXPANSION (only when a Windows run is also scoped to an engagement): mine
    # the output for hosts and sort them by the engagement scope. Approves nothing.
    if eng is not None:
        try:
            found = engagement.record_discoveries(
                eng, record.stdout + record.stderr, run_id=run_id
            )
            if found["added"] or found["out_of_scope"]:
                yield {
                    "type": "discovered",
                    "run_id": run_id,
                    "in_scope": found["added"],
                    "out_of_scope": found["out_of_scope"],
                    "truncated": found["truncated"],
                }
        except Exception as exc:  # pragma: no cover - never load-bearing
            yield {"type": "error", "reason": f"scope expansion skipped: {exc}"}

    yield {"type": "exit", "run_id": run_id, "code": exit_code, "finished_at": finished_at}


def run_command(request: ExecRequest) -> RunRecord:
    """Non-streaming convenience: run to completion and return the RunRecord.

    Raises SandboxError/ValueError semantics via the ExecRejected path — used by tests
    and the dry-run. Prefer iter_run() for the live UI.
    """
    rejected = validate_request(request)
    if rejected is not None:
        raise PermissionError(f"[{rejected.gate}] {rejected.reason}")

    last_exit: int | None = None
    run_id = None
    for ev in iter_run(request):
        if ev["type"] == "start":
            run_id = ev["run_id"]
        elif ev["type"] == "exit":
            last_exit = ev["code"]
    assert run_id is not None
    record = runstore.get_run(run_id)
    if record is None:  # pragma: no cover - defensive
        raise RuntimeError("run completed but record not found")
    return record


# --------------------------------------------------------------------------- #
# GATED WINDOWS FILE DELIVERY (build #13 part 2)
#
# WHY THIS LIVES HERE AND NOT IN THE CALLER. `test_winrm_safety` scans the whole tree and
# allows only this module and the router to reach `winrm_transport` — the orchestrator
# PROPOSES, it must never fire WinRM. The evasion engine genuinely needs to put a file on a
# Windows host, and its first implementation imported the transport directly. That trips the
# scan, and adding the engine to the allow-list would have been the wrong fix: it would mean a
# THIRD module that can fire WinRM, and it would leave that module re-implementing the gates
# beside the ones that already live here.
#
# So the capability lives at the gated execution point, where every other Windows command
# already goes, and callers get it by asking rather than by reaching around. The gate runs
# HERE — one human approval for one delivery, with the chunking an implementation detail of
# that single approved operation rather than N separate commands nobody could sanely approve.
# --------------------------------------------------------------------------- #
def send_windows_scripts(
    request: ExecRequest,
    scripts: list[str],
    *,
    timeout_seconds: int = 300,
) -> list[dict[str, Any]]:
    """Run a SEQUENCE of PowerShell scripts on the request's profile host, as ONE gated act.

    The whole sequence is one approved operation: a chunked upload is not N commands a human
    could meaningfully approve one at a time, it is one transfer. So the gates run once, here,
    against the request the caller built — and if any of them refuses, NOTHING is sent.

    Stops at the first non-zero status: a chunk that failed means every later chunk would be
    appending to a file that is already wrong.
    """
    rejected = _validate_windows(request)
    if rejected is not None:
        raise WindowsDeliveryRefused(rejected.reason, rejected.gate)
    if not request.approved:
        raise WindowsDeliveryRefused(
            "windows delivery: every delivery needs an individual human approval "
            "(approved=true) — the orchestrator proposes, it never auto-runs a WinRM command",
            "approval",
        )

    resolved = resolve_mode(request)
    profile = resolved.windows_profile or {}
    out: list[dict[str, Any]] = []
    for script in scripts:
        try:
            res = winrm_transport.run(profile, script, timeout_seconds)
            out.append({"status_code": res.status_code, "stdout": res.stdout,
                        "stderr": res.stderr})
        except winrm_transport.WinRMError as exc:
            out.append({"status_code": 1, "stdout": "", "stderr": str(exc)})
        if out[-1]["status_code"] != 0:
            break
    return out


class WindowsDeliveryRefused(RuntimeError):
    """A gated Windows delivery that was refused. Carries the gate that refused it."""

    def __init__(self, reason: str, gate: str = "windows") -> None:
        super().__init__(reason)
        self.reason = reason
        self.gate = gate


# --------------------------------------------------------------------------- #
# GATED OOB CANARY DEPLOY (build #13 part 3, spec §3.5)
#
# WHY IT IS HERE. Shipping `oob/server.py` to a VPS and starting it is a NEW REMOTE-EXECUTION
# PATH — a third transport after docker exec and WinRM. Part 2 of this build already made the
# mistake this avoids: `deliver` grew its own WinRM call, reached around the gated execution
# point, and a whole-tree guard caught it. Adding that module to the guard's allow-list would
# have meant a second module that can fire a remote command while re-implementing the gates
# next to the ones that already live in this file. So the capability lives here, where every
# other remote command already goes, and callers get it by asking.
#
# WHY IT TAKES NO DESTINATION. There is no host, user, port or key parameter below — not a
# defaulted one, not an optional one. The destination is read from `oob.config.deploy_target()`,
# which itself takes no arguments. That is the entire containment argument: there is no way to
# EXPRESS "deploy somewhere else", so no request field, no agent proposal and no future
# refactor can redirect it. `test_oob_deploy_safety.py` asserts the signature over the AST
# rather than trusting this comment.
#
# WHY THE SUBPROCESS RUNS ON THE HOST, when cockpit/repeater.py deliberately refused to.
# The repeater sends OPERATOR-COMPOSED requests to ARBITRARY hosts; doing that from the backend
# process would have created a general egress path out of the operator's machine, so it execs
# curl inside the open sandbox instead. Neither half of that applies here: the destination is
# one validated hostname from the store, and the request is a fixed command. Running it in the
# sandbox would additionally require mounting the operator's SSH PRIVATE KEY into a container
# that also runs attack tooling — strictly worse than the thing it would be avoiding.
# --------------------------------------------------------------------------- #

# Where server.py comes from. The repository's own copy — never a caller's bytes, so a deploy
# cannot be used to put an arbitrary file on the VPS.
_OOB_SERVER_SOURCE = Path(__file__).resolve().parent.parent.parent / "oob" / "server.py"

# SSH options, fixed. BatchMode refuses a password prompt rather than hanging a request thread
# forever on a box whose key is wrong; accept-new pins the host key on first contact and then
# refuses a CHANGED one, which is the useful half of StrictHostKeyChecking for a box the
# operator just created.
_SSH_OPTIONS = (
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=10",
)

_DEPLOY_TIMEOUT = 120


class OOBDeployRefused(RuntimeError):
    """A gated canary deploy that was refused. Carries the gate that refused it."""

    def __init__(self, reason: str, gate: str = "oob") -> None:
        super().__init__(reason)
        self.reason = reason
        self.gate = gate


def _ssh_argv(target: Any, remote_command: str) -> list[str]:
    """The argv for ONE ssh invocation to the configured canary host.

    Argv-style, never a local shell: the remote command is a single argument, so nothing in
    it is parsed by the operator's own shell. The remote side does run it through `sh` — that
    is what SSH does — which is why every value interpolated into `remote_command` by the
    callers below is drawn from the config store, validated against a character allow-list
    when it was saved, and single-quoted at the point of use. The read secret is never one of
    those values: it travels on STDIN, so it cannot appear in `ps` on either machine.
    """
    argv = ["ssh", *_SSH_OPTIONS, "-p", str(target.port)]
    if target.key_path:
        argv += ["-i", target.key_path, "-o", "IdentitiesOnly=yes"]
    argv += [f"{target.user}@{target.host}", remote_command]
    return argv


def _ssh(target: Any, remote_command: str, stdin: bytes = b"") -> dict[str, Any]:
    """Run one remote command, feeding `stdin` to it. Never raises for a remote failure."""
    try:
        proc = subprocess.run(
            _ssh_argv(target, remote_command),
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_DEPLOY_TIMEOUT,
        )
    except FileNotFoundError:
        return {"exit_code": 127, "stdout": "", "stderr": "ssh not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "", "stderr": f"timed out after {_DEPLOY_TIMEOUT}s"}
    return {
        "exit_code": proc.returncode,
        "stdout": proc.stdout.decode("utf-8", "replace")[:4000],
        "stderr": proc.stderr.decode("utf-8", "replace")[:4000],
    }


def _run_script(target: Any) -> bytes:
    """The launcher written to the VPS, mode 0700, carrying the read secret.

    The secret lives in a 0700 file that the daemon sources, rather than on the start command
    line, because a command line is world-readable in `ps` on a multi-user box. Every other
    value here was validated against a character allow-list before it was stored, and is
    single-quoted regardless.
    """
    return (
        "#!/bin/sh\n"
        "# Written by HackPit. Mode 0700: it holds the canary's read secret.\n"
        f"HACKPIT_OOB_TOKEN='{target.secret}'\n"
        "export HACKPIT_OOB_TOKEN\n"
        f"cd '{target.remote_dir}' || exit 1\n"
        "exec python3 server.py \\\n"
        f"  --zone '{target.zone}' \\\n"
        f"  --answer-ip '{target.answer_ip}' \\\n"
        f"  --dns-port '{target.dns_port}' \\\n"
        f"  --http-port '{target.http_port}' \\\n"
        f"  --hits '{target.remote_dir}/hits.jsonl'\n"
    ).encode("utf-8")


class _Artifact(NamedTuple):
    """WHAT gets shipped, as a value the ENGINE consumes and no caller constructs.

    Build #13 part 4 needed to ship a second file to the same box, and there were three ways to
    do it. A second deploy function with its own transport would have been part 2's mistake
    again — two places implementing the same gates. A `path` parameter would have been worse:
    it turns a deploy button into an arbitrary-write primitive on a machine the operator
    reaches over SSH.

    So the transport, the target resolution, the gates and the step orchestration are ONE
    engine, and the thing that varies is this — built inside a wrapper from repository
    constants and the server-side config, never from anything a request carried. The public
    wrappers stay free of any parameter naming a destination, a path or a file, which is what
    keeps `test_oob_deploy_safety`'s signature assertion meaningful for both of them.
    """

    label: str          # for messages: "canary" | "redirector"
    filename: str       # what it is called on the VPS
    source: Path        # the repository file to ship — never a caller's bytes
    remote_dir: str
    launcher: bytes     # the 0700 run.sh, which may carry a secret (so it rides stdin)
    log_name: str


def _deploy_artifact(*, approved: bool, artifact: _Artifact, target: Any,
                     restart: bool) -> dict[str, Any]:
    """THE deploy engine. Ship one repository file to the configured VPS and start it.

    The remote steps are ONE approved operation for the same reason a chunked upload is:
    "write the file", "write the launcher" and "start it" are not three things a human could
    meaningfully approve separately, and stopping between any two leaves something
    half-installed rather than safely not installed.

    Stops at the first non-zero status. Returns a record with NO secret in it.
    """
    try:
        payload = artifact.source.read_bytes()
    except OSError as exc:
        raise OOBDeployRefused(f"cannot read {artifact.source.name}: {exc}", "oob") from exc

    quoted_dir = f"'{artifact.remote_dir}'"
    name = artifact.filename
    steps: list[tuple[str, str, bytes]] = [
        (
            "install",
            # The python3 check is first and is the useful one: without it a missing
            # interpreter surfaces two steps later as "started, then died", with the reason
            # only in a log file on a box the operator reaches once.
            f"command -v python3 >/dev/null || {{ echo 'python3 is not installed on the VPS' "
            f">&2; exit 1; }}; mkdir -p {quoted_dir} && cat > {quoted_dir}/{name} && "
            f"chmod 0644 {quoted_dir}/{name} && echo installed",
            payload,
        ),
        (
            "configure",
            f"cat > {quoted_dir}/run.sh && chmod 0700 {quoted_dir}/run.sh && echo configured",
            artifact.launcher,
        ),
    ]
    if restart:
        steps.append((
            "start",
            # pkill by the full path so a restart cannot take down an unrelated python3.
            f"pkill -f {quoted_dir}/{name} >/dev/null 2>&1; sleep 1; "
            f"setsid nohup {quoted_dir}/run.sh >> {quoted_dir}/{artifact.log_name} 2>&1 "
            f"< /dev/null & sleep 2; pgrep -f {quoted_dir}/{name} >/dev/null && echo started "
            f"|| (tail -n 20 {quoted_dir}/{artifact.log_name} >&2; exit 1)",
            b"",
        ))

    results: list[dict[str, Any]] = []
    for step_name, remote_command, stdin in steps:
        outcome = _ssh(target, remote_command, stdin)
        results.append({"step": step_name, **outcome})
        if outcome["exit_code"] != 0:
            break

    ok = bool(results) and all(r["exit_code"] == 0 for r in results)
    return {
        "ok": ok,
        "artifact": artifact.label,
        # describe() carries the destination and NOT the secret, so this record is safe to
        # return to the browser and safe to keep.
        "target": target.describe(),
        "bytes_sent": len(payload),
        "steps": results,
    }


def _resolve_target(what: str) -> Any:
    """THE destination, resolved server-side. Takes no address — see the block comment above."""
    # Imported here rather than at module scope so that `cockpit` keeps no import-time
    # dependency on the oob package: the executor is loaded by every gate check in the suite,
    # and the canary store is only ever touched on these paths.
    from oob import config as oob_config

    target = oob_config.deploy_target()
    if target is None:
        raise OOBDeployRefused(
            f"no VPS is configured — set the zone, address and read secret before deploying "
            f"the {what}",
            "oob",
        )
    return target


def deploy_oob_canary(*, approved: bool, restart: bool = True) -> dict[str, Any]:
    """Ship `oob/server.py` to the CONFIGURED host and start it. ONE gated act.

    Takes no destination of any kind — see the block comment above.
    """
    if not approved:
        raise OOBDeployRefused(
            "canary deploy: every deploy needs an individual human approval (approved=true) — "
            "this starts a listener on the public internet",
            "approval",
        )
    target = _resolve_target("canary")
    if not target.secret:
        raise OOBDeployRefused(
            "the canary has no read secret stored — the server refuses to start without one, "
            "because its hit log holds a target's internal hostnames",
            "oob",
        )
    artifact = _Artifact(
        label="canary",
        filename="server.py",
        source=_OOB_SERVER_SOURCE,
        remote_dir=target.remote_dir,
        launcher=_run_script(target),
        log_name="canary.log",
    )
    result = _deploy_artifact(
        approved=approved, artifact=artifact, target=target, restart=restart
    )
    if result["ok"]:
        from oob import config as oob_config

        oob_config.mark_deployed()
    return result


# --------------------------------------------------------------------------- #
# GATED C2 REDIRECTOR DEPLOY (build #13 part 4, spec §3.4)
#
# The SAME engine, the SAME target resolution, the SAME gates — a second artifact, not a second
# path. Note what this wrapper does NOT take: no host, no port list, no file. The ports come
# from the stored remote profile, resolved server-side exactly like the address, so a request
# cannot widen what becomes publicly reachable.
#
# And note `stop_c2_redirector` below. It exists because this one starts a PUBLIC listener that
# relays into the operator's own machine, and a start button without an equally reachable stop
# is how a redirector outlives the engagement it was built for.
# --------------------------------------------------------------------------- #
_REDIRECTOR_SOURCE = Path(__file__).resolve().parent.parent.parent / "redirector" / "forward.py"


def _redirector_launcher(ports: list[tuple[int, str]], remote_dir: str) -> bytes:
    """The 0700 launcher for the forwarder. Carries no secret — there is none to carry.

    Written through the same 0700 path as the canary's anyway, so there is one shape of
    launcher on that box rather than two, and a secret added here later inherits the handling
    instead of needing it remembered.
    """
    from . import redirector as redirector_mod

    argv = redirector_mod.forwarder_argv(ports)
    return (
        "#!/bin/sh\n"
        "# Written by HackPit. A PUBLIC forwarder: it relays inbound connections down the\n"
        "# operator's reverse tunnel. Take it down when the engagement ends.\n"
        f"cd '{remote_dir}' || exit 1\n"
        "exec " + " ".join(f"'{a}'" for a in argv) + "\n"
    ).encode("utf-8")


def deploy_c2_redirector(*, approved: bool, restart: bool = True) -> dict[str, Any]:
    """Ship `redirector/forward.py` to the CONFIGURED host and start it. ONE gated act.

    Takes no destination and no port list. Both are resolved server-side — the address from the
    canary config store, the ports from the stored remote listener profile.
    """
    if not approved:
        raise OOBDeployRefused(
            "redirector deploy: every deploy needs an individual human approval "
            "(approved=true) — this starts a PUBLIC listener that relays inbound traffic into "
            "this machine",
            "approval",
        )
    from . import exposure as exposure_mod
    from . import redirector as redirector_mod

    profile = exposure_mod.live_remote_profile()
    if profile is None:
        raise OOBDeployRefused(
            "no remote listener profile is saved — choose the ports that become publicly "
            "reachable before shipping anything",
            "exposure",
        )
    result = exposure_mod.validate(profile)
    if not result.ok:
        # The saved profile is re-validated at deploy time, not only at write time: the
        # acknowledgement that made it writable has to still be true of the thing being
        # shipped, and a hand-edited profile file must not reach the VPS unchecked.
        raise OOBDeployRefused("; ".join(result.refusals), "exposure")

    target = _resolve_target("redirector")
    artifact = _Artifact(
        label="redirector",
        filename="forward.py",
        source=_REDIRECTOR_SOURCE,
        remote_dir=redirector_mod.REMOTE_DIR,
        launcher=_redirector_launcher(result.ports, redirector_mod.REMOTE_DIR),
        log_name="redirector.log",
    )
    shipped = _deploy_artifact(
        approved=approved, artifact=artifact, target=target, restart=restart
    )
    # What is now reachable, in the words it needs to be said in — returned with the result so
    # a panel cannot render a successful deploy without also rendering what it exposed.
    shipped["describe"] = redirector_mod.describe(target, result.ports)
    return shipped


def stop_c2_redirector(*, approved: bool) -> dict[str, Any]:
    """Kill the forwarder on the configured host. Gated like the start.

    Approval-gated even though it CLOSES a public port rather than opening one, for the same
    reason applying a listener profile is: it kills a live session path, and an operator who
    did not mean it loses whatever was riding it. It is deliberately as easy to reach as the
    deploy — a start button without an equally reachable stop is how a public forwarder
    outlives the engagement it was built for.
    """
    if not approved:
        raise OOBDeployRefused(
            "stopping the redirector kills any session riding it — set approved=true",
            "approval",
        )
    from . import redirector as redirector_mod

    target = _resolve_target("redirector")
    quoted_dir = f"'{redirector_mod.REMOTE_DIR}'"
    outcome = _ssh(
        target,
        f"pkill -f {quoted_dir}/forward.py >/dev/null 2>&1; sleep 1; "
        f"pgrep -f {quoted_dir}/forward.py >/dev/null && "
        f"{{ echo 'still running' >&2; exit 1; }} || echo stopped",
    )
    return {
        "ok": outcome["exit_code"] == 0,
        "artifact": "redirector",
        "target": target.describe(),
        "steps": [{"step": "stop", **outcome}],
    }
