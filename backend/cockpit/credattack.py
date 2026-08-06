"""Credential attack — the PURE planner + result-correlator for spray / crack jobs.

*** WHY THIS FITS THE APPROVAL MODEL, WRITTEN DOWN SO NOBODY RE-LITIGATES IT. ***
A spray of 300 accounts and a crack of 40 hashes are each ONE job that produces many
attempts. HackPit refuses BATCHING ACROSS APPROVALS — an agent queueing five commands
behind one human click. It has never refused ONE approval that produces many requests, and
could not: `ffuf`, `nuclei`, the ZAP active scanner and the intruder are each a single
approval buying thousands. A spray/crack is that same shape: ONE gated job, gated by the
SAME gates the executor already runs, with NO new ones. The stop button (in `credjobs.py`)
is UNGATED — the panic switch, like every other stop in this codebase.

*** THIS MODULE EXECUTES NOTHING. ***
It builds argv (as lists, never a shell string), detects hash modes, and turns tool output
back into typed state records. The EXECUTION lives in `cockpit/credjobs.py` (the job worker)
and, underneath it, the same gated `executor`/loot path everything else uses. That split is
regression-locked in `test_credattack_safety.py` by an AST walk over this file: it may import
no execution or network module and may call no `subprocess`/`os.system`. It is the same
position `state/` takes — a module that runs after a job with no approval of its own must sit
outside every execution path, or it would sit outside the gates.

*** SECRETS NEVER LAND ON AN ARGV. ***
The user list, the password list and the hash list are written to files under the sandbox's
loot directory (by the worker) and the argv references those files. A password on the command
line ends up in `ps`, in the shell history of any wrapper, and — worst of all — in the
persisted `RunRecord` that `report.py` renders verbatim. The file paths this module puts on the
argv are non-host operands the target-lock ignores; the secrets stay in the file.
"""

from __future__ import annotations

import re
from typing import Iterable

from pydantic import BaseModel, Field

from state import credvault
from state.models import Credential, Finding

# --------------------------------------------------------------------------- #
# services -> spray driver
# --------------------------------------------------------------------------- #
#: Each spray service maps to a driver tool and, for netexec, the protocol token. netexec is
#: the spray workhorse (crackmapexec is deliberately NOT catalogued — netexec is its
#: maintained successor); kerbrute owns Kerberos pre-auth spraying; hydra owns HTTP form login
#: brute, which netexec does not do. The set is intentionally small and honest: a service with
#: no driver is reported, never guessed at.
NETEXEC_PROTOS = ("smb", "winrm", "ldap", "ssh", "mssql", "rdp", "ftp", "wmi", "vnc")

#: service -> (driver, netexec-proto-or-empty). "http-form" is hydra's; "kerberos" is kerbrute's.
SPRAY_SERVICES: dict[str, tuple[str, str]] = {
    **{p: ("netexec", p) for p in NETEXEC_PROTOS},
    "kerberos": ("kerbrute", ""),
    "http-form": ("hydra", ""),
}


class SprayRequest(BaseModel):
    """One spray job: a service, a target, a user list and a password list.

    The user/password lists are the OPERATOR'S choice — seeded from captured state in the UI,
    but plain fields here so the planner stays pure and testable. The two "safety knobs"
    (`delay`, `stop_on_lockouts`) are PARAMETERS the operator sets, NOT gates: a slower spray
    is a quieter spray, not a safer one, and refusing to run because a number was left at zero
    would be a prohibition the tooling invented.
    """

    service: str = Field("smb", description="smb|winrm|ldap|ssh|mssql|rdp|ftp|kerberos|http-form")
    target: str = Field(..., min_length=1, description="Host/IP to spray. Target-locked by the gate.")
    usernames: list[str] = Field(default_factory=list, description="The user list.")
    passwords: list[str] = Field(
        default_factory=list, description="The password list — written to a file, never an argv."
    )
    domain: str = Field("", description="AD domain / realm (fills <domain>).")
    # http-form only: the hydra form template, e.g. "/login:user=^USER^&pass=^PASS^:F=incorrect".
    http_form: str = Field("", description="hydra http-post-form path:body:failstring (http-form only).")
    delay: int = Field(0, ge=0, le=3600, description="Seconds between attempts (operator knob).")
    stop_on_lockouts: int = Field(
        0, ge=0, le=1000,
        description="Stop the job after this many account-lockout signals (0 = never). An "
        "operator knob the worker enforces by WATCHING output, not a gate.",
    )
    engagement_id: str | None = None
    session_id: str | None = None
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False, description="The red-confirm, WHEN THE GATE ASKS FOR IT — not demanded here."
    )


class CrackRequest(BaseModel):
    """One crack job: which captured hashes to crack, and with what wordlist.

    `principals` selects captured credentials by account name; empty means "every crackable
    hash in state". The wordlist is an operator input defaulting to the image's rockyou.
    """

    principals: list[str] = Field(
        default_factory=list, description="Accounts to crack; empty = all crackable hashes in state."
    )
    wordlist: str = Field(
        "/usr/share/wordlists/rockyou.txt", min_length=1,
        description="Wordlist path inside the sandbox (operator input).",
    )
    rule: str = Field("", description="Optional hashcat rule file path.")
    engagement_id: str | None = None
    session_id: str | None = None
    approved: bool = Field(False, description="Explicit human approval. Never defaulted true.")
    dangerous_ack: bool = Field(
        False, description="The red-confirm, WHEN THE GATE ASKS FOR IT — not demanded here."
    )


# --------------------------------------------------------------------------- #
# hash-mode detection (hash shape -> hashcat -m)
# --------------------------------------------------------------------------- #
class HashMode(BaseModel):
    """A detected hashcat mode, or a miss with a reason."""

    mode: int | None = None
    name: str = ""
    reason: str = ""


_HEX32 = re.compile(r"^[a-fA-F0-9]{32}$")
_HEX40 = re.compile(r"^[a-fA-F0-9]{40}$")
_HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")
#: NetNTLMv2 challenge/response: `user::domain:serverchal:ntproofstr:blob` — five `:`-joined
#: fields with a leading `::`. NetNTLMv1 has the same head but a shorter body.
_NETNTLMV2 = re.compile(r"^[^:]*::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$")
_NETNTLMV1 = re.compile(r"^[^:]*::[^:]+:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$")


def detect_hash_mode(secret: str, kind: str = "") -> HashMode:
    """Map a captured secret's SHAPE to a hashcat `-m`. PURE.

    Prefix-tagged formats (Kerberos tickets, the crypt family) are unambiguous and checked
    first. A bare 32-hex string is treated as NTLM (`-m 1000`): inside HackPit that string is
    an NT hash far more often than a raw MD5, and the `kind` (`ntlm`) usually confirms it. An
    unrecognised shape returns `mode=None` with a reason rather than a wrong guess — cracking
    with the wrong mode silently finds nothing and reads as "the password held".
    """
    s = (secret or "").strip()
    if not s:
        return HashMode(reason="empty secret")

    # Kerberos tickets carry their own type tag.
    low = s.lower()
    if low.startswith("$krb5tgs$23$"):
        return HashMode(mode=13100, name="Kerberos 5 TGS-REP etype 23 (kerberoast)")
    if low.startswith("$krb5tgs$17$") or low.startswith("$krb5tgs$18$"):
        return HashMode(mode=19700, name="Kerberos 5 TGS-REP etype 17/18")
    if low.startswith("$krb5asrep$23") or low.startswith("$krb5asrep$18") or low.startswith("$krb5asrep$17"):
        return HashMode(mode=18200, name="Kerberos 5 AS-REP etype 23 (AS-REP roast)")
    if low.startswith("$krb5pa$"):
        return HashMode(mode=7500, name="Kerberos 5 AS-REQ Pre-Auth etype 23")

    # crypt(3) family — the leading $id$ is the mode.
    if s.startswith("$2a$") or s.startswith("$2b$") or s.startswith("$2y$"):
        return HashMode(mode=3200, name="bcrypt $2*$")
    if s.startswith("$6$"):
        return HashMode(mode=1800, name="sha512crypt $6$")
    if s.startswith("$5$"):
        return HashMode(mode=7400, name="sha256crypt $5$")
    if s.startswith("$1$"):
        return HashMode(mode=500, name="md5crypt $1$")

    # Net-NTLM (network capture) before bare NTLM — its `::` head is distinctive.
    if _NETNTLMV2.match(s):
        return HashMode(mode=5600, name="NetNTLMv2")
    if _NETNTLMV1.match(s):
        return HashMode(mode=5500, name="NetNTLMv1")

    k = (kind or "").strip().lower()
    if _HEX32.match(s):
        # kind wins when it is explicit; otherwise assume NTLM in this AD-heavy tool.
        return HashMode(mode=1000, name="NTLM" if k in ("", "ntlm", "nt", "hash") else "NTLM (assumed)")
    if _HEX40.match(s):
        return HashMode(mode=100, name="SHA1")
    if _HEX64.match(s):
        return HashMode(mode=1400, name="SHA-256")

    return HashMode(reason=f"unrecognised hash shape for {kind or 'hash'!r} — set the mode by hand")


CRACKABLE_KINDS = ("ntlm", "hash", "ticket", "nt", "ntlm-hash")


def crackable(cred: Credential) -> bool:
    """A credential worth handing to a cracker: a hash/ticket with a detectable mode and no
    plaintext already known."""
    if (cred.kind or "").strip().lower() not in CRACKABLE_KINDS:
        return False
    if not (cred.secret or "").strip():
        return False
    return detect_hash_mode(cred.secret, cred.kind).mode is not None


# --------------------------------------------------------------------------- #
# argv builders — PURE. File paths are inputs; the worker writes the files.
# --------------------------------------------------------------------------- #
def spray_argv(req: SprayRequest, *, users_path: str, pass_path: str) -> tuple[list[str], list[str]]:
    """The spray command as argv, plus any warnings. PURE — never a shell string.

    `<domain>` is filled with :func:`state.credvault.fill` so the ONE placeholder-to-field
    mapping in the product is reused rather than re-implemented here. The user/password lists
    are referenced by FILE PATH; nothing secret is on the argv.
    """
    service = (req.service or "").strip().lower()
    driver, proto = SPRAY_SERVICES.get(service, ("", ""))
    warnings: list[str] = []
    dom_cred = Credential(session_id="", kind="password", principal="x", domain=req.domain)

    if driver == "netexec":
        argv = ["netexec", proto, req.target, "-u", users_path, "-p", pass_path]
        if req.domain:
            argv += ["-d", req.domain]
        if req.delay:
            # netexec has no per-attempt delay flag; the worker paces the job instead. Say so.
            warnings.append(
                f"netexec has no per-attempt delay flag — the {req.delay}s pacing is applied by "
                "the job between passwords, not by the tool"
            )
        return argv, warnings

    if driver == "kerbrute":
        # kerbrute passwordspray --dc <target> -d <domain> <userfile> <password>
        if not req.domain:
            warnings.append("kerbrute needs a realm (-d/domain) — set the domain")
        argv = ["kerbrute", "passwordspray", "--dc", req.target, "-d", req.domain or "<domain>",
                users_path, pass_path]
        if req.delay:
            argv += ["--delay", str(int(req.delay) * 1000)]  # kerbrute delay is milliseconds
        # fill <domain> if it was left as a placeholder
        filled, _ = credvault.fill(" ".join(argv), dom_cred)
        return filled.split(" ") if req.domain else argv, warnings

    if driver == "hydra":
        form = (req.http_form or "").strip()
        if not form:
            warnings.append(
                "http-form spray needs a hydra form template "
                "(path:body:failstring, e.g. /login:user=^USER^&pass=^PASS^:F=incorrect)"
            )
        argv = ["hydra", "-L", users_path, "-P", pass_path]
        if req.delay:
            argv += ["-c", str(int(req.delay))]  # hydra wait time between attempts (seconds)
        argv += [req.target, "http-post-form", form or "<form>"]
        return argv, warnings

    warnings.append(
        f"unknown spray service {req.service!r} — known: {', '.join(sorted(SPRAY_SERVICES))}"
    )
    return [], warnings


def crack_argv(req: CrackRequest, *, hash_path: str, mode: int) -> list[str]:
    """The hashcat command as argv. PURE. Hashes are in a FILE; only its path is on the argv.

    `-a 0` (straight wordlist), `-m <mode>`, `--quiet` so the cracked `hash:plain` lines are
    not buried under the status screen, and `--potfile-disable` so a stale pot from a previous
    job does not make a fresh crack look instant-and-empty.
    """
    argv = ["hashcat", "-a", "0", "-m", str(int(mode)), "--quiet", "--potfile-disable",
            hash_path, req.wordlist]
    if (req.rule or "").strip():
        argv += ["-r", req.rule.strip()]
    return argv


# --------------------------------------------------------------------------- #
# planning — PURE, so the operator sees the exact argv before approving
# --------------------------------------------------------------------------- #
class SprayStep(BaseModel):
    argv: list[str]
    users: int
    passwords: int
    warnings: list[str] = Field(default_factory=list)


class CrackGroup(BaseModel):
    """One hashcat invocation: every captured hash that shares a mode."""

    mode: int
    name: str
    principals: list[str]
    hashes: int
    argv: list[str]


class CredPlan(BaseModel):
    """The dry preview of what a spray/crack WOULD run — executes nothing."""

    kind: str  # "spray" | "crack"
    spray: SprayStep | None = None
    crack: list[CrackGroup] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


#: Symbolic loot paths used for the PREVIEW/gate argv. The real worker substitutes concrete
#: per-job paths; both are non-host file operands, so the gate verdict is identical either way.
def _preview_loot(session_id: str | None, name: str) -> str:
    sid = (session_id or "session").strip() or "session"
    return f"/loot/{sid}/credattack-{name}"


def state_usernames(creds: Iterable[Credential]) -> list[str]:
    """Distinct account names in captured state — the natural spray user list."""
    seen: list[str] = []
    for c in creds:
        p = (c.principal or "").strip()
        if p and p not in seen:
            seen.append(p)
    return seen


def state_passwords(creds: Iterable[Credential]) -> list[str]:
    """Distinct KNOWN PLAINTEXTS in captured state — passwords worth spraying elsewhere."""
    seen: list[str] = []
    for c in creds:
        if (c.kind or "").strip().lower() not in ("password", "cleartext", "plaintext"):
            continue
        s = (c.secret or "").strip()
        if s and s not in seen:
            seen.append(s)
    return seen


def plan_spray(req: SprayRequest) -> CredPlan:
    """Preview a spray. Sends nothing."""
    argv, warnings = spray_argv(
        req,
        users_path=_preview_loot(req.session_id, "users.txt"),
        pass_path=_preview_loot(req.session_id, "pass.txt"),
    )
    users = [u.strip() for u in req.usernames if u.strip()]
    passwords = [p for p in req.passwords if p]
    if not users:
        warnings.append("no usernames — add a user list (or seed it from captured state)")
    if not passwords:
        warnings.append("no passwords — add a password list")
    step = SprayStep(argv=argv, users=len(users), passwords=len(passwords), warnings=warnings)
    return CredPlan(kind="spray", spray=step, warnings=warnings)


def plan_crack(req: CrackRequest, creds: Iterable[Credential]) -> CredPlan:
    """Preview a crack from captured state, grouped by hashcat mode. Sends nothing."""
    warnings: list[str] = []
    wanted = {p.strip().lower() for p in req.principals if p.strip()}
    groups: dict[int, CrackGroup] = {}
    for c in creds:
        if wanted and c.principal.strip().lower() not in wanted:
            continue
        if not crackable(c):
            continue
        hm = detect_hash_mode(c.secret, c.kind)
        if hm.mode is None:
            warnings.append(f"{c.principal}: {hm.reason}")
            continue
        grp = groups.get(hm.mode)
        if grp is None:
            grp = CrackGroup(
                mode=hm.mode, name=hm.name, principals=[], hashes=0,
                argv=crack_argv(req, hash_path=_preview_loot(req.session_id, f"m{hm.mode}.txt"),
                                mode=hm.mode),
            )
            groups[hm.mode] = grp
        grp.principals.append(c.principal)
        grp.hashes += 1
    if not groups:
        warnings.append("no crackable hashes in state for that selection")
    return CredPlan(kind="crack", crack=list(groups.values()), warnings=warnings)


# --------------------------------------------------------------------------- #
# the equivalent command — what the human approves (the gate reads this)
# --------------------------------------------------------------------------- #
def spray_exec_request(req: SprayRequest, *, users_path: str, pass_path: str):
    """The `ExecRequest` a spray is EQUIVALENT TO, for the gate. Lazy-imports the executor so
    this module's top level stays free of anything that executes."""
    from .models import ExecRequest

    argv, _warn = spray_argv(req, users_path=users_path, pass_path=pass_path)
    return ExecRequest(
        command=argv[0] if argv else "netexec", args=argv[1:] if argv else [],
        approved=req.approved, dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id, session_id=req.session_id,
    )


def crack_exec_request(req: CrackRequest, *, hash_path: str, mode: int):
    """The `ExecRequest` a crack is EQUIVALENT TO, for the gate."""
    from .models import ExecRequest

    argv = crack_argv(req, hash_path=hash_path, mode=mode)
    return ExecRequest(
        command=argv[0], args=argv[1:],
        approved=req.approved, dangerous_ack=req.dangerous_ack,
        engagement_id=req.engagement_id, session_id=req.session_id,
    )


def validate_spray(req: SprayRequest):
    """The gate verdict for a spray, attacking nothing. Returns None when it passes.

    The real per-mode gates, in the executor's order, unchanged — so a UI can ask "would this
    be refused" without launching anything, exactly the split `intruder.validate` makes.
    """
    from . import executor

    return executor.validate_request(
        spray_exec_request(
            req,
            users_path=_preview_loot(req.session_id, "users.txt"),
            pass_path=_preview_loot(req.session_id, "pass.txt"),
        )
    )


def validate_crack(req: CrackRequest):
    """The gate verdict for a crack. A crack names no host, so it is an engagement-mode
    target-less command (allowed) — and refused in lab mode, which is why the UI asks for an
    engagement."""
    from . import executor

    # Any mode is fine for the gate check; the argv shape (no host token) is what matters.
    return executor.validate_request(
        crack_exec_request(req, hash_path=_preview_loot(req.session_id, "hashes.txt"), mode=1000)
    )


# --------------------------------------------------------------------------- #
# result correlation — tool output -> typed state records. PURE.
# --------------------------------------------------------------------------- #
def correlate_spray(
    req: SprayRequest, text: str, session_id: str, run_id: str | None = None
) -> tuple[list[Credential], list[Finding]]:
    """A spray's `[+]` hits -> validated Credentials + high-severity Findings.

    Reuses :func:`state.parsers.parse_netexec` for the line format so there is one parser for
    that output, not two. Every hit becomes a `validated=True` credential (`note="sprayed OK on
    <target>"`) — the whole point of a spray is that the credential now WORKS — and a `high`
    finding, because a valid credential on a live service is a reportable result.
    """
    from state import parsers

    parsed = parsers.parse_netexec(text, session_id, run_id)
    creds: list[Credential] = []
    findings: list[Finding] = []
    for c in parsed.credentials:
        admin = "Pwn3d" in (c.note or "")
        c.validated = True
        c.note = f"sprayed OK on {req.target}" + (" (Pwn3d! — local admin)" if admin else "")
        creds.append(c)
        who = f"{c.principal}@{c.domain}" if c.domain else c.principal
        findings.append(
            Finding(
                session_id=session_id,
                title=f"valid {req.service} credential: {who}",
                severity="high", target=req.target, tool="netexec",
                evidence=f"{c.principal} authenticates on {req.service}://{req.target}",
                reference="password-spray", source_run_id=run_id,
            )
        )
    return creds, findings


def correlate_crack(
    text: str, before: Iterable[Credential], session_id: str, run_id: str | None = None
) -> tuple[list[Credential], list[Finding]]:
    """hashcat `hash:plain` output -> a recovered password per principal + a high Finding.

    THE PRINCIPAL COMES FROM `before`, NOT FROM THE HASHCAT LINE. A bare `hash:plain` line
    carries no account name, and for salted/Kerberos hashes the `:` split is ambiguous — so the
    known hashes that were SUBMITTED are matched against each line by prefix, which recovers the
    account unambiguously. This is why crack correlation is not a generic stdout parser: it
    needs the state that produced the job.

    A NEW `password` credential is emitted (not an overwrite of the hash): the NT hash stays
    usable for pass-the-hash, and a fresh cleartext credential is what lights the AD graph and
    what an authenticated rescan spends. Both are the same principal, so the vault shows the
    account with both a hash and a password.
    """
    from state import parsers

    known = {(c.secret or "").strip(): c for c in before if (c.secret or "").strip()}
    cracked = parsers.parse_hashcat_pairs(text, set(known))
    creds: list[Credential] = []
    findings: list[Finding] = []
    for h, plain in cracked.items():
        owner = known.get(h)
        if owner is None or not plain:
            continue
        creds.append(
            Credential(
                session_id=session_id, kind="password", principal=owner.principal,
                domain=owner.domain, secret=plain, validated=True,
                note=f"cracked from {owner.kind} hash", source_run_id=run_id,
            )
        )
        who = f"{owner.principal}@{owner.domain}" if owner.domain else owner.principal
        findings.append(
            Finding(
                session_id=session_id, title=f"cracked {who}", severity="high",
                target=who, tool="hashcat",
                evidence=f"{owner.kind} hash for {who} cracked to a {len(plain)}-char password",
                reference="offline-crack", source_run_id=run_id,
            )
        )
    return creds, findings


def owned_from(creds: Iterable[Credential]) -> list[str]:
    """The account names a fresh working credential should mark OWNED in an AD graph.

    Best-effort labels — the graph store matches them against node SAM/label; a miss simply
    marks nothing, never raises.
    """
    out: list[str] = []
    for c in creds:
        p = (c.principal or "").strip()
        if p and p not in out:
            out.append(p)
    return out
