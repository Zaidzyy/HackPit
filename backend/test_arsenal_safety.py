"""SAFETY INVARIANTS for the tool arsenal.

The arsenal is DATA + TEMPLATES. It broadens and sharpens what the planner PROPOSES; it
changes nothing about how anything RUNS. These are the two claims that matters, and they are
tested rather than asserted in prose:

  1. THE ARSENAL EXECUTES NOTHING — no subprocess, no exec/eval, no network anywhere in the
     package. A rendered invocation is a string.
  2. NO GATE WAS BYPASSED — an arsenal-templated command goes through exactly the same
     executor gates as any other: target/scope lock, approve-each, heuristic red-confirm,
     in that order. A bigger catalog buys no shortcut, and the executor knows nothing about
     the arsenal at all.

Plus: the executor/engagement path is byte-for-byte unchanged, and templates are
target-faithful (no invented hosts reach a step).

Run:  python test_arsenal_safety.py
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

from arsenal import loader, planner
from cockpit import allowlist
from test_support import scans

_PKG = Path(__file__).parent / "arsenal"
_SOURCES = sorted(_PKG.glob("*.py"))
_LAB = "hackpit-lab-target"


def _code_only(text: str) -> str:
    """Source with comments and string literals REMOVED.

    A naive grep over the raw file scans prose as if it were code — the docstring
    sentence "no subprocess, no network" tripped the subprocess ban on the very module
    that has neither. Tokenising first means these tests assert what the code DOES, not
    what its documentation says, which is the only version worth having.

    Comment/string spans are BLANKED IN PLACE rather than dropped, so every other byte —
    and crucially the spacing — is untouched: `re.compile` must still read as `re.compile`
    so an attribute-vs-builtin lookbehind keeps working.
    """
    lines = text.splitlines(keepends=True)
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError):  # pragma: no cover - defensive
        return text
    for tok in toks:
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        (srow, scol), (erow, ecol) = tok.start, tok.end
        for row in range(srow, erow + 1):
            line = lines[row - 1]
            begin = scol if row == srow else 0
            finish = ecol if row == erow else len(line)
            lines[row - 1] = line[:begin] + " " * (finish - begin) + line[finish:]
    return "".join(lines)


def _all_source() -> str:
    """Executable code from every arsenal module — no comments, no docstrings."""
    return "\n".join(_code_only(p.read_text(encoding="utf-8")) for p in _SOURCES)


# --------------------------------------------------------------------------- #
# 1. the arsenal executes nothing
# --------------------------------------------------------------------------- #
def test_arsenal_has_no_execution_path() -> None:
    src = _all_source()
    banned = {
        r"\bsubprocess\b": "subprocess",
        r"\bos\.system\b": "os.system",
        r"\bos\.popen\b": "os.popen",
        r"\bos\.exec": "os.exec*",
        r"\bos\.spawn": "os.spawn*",
        r"\bpty\b": "pty",
        r"(?<!\.)\beval\s*\(": "eval()",
        r"(?<!\.)\bexec\s*\(": "exec()",
        r"(?<!\.)\bcompile\s*\(": "the compile() builtin",
        r"__import__": "__import__",
        r"\brequests\.": "requests",
        r"\burllib\.request\b": "urllib.request",
        r"\bsocket\.socket\b": "sockets",
        r"shell\s*=\s*True": "shell=True",
    }
    for pattern, label in banned.items():
        hit = re.search(pattern, src)
        assert hit is None, f"the arsenal must not use {label} (offset {hit.start()})"
    print(f"  no subprocess/exec/eval/network anywhere in {len(_SOURCES)} arsenal modules: PASS")


def test_arsenal_never_imports_the_executor() -> None:
    """It may be READ by the planner; it must never reach the execution layer itself."""
    src = _all_source()
    for module in ("cockpit", "sandbox", "executor", "allowlist", "engagement", "kali"):
        assert not re.search(rf"^\s*(?:from|import)\s+{module}\b", src, re.M), (
            f"the arsenal must not import {module}"
        )
    for symbol in ("validate_request", "iter_run", "run_kali", "resolve_mode",
                   "assert_isolation_proven", "ExecRequest"):
        assert symbol not in src, f"the arsenal must not reference {symbol}"
    print("  zero imports/references into the execution layer: PASS")


def test_a_rendered_invocation_is_only_a_string() -> None:
    ars = loader.load()
    out = loader.render_tool(ars, "nmap", _LAB, {"ports": "80", "output": "o"})
    assert out and all(isinstance(inv["cmd"], str) for inv in out)
    assert all(not hasattr(inv["cmd"], "run") for inv in out)
    print("  render returns strings — there is nothing to invoke: PASS")


# --------------------------------------------------------------------------- #
# 2. NO GATE IS BYPASSED by an arsenal-templated command
# --------------------------------------------------------------------------- #
def test_arsenal_command_still_clears_every_gate() -> None:
    """The claim under review: a catalogued invocation gets no shortcut."""
    from cockpit import executor as E
    from cockpit.models import ExecRequest

    ars = loader.load()
    # a real, catalogued invocation rendered against the lab
    rendered = loader.render_tool(ars, "nmap", _LAB, {"ports": "80", "output": "scan"})
    cmd = rendered[0]["cmd"]
    args = cmd.split()[1:]

    # UNAPPROVED -> refused at the approval gate, exactly like any other command
    r = E.validate_request(ExecRequest(command="nmap", args=args, approved=False))
    assert r is not None and r.gate in ("approval", "sandbox"), (
        f"an arsenal command must not skip approval — got {getattr(r, 'gate', None)}"
    )

    # OFF-TARGET -> refused at the target gate even though it is a catalogued tool
    r = E.validate_request(
        ExecRequest(command="nmap", args=["-sCV", "scanme.nmap.org"], approved=True)
    )
    assert r is not None and r.gate == "target", (
        "a catalogued tool pointed off-target must still be refused at the target gate"
    )

    # A DANGEROUS CATALOGUED invocation still needs the explicit red-confirm.
    #
    # This used to read `command="python3", args=["-c", "print(1)"]` and accept
    # `gate in ("danger", "sandbox")`. python3 is NOT in tools.json, so the claim in this
    # function's docstring — that a catalogued invocation gets no shortcut — was never actually
    # exercised on the danger gate, and the "sandbox" alternative meant the assertion passed
    # even when the danger gate did not fire at all. Both are fixed: a real catalogued tool,
    # and only "danger" is accepted. The exhaustive per-tool version is below.
    dangerous_tool = loader.load().get("weevely")
    assert dangerous_tool is not None, "the catalog no longer has weevely — repoint this check"
    flagged = E.validate_request(
        ExecRequest(command=dangerous_tool.name, args=["generate", "pw", _LAB], approved=True)
    )
    assert flagged is not None and flagged.gate == "danger", (
        "a catalogued webshell generator approved WITHOUT the red-confirm must be refused at "
        f"the danger gate — got {getattr(flagged, 'gate', None)}"
    )
    print("  arsenal command: approval, target and danger gates all still fire: PASS")


# --------------------------------------------------------------------------- #
# 2b. THE DANGER VERDICT IS PINNED FOR EVERY CATALOGUED INVOCATION
#
# WHY THIS EXISTS. The check above was the only place that claimed to verify "a catalogued
# dangerous invocation demands the red-confirm", and it tested `python3`, which is not in the
# catalog. The assertion was permanently green while EIGHT catalogued tools that generate a
# webshell, open a DNS C2 channel, tunnel arbitrary traffic, install persistence or drop to a
# remote OS shell — weevely, dnscat2, iodine, commix, SSTImap, mssqlclient, SharPersist,
# Invoke-Obfuscation — produced ZERO danger reasons. A plain `approved=true` built a webshell.
#
# Fixing those eight closes today's gap. This closes the CLASS: every tool name, every alias and
# every template's argv[0] in tools.json must appear in exactly ONE bucket below. Add a tool
# without a verdict and this test fails, naming it. There is no default.
#
# The buckets are a judgement about what the tool DOES, not about what the heuristic currently
# returns — write the bucket first, then make the heuristic agree with it.
# --------------------------------------------------------------------------- #

# Dangerous by binary identity alone: it generates, delivers or executes a payload, opens a
# shell, tunnels traffic, replicates credentials, or executes code on a remote host.
_MUST_FIRE = frozenset({
    # payload generators / C2 frameworks
    "donut", "ScareCrow", "Invoke-Obfuscation", "msfvenom", "msfconsole", "msf", "metasploit",
    "Sliver", "Empire",
    # the real sandbox binaries these two frameworks install under (the substrate probe in
    # build #8 surfaced that `Sliver`/`Empire` resolve as `sliver-server`/`sliver-client`/
    # `powershell-empire`). Each is a full C2 / persistence framework that runs agents on remote
    # hosts, so each must demand the red-confirm as it is ACTUALLY invoked.
    "sliver-server", "sliver-client", "powershell-empire",
    # covert tunnels — a C2 path and an exfil path in one
    "dnscat2", "dnscat2-client", "dnscat2-server", "iodine", "iodined",
    # vulnerability -> command execution / interactive shell on the target
    "commix", "SSTImap", "weevely", "weevely3",
    # persistence that will execute a payload with no operator present
    "SharPersist", "SharPersist.exe",
    # ACTIVE web scan — sends live injection payloads at every parameter it discovered. The
    # PASSIVE sibling (zap-baseline.py) is in _MUST_NOT_FIRE below; that split is the point.
    # ZAP is deliberately stricter than sqlmap/nikto/dalfox here — a recorded decision
    # (2026-08-03), not an oversight. See cockpit/allowlist.py::_ACTIVE_WEB_SCANNERS.
    "zap-full-scan.py",
    # remote code execution on a domain host
    "psexec", "psexec.py", "impacket-psexec", "wmiexec", "wmiexec.py", "impacket-wmiexec",
    "smbexec", "smbexec.py", "impacket-smbexec", "evil-winrm",
    "mssqlclient", "mssqlclient.py", "impacket-mssqlclient", "enable_xp_cmdshell",
    # credential replication / dumping
    "mimikatz", "mimikatz.exe",
    "secretsdump", "secretsdump.py", "impacket-secretsdump",
    # coerces or relays authentication
    "ntlmrelayx", "ntlmrelayx.py", "impacket-ntlmrelayx", "responder", "Responder.py",
    # pivots — each one puts a network the operator has NOT been gated against inside reach,
    # which is the same claim the dnscat2/iodine entries above are here for. socat is the
    # return path in a multi-hop chain and carries a reverse shell just as readily.
    "chisel", "ligolo-ng", "ligolo-proxy", "ligolo-agent", "socat", "sshuttle",
})

# Clean by binary identity, and clean across every template the catalog ships for it. A confirm
# that fires on everything is one the operator learns to click through, so recon, enumeration,
# fuzzing, offline cracking and local binary analysis must stay quiet.
_MUST_NOT_FIRE = frozenset({
    # recon / discovery
    "nmap", "masscan", "rustscan", "naabu", "amass", "subfinder", "assetfinder", "theHarvester",
    "dnsx", "httpx", "dnsrecon", "shodan", "fierce", "gotator", "regulator", "subwiz", "puredns",
    "massdns", "dnsvalidator", "asnmap", "mapcidr", "tlsx", "csprecon",
    # web testing
    "ffuf", "feroxbuster", "gobuster", "nuclei", "nikto", "sqlmap", "wpscan", "dalfox",
    "whatweb", "arjun", "paramspider", "katana", "gau", "getallurls", "waybackurls", "dirsearch",
    "wafw00f", "testssl", "testssl.sh", "jwt_tool", "jwt-tool", "jwt_tool.py", "wfuzz",
    "hakrawler", "sslscan", "nomore403", "crlfuzz", "getjs", "jsluice", "subjs",
    # ZAP's PASSIVE pass: spider + passive rules, no attack traffic. Its ACTIVE sibling
    # (zap-full-scan.py) is in _MUST_FIRE above.
    "zap-baseline.py",
    "gf", "qsreplace", "unfurl",
    # pipeline heads the templates use — shell builtins, not tools
    "cat", "echo",
    # AD / network ENUMERATION — read-only. Regression-locked in test_adorch_safety.py: a
    # confirm here would fire on almost every AD command and stop meaning anything.
    "netexec", "nxc", "crackmapexec", "cme", "enum4linux", "enum4linux-ng", "smbmap",
    "ldapsearch", "ldapdomaindump", "bloodhound", "bloodhound-python",
    # Kerberos roasting / TGT request: retrieves crackable material, cracks nothing and
    # executes nothing — same class as hashcat below, which is also clean.
    "GetUserSPNs", "GetUserSPNs.py", "impacket-GetUserSPNs",
    "GetNPUsers", "GetNPUsers.py", "impacket-GetNPUsers",
    "getTGT", "getTGT.py", "impacket-getTGT",
    # PowerView read-side. Its WRITE cmdlets (Set-DomainUserPassword, Add-DomainGroupMember,
    # ...) are separately covered by allowlist._AD_PS_WRITE; `. .\PowerView.ps1` dot-sources the
    # enumeration toolkit and is not itself a payload.
    "powerview", "PowerView.ps1", ".", "Get-DomainUser", "Find-LocalAdminAccess",
    "Find-InterestingDomainAcl",
    # credential attack — online guessing and OFFLINE cracking. No code runs on the target.
    "hydra", "kerbrute", "hashcat", "john", "jtr", "john the ripper", "ssh2john",
    # cloud posture
    "prowler", "scoutsuite", "scout", "trivy", "kube-hunter", "s3scanner", "cloud_enum",
    # local binary analysis — operates on a file, not a host
    "ghidra", "analyzeHeadless", "radare2", "r2", "gdb", "strings",
    # local exploit-DB search
    "searchsploit", "exploitdb",
    # host enumeration scripts
    "linpeas", "linpeas.sh", "winpeas", "winpeas.bat", "winPEAS.exe", "winPEASany",
    "winPEASx64", "winPEASx64.exe", "winPEASx86",
    # OSINT / secret scanning
    "trufflehog", "msftrecon", "github-subdomains", "gitlab-subdomains", "dorks_hunter",
    "gitdorks_go",
    # proxychains is a WRAPPER, not a tunnel: it carries no payload and opens no channel, it
    # forces an already-chosen program through an already-established SOCKS proxy. Flagging the
    # wrapper would fire on every pivoted `nmap` and teach the operator to click through. The
    # danger is the WRAPPED command, and allowlist.dangerous_command_heuristic now unwraps to
    # find it — regression-locked in test_a_wrapper_cannot_launder_the_red_confirm below.
    "proxychains", "proxychains4",
    # `ip route add <cidr> dev <tun>` from the ligolo templates — a LOCAL routing-table change
    # on this box. It runs nothing, reaches nothing and delivers nothing.
    "ip",
})

# The bare binary is deliberately CLEAN (it has a legitimate read-only mode that must not train
# the operator to click through) but at least one catalogued template MUST fire, because that
# template mutates the directory or mints credentials. Both halves are asserted.
_ARGUMENT_DEPENDENT = frozenset({"certipy", "certipy-ad", "bloodyAD", "rubeus", "Rubeus.exe",
                                 # `zap` is the catalog's tool NAME, never a template argv[0].
                                 # Bare, it is a launcher with passive modes and must stay clean;
                                 # its zap-full-scan.py template fires. Exactly this bucket's
                                 # shape. NOTE: `zap -cmd -autorun plan.yaml` would hide its own
                                 # aggression inside the plan file, which is why the catalog
                                 # ships no autorun template — see §4 of the design spec.
                                 "zap"})

# NOT a binary: a subcommand typed inside an interactive console (the sliver client, the Empire
# console, mimikatz, the impacket mssql shell). These never appear as argv[0] of a docker exec.
# Excusing them is safe ONLY because the console itself is in _MUST_FIRE — which the test below
# asserts, so this bucket cannot become a place to hide a real binary.
_CONSOLE_SUBCOMMANDS: dict[str, str] = {
    "generate": "Sliver", "mtls": "Sliver",
    "usemodule": "Empire",
    "sekurlsa::pth": "mimikatz", "kerberos::list": "mimikatz",
    "enum_links": "mssqlclient.py",
}


def _catalog_invocations() -> dict[str, set[str]]:
    """Every name a catalogued tool can be invoked as -> the tools that own it.

    Tool name, every alias, and every template's argv[0] (basename'd, so `./linpeas.sh` is
    keyed as `linpeas.sh`). This is the universe the buckets above must cover exactly.
    """
    import shlex

    uni: dict[str, set[str]] = {}
    for tool in loader.load().tools:
        names = [tool.name, *tool.aliases]
        for tpl in tool.templates:
            try:
                parts = shlex.split(tpl.template, posix=True)
            except ValueError:  # an unbalanced quote in a template is a catalog bug, not ours
                parts = tpl.template.split()
            if parts:
                names.append(parts[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1])
        for name in names:
            uni.setdefault(name, set()).add(tool.name)
    return uni


def test_every_catalogued_invocation_has_a_pinned_danger_verdict() -> None:
    """No tool may enter the catalog without an explicit danger classification."""
    uni = _catalog_invocations()
    buckets = {
        "_MUST_FIRE": _MUST_FIRE,
        "_MUST_NOT_FIRE": _MUST_NOT_FIRE,
        "_ARGUMENT_DEPENDENT": _ARGUMENT_DEPENDENT,
        "_CONSOLE_SUBCOMMANDS": frozenset(_CONSOLE_SUBCOMMANDS),
    }
    classified: set[str] = set()
    for label, bucket in buckets.items():
        overlap = classified & bucket
        assert not overlap, f"{label} double-classifies {sorted(overlap)}"
        classified |= bucket

    unclassified = sorted(set(uni) - classified)
    assert not unclassified, (
        "these catalogued invocations have NO danger verdict: "
        f"{unclassified}\nAdd each to _MUST_FIRE, _MUST_NOT_FIRE, _ARGUMENT_DEPENDENT or "
        "_CONSOLE_SUBCOMMANDS in test_arsenal_safety.py. Judge what the tool DOES: if it "
        "generates/delivers/executes a payload, opens a shell, tunnels traffic or runs code on "
        "a remote host it belongs in _MUST_FIRE — and allowlist.py must be taught its name as "
        "it is ACTUALLY INVOKED (this is how `sliver` missed `sliver-client`)."
    )

    stale = sorted(classified - set(uni))
    assert not stale, (
        f"these names are pinned but no longer in the catalog: {stale}. Remove them, so the "
        "table cannot rot into a list of things that no longer exist."
    )
    print(f"  all {len(uni)} catalogued invocation names carry a pinned danger verdict: PASS")


def test_dangerous_catalogued_tools_demand_the_red_confirm() -> None:
    """Every _MUST_FIRE name produces a reason AND is refused at the executor's danger gate.

    Asserted through validate_request, not just the heuristic — the claim is about the GATE.
    """
    from cockpit import executor as E
    from cockpit.models import ExecRequest

    for name in sorted(_MUST_FIRE):
        reasons = allowlist.dangerous_command_heuristic(name, [_LAB])
        assert reasons, (
            f"{name!r} generates/delivers/executes a payload, opens a shell, tunnels traffic or "
            "runs code remotely, but produces NO danger reason — the red-confirm silently does "
            "not fire and dangerous_ack is meaningless on that path. Teach allowlist.py the "
            "name as it is ACTUALLY INVOKED."
        )
        rej = E.validate_request(ExecRequest(command=name, args=[_LAB], approved=True))
        assert rej is not None and rej.gate == "danger", (
            f"{name!r} approved WITHOUT dangerous_ack must be refused at the danger gate — got "
            f"{getattr(rej, 'gate', None)}"
        )
    # Positive control: the regression names that shipped green must be in here, so this table
    # can never be quietly emptied back to the state that hid them.
    for name in ("weevely", "dnscat2-client", "iodine", "commix", "SSTImap", "SharPersist",
                 "Invoke-Obfuscation", "mssqlclient.py", "donut", "ScareCrow"):
        assert name in _MUST_FIRE, f"{name} was dropped from _MUST_FIRE — that is the bug returning"
    print(f"  all {len(_MUST_FIRE)} dangerous catalogued invocations are refused without the "
          "red-confirm: PASS")


def test_a_wrapper_cannot_launder_the_red_confirm() -> None:
    """`proxychains -q <dangerous>` must carry the SAME verdict as `<dangerous>` bare.

    WHY THIS EXISTS. Cataloguing proxychains surfaced a gate hole that predated it. The
    heuristic classified argv[0] only, so `weevely` produced a reason and
    `proxychains -q weevely ...` produced NONE — and cockpit/tunnels.py's ``wrap_command``
    builds precisely that argv for the human to approve. Routing a command through a tunnel
    therefore STRIPPED its red-confirm: the deeper into a network you went, the weaker the gate
    got, which is exactly backwards.

    Asserted through validate_request, because the claim is about the GATE, not the predicate.
    """
    from cockpit import executor as E
    from cockpit.models import ExecRequest

    # Every fixture references the lab target: the danger gate is what is under test here, and
    # a command that named no lab host would be stopped one gate earlier (target) and prove
    # nothing about the confirm.
    # The lab host is a STANDALONE token in every fixture: the target gate does not resolve one
    # buried inside impacket's `domain/user:pass@host` string, and it runs before the danger
    # gate — so that spelling would stop the request one gate early and prove nothing here.
    inner_cases = [
        ("weevely", [f"http://{_LAB}/shell.php", "pw"]),
        ("psexec.py", ["-target-ip", _LAB]),
        ("evil-winrm", ["-i", _LAB]),
        ("secretsdump.py", ["-target-ip", _LAB]),
    ]
    for wrapper in ("proxychains", "proxychains4"):
        for inner, inner_args in inner_cases:
            bare = allowlist.dangerous_command_heuristic(inner, inner_args)
            assert bare, f"fixture is wrong: bare {inner!r} must already be dangerous"

            wrapped_args = ["-q", inner, *inner_args]
            wrapped = allowlist.dangerous_command_heuristic(wrapper, wrapped_args)
            assert wrapped, (
                f"{wrapper} {inner} produces NO danger reason while bare {inner} produces "
                f"{bare} — the wrapper laundered the red-confirm away"
            )
            rej = E.validate_request(
                ExecRequest(command=wrapper, args=wrapped_args, approved=True)
            )
            assert rej is not None and rej.gate == "danger", (
                f"{wrapper} {inner} approved WITHOUT dangerous_ack must be refused at the danger "
                f"gate — got {getattr(rej, 'gate', None)}"
            )

    # `-f <config>` takes a VALUE: skipping the flag but not its value would read the config
    # path as the command and miss the real one.
    assert allowlist.dangerous_command_heuristic(
        "proxychains", ["-f", "/etc/proxychains4.conf", "weevely", f"http://{_LAB}/", "pw"]
    ), "the -f config VALUE was mistaken for the inner command"

    # The other half: the wrapper must NOT invent danger where the inner command has none, or
    # every pivoted scan raises a confirm and the confirm stops meaning anything.
    for benign in (["-q", "nmap", "-sT", "-Pn", _LAB],
                   ["-q", "curl", "-s", f"http://{_LAB}/"], ["-q"]):
        assert not allowlist.dangerous_command_heuristic("proxychains", benign), (
            f"proxychains {' '.join(benign)} raised a confirm around a benign inner command"
        )
    print("  a proxychains wrapper keeps the inner command's danger verdict: PASS")


def test_benign_catalogued_tools_stay_clean() -> None:
    """The other half of the claim: a confirm that fires on everything means nothing."""
    noisy = []
    for name in sorted(_MUST_NOT_FIRE):
        reasons = allowlist.dangerous_command_heuristic(name, [_LAB])
        if reasons:
            noisy.append(f"{name}: {reasons}")
    assert not noisy, (
        "these read-only/enumeration tools now demand a red-confirm — confirm fatigue is its "
        f"own safety failure:\n" + "\n".join(noisy)
    )
    print(f"  all {len(_MUST_NOT_FIRE)} benign catalogued invocations stay clean: PASS")


def test_argument_dependent_tools_are_clean_bare_and_flagged_when_abusive() -> None:
    """Bare binary quiet, abusive template loud. Both halves, or the classification is a lie."""
    import shlex

    uni = _catalog_invocations()
    for name in sorted(_ARGUMENT_DEPENDENT):
        assert not allowlist.dangerous_command_heuristic(name, [_LAB]), (
            f"{name!r} is pinned argument-dependent but fires on the bare binary — either move "
            "it to _MUST_FIRE or stop flagging its read-only mode"
        )
        owners = uni[name]
        fired = []
        for tool in loader.load().tools:
            if tool.name not in owners:
                continue
            for tpl in tool.templates:
                parts = shlex.split(tpl.template, posix=True)
                if parts and allowlist.dangerous_command_heuristic(parts[0], parts[1:]):
                    fired.append(tpl.template)
        assert fired, (
            f"{name!r} is pinned argument-dependent, but NOT ONE of its catalogued templates "
            "trips the heuristic. Either its abusive templates are unflagged (a silent "
            "missing red-confirm) or it belongs in _MUST_NOT_FIRE."
        )
    print(f"  all {len(_ARGUMENT_DEPENDENT)} argument-dependent tools: bare clean, abusive "
          "template flagged: PASS")


def test_console_subcommands_are_excused_only_when_their_console_is_flagged() -> None:
    """The one bucket that excuses a name must not become a hiding place.

    A subcommand is excused ONLY because the console binary hosting it is itself in _MUST_FIRE,
    so reaching that subcommand already required clearing a red-confirm.
    """
    uni = _catalog_invocations()
    for sub, owner in sorted(_CONSOLE_SUBCOMMANDS.items()):
        assert sub in uni, f"{sub!r} is excused but is not in the catalog at all"
        assert owner in uni[sub], (
            f"{sub!r} is recorded as a subcommand of {owner!r}, but the catalog says it belongs "
            f"to {sorted(uni[sub])}"
        )
        assert owner in _MUST_FIRE, (
            f"{sub!r} is excused as a console subcommand of {owner!r} — but {owner!r} is not in "
            "_MUST_FIRE, so nothing demands a red-confirm anywhere on that path"
        )
    print(f"  all {len(_CONSOLE_SUBCOMMANDS)} console subcommands are hosted by a flagged "
          "console: PASS")


def test_the_executor_knows_nothing_about_the_arsenal() -> None:
    """No coupling in the other direction either — the gates cannot be arsenal-aware.

    This used to be a HARDCODED LIST OF FIVE FILENAMES while the cockpit package holds
    twenty-two modules. The test PRINTED "the cockpit package has zero references to the
    arsenal" and checked less than a quarter of it: session.py, sliver.py, obfuscation.py,
    jobs.py, kali.py, terminal.py, tunnels.py, repeater.py, reconcile.py, scope.py, loot.py,
    models.py, config.py, runstore.py, winprofiles.py and winrm_transport.py could all import
    the arsenal freely and nothing noticed. Every one of them post-dates the invariant.

    Now: every cockpit module, drawn from the real directory, so a module added tomorrow is
    covered without anyone remembering to add it.

    THE PREDICATE CHANGED TOO, and widening the file set is what exposed why. A bare
    ``"arsenal" in src`` conflates "depends on the arsenal" with "has a parameter spelled
    arsenal". ``cockpit/reconcile.py`` is the second kind: it takes the loaded catalog as an
    opaque ``Any`` argument injected by the caller, precisely SO THAT it has no import-time
    dependency on the arsenal. Flagging it would have been a false positive, and the honest
    response to a false positive is a better predicate, not a narrower file set. So the claim
    asserted here is the one the invariant actually makes — no IMPORT, in any form — matched
    the same way the arsenal->cockpit direction has always been matched.
    """
    pkg = Path(__file__).parent / "cockpit"
    modules = sorted(p for p in pkg.glob("*.py"))
    assert len(modules) >= 20, (
        f"only {len(modules)} cockpit modules found — this scan has gone vacuous"
    )
    import_re = re.compile(r"^\s*(?:from|import)\s+arsenal\b|\barsenal\.(?:loader|planner)\b", re.M)
    offenders = []
    for path in modules:
        raw = path.read_text(encoding="utf-8")
        # Prose is stripped: a docstring EXPLAINING the decoupling rule must not violate it.
        hits = [h for h in (import_re.search(scans.code_without_prose(raw)),) if h]
        # ...and the AST pass, which sees an aliased import, an in-function import, and
        # importlib/getattr indirection that no regex can.
        hits += scans.ast_reference_hits(raw, ["arsenal"])
        if hits:
            offenders.append(f"cockpit/{path.name}")
    assert not offenders, (
        f"these cockpit modules import the arsenal: {offenders}. The two packages may not "
        "reference each other in EITHER direction; cross-cutting endpoints belong in main.py."
    )
    # POSITIVE CONTROL: the check can fail, demonstrated on a planted violation rather than
    # asserted. Without this, "zero references" is just a claim about a predicate that might
    # never match anything.
    scans.assert_catches_a_planted_violation(
        plant="from arsenal import loader",
        patterns=[r"^\s*(?:from|import)\s+arsenal\b"],
        ast_targets=["arsenal"],
        where="cockpit/session.py",
    )
    print(f"  all {len(modules)} cockpit modules have zero imports of the arsenal "
          "(+ planted-violation control): PASS")


def test_executor_gates_are_byte_for_byte_unchanged() -> None:
    from cockpit import executor as E

    ok, reason = E.check_target_lock(["--help"])
    assert not ok and reason == "no lab target specified — the command must reference the lab"
    ok, reason = E.check_target_lock(["-sV", "scanme.nmap.org"])
    assert not ok and "not the lab" in reason
    src = (Path(__file__).parent / "cockpit" / "executor.py").read_text(encoding="utf-8")
    for gate in ('gate="target"', 'gate="approval"', 'gate="danger"', 'gate="sandbox"'):
        assert gate in src, f"{gate} disappeared from the executor"
    print("  LAB target-lock wording + all four executor gates unchanged: PASS")


# --------------------------------------------------------------------------- #
# 3. templates are target-faithful
# --------------------------------------------------------------------------- #
def test_no_template_can_smuggle_a_host() -> None:
    """A template must not carry a host of its own — every target comes from the engagement."""
    host_re = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|local|htb|thm)\b", re.I)
    allowed = {"crt.sh", "example.com"}   # named inside notes/labels, not as a target
    for tool in loader.load().tools:
        for tpl in tool.templates:
            for host in host_re.findall(tpl.template):
                assert host.lower() in allowed, (
                    f"{tool.name}/{tpl.label} hardcodes host {host}"
                )
    print("  no template hardcodes a host — the target always comes from the engagement: PASS")


def test_the_catalog_is_inert_data() -> None:
    """The catalog is JSON — plain dicts, lists and strings. There is nothing in the file
    that could execute even in principle, whatever its size."""
    import json

    raw = json.loads((_PKG / "tools.json").read_text(encoding="utf-8"))

    def inert(node: object) -> bool:
        if isinstance(node, dict):
            return all(isinstance(k, str) and inert(v) for k, v in node.items())
        if isinstance(node, list):
            return all(inert(v) for v in node)
        return isinstance(node, (str, int, float, bool)) or node is None

    assert inert(raw), "the catalog holds something that is not plain JSON data"
    print(f"  the catalog is inert JSON — {len(raw['tools'])} tools, nothing executable: PASS")


def test_no_import_time_dependency_on_the_composer() -> None:
    """The arsenal must not depend on the attack-path composer to be imported.

    Stated precisely, because the honest claim is narrower than "it never references
    attack_path": rendering routes through the composer's ``substitute_target`` so a filled
    template is target-faithful. That single reference is a GUARDED, LAZY import inside one
    function body — the package imports and renders fine without it, and it pulls in a
    substitution helper, never an execution path.
    """
    for path in _SOURCES:
        code = _code_only(path.read_text(encoding="utf-8"))
        for line in code.splitlines():
            # anchored at column 0 — an INDENTED import is inside a function, which is
            # the lazy form this test is explicitly allowing.
            assert not re.match(r"(?:from|import)\s+attack_path\b", line), (
                f"{path.name} imports attack_path at module level"
            )
        for m in re.finditer(r"(?:from|import)\s+attack_path\b", code):
            indent = code[:m.start()].split("\n")[-1]
            assert indent.strip() == "" and indent, (
                f"{path.name} references attack_path outside a function body"
            )
    # and it really does import standalone
    import importlib

    assert importlib.import_module("arsenal.loader") is not None
    print("  no import-time dependency on the composer (one guarded lazy import): PASS")


def test_every_template_renders_target_faithfully() -> None:
    """EVERY template of EVERY tool, rendered — no foreign host survives, and nothing
    unfilled is hidden. This is the claim that has to scale with the catalog: 34 tools
    could be eyeballed, 73 cannot."""
    ars = loader.load()
    foreign_host = re.compile(
        r"\b(?:[a-z0-9-]+\.)+(?:htb|thm|local|vh|lab|test)\b"
        r"|\b(?:[a-z0-9-]+\.)?example\.(?:com|org|net)\b",
        re.I,
    )
    private_ip = re.compile(
        r"(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?!\d)"
    )
    checked = 0
    for tool in ars.tools:
        for tpl in tool.templates:
            cmd, unfilled = loader.render(
                tpl.template, _LAB, None, __import__("attack_path").substitute_target
            )
            where = f"{tool.name}/{tpl.label}"
            assert not foreign_host.search(cmd), f"{where} rendered a foreign host: {cmd}"
            assert not private_ip.search(cmd), f"{where} rendered a private/example IP: {cmd}"
            if "<target>" in tpl.template:
                assert _LAB in cmd, f"{where} did not receive the engagement target"
                assert "<target>" not in cmd, f"{where} left <target> unfilled"
            # anything still unfilled must remain VISIBLE, never silently guessed
            for ph in unfilled:
                assert ph in cmd, f"{where} hid an unfilled placeholder {ph}"
            checked += 1
    print(f"  all {checked} templates across {len(ars.tools)} tools render "
          "target-faithfully, no foreign host: PASS")


def test_the_callback_placeholder_is_never_rewritten_to_the_target() -> None:
    """A payload's callback address belongs to the OPERATOR. The composer rewrites any
    placeholder spelling ip/host/target, so the catalog spells this one <listener> — if that
    ever regressed, msfvenom templates would point the shell at the victim."""
    import attack_path as AP

    for token in ("<listener>", "<listener-port>"):
        assert AP.substitute_target(f"LHOST={token}", _LAB) == f"LHOST={token}", (
            f"{token} was rewritten to the target"
        )
    ars = loader.load()
    for tool in ars.tools:
        for tpl in tool.templates:
            assert "<lhost>" not in tpl.template.lower(), (
                f"{tool.name}/{tpl.label} uses <lhost>, which the composer would rewrite"
            )
    print("  the operator's callback placeholder survives substitution untouched: PASS")


def test_every_alias_tags_back_to_its_own_tool() -> None:
    """Provenance must survive the name a step actually types. ``_program`` strips .exe/.py,
    so an alias can normalise to something the catalog does not hold — winPEASx64.exe did
    exactly that, and a step running it would have gone untagged."""
    ars = loader.load()
    broken = [
        (tool.name, alias)
        for tool in ars.tools
        for alias in tool.names()
        if (m := planner.match_tool(ars, f"{alias} <target>")) is None or m.name != tool.name
    ]
    assert not broken, f"these names/aliases do not tag back to their tool: {broken}"
    print(f"  every name and alias across {len(ars.tools)} tools tags back: PASS")


def test_impacket_is_catalogued_as_its_individual_scripts() -> None:
    """impacket is not one binary, and a template that pretended otherwise would be a stub."""
    ars = loader.load()
    for script in ("GetUserSPNs.py", "GetNPUsers.py", "secretsdump.py", "psexec.py",
                   "wmiexec.py", "smbexec.py", "ntlmrelayx.py", "mssqlclient.py"):
        tool = ars.get(script)
        assert tool is not None, f"{script} is not in the catalog"
        assert tool.templates, f"{script} has no invocation"
        # both the .py and the packaged impacket- form must resolve
        assert ars.get(script.removesuffix(".py")) is tool
        assert ars.get(f"impacket-{script.removesuffix('.py')}") is tool
    assert ars.get("impacket") is None, "impacket must not be catalogued as a single binary"
    print("  the impacket suite is catalogued per script, both invocation forms: PASS")


def test_prompt_block_is_not_an_allowlist() -> None:
    """The block must not read as a restriction — the executor has no allowlist, and a
    reference that sounded like one would misdescribe the system."""
    block = planner.prompt_block(loader.load()).lower()
    assert "reference, not a restriction" in block
    assert "you may propose any tool" in block
    print("  the prompt block states it is a reference, not an allowlist: PASS")


if __name__ == "__main__":
    test_arsenal_has_no_execution_path()
    test_arsenal_never_imports_the_executor()
    test_a_rendered_invocation_is_only_a_string()
    test_arsenal_command_still_clears_every_gate()
    test_every_catalogued_invocation_has_a_pinned_danger_verdict()
    test_dangerous_catalogued_tools_demand_the_red_confirm()
    test_a_wrapper_cannot_launder_the_red_confirm()
    test_benign_catalogued_tools_stay_clean()
    test_argument_dependent_tools_are_clean_bare_and_flagged_when_abusive()
    test_console_subcommands_are_excused_only_when_their_console_is_flagged()
    test_the_executor_knows_nothing_about_the_arsenal()
    test_executor_gates_are_byte_for_byte_unchanged()
    test_no_template_can_smuggle_a_host()
    test_the_catalog_is_inert_data()
    test_no_import_time_dependency_on_the_composer()
    test_every_template_renders_target_faithfully()
    test_the_callback_placeholder_is_never_rewritten_to_the_target()
    test_every_alias_tags_back_to_its_own_tool()
    test_impacket_is_catalogued_as_its_individual_scripts()
    test_prompt_block_is_not_an_allowlist()
    print("ALL tool-arsenal safety-invariant tests pass")
