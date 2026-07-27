"""Functional tests for the detection-footprint (purple-team) layer.

Covers what the panel promises:

  1. MATCHING — the curated catalog resolves real commands to the right activity, through plain
     aliases, protocol subcommands (``nxc smb``), verbs (``net rpc password``) and interpreter-run
     scripts (``python3 targetedKerberoast.py``).
  2. ARGUMENT SIGNALS — ``-just-dc`` escalates a dump to DCSync; stealth-shaped flags are
     surfaced with their ATT&CK Stealth technique; a flag scoped to one activity does not fire on
     an unrelated command that happens to reuse the letter.
  3. ATT&CK RESOLUTION — ids resolve to the right technique, tactic and telemetry, and the
     TA0005 "Stealth" / "Defense Evasion" alias is carried through.
  4. GROUNDED vs AI_SUGGESTED — grounded footprints come entirely from the curated map; an
     uncatalogued command falls to the model, and the answer is re-grounded (invented technique
     ids dropped, and the model can never introduce a Sigma rule).
  5. TAGGING — steps and runs get the compact tag, unmapped commands honestly get none, and the
     roll-up counts both.
  6. REPORT — the per-run Detection footprint block and the engagement roll-up render, and say
     so plainly when a command is unmapped.
  7. KNOWLEDGE CONSISTENCY — every id the catalog references resolves (the offline half of
     ``pipeline/detection_sources.py``).

Hermetic: llm.chat is monkeypatched, so no LLM, no network, no Docker.
Run:  python test_detection.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import llm
import report as report_gen
from detection import attck as A
from detection import catalog as C
from detection import resolver as R
from detection import tagging as T


class _FakeLLM:
    """Swap llm.chat for a canned response; restore on exit."""

    def __init__(self, response: str):
        self.response = response

    def __enter__(self):
        self._orig = llm.chat
        llm.chat = lambda system, user, cfg, max_tokens=0: self.response
        return self

    def __exit__(self, *exc):
        llm.chat = self._orig


# --------------------------------------------------------------------------- #
# 1. matching
# --------------------------------------------------------------------------- #
def test_matching() -> None:
    cases = [
        ("nmap", ["-sV", "10.0.0.1"], "portscan", "tool"),
        ("/usr/bin/gobuster", ["dir", "-u", "http://x"], "dir_brute", "tool"),
        ("impacket-secretsdump", ["d/u:p@dc"], "secretsdump", "tool"),
        ("secretsdump.py", ["d/u:p@dc"], "secretsdump", "tool"),
        ("nxc", ["smb", "10.0.0.0/24"], "smb_enum", "subcommand"),
        ("nxc", ["ldap", "dc01"], "ldap_query", "subcommand"),
        ("net", ["rpc", "password", "victim", "New1!"], "password_reset", "subcommand"),
        ("net", ["rpc", "group", "addmem", "Domain Admins", "x"], "group_add", "subcommand"),
        ("certipy", ["shadow", "auto", "-account", "x"], "shadow_credentials", "subcommand"),
        ("python3", ["targetedKerberoast.py", "-d", "d"], "kerberoast", "script"),
        ("C:\\tools\\Rubeus.exe", ["kerberoast"], "ticket_use", "tool"),
    ]
    for cmd, args, want_key, want_how in cases:
        m = C.lookup(cmd, args)
        assert m.spec is not None, f"{cmd} {args}: expected a match"
        assert m.spec.key == want_key, f"{cmd} {args}: got {m.spec.key}, want {want_key}"
        assert m.matched_on == want_how, f"{cmd}: matched_on {m.matched_on}, want {want_how}"

    # an uncatalogued command matches nothing — and says so, rather than guessing
    assert C.lookup("some-tool-we-never-heard-of", ["-x"]).spec is None
    print(f"  {len(cases)} commands resolve via alias / subcommand / verb / script: PASS")


# --------------------------------------------------------------------------- #
# 2. argument signals
# --------------------------------------------------------------------------- #
def test_arg_signals() -> None:
    # -just-dc escalates a credential dump into a replication request (DCSync)
    fp = R.footprint("impacket-secretsdump", ["-just-dc", "d/u:p@dc01"], allow_llm=False)
    ids = [t["id"] for t in fp["techniques"]]
    assert "T1003.006" in ids, ids
    assert "dcsync" in [s["id"] for s in fp["signals"]]
    assert fp["loudness"]["level"] == "loud"

    # stealth-shaped scan flags are SURFACED with their ATT&CK Stealth technique
    st = R.footprint("nmap", ["-sS", "-f", "-D", "RND:5", "10.0.0.1"], allow_llm=False)
    assert st["stealth"]["present"], st["stealth"]
    assert {"T1027", "T1036"} <= set(t["id"] for t in st["techniques"])
    assert any(t["id"] == "TA0005" for t in st["tactics"])

    # ...and the SAME letters on an unrelated command must NOT fire (nmap -S is a spoofed
    # source; net -S is a server). This is the applies_to scoping.
    other = R.footprint("net", ["rpc", "password", "v", "p", "-S", "dc01"], allow_llm=False)
    assert not other["stealth"]["present"], other["stealth"]
    assert other["signals"] == [], other["signals"]

    # case sensitivity: -f (fragment) is not -F (fast scan)
    assert C.lookup("nmap", ["-F", "host"]).signals == ()

    print("  arg signals escalate, surface stealth, and stay scoped to their activity: PASS")


# --------------------------------------------------------------------------- #
# 3. ATT&CK resolution
# --------------------------------------------------------------------------- #
def test_attck_resolution() -> None:
    d = A.describe("T1003.006")
    assert d["known"] and d["name"] == "OS Credential Dumping: DCSync"
    assert [t["id"] for t in d["tactics"]] == ["TA0006"]
    assert d["tactics"][0]["name"] == "Credential Access"
    assert d["url"] == "https://attack.mitre.org/techniques/T1003/006"
    assert any("4662" in ls for ls in d["log_sources"]), d["log_sources"]

    # TA0005 is "Stealth" in ATT&CK v19; the old name must stay visible
    s = A.describe("T1027")
    assert s["stealth"] is True
    assert s["tactics"][0]["name"] == "Stealth"
    assert s["tactics"][0]["also_known_as"] == "Defense Evasion"

    # an id we do not carry resolves to a clearly-unknown row, never a fabricated one
    u = A.describe("T9999")
    assert u["known"] is False and u["tactics"] == []
    print("  technique ids resolve to the right tactic/telemetry; TA0005 keeps its old name: PASS")


# --------------------------------------------------------------------------- #
# 4. grounded vs ai_suggested
# --------------------------------------------------------------------------- #
def test_grounded_footprint() -> None:
    fp = R.footprint("bloodhound-python", ["-d", "d", "-c", "All"], allow_llm=False)
    assert fp["grounded"] is True and fp["ai_suggested"] is False
    assert fp["activity"], fp
    assert fp["blue_view"] and fp["loudness"]["level"] and fp["telemetry"]
    assert fp["sigma"], "a grounded AD collection must cite real Sigma rules"
    for rule in fp["sigma"]:
        assert rule["url"].startswith("https://github.com/SigmaHQ/sigma/blob/master/")
        assert len(rule["id"]) == 36, rule
    assert all(t["source"] == "grounded" for t in fp["techniques"])
    print("  a grounded footprint is built entirely from the curated map: PASS")


def test_ai_suggested_is_reground_and_cannot_invent_rules() -> None:
    answer = json.dumps({
        "activity": "Compiling a local exploit",
        # one real id we carry, one real id we don't, one that does not exist at all
        "techniques": ["T1059.004", "T1068", "T9999"],
        "telemetry": ["auditd execve of gcc by a service account"],
        "loudness": "notable",
        "why_rating": "Compiler execution on a server is rare and stands out in process auditing.",
        "blue_view": "A compiler running on a host that has no business compiling anything.",
    })
    with _FakeLLM(answer):
        fp = R.footprint("gcc", ["exploit.c", "-o", "x"])

    assert fp["ai_suggested"] is True and fp["grounded"] is False
    assert [t["id"] for t in fp["techniques"]] == ["T1059.004"], "unresolvable ids must be dropped"
    assert fp["techniques"][0]["source"] == "ai_suggested"
    assert "T1068" in fp["why"] and "T9999" in fp["why"], "dropped ids must be disclosed"
    assert fp["sigma"] == [], "the model may NEVER introduce a detection rule"
    print("  an ai_suggested footprint is re-grounded and cannot introduce a Sigma rule: PASS")


def test_curated_signals_still_ground_an_unknown_command() -> None:
    """A command the catalog does not know can still get a GROUNDED stealth annotation, because
    the argument signals are curated even when the tool is not."""
    answer = json.dumps({
        "activity": "Unknown tooling", "techniques": [], "telemetry": ["process creation"],
        "loudness": "moderate", "why_rating": "Unrecognised binary.",
        "blue_view": "An unfamiliar process running.",
    })
    with _FakeLLM(answer):
        fp = R.footprint("mytool", ["--tamper=space2comment"])
    assert fp["ai_suggested"] is True
    assert [s["id"] for s in fp["signals"]] == ["payload_tamper"]
    assert fp["sigma"], "the signal's curated Sigma rules still apply"
    assert any(t["source"] == "grounded" for t in fp["techniques"])
    print("  curated arg signals still ground an uncatalogued command: PASS")


def test_no_llm_means_honest_unknown() -> None:
    fp = R.footprint("totally-unknown-binary", ["-x"], allow_llm=False)
    assert fp["grounded"] is False and fp["ai_suggested"] is False
    assert fp["techniques"] == [] and fp["sigma"] == []
    assert "unknown" in fp["why"].lower(), fp["why"]
    print("  with no map hit and no model, the footprint is an explicit UNKNOWN: PASS")


# --------------------------------------------------------------------------- #
# 5. tagging
# --------------------------------------------------------------------------- #
def test_first_command_line() -> None:
    block = "# reset the password\nnet rpc password 'v' 'N1!' \\\n  -U 'd/u%p' -S dc01"
    line = R.first_command_line(block)
    assert line.startswith("net rpc password"), line
    assert "-S dc01" in line, "a shell continuation must be folded into the command line"
    assert R.first_command_line("# only a comment\n\n") == ""
    print("  the annotated command skips comments and folds continuations: PASS")


def test_step_and_run_tagging() -> None:
    step = {"id": "recon-1", "title": "Scan", "commands": [
        {"lang": "bash", "cmd": "# find services\nnmap -sV -p- 10.10.10.5"}]}
    tag = T.tag_step(step)
    assert tag and tag["grounded"] and "T1046" in [t["id"] for t in tag["techniques"]]
    assert tag["loudness"] == "loud" and tag["loudness_score"] == 4

    # a step whose command we cannot map gets NO tag (never a guess)
    assert T.tag_step({"id": "x", "commands": [{"cmd": "weirdtool --go"}]}) is None
    # a step with no command at all
    assert T.tag_step({"id": "x", "commands": []}) is None

    runs = [
        {"command": "impacket-secretsdump", "args": ["-just-dc", "d/u:p@dc"]},
        {"command": "gobuster", "args": ["dir", "-u", "http://x"]},
        {"command": "weirdtool", "args": []},
    ]
    tags = [T.tag_run(r) for r in runs]
    assert [bool(t) for t in tags] == [True, True, False]
    s = T.summarize(tags)
    assert s["tagged"] == 2 and s["untagged"] == 1
    assert s["loudest"] == "loud"
    assert {"TA0006", "TA0008", "TA0043"} <= {t["id"] for t in s["tactics"]}

    # tag_phases attaches the tag in place, and marks the unmapped one null
    phases = [{"phase": "recon", "steps": [step, {"id": "y", "commands": [{"cmd": "weird --x"}]}]}]
    T.tag_phases(phases)
    assert phases[0]["steps"][0]["attck"] is not None
    assert phases[0]["steps"][1]["attck"] is None
    print("  steps + runs tag correctly; unmapped stays honestly null; roll-up counts both: PASS")


# --------------------------------------------------------------------------- #
# 6. report integration
# --------------------------------------------------------------------------- #
def _session(runs: list[dict]) -> dict:
    return {"goal": "t", "phases": [], "steps": {}, "execution_runs": runs}


def test_report_detection_sections() -> None:
    runs = [
        {"run_id": "aa11", "command": "impacket-secretsdump", "args": ["-just-dc", "d/u:p@dc"],
         "target": "dc01", "mode": "engagement", "exit_code": 0, "stdout": "krbtgt:x",
         "stderr": "", "started_at": "t"},
        {"run_id": "bb22", "command": "weirdtool", "args": ["-x"], "target": "h", "mode": "lab",
         "exit_code": 0, "stdout": "o", "stderr": "", "started_at": "t"},
    ]
    ev = report_gen.build_evidence_section(_session(runs))
    assert ev.count("**Detection footprint**") == 2, "every recorded run gets a footprint block"
    assert "T1003.006" in ev and "attack.mitre.org" in ev
    assert "SigmaHQ" in ev and "github.com/SigmaHQ/sigma" in ev
    assert "no footprint is asserted" in ev, "an unmapped run must say so, not stay silent"
    assert "Unmapped is not the same as untraceable" in ev

    roll = report_gen.build_detection_summary(_session(runs))
    assert roll.startswith("## Detection footprint (purple team)")
    assert "1 of 2" in roll or "1 not in the curated map" in roll
    assert "| ATT&CK | Technique | Tactic(s) |" in roll
    assert report_gen.build_detection_summary(_session([])) == "", "no runs -> no section"
    print("  the report carries a per-run footprint + an engagement ATT&CK roll-up: PASS")


# --------------------------------------------------------------------------- #
# 6b. the OPSEC channel (D10)
# --------------------------------------------------------------------------- #
def test_grounded_opsec_channel() -> None:
    """A grounded footprint gains an `opsec` block only on request, with the honesty marker."""
    # Off by default: no key.
    plain = R.footprint("nmap", ["-sS", "-p-", "10.0.0.1"], allow_llm=False)
    assert "opsec" not in plain

    fp = R.footprint("nmap", ["-sS", "-p-", "10.0.0.1"], allow_llm=False, include_opsec=True)
    op = fp["opsec"]
    assert op and op["grounded"] is True
    assert op["quieter"], "a grounded port-scan OPSEC note must offer quieter tradecraft"
    assert op["still_recorded"].strip(), "the honesty marker is mandatory"

    # An uncatalogued command, grounded-only: opsec is explicitly None (not fabricated).
    unknown = R.footprint("totally-unknown-binary", ["-x"], allow_llm=False, include_opsec=True)
    assert unknown["opsec"] is None
    print("  the OPSEC channel is opt-in, grounded, and honest about what still records it: PASS")


def test_report_opsec_summary_is_opt_in() -> None:
    runs = [
        {"run_id": "aa11", "command": "nmap", "args": ["-sS", "-p-", "h"], "target": "h",
         "mode": "engagement", "exit_code": 0, "stdout": "open", "stderr": "", "started_at": "t"},
    ]
    # Off by default (build_detection_summary carries no offensive content).
    assert "OPSEC assessment" not in report_gen.build_detection_summary(_session(runs))
    # The opt-in summary renders the red-team half with the honesty marker per family.
    op = report_gen.build_opsec_summary(_session(runs))
    assert op.startswith("## OPSEC assessment (red team)")
    assert "**Loud because:**" in op and "**Still recorded:**" in op
    # Every rendered family carries the honesty marker (build #4: the guard no longer bans
    # prescriptive/sensor-blinding copy — the still-recorded marker is the surviving invariant).
    assert op.count("**Still recorded:**") >= 1, "each OPSEC family must name what still records it"
    assert report_gen.build_opsec_summary(_session([])) == "", "no runs -> no OPSEC section"
    print("  the report OPSEC summary is opt-in and carries the still-recorded marker: PASS")


# --------------------------------------------------------------------------- #
# 7. knowledge consistency (offline half of pipeline/detection_sources.py)
# --------------------------------------------------------------------------- #
def test_c2_obfuscation_specs_present_and_grounded() -> None:
    for key in ("c2_dns_tunnel", "c2_malleable_profile", "c2_jitter_beacon", "c2_domain_fronting"):
        assert key in C.SPECS, f"missing C2/obfuscation spec {key!r}"
        R._grounded("x", [], C.Match(spec=C.SPECS[key], signals=(), matched_on="tool"))
    # every id these specs cite must resolve (also covered by the consistency test)
    print("  C2/obfuscation footprints present, grounded, describe-only: PASS")


def test_knowledge_is_internally_consistent() -> None:
    pipeline = Path(__file__).resolve().parents[1] / "pipeline"
    if str(pipeline) not in sys.path:
        sys.path.insert(0, str(pipeline))
    import detection_sources as DS

    errs = DS.check_internal()
    assert not errs, "catalog/ATT&CK consistency:\n" + "\n".join(errs)
    kb_errs = DS.check_kb_citations(None, None)
    assert not kb_errs, "defensive KB pages:\n" + "\n".join(kb_errs)
    print(f"  {len(C.SPECS)} specs / {len(C.ARG_SIGNALS)} signals / {len(A.TECHNIQUES)} techniques"
          f" / {len(C.SIGMA)} Sigma rules all resolve: PASS")
    print("  (run `python pipeline/detection_sources.py --verify` to diff against live upstream)")


if __name__ == "__main__":
    test_matching()
    test_arg_signals()
    test_attck_resolution()
    test_grounded_footprint()
    test_ai_suggested_is_reground_and_cannot_invent_rules()
    test_curated_signals_still_ground_an_unknown_command()
    test_no_llm_means_honest_unknown()
    test_first_command_line()
    test_step_and_run_tagging()
    test_report_detection_sections()
    test_grounded_opsec_channel()
    test_report_opsec_summary_is_opt_in()
    test_c2_obfuscation_specs_present_and_grounded()
    test_knowledge_is_internally_consistent()
    print("ALL detection-footprint tests pass")
