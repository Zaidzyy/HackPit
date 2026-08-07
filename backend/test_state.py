"""Phase 2 — structured engagement state, parsers, task tree, prompt grounding.

Hermetic: no container, no network, no LLM. Parsers are pure functions tested against
captured tool output; the store writes to the real SQLite file under throwaway session ids
that each test clears.

The invariants that matter here:
  * ingest runs AUTOMATICALLY after every command, so the state package must never be able
    to execute anything — that is the one position from which code would sit outside the
    approval gate
  * empty state must render as "" so an existing loop's prompt is byte-for-byte unchanged
  * every write is an upsert, or ingesting each run would multiply the inventory
  * the model can only mutate the task tree in defined ways, and one bad op must not cost
    the good ones in the same response
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import state  # noqa: E402
from state import ingest, parsers, render, store, tasks  # noqa: E402
from state.models import Credential, Endpoint, Finding, Host, Service  # noqa: E402

state.init_db()

_S = "test-state-session"


def _reset() -> None:
    store.clear(_S)
    tasks.clear(_S)


# --------------------------------------------------------------------------- #
# safety
# --------------------------------------------------------------------------- #
_STATE_MODULES = (
    "models.py", "store.py", "parsers.py", "ingest.py", "tasks.py", "render.py",
    "governance.py", "killchain.py",
)


_BANNED_IMPORTS = {
    "subprocess", "socket", "requests", "httpx", "urllib", "docker", "pty", "ctypes",
    "multiprocessing", "asyncio",
}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "os.system", "os.popen", "os.execv"}


def test_the_state_package_executes_nothing() -> None:
    """It runs after EVERY command, automatically, with no approval of its own. An
    execution path here would sit entirely outside the gates.

    Checked against the parsed AST rather than the raw text, so this asserts what the code
    DOES, not what its prose says — a docstring explaining "no subprocess here" must not
    read as a violation, and `subprocess` hidden inside a string must not read as clean.
    """
    import ast

    for name in _STATE_MODULES:
        tree = ast.parse((Path(__file__).parent / "state" / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in _BANNED_IMPORTS, f"state/{name} imports {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                assert root not in _BANNED_IMPORTS, f"state/{name} imports from {node.module}"
            elif isinstance(node, ast.Call):
                fn = node.func
                dotted = ""
                if isinstance(fn, ast.Name):
                    dotted = fn.id
                elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                    dotted = f"{fn.value.id}.{fn.attr}"
                assert dotted not in _BANNED_CALLS, f"state/{name} calls {dotted}"
    print(f"  no subprocess/exec/eval/network/docker in {len(_STATE_MODULES)} state modules: PASS")


def test_ingest_never_raises_on_garbage() -> None:
    """Ingest runs after a command that ALREADY completed. Nothing it sees may propagate."""
    _reset()
    for junk in ("", "\x00\xff not json <<<", "{", "<nmaprun", "a" * 100_000):
        for prog in ("nmap", "httpx", "nuclei", "ffuf", "secretsdump.py", "totally-unknown"):
            got = ingest.parse_run(
                session_id=_S, run_id="r", command=prog, stdout=junk
            )
            assert got.counts() is not None
    counts = ingest.ingest_run(session_id=_S, run_id="r", command="nmap", stdout="garbage")
    assert counts == {"hosts": 0, "services": 0, "endpoints": 0, "credentials": 0, "findings": 0}
    print("  ingest survives empty / malformed / huge output without raising: PASS")


# --------------------------------------------------------------------------- #
# parsers
# --------------------------------------------------------------------------- #
_NMAP_XML = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="10.10.10.5" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac"/>
<hostnames><hostname name="dc01.corp.local"/></hostnames>
<ports>
<port protocol="tcp" portid="445"><state state="open"/>
  <service name="microsoft-ds" product="Windows Server 2019"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/></port>
<port protocol="tcp" portid="8080"><state state="filtered"/></port>
</ports><os><osmatch name="Windows Server 2019"/></os></host></nmaprun>"""


def test_nmap_xml_parses_and_drops_non_open_ports() -> None:
    got = parsers.parse_nmap_xml(_NMAP_XML, _S, "run-a")
    assert [h.address for h in got.hosts] == ["10.10.10.5"], "a MAC is not an addressable host"
    assert got.hosts[0].hostname == "dc01.corp.local"
    assert got.hosts[0].os == "Windows Server 2019"
    ports = sorted(s.port for s in got.services)
    assert ports == [445], f"only OPEN ports belong in the inventory, got {ports}"
    print("  nmap XML: address/hostname/os + open ports only (a -p- scan would add 65k rows): PASS")


def test_secretsdump_drops_the_empty_hash() -> None:
    """The blank-password NTLM hash is a real value that authenticates nothing. Recording
    it as a credential sends you chasing an account with no password set."""
    dump = (
        "corp.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
        "31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "corp.local\\svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:"
        "64f12cddaa88057e06a81b54e73b949b:::\n"
        "[*] Cleaning up...\n"
    )
    got = parsers.parse_secretsdump(dump, _S, "run-d")
    principals = [c.principal for c in got.credentials]
    assert principals == ["svc_sql"], f"expected only svc_sql, got {principals}"
    assert got.credentials[0].domain == "corp.local"
    assert got.credentials[0].kind == "ntlm"
    print("  secretsdump: hashes parsed, the empty-password hash dropped: PASS")


def test_kali_impacket_binary_names_reach_their_parser() -> None:
    """Kali's `impacket-secretsdump` must resolve to the same parser as `secretsdump.py`.

    Build #9's live DCSync against a real domain returned four NTLM hashes, krbtgt included,
    and ingested NONE of them: the parser registry knew `secretsdump` / `secretsdump.py` while
    HackPit's own AD technique catalog proposes Kali's `impacket-secretsdump`. Two halves of
    this codebase disagreed about the name of one tool. No hermetic test could catch it —
    they all fed the parser a program string they had picked themselves.
    """
    dump = ("corp.local\\svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:"
            "64f12cddaa88057e06a81b54e73b949b:::\n")
    for command in ("impacket-secretsdump", "/usr/bin/impacket-secretsdump",
                    "secretsdump.py", "secretsdump"):
        program = ingest.program_name(command)
        got = parsers.parse_stdout(program, dump, _S, "run-e")
        assert got.credentials, f"{command!r} (-> {program!r}) reached no parser"
        assert got.credentials[0].principal == "svc_sql", command

    # The prefix strip must not turn every impacket script into a secretsdump parser.
    assert ingest.program_name("impacket-wmiexec") == "wmiexec"
    assert not parsers.parse_stdout(ingest.program_name("impacket-wmiexec"), dump,
                                    _S, "run-e").credentials
    # ...and an ordinary tool is untouched.
    assert ingest.program_name("/usr/bin/nmap") == "nmap"
    print("  Kali's impacket-* binary names resolve to the same parsers: PASS")


def test_json_shapes_all_parse() -> None:
    """httpx emits JSONL, ffuf wraps a results array, dalfox writes a bare array. All three
    reach the same place, so no caller has to guess."""
    httpx = (
        '{"url":"https://a/1","status_code":200,"title":"One","tech":["nginx"]}\n'
        '{"url":"https://a/2","status_code":403}\n'
    )
    assert len(parsers.parse_httpx(httpx, _S).endpoints) == 2
    ffuf = '{"results":[{"url":"https://a/admin","status":200,"length":12}]}'
    assert len(parsers.parse_ffuf(ffuf, _S).endpoints) == 1
    nuclei = '[{"template-id":"x","info":{"name":"N","severity":"high"},"matched-at":"https://a/"}]'
    got = parsers.parse_nuclei(nuclei, _S)
    assert len(got.findings) == 1 and got.findings[0].severity == "high"
    print("  JSONL, wrapped-array and bare-array output all parse: PASS")


# --------------------------------------------------------------------------- #
# store
# --------------------------------------------------------------------------- #
def test_writes_are_upserts_not_appends() -> None:
    """Ingest runs after EVERY command. Without upserts, rescanning a host would multiply
    its services on every pass."""
    _reset()
    for _ in range(3):
        store.upsert_hosts([Host(session_id=_S, address="10.0.0.1", status="up")])
        store.upsert_services([Service(session_id=_S, address="10.0.0.1", port=80, name="http")])
        store.upsert_endpoints([Endpoint(session_id=_S, url="https://a/x")])
        store.upsert_credentials([Credential(session_id=_S, kind="password", principal="bob", secret="s")])
        store.upsert_findings([Finding(session_id=_S, title="T", target="10.0.0.1")])
    summary = store.load(_S)
    assert summary.counts() == {
        "hosts": 1, "services": 1, "endpoints": 1, "credentials": 1, "findings": 1
    }, summary.counts()
    print("  three identical ingests leave one row of each — upserts, not appends: PASS")


def test_a_later_run_never_blanks_what_an_earlier_one_learned() -> None:
    """A bare ping sweep sees an address with no hostname or OS. It must not erase what a
    full -A scan already established about that host."""
    _reset()
    store.upsert_hosts([
        Host(session_id=_S, address="10.0.0.2", hostname="web01", os="Ubuntu 22.04", status="up")
    ])
    store.upsert_hosts([Host(session_id=_S, address="10.0.0.2")])
    host = store.load(_S).hosts[0]
    assert host.hostname == "web01" and host.os == "Ubuntu 22.04", vars(host)
    print("  a later, less-detailed run does not blank earlier detail: PASS")


def test_validated_credentials_survive_a_redump() -> None:
    """`validated` is evidence. Re-dumping hashes must not reset a credential you PROVED
    works — that would send you re-testing something already known good."""
    _reset()
    store.upsert_credentials([
        Credential(session_id=_S, kind="ntlm", principal="svc", secret="h", validated=True)
    ])
    store.upsert_credentials([
        Credential(session_id=_S, kind="ntlm", principal="svc", secret="h", validated=None)
    ])
    assert store.load(_S).credentials[0].validated is True
    print("  a re-dump does not reset a validated credential: PASS")


def test_findings_fingerprint_instead_of_accumulating() -> None:
    _reset()
    for _ in range(4):
        store.upsert_findings([
            Finding(session_id=_S, title="Log4j RCE", target="https://a/", reference="CVE-2021-44228")
        ])
    assert len(store.load(_S).findings) == 1, "the same issue re-detected must stay one row"
    store.upsert_findings([
        Finding(session_id=_S, title="Log4j RCE", target="https://b/", reference="CVE-2021-44228")
    ])
    assert len(store.load(_S).findings) == 2, "the same issue on a DIFFERENT target is separate"
    print("  findings deduplicate by what+where, not by run: PASS")


def test_sessions_do_not_leak_into_each_other() -> None:
    _reset()
    other = _S + "-other"
    store.clear(other)
    store.upsert_hosts([Host(session_id=_S, address="10.0.0.9")])
    assert store.load(other).is_empty(), "one engagement must never see another's state"
    store.clear(other)
    print("  state is scoped per session — no cross-engagement leakage: PASS")


# --------------------------------------------------------------------------- #
# task tree
# --------------------------------------------------------------------------- #
def test_task_ops_apply_individually_and_reject_individually() -> None:
    """One wrong id must not cost the four correct observations in the same response."""
    _reset()
    tasks.seed(_S, ["Recon", "Enumeration", "Exploitation"])
    result = tasks.apply_ops(_S, [
        {"op": "mark_done", "id": "1", "evidence_run": "run-a"},
        {"op": "add_subtask", "parent": "2", "title": "Kerberoast svc_sql"},
        {"op": "mark_na", "id": "3", "why": "no exploitable service"},
        {"op": "mark_done", "id": "99"},           # unknown id
        {"op": "add_subtask", "parent": "nope", "title": "x"},  # malformed parent
        {"op": "teleport"},                        # unknown op
        "not-an-object",                           # wrong type
    ])
    assert len(result.applied) == 3, result.applied
    assert len(result.rejected) == 4, result.rejected
    loaded = {t.task_id: t for t in tasks.load(_S)}
    assert loaded["1"].status == "done" and loaded["1"].evidence_run_id == "run-a"
    assert loaded["3"].status == "n/a" and "exploitable" in loaded["3"].why
    assert "2.1" in loaded and loaded["2.1"].title == "Kerberoast svc_sql"
    print("  task ops: valid applied, invalid rejected individually, tree intact: PASS")


def test_the_tree_cannot_be_grown_without_bound() -> None:
    """A model re-proposing the same sub-task every turn would grow the tree forever, and
    an unbounded tree eats the prompt budget the state summary needs."""
    _reset()
    tasks.seed(_S, ["Recon"])
    first = tasks.apply_ops(_S, [{"op": "add_subtask", "parent": "1", "title": "Same thing"}])
    assert len(first.applied) == 1
    dup = tasks.apply_ops(_S, [{"op": "add_subtask", "parent": "1", "title": "same THING"}])
    assert not dup.applied and "already exists" in dup.rejected[0]["reason"]

    ops = [{"op": "add_subtask", "parent": "1", "title": f"t{i}"} for i in range(tasks.MAX_OPS_PER_TURN + 5)]
    capped = tasks.apply_ops(_S, ops)
    assert any("too many operations" in r["reason"] for r in capped.rejected)
    children = [t for t in tasks.load(_S) if t.parent_id == "1"]
    assert len(children) <= tasks.MAX_CHILDREN, f"{len(children)} children escaped MAX_CHILDREN"

    # Depth needs its own branch — parent "1" is now full from the batch above.
    _reset()
    tasks.seed(_S, ["Root"])
    node = "1"
    for _ in range(tasks.MAX_DEPTH + 3):
        before = {t.task_id for t in tasks.load(_S)}
        res = tasks.apply_ops(_S, [{"op": "add_subtask", "parent": node, "title": "deeper"}])
        if not res.applied:
            break
        added = {t.task_id for t in tasks.load(_S)} - before
        node = next(iter(added))
    assert node.count(".") + 1 <= tasks.MAX_DEPTH, f"depth escaped its bound at {node}"
    print("  duplicate titles, oversized batches and runaway depth are all bounded: PASS")


def test_seeding_never_wipes_recorded_progress() -> None:
    """Re-plotting the attack path must not erase what the tree already recorded."""
    _reset()
    tasks.seed(_S, ["Recon", "Enumeration"])
    tasks.apply_ops(_S, [{"op": "mark_done", "id": "1"}])
    tasks.seed(_S, ["Something", "Completely", "Different"])
    loaded = tasks.load(_S)
    assert [t.title for t in loaded] == ["Recon", "Enumeration"], [t.title for t in loaded]
    assert loaded[0].status == "done"
    print("  re-seeding an existing tree is a no-op — progress survives a re-plot: PASS")


def test_task_ids_sort_numerically() -> None:
    _reset()
    tasks.seed(_S, [f"task {i}" for i in range(12)])
    ids = [t.task_id for t in tasks.load(_S)]
    assert ids[:11] == [str(i) for i in range(1, 12)], ids
    print("  1.10 sorts after 1.9, not after 1.1: PASS")


# --------------------------------------------------------------------------- #
# rendering / prompt grounding
# --------------------------------------------------------------------------- #
def test_empty_state_renders_as_nothing() -> None:
    """The single most important property for adding this to a working loop: a session with
    no state must produce byte-for-byte the prompt it produced before this package existed."""
    _reset()
    assert render.render_state(store.load(_S), _S) == ""
    print("  empty state renders as '' — an existing loop's prompt is unchanged: PASS")


def test_render_carries_the_facts_a_planner_needs() -> None:
    _reset()
    store.upsert_hosts([Host(session_id=_S, address="10.10.10.5", hostname="dc01", os="Windows")])
    store.upsert_services([
        Service(session_id=_S, address="10.10.10.5", port=445, name="microsoft-ds")
    ])
    store.upsert_endpoints([Endpoint(session_id=_S, url="https://a/login", status=200, title="Sign in")])
    store.upsert_credentials([
        Credential(session_id=_S, kind="ntlm", principal="svc_sql", domain="corp.local", secret="DEADBEEF")
    ])
    store.upsert_findings([
        Finding(session_id=_S, title="Log4j RCE", severity="critical", target="https://a/")
    ])
    text = render.render_state(store.load(_S), _S)
    for needed in ("10.10.10.5", "dc01", "445/tcp", "https://a/login", "svc_sql", "Log4j RCE", "CRITICAL"):
        assert needed in text, f"the state block must carry {needed!r}"
    assert "do not re-run something whose answer is already here" in text
    print("  rendered state carries hosts, services, endpoints, creds and findings: PASS")


def test_credential_secret_exposure_is_one_switch() -> None:
    """Whether real secrets reach the LLM prompt is a deliberate, single-constant decision.
    It is True by Zaid's explicit choice; this guards that flipping it actually works, so
    the choice stays reversible rather than baked in."""
    _reset()
    store.upsert_credentials([
        Credential(session_id=_S, kind="password", principal="bob", secret="hunter2")
    ])
    assert render.INCLUDE_CREDENTIAL_SECRETS is True, "current, deliberate setting"
    assert "hunter2" in render.render_state(store.load(_S), _S)
    original = render.INCLUDE_CREDENTIAL_SECRETS
    try:
        render.INCLUDE_CREDENTIAL_SECRETS = False
        redacted = render.render_state(store.load(_S), _S)
        assert "hunter2" not in redacted, "flipping the switch must actually withhold the secret"
        assert "value withheld" in redacted and "bob" in redacted, (
            "the planner must still know the credential EXISTS and what it is for"
        )
    finally:
        render.INCLUDE_CREDENTIAL_SECRETS = original
    print("  secret exposure is one switch, and redaction still names the credential: PASS")


def test_state_beats_a_stdout_tail_for_size() -> None:
    """The claim this whole package rests on: the structured picture is SMALLER than the
    raw output it replaces, because each fact appears once instead of once per run."""
    _reset()
    raw = _NMAP_XML * 12                     # what 12 runs of tails would carry
    for i in range(12):
        got = parsers.parse_nmap_xml(_NMAP_XML, _S, f"run-{i}")
        store.upsert_hosts(got.hosts)
        store.upsert_services(got.services)
    rendered = render.render_state(store.load(_S), _S)
    assert len(rendered) < len(raw), f"state {len(rendered)} vs raw {len(raw)}"
    assert rendered.count("10.10.10.5") == 1, "twelve scans of one host must render once"
    print(f"  12 runs -> {len(rendered)} chars of state vs {len(raw)} of raw output: PASS")


def test_orchestrator_prompt_is_unchanged_without_a_session() -> None:
    """The state block is additive: no session id, no state, byte-identical prompt."""
    import orchestrator as O

    plan = {"goal": "test", "phases": []}
    base = O.build_user_prompt(plan, [], [])
    assert O.build_user_prompt(plan, [], [], None, None) == base
    assert O.build_user_prompt(plan, [], [], None, "no-such-session") == base
    print("  no session / no state -> the proposer prompt is byte-for-byte unchanged: PASS")


def test_orchestrator_prompt_carries_state_when_there_is_some() -> None:
    import orchestrator as O

    _reset()
    store.upsert_hosts([Host(session_id=_S, address="10.10.10.5")])
    store.upsert_services([Service(session_id=_S, address="10.10.10.5", port=445, name="smb")])
    plan = {"goal": "test", "phases": []}
    with_state = O.build_user_prompt(plan, [], [], None, _S)
    assert "10.10.10.5" in with_state and "445/tcp" in with_state
    assert "the state is authoritative" in with_state, (
        "the prompt must tell the model which source wins"
    )
    print("  a session with state gets it in the prompt, marked authoritative: PASS")


# --------------------------------------------------------------------------- #
# loot ingest
# --------------------------------------------------------------------------- #
def test_only_files_this_run_wrote_are_ingested(tmp: Path | None = None) -> None:
    """Loot directories persist across runs. Ingesting everything present would
    re-attribute an old scan's XML to whatever ran last, making source_run_id a lie."""
    import tempfile

    _reset()
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        old = d / "old.xml"
        old.write_text(_NMAP_XML, encoding="utf-8")
        old_mtime = time.time() - 3600
        import os as _os
        _os.utime(old, (old_mtime, old_mtime))

        started = time.time()
        time.sleep(0.05)
        (d / "new.xml").write_text(_NMAP_XML, encoding="utf-8")

        picked = ingest.new_loot_files(d, started)
        assert [p.name for p in picked] == ["new.xml"], [p.name for p in picked]

        assert ingest.new_loot_files(None, started) == []
        assert ingest.new_loot_files(d / "nope", started) == []
    print("  only files written DURING the run are ingested; old loot is not re-attributed: PASS")


if __name__ == "__main__":
    test_the_state_package_executes_nothing()
    test_ingest_never_raises_on_garbage()
    test_nmap_xml_parses_and_drops_non_open_ports()
    test_secretsdump_drops_the_empty_hash()
    test_kali_impacket_binary_names_reach_their_parser()
    test_json_shapes_all_parse()
    test_writes_are_upserts_not_appends()
    test_a_later_run_never_blanks_what_an_earlier_one_learned()
    test_validated_credentials_survive_a_redump()
    test_findings_fingerprint_instead_of_accumulating()
    test_sessions_do_not_leak_into_each_other()
    test_task_ops_apply_individually_and_reject_individually()
    test_the_tree_cannot_be_grown_without_bound()
    test_seeding_never_wipes_recorded_progress()
    test_task_ids_sort_numerically()
    test_empty_state_renders_as_nothing()
    test_render_carries_the_facts_a_planner_needs()
    test_credential_secret_exposure_is_one_switch()
    test_state_beats_a_stdout_tail_for_size()
    test_orchestrator_prompt_is_unchanged_without_a_session()
    test_orchestrator_prompt_carries_state_when_there_is_some()
    test_only_files_this_run_wrote_are_ingested()
    store.clear(_S)
    tasks.clear(_S)
    print("ALL state / task-tree tests pass")
