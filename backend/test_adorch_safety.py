"""SAFETY INVARIANTS for AD orchestration — the highest-stakes surface in the system.

An agent DRAFTING Active Directory abuse is different in kind from an agent drafting web
recon. DCSync replicates every secret in the domain. ForceChangePassword overwrites a real
person's password. psexec drops a service on a production host. None of that is reversible by
clicking undo, which means "a human approves every single step" is not one safety layer among
several here — it is carrying essentially the whole load.

So these are the claims, and they are tested rather than asserted in prose:

  1. THE AGENT PROPOSES, IT DOES NOT RUN. Source-scanned: the AD orchestrator has no process
     spawning, no path into the executor's run entrypoints, and no :kali path.
  2. IT CANNOT APPROVE. Source-scanned: nothing in it can set ``approved`` / ``dangerous_ack``.
     A proposal is data, and the field does not appear in it.
  3. NEVER-AUTO-RUN. The exact proposal the agent produced, submitted unapproved, is REFUSED
     and nothing runs. There is no batch, no approve-all, and no run endpoint to reach for.
  4. DESTRUCTIVE AD ABUSE DEMANDS THE RED CONFIRM. DCSync/secretsdump/psexec/password-reset
     are flagged by the heuristic and refused at the danger gate without an explicit ack.
  5. THE CATALOG IS THE ORACLE. Every edge the technique catalog calls destructive must
     resolve to a command the heuristic flags. This is the test that found the original hole:
     10 of 12 destructive abuses were sailing through on approval alone.
  6. ENGAGEMENT-SCOPED. An AD host outside the engagement scope is refused at the target gate.
  7. LAB MODE BYTE-FOR-BYTE UNCHANGED.

Hermetic: no Docker, no LLM, no network. Run:  python test_adorch_safety.py
"""
from __future__ import annotations

import inspect
from pathlib import Path

from adgraph import orchestrator as O
from adgraph import parser as P
from adgraph import router as R
from adgraph import sample_data as S
from adgraph import schema as SC
from adgraph.schema import Edge
from cockpit import allowlist as A
from cockpit import executor as E
from cockpit.models import EngagementRecord, ExecRequest

_SRC = Path(O.__file__).read_text(encoding="utf-8")
_ROUTER_SRC = Path(R.__file__).read_text(encoding="utf-8")
_LAB = "hackpit-lab-target"


# --------------------------------------------------------------------------- #
# 1 + 2. the agent proposes; it cannot run and cannot approve
# --------------------------------------------------------------------------- #
def test_orchestrator_has_no_execution_path() -> None:
    banned = [
        "subprocess", "Popen", "os.system", "os.exec", "pty.spawn", "docker exec",
        "iter_run(", "run_command(", "run_kali", "KALI_OPEN", "/cockpit/kali",
    ]
    for tok in banned:
        assert tok not in _SRC, f"the AD orchestrator must not reference {tok!r}"
    print("  the AD orchestrator has no execution path and no :kali path: PASS")


def test_orchestrator_cannot_approve() -> None:
    """It may READ the gates to pre-check a proposal; it must never be able to SATISFY one."""
    for tok in ("approved=True", "approved = True", "dangerous_ack=True", "dangerous_ack = True",
                "approved=req", "ExecRequest("):
        assert tok not in _SRC, f"the AD orchestrator must not be able to set {tok!r}"
    # …and the proposal it emits carries no approval field at all
    g = P.parse_collection(S.sample_collection())
    edge = next(e for e in g.edges if e.kind == "ForceChangePassword")
    prop = O.proposal_for_edge(g, edge, "why")
    for field in ("approved", "dangerous_ack", "run", "exec"):
        assert field not in prop, f"a proposal must not carry {field!r}"
    print("  the AD orchestrator cannot set approved/dangerous_ack, and a proposal has no "
          "approval field: PASS")


def test_there_is_no_second_execution_path() -> None:
    """Approval routes to the EXISTING gated executor. No run endpoint exists here."""
    routes = [r for r in _ROUTER_SRC.splitlines() if "@router." in r]
    orch = [r for r in routes if "orchestrate" in r]
    assert orch, "the orchestrate routes should exist"
    for r in orch:
        assert "/run" not in r and "/exec" not in r, f"orchestration must expose no run path: {r}"
    # and no batch / approve-all affordance anywhere in the module
    for tok in ("approve_all", "run_all", "run_path", "execute_path", "autorun", "auto_run"):
        assert tok not in _ROUTER_SRC and tok not in _SRC, f"no batch/auto affordance ({tok!r})"
    print("  no run endpoint, no batch, no approve-all — approval goes to the existing "
          "gated executor: PASS")


def test_proposer_cannot_resolve_an_engagement() -> None:
    """Mode resolution lives in the app, exactly as it does for the cockpit loop: the proposer
    receives an inert description and has no way to look one up or enter one."""
    for tok in ("get_active", "enter_engagement", "cockpit.engagement", "from cockpit import engagement"):
        assert tok not in _SRC, f"the AD proposer must not reference {tok!r}"
    sig = inspect.signature(O.propose_next)
    assert "scope_ctx" in sig.parameters, "the scope context is HANDED IN, never resolved here"
    print("  the proposer is handed an inert scope context; it cannot resolve or enter one: PASS")


# --------------------------------------------------------------------------- #
# 3. NEVER-AUTO-RUN — the load-bearing one
# --------------------------------------------------------------------------- #
def _eng(scope: str, target: str) -> EngagementRecord:
    include = [p.strip() for p in scope.split(",") if not p.strip().startswith("!")]
    return EngagementRecord(
        engagement_id="eng-adorch00001", target=target, authorization="ok", active=True,
        entered_at="2026-07-25T00:00:00+00:00", scope=scope, scope_include=include,
        allowed_hosts=[target],
    )


def _patch(rec):
    orig = E.engagement.get_active
    E.engagement.get_active = lambda _id: rec  # type: ignore[assignment]
    return orig


def test_a_proposed_ad_step_runs_nothing_unapproved() -> None:
    """THE claim. Take the agent's ACTUAL proposal for a real destructive edge and submit it
    exactly as proposed: unapproved. It must be refused, and nothing may run."""
    g = P.parse_collection(S.sample_collection())
    edge = next(e for e in g.edges if e.kind == "ForceChangePassword")
    prop = O.proposal_for_edge(g, edge, "shortens the path to DA")
    assert prop["command"], "this edge should resolve to a real command"

    eng = _eng("sevenkingdoms.local, dc01.sevenkingdoms.local", "dc01.sevenkingdoms.local")
    orig = _patch(eng)
    try:
        req = ExecRequest(command=prop["command"], args=prop["args"], approved=False,
                          engagement_id=eng.engagement_id)
        rej = E.validate_request(req)
        assert rej is not None, "an unapproved AD abuse step must be REFUSED"
        assert rej.gate in ("approval", "danger", "target"), rej
        # approving alone is still not enough for a destructive step — see the danger test
        print(f"  a proposed AD step submitted unapproved is refused at the {rej.gate} "
              "gate — nothing runs: PASS")
    finally:
        E.engagement.get_active = orig


# --------------------------------------------------------------------------- #
# 4 + 5. destructive AD abuse demands the red confirm — and the catalog is the oracle
# --------------------------------------------------------------------------- #
def test_destructive_ad_abuse_requires_the_red_confirm() -> None:
    eng = _eng("sevenkingdoms.local, dc01.sevenkingdoms.local", "dc01.sevenkingdoms.local")
    orig = _patch(eng)
    try:
        for command, args in (
            ("impacket-secretsdump", ["-just-dc", "sevenkingdoms.local/tywin:pw@dc01.sevenkingdoms.local"]),
            ("secretsdump.py", ["sevenkingdoms.local/tywin:pw@dc01.sevenkingdoms.local"]),
            ("impacket-psexec", ["sevenkingdoms.local/tywin:pw@dc01.sevenkingdoms.local"]),
            ("wmiexec.py", ["sevenkingdoms.local/tywin:pw@dc01.sevenkingdoms.local"]),
            ("net", ["rpc", "password", "jaime", "NewPass1", "-S", "dc01.sevenkingdoms.local"]),
            ("bloodyAD", ["--host", "dc01.sevenkingdoms.local", "set", "password", "jaime", "P1"]),
            ("mimikatz.exe", ["lsadump::dcsync", "/user:sevenkingdoms.local\\krbtgt"]),
        ):
            flags = A.dangerous_command_heuristic(command, args)
            assert flags, f"{command} must be flagged dangerous"
            # approved but NOT acked -> refused at the danger gate
            rej = E.validate_request(ExecRequest(
                command=command, args=args, approved=True, engagement_id=eng.engagement_id))
            assert rej is not None and rej.gate == "danger", (
                f"{command} approved-without-ack must be refused at the danger gate, got "
                f"{getattr(rej, 'gate', None)}"
            )
        print("  destructive AD abuse (DCSync/secretsdump/psexec/wmiexec/password-reset) is "
              "refused without the explicit red confirm: PASS")
    finally:
        E.engagement.get_active = orig


def _synthetic_edge(g, kind: str) -> Edge:
    users = [n.id for n in g.nodes.values() if n.type == "user"]
    comps = [n.id for n in g.nodes.values() if n.type == "computer"]
    groups = [n.id for n in g.nodes.values() if n.type == "group"]
    doms = [n.id for n in g.nodes.values() if n.type == "domain"]
    if kind in ("AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "HasSession", "SQLAdmin",
                "AllowedToAct", "AddAllowedToAct", "ReadLAPSPassword"):
        tgt = comps[0] if comps else users[1]
    elif kind in ("MemberOf", "AddMember", "AddSelf"):
        tgt = groups[0]
    elif kind in ("DCSync", "AllExtendedRights"):
        tgt = doms[0] if doms else users[1]
    else:
        tgt = users[1]
    return Edge(source=users[0], target=tgt, kind=kind, abusable=True)


def test_every_destructive_technique_trips_the_heuristic() -> None:
    """THE ORACLE. The technique catalog independently marks abuses destructive; the executor
    independently decides what needs a confirm. Any edge the catalog calls destructive whose
    command the heuristic does NOT flag is a hole — the human would be asked to approve a
    domain-altering step with no red confirm at all.

    This is the check that found the original problem: DCSync, WriteDacl, WriteOwner, Owns,
    AddMember, AddSelf, ForceChangePassword, AddKeyCredentialLink, AddAllowedToAct and
    AllExtendedRights all resolved to commands nothing flagged.
    """
    g = P.parse_collection(S.sample_collection())
    holes = []
    for kind in SC.ABUSABLE_EDGES:
        prop = O.proposal_for_edge(g, _synthetic_edge(g, kind), "")
        if prop["destructive_technique"] and not prop["dangerous_flags"]:
            holes.append((kind, prop["command"]))
    assert not holes, (
        "these destructive abuses would run without a red confirm: "
        + ", ".join(f"{k} -> {c}" for k, c in holes)
    )
    print(f"  every destructive edge in the catalog ({len(SC.ABUSABLE_EDGES)} kinds checked) "
          "trips the danger gate: PASS")


def test_every_destructive_windows_variant_trips_the_heuristic() -> None:
    """THE ORACLE, for the NATIVE WINDOWS variants (Rubeus/PowerView/Mimikatz that run on the
    box over WinRM). Adding native command variants must not open a hole: any edge the catalog
    calls destructive whose WINDOWS command the heuristic does NOT flag would let a domain-
    altering PowerShell command run over WinRM without a red confirm."""
    g = P.parse_collection(S.sample_collection())
    holes, checked = [], 0
    for kind in SC.ABUSABLE_EDGES:
        prop = O.proposal_for_edge(g, _synthetic_edge(g, kind), "")
        if not prop["destructive_technique"]:
            continue
        checked += 1
        # a destructive edge must HAVE a native variant, and it must trip the heuristic
        if not prop["windows_command"]:
            holes.append((kind, "(no windows variant)"))
        elif not prop["windows_dangerous_flags"]:
            holes.append((kind, prop["windows_command"]))
    assert not holes, (
        "these destructive Windows variants would run over WinRM without a red confirm: "
        + ", ".join(f"{k} -> {c}" for k, c in holes)
    )
    assert checked, "no destructive edges were exercised"
    print(f"  every destructive edge's NATIVE WINDOWS variant ({checked} checked) trips the "
          "danger gate too: PASS")


def test_windows_variant_runs_through_the_same_gates() -> None:
    """A native Windows abuse submitted through the executor is refused unapproved and demands
    the red confirm — the SAME gates as the Linux command, now for the WinRM transport."""
    import tempfile
    from pathlib import Path as _P
    from cockpit import winprofiles

    g = P.parse_collection(S.sample_collection())
    edge = next(e for e in g.edges if e.kind == "DCSync") if any(
        e.kind == "DCSync" for e in g.edges) else _synthetic_edge(g, "DCSync")
    prop = O.proposal_for_edge(g, edge, "")
    assert prop["windows_command"] and prop["windows_requires_confirm"], prop

    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_orig = winprofiles.DB_PATH
    winprofiles.DB_PATH = _P(tmp.name) / "sessions.db"
    try:
        winprofiles.init_db()
        p = winprofiles.create_profile("DC01", "10.0.0.5", "administrator", secret="pw")
        # unapproved -> refused
        rej = E.validate_request(ExecRequest(
            command=prop["windows_command"], args=prop["windows_args"],
            windows_profile_id=p["profile_id"], approved=False))
        assert rej is not None and rej.gate in ("approval", "danger"), rej
        # approved but not acked -> danger gate
        rej2 = E.validate_request(ExecRequest(
            command=prop["windows_command"], args=prop["windows_args"],
            windows_profile_id=p["profile_id"], approved=True))
        assert rej2 is not None and rej2.gate == "danger", rej2
    finally:
        winprofiles.DB_PATH = db_orig
        tmp.cleanup()
    print("  a native Windows abuse runs through the SAME gates (approval + danger) on WinRM: PASS")


def test_a_destructive_abuse_never_renders_as_benign() -> None:
    """REGRESSION — found by driving a real model against the running backend.

    The hermetic tests passed ``grounder=None``, so techniques always fell back to their
    catalog template and always produced a command. With the KB grounder wired, a grounded
    entry can come back empty or comment-only: DCSync and ForceChangePassword resolved to NO
    command, which made ``requires_confirm`` False and rendered a domain-wide credential
    replication as though it were free.

    "No command" now has to say WHY. ``no-command`` is the benign case (MemberOf is inherited
    rights). ``unresolved`` is a real abuse whose command did not come back usable, and when
    the technique is destructive that combination is flagged explicitly — there is no executor
    gate to lean on, because there is nothing to send to it.
    """
    g = P.parse_collection(S.sample_collection())

    def empty_grounder(seeds):
        """A KB hit whose commands are unusable — exactly the live failure."""
        return {"id": "kb-1", "title": "Empty entry", "commands": [{"lang": "bash", "cmd": "# just a note\n"}]}

    destructive_seen = 0
    for kind in SC.ABUSABLE_EDGES:
        prop = O.proposal_for_edge(g, _synthetic_edge(g, kind), "", empty_grounder)
        if not prop["destructive_technique"]:
            continue
        destructive_seen += 1
        if not prop["runnable"]:
            assert prop["destructive_unresolved"], (
                f"{kind}: a destructive abuse with no usable command must be flagged, not "
                "presented as benign"
            )
    assert destructive_seen, "no destructive edges were exercised"

    # and the benign case is still classed benign
    member_of = _synthetic_edge(g, "MemberOf")
    benign = O.proposal_for_edge(g, member_of, "")
    assert benign["resolution"] == "note-only" and not benign["destructive_unresolved"], benign
    print(f"  a destructive abuse whose command does not resolve is FLAGGED, never rendered "
          f"as benign ({destructive_seen} destructive kinds, grounder wired): PASS")


def test_read_only_ad_enumeration_stays_clean() -> None:
    """The other half of the same claim. A confirm that fires on everything is one the operator
    learns to click through, so read-only enumeration must NOT be flagged."""
    for command, args in (
        ("nmap", ["-sCV", "dc01.sevenkingdoms.local"]),
        ("ldapsearch", ["-x", "-H", "ldap://dc01", "-b", "dc=seven,dc=local"]),
        ("bloodhound-python", ["-d", "seven.local", "-u", "u", "-p", "p", "-c", "DCOnly"]),
        ("ldapdomaindump", ["-u", "seven\\u", "-p", "p", "ldap://dc01"]),
        ("nxc", ["smb", "dc01", "-u", "u", "-p", "p", "--shares"]),
    ):
        assert A.dangerous_command_heuristic(command, args) == [], (
            f"read-only enumeration must stay clean: {command} {args}"
        )
    print("  read-only AD enumeration is NOT flagged — the confirm keeps its meaning: PASS")


# --------------------------------------------------------------------------- #
# 6 + 7. engagement scope, argv-only, lab unchanged
# --------------------------------------------------------------------------- #
def test_off_scope_ad_host_is_refused() -> None:
    eng = _eng("sevenkingdoms.local, dc01.sevenkingdoms.local", "dc01.sevenkingdoms.local")
    orig = _patch(eng)
    try:
        rej = E.validate_request(ExecRequest(
            command="impacket-secretsdump", args=["-just-dc", "other.corp/u:p@dc.other.corp"],
            approved=True, dangerous_ack=True, engagement_id=eng.engagement_id))
        assert rej is not None and rej.gate == "target", (
            f"an off-scope DC must be refused at the target gate, got {getattr(rej, 'gate', None)}"
        )
        print("  an AD abuse aimed outside the engagement scope is refused at the target "
              "gate, even fully approved + acked: PASS")
    finally:
        E.engagement.get_active = orig


def test_proposal_is_argv_only() -> None:
    """The executor runs argv, never a shell. A proposal must therefore be a program plus a
    token list — never a shell string with a pipeline in it."""
    g = P.parse_collection(S.sample_collection())
    for e in g.edges:
        prop = O.proposal_for_edge(g, e, "")
        if not prop["runnable"]:
            continue
        assert isinstance(prop["command"], str) and " " not in prop["command"], prop["command"]
        assert isinstance(prop["args"], list)
        assert all(isinstance(a, str) for a in prop["args"])
        for shell_char in ("|", ">", "<", "&&", ";"):
            assert shell_char not in prop["command"], f"shell metachar in program: {prop}"
    print("  every proposal is argv-only — a program plus a token list: PASS")


def test_lab_mode_unchanged() -> None:
    ok, _ = E.check_target_lock(["-sV", _LAB], "nmap")
    assert ok
    ok, reason = E.check_target_lock(["-sV", "dc01.sevenkingdoms.local"], "nmap")
    assert not ok and reason == (
        "target 'dc01.sevenkingdoms.local' is not the lab — only the lab is allowed"
    )
    rej = E.validate_request(ExecRequest(command="nmap", args=["-sV", _LAB], approved=False))
    assert rej is not None and rej.gate == "approval"
    print("  LAB target-lock wording + gate order byte-for-byte unchanged: PASS")


def test_agent_cannot_advance_the_graph_by_itself() -> None:
    """advance() is a pure state function. It is never reached from propose_next, so a
    proposal cannot mark itself walked — the human's approved, successful run is what does."""
    src_propose = inspect.getsource(O.propose_next)
    assert "advance(" not in src_propose, "propose_next must never advance the walk"
    g = P.parse_collection(S.sample_collection())
    st = O.AdState(owned=("a",))
    st2 = O.advance(st, "a", "b", "GenericAll")
    assert st.owned == ("a",), "advance must not mutate the state it was given"
    assert st2.owned == ("a", "b")
    print("  the agent cannot advance the walk itself; advance() is pure and separate: PASS")


def test_an_inherited_rights_edge_never_acquires_a_command() -> None:
    """A ``no_command`` edge stays note-only EVEN WITH a grounder that offers a command.

    Build #9's live walk found this the hard way. MemberOf's catalog spec is prose — "its rights
    are already yours", tool "(none)" — but its kb_seeds still matched a real ACL-abuse KB entry,
    whose example commands were adopted wholesale. On the real corp.local graph the orchestrator
    proposed a runnable, DESTRUCTIVE `net rpc password` for ADMINISTRATOR -MemberOf-> DOMAIN
    ADMINS: a password reset against a live domain user, for an edge that requires no action.

    The gates held (nothing ran unapproved, the red-confirm was demanded), so this is a
    CORRECTNESS lock, not a containment one — but a panel that asks a human to approve a domain
    change for a free step is how a hurried operator makes a change they never meant to.
    """
    from adgraph import techniques as T

    g = P.parse_collection(S.sample_collection())

    def loud_grounder(_seeds: str) -> dict:
        """A grounder that always offers a destructive command — the adversarial case."""
        return {
            "id": "ht-acl-persistence-abuse",
            "title": "Abusing Active Directory ACLs/ACEs",
            "commands": [{"lang": "bash", "cmd": "net rpc password victim 'N3wPass!' -U dom/u%p"}],
        }

    for kind in ("MemberOf", "HasSIDHistory"):
        assert T._CATALOG[kind].no_command, f"{kind} must be marked no_command"
        edge = Edge(source="a", target="b", kind=kind)
        tech = T.technique_for_edge(edge, g, loud_grounder, "dc01.lab.local")
        cmds = [c.get("cmd", "") for c in tech.get("commands") or []]
        assert all(c.strip().startswith("#") for c in cmds), (
            f"{kind} must stay a prose note, got {cmds!r}"
        )
        assert not any("net rpc password" in c for c in cmds), (
            f"the grounder must not hand {kind} a destructive command"
        )
        # The CITATION is still kept — the KB explains the edge, it just supplies no action.
        assert tech.get("entry_id") == "ht-acl-persistence-abuse", "the KB citation is retained"

        # And the proposal built from it must report note-only / not runnable.
        prop = O.proposal_for_edge(g, edge, "why", loud_grounder, "dc01.lab.local")
        assert prop["resolution"] == "note-only", prop["resolution"]
        assert prop["runnable"] is False and not prop["command"], prop
        assert prop["requires_confirm"] is False, "a free step must not demand a red confirm"

    # POSITIVE CONTROL: an edge that IS an action still takes the grounder's command, or the
    # check above would pass just as well with grounding switched off entirely.
    edge = Edge(source="a", target="b", kind="ForceChangePassword")
    tech = T.technique_for_edge(edge, g, loud_grounder, "dc01.lab.local")
    assert any("net rpc password" in (c.get("cmd") or "") for c in tech["commands"]), (
        "an actionable edge must still be groundable — the fix must not disable grounding"
    )
    print("  inherited-rights edges never acquire a command, even from the KB grounder: PASS")


if __name__ == "__main__":
    test_an_inherited_rights_edge_never_acquires_a_command()
    test_orchestrator_has_no_execution_path()
    test_orchestrator_cannot_approve()
    test_there_is_no_second_execution_path()
    test_proposer_cannot_resolve_an_engagement()
    test_a_proposed_ad_step_runs_nothing_unapproved()
    test_destructive_ad_abuse_requires_the_red_confirm()
    test_every_destructive_technique_trips_the_heuristic()
    test_every_destructive_windows_variant_trips_the_heuristic()
    test_windows_variant_runs_through_the_same_gates()
    test_a_destructive_abuse_never_renders_as_benign()
    test_read_only_ad_enumeration_stays_clean()
    test_off_scope_ad_host_is_refused()
    test_proposal_is_argv_only()
    test_lab_mode_unchanged()
    test_agent_cannot_advance_the_graph_by_itself()
    print("ALL AD-orchestration safety-invariant tests pass")
