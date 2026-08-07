"""Tests for the WEB3 / smart-contract audit playbooks (spec §3).

Covers, without a network or an LLM:
  1. the three web3 playbooks are registered and language-scoped;
  2. each fans out over its bundled fixture and returns the EXPECTED concrete findings-or-stubs,
     tagged with chain/contract/function (the deterministic heuristic analyst, no LLM);
  3. a slither / mythril / echidna fixture output parses into normalized findings;
  4. the tool pass is PROPOSE-ONLY (command strings, approve-each) and executes nothing;
  5. KB grounding cites a web3 entry (via an injected search — hermetic);
  6. the router surfaces the playbook list, the per-playbook sample, and the tool-pass proposal.

Run:  python test_web3_audit.py
"""

from __future__ import annotations

from pathlib import Path

from codescan import ai_audit, web3_tools
from codescan import router as cs_router

_PKG = Path(__file__).parent / "codescan"
_EVM = _PKG / "sample_web3" / "evm"
_COSMOS = _PKG / "sample_web3" / "cosmos"
_ANCHOR = _PKG / "sample_web3" / "anchor"


def _classes(result: dict) -> set[str]:
    return {f["vuln_class"] for f in result["findings"]}


# --------------------------------------------------------------------------- #
# 1. playbooks registered + language-scoped
# --------------------------------------------------------------------------- #
def test_playbooks_registered() -> None:
    keys = {p["key"] for p in ai_audit.list_playbooks()}
    assert {"external-flow-analysis", "evm-external-flow", "cosmos-abci-halt",
            "anchor-solana"} <= keys, keys
    # resolve defaults an unknown/empty key to the generic web-app playbook
    assert ai_audit.resolve_playbook("nope").key == "external-flow-analysis"
    assert ai_audit.resolve_playbook("").key == "external-flow-analysis"
    assert ai_audit.resolve_playbook("cosmos-abci-halt").chain == "cosmos"
    print("  4 playbooks registered; resolve defaults unknown keys; chains tagged: PASS")


def test_playbook_language_scoping() -> None:
    # the EVM playbook maps only .sol — pointed at the Cosmos (.go) fixture it finds no files
    r = ai_audit.run_heuristic_audit(_COSMOS, playbook="evm-external-flow")
    assert r["summary"]["findings"] == 0
    assert any("maps only" in w for w in r["warnings"]), r["warnings"]
    print("  a playbook maps only its language's files (evm on a Go tree finds nothing): PASS")


# --------------------------------------------------------------------------- #
# 2. each playbook returns the expected concrete findings on its fixture
# --------------------------------------------------------------------------- #
def test_evm_external_flow_finds_loss_of_funds() -> None:
    r = ai_audit.run_heuristic_audit(_EVM, playbook="evm-external-flow")
    assert r["chain"] == "evm" and r["playbook"] == "evm-external-flow"
    got = _classes(r)
    for expected in ("reentrancy", "access-control", "oracle-manipulation"):
        assert expected in got, f"{expected} not in {got}"
    # every finding is chain/contract/function-tagged and carries a string PoC
    for f in r["findings"]:
        assert f["chain"] == "evm" and f["contract"] and f["function"]
        assert isinstance(f["poc"], str) and f["poc"]
        assert f["source_refs"], f["title"]
    print(f"  evm-external-flow: {r['summary']['findings']} findings incl "
          "reentrancy/access-control/oracle, all chain-tagged: PASS")


def test_cosmos_abci_halt_finds_consensus_halts() -> None:
    r = ai_audit.run_heuristic_audit(_COSMOS, playbook="cosmos-abci-halt")
    assert r["chain"] == "cosmos"
    assert _classes(r) == {"consensus-halt"}, _classes(r)
    # the four panic classes each map to a real ABCI method line
    titles = " ".join(f["title"].lower() for f in r["findings"])
    for panic_word in ("explicit panic", "arithmetic", "must", "slice index"):
        assert panic_word in titles, f"{panic_word!r} not represented in {titles}"
    for f in r["findings"]:
        assert f["function"] in ("EndBlocker", "ProcessProposal"), f["function"]
    print(f"  cosmos-abci-halt: {r['summary']['findings']} consensus-halt findings across the "
          "four panic classes, mapped to ABCI methods: PASS")


def test_anchor_solana_finds_account_model_bugs() -> None:
    r = ai_audit.run_heuristic_audit(_ANCHOR, playbook="anchor-solana")
    assert r["chain"] == "solana"
    got = _classes(r)
    for expected in ("missing-owner-check", "signer-spoof", "integer-overflow", "cpi-confusion"):
        assert expected in got, f"{expected} not in {got}"
    print(f"  anchor-solana: {r['summary']['findings']} findings incl missing-owner/signer-spoof/"
          "overflow/CPI-confusion: PASS")


# --------------------------------------------------------------------------- #
# 3. tool output parses into findings
# --------------------------------------------------------------------------- #
def test_slither_output_parses() -> None:
    raw = {
        "success": True,
        "results": {"detectors": [
            {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
             "description": "Reentrancy in Vault.withdraw (Vault.sol#36-40)",
             "elements": [{"source_mapping": {"filename_short": "Vault.sol", "lines": [36]}}]},
            {"check": "arbitrary-send-eth", "impact": "High", "confidence": "High",
             "description": "Vault.rescue sends eth to arbitrary user",
             "elements": [{"source_mapping": {"filename_short": "Vault.sol", "lines": [73]}}]},
        ]},
    }
    out = web3_tools.parse_slither(raw)
    assert len(out) == 2
    assert out[0]["tool"] == "slither" and out[0]["severity"] == "high"
    assert out[0]["source_refs"] == ["Vault.sol:36"]
    # also accepts a JSON string, and returns [] on garbage rather than raising
    assert web3_tools.parse_slither('{"results":{"detectors":[]}}') == []
    assert web3_tools.parse_output("slither", "not json") == []
    print("  slither JSON output parses into ranked findings with file:line refs: PASS")


def test_mythril_and_echidna_output_parses() -> None:
    myth = {"issues": [{"title": "External Call To User-Supplied Address", "severity": "High",
                        "filename": "Vault.sol", "lineno": 67, "swc-id": "107"}]}
    m = web3_tools.parse_mythril(myth)
    assert len(m) == 1 and m[0]["reference"] == "SWC-107" and m[0]["source_refs"] == ["Vault.sol:67"]
    ech = {"tests": [{"name": "echidna_no_overflow", "status": "failed"},
                     {"name": "echidna_ok", "status": "passed"}]}
    e = web3_tools.parse_echidna(ech)
    assert len(e) == 1 and e[0]["vuln_class"] == "broken-invariant"
    print("  mythril (SWC) and echidna (falsified invariant) output parse into findings: PASS")


# --------------------------------------------------------------------------- #
# 4. the tool pass is PROPOSE-ONLY
# --------------------------------------------------------------------------- #
def test_tool_pass_is_propose_only() -> None:
    props = web3_tools.propose_pass("evm", "/audits/vault")
    tools = {p["tool"] for p in props}
    assert {"slither", "mythril", "echidna", "forge"} <= tools, tools
    for p in props:
        assert p["approve_each"] is True
        assert isinstance(p["command"], str) and p["command"]
        assert "propose-only" in p["note"].lower()
    # solana + cosmos have their own tool sets; an unknown chain yields nothing
    assert {p["tool"] for p in web3_tools.propose_pass("solana", "x")} == {"clippy", "anchor"}
    assert web3_tools.propose_pass("unknown-chain", "x") == []
    print("  tool pass returns approve-each command strings (proposals), never a run: PASS")


# --------------------------------------------------------------------------- #
# 5. KB grounding cites a web3 entry (injected search — hermetic)
# --------------------------------------------------------------------------- #
def test_kb_grounding_cites_web3_entry() -> None:
    def fake_search(query: str, limit: int, mode: str) -> list[dict]:
        assert mode == "hybrid"
        return [{"id": "authored-web3-external-flow-analysis",
                 "title": "External-Flow Analysis — Loss-of-Funds"}]

    r = ai_audit.run_heuristic_audit(_EVM, kb_search=fake_search, playbook="evm-external-flow")
    assert r["grounded"] is True
    cited = {k["id"] for f in r["findings"] for k in f["kb_refs"]}
    assert "authored-web3-external-flow-analysis" in cited, cited
    print("  fan-out grounds each flow in the KB and the finding cites the web3 entry: PASS")


# --------------------------------------------------------------------------- #
# 6. the router surfaces playbooks / per-playbook sample / tool-pass proposal
# --------------------------------------------------------------------------- #
def test_router_playbooks_sample_and_toolpass() -> None:
    keys = {p["key"] for p in cs_router.codescan_playbooks()["playbooks"]}
    assert "cosmos-abci-halt" in keys

    sample = cs_router.codescan_ai_audit_sample("anchor-solana")
    assert sample["is_sample"] is True and sample["chain"] == "solana"
    assert sample["summary"]["findings"] > 0

    tp = cs_router.codescan_tool_pass(cs_router.ToolPassIn(path="/audits/vault", chain="evm"))
    assert tp["static_only"] is True and tp["approve_each"] is True
    assert any(p["tool"] == "slither" for p in tp["proposals"])

    parsed = cs_router.codescan_tool_pass_parse(
        cs_router.ToolParseIn(tool="mythril",
                              output='{"issues":[{"title":"X","severity":"Low","filename":"A.sol",'
                                     '"lineno":1,"swc-id":"101"}]}'))
    assert parsed["count"] == 1 and parsed["findings"][0]["reference"] == "SWC-101"
    print("  router: /playbooks, per-playbook /ai-audit/sample, /tool-pass (+parse) all wired: PASS")


if __name__ == "__main__":
    test_playbooks_registered()
    test_playbook_language_scoping()
    test_evm_external_flow_finds_loss_of_funds()
    test_cosmos_abci_halt_finds_consensus_halts()
    test_anchor_solana_finds_account_model_bugs()
    test_slither_output_parses()
    test_mythril_and_echidna_output_parses()
    test_tool_pass_is_propose_only()
    test_kb_grounding_cites_web3_entry()
    test_router_playbooks_sample_and_toolpass()
    print("ALL web3 smart-contract audit tests pass")
