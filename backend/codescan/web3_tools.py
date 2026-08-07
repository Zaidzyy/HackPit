"""Web3 static-analysis TOOL PASS — a propose-only command builder + output parsers.

WHAT THIS IS
The AI audit (``ai_audit.py``) and the rule scan read source and PROPOSE; they execute nothing
(§0 of the spec, locked by ``test_ai_audit_safety.py``). A smart-contract audit still wants the
option of a real tool pass — slither / mythril / echidna / forge — so this module builds the exact
COMMAND STRINGS the operator runs **approve-each** through HackPit's existing gated executor + kali
sandbox, and parses those tools' JSON/text output back into the same normalized finding shape the
audit uses. It is the tool-pass analogue of a finding's PoC: a proposal carried as data.

THE INVARIANT (do not weaken)
This module launches no scanner, opens no socket, spawns no process, and imports no
executor / sandbox / engagement / gate module. It only *builds strings* and *parses text/JSON*.
The whole ``codescan`` package still spawns exactly one program — ``runner._spawn``'s asserted
semgrep/bandit — and this file does not change that. The tool commands here are run elsewhere,
approve-each, never from here.
"""

from __future__ import annotations

import json
from typing import Any

# open·kritt's IMPACT_LEVELS, shared with ai_audit — the tool findings rank on the same scale.
_IMPACT_LEVELS = ("critical", "high", "medium", "low", "informational")

# how each tool's own severity vocabulary maps onto IMPACT_LEVELS
_SLITHER_IMPACT = {
    "high": "high", "medium": "medium", "low": "low",
    "informational": "informational", "optimization": "informational",
}
_MYTHRIL_SEV = {"high": "high", "medium": "medium", "low": "low"}


# --------------------------------------------------------------------------- #
# tool catalog — what each tool is, per chain (metadata the picker + install hints use)
# --------------------------------------------------------------------------- #
TOOLS: dict[str, dict[str, str]] = {
    "slither": {
        "name": "slither", "chain": "evm", "kind": "static-analysis",
        "purpose": "Solidity static analysis — reentrancy, access control, arithmetic, 90+ detectors.",
        "install_hint": "pip install slither-analyzer",
    },
    "mythril": {
        "name": "mythril", "chain": "evm", "kind": "symbolic-execution",
        "purpose": "Symbolic execution of EVM bytecode — SWC-classified vulnerabilities.",
        "install_hint": "pip install mythril",
    },
    "echidna": {
        "name": "echidna", "chain": "evm", "kind": "property-fuzzing",
        "purpose": "Property-based fuzzing — falsifies invariants an attacker could break.",
        "install_hint": "see docker/Dockerfile.sandbox (crytic/echidna release binary)",
    },
    "forge": {
        "name": "forge", "chain": "evm", "kind": "poc-harness",
        "purpose": "Foundry build/test — runs a fork PoC that proves the exploit.",
        "install_hint": "curl -L https://foundry.paradigm.xyz | bash && foundryup",
    },
    "clippy": {
        "name": "clippy", "chain": "solana", "kind": "lints",
        "purpose": "Rust/Anchor lints — unchecked arithmetic, panics, unwrap in on-chain code.",
        "install_hint": "rustup component add clippy",
    },
    "anchor": {
        "name": "anchor", "chain": "solana", "kind": "poc-harness",
        "purpose": "Anchor test harness — runs an instruction-level PoC.",
        "install_hint": "cargo install --git https://github.com/coral-xyz/anchor anchor-cli",
    },
    "gosec": {
        "name": "gosec", "chain": "cosmos", "kind": "static-analysis",
        "purpose": "Go static analysis — surfaces panics/unhandled errors in ABCI paths.",
        "install_hint": "go install github.com/securego/gosec/v2/cmd/gosec@latest",
    },
    "govet": {
        "name": "govet", "chain": "cosmos", "kind": "static-analysis",
        "purpose": "go vet — reachable nil/bounds/type issues in consensus handlers.",
        "install_hint": "ships with the Go toolchain",
    },
}

# which tools a playbook's chain offers as a tool pass, best/most-specific first
_CHAIN_TOOLS: dict[str, tuple[str, ...]] = {
    "evm": ("slither", "mythril", "echidna", "forge"),
    "solana": ("clippy", "anchor"),
    "cosmos": ("gosec", "govet"),
}

# the parseable structured-output tools (the rest return free text a human reads)
_STRUCTURED = {"slither", "mythril", "echidna"}


def _sh_quote(p: str) -> str:
    """Minimal shell-safe single-quote for a path that goes into a PROPOSED command string.

    This does not run anything — it just keeps a path with spaces from mangling the proposal the
    operator reviews before approving it in the sandbox."""
    s = str(p)
    if s and all(c.isalnum() or c in "._-/:\\" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def _command(tool: str, target: str, contract: str | None = None) -> str:
    """The exact command line for a tool pass over ``target`` (a contract file or project dir)."""
    t = _sh_quote(target)
    if tool == "slither":
        return f"slither {t} --json -"
    if tool == "mythril":
        return f"myth analyze {t} -o json"
    if tool == "echidna":
        c = f" --contract {contract}" if contract else ""
        return f"echidna {t}{c} --format json"
    if tool == "forge":
        return "forge test -vvv"
    if tool == "clippy":
        return "cargo clippy --all-targets -- -W clippy::arithmetic_side_effects"
    if tool == "anchor":
        return "anchor test"
    if tool == "gosec":
        return f"gosec -fmt=json {t}/..."
    if tool == "govet":
        return f"go vet {t}/..."
    return f"{tool} {t}"


def propose(tool: str, target: str, contract: str | None = None) -> dict[str, Any]:
    """A single propose-only tool-pass command (NOT executed here)."""
    meta = TOOLS.get(tool, {"name": tool, "chain": "", "kind": "", "purpose": "",
                            "install_hint": ""})
    return {
        "tool": tool,
        "chain": meta.get("chain", ""),
        "kind": meta.get("kind", ""),
        "purpose": meta.get("purpose", ""),
        "command": _command(tool, target, contract),
        "install_hint": meta.get("install_hint", ""),
        "parseable": tool in _STRUCTURED,
        "approve_each": True,
        "note": "Propose-only. HackPit runs nothing here — take this to the executor and confirm "
                "it approve-each in the :kali sandbox, then paste the output back to normalize it.",
    }


def propose_pass(chain: str, target: str, contract: str | None = None) -> list[dict[str, Any]]:
    """The tool pass HackPit offers for a chain — every relevant tool, propose-only."""
    tools = _CHAIN_TOOLS.get((chain or "").strip().lower(), ())
    return [propose(t, target, contract) for t in tools]


# --------------------------------------------------------------------------- #
# output parsers — the tools' JSON/text -> normalized findings (same shape as the audit)
# --------------------------------------------------------------------------- #
def _norm_sev(word: str, table: dict[str, str]) -> str:
    return table.get(str(word or "").strip().lower(), "medium")


def _loc(el: dict[str, Any]) -> str:
    """A file:line ref from a slither source_mapping element, best-effort."""
    sm = el.get("source_mapping") or {}
    fname = sm.get("filename_short") or sm.get("filename_relative") or sm.get("filename") or ""
    lines = sm.get("lines") or []
    if fname and lines:
        return f"{fname}:{lines[0]}"
    return fname or ""


def parse_slither(data: Any) -> list[dict[str, Any]]:
    """Slither ``--json -`` output -> findings. Accepts the parsed dict or a JSON string."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return []
    if not isinstance(data, dict):
        return []
    detectors = ((data.get("results") or {}).get("detectors")) or []
    out: list[dict[str, Any]] = []
    for d in detectors:
        if not isinstance(d, dict):
            continue
        refs = [r for r in (_loc(el) for el in (d.get("elements") or [])) if r]
        out.append({
            "tool": "slither",
            "vuln_class": str(d.get("check") or "").strip(),
            "severity": _norm_sev(d.get("impact"), _SLITHER_IMPACT),
            "confidence": str(d.get("confidence") or "").strip().lower(),
            "title": (str(d.get("description") or "").strip().splitlines() or [""])[0][:220],
            "source_refs": refs,
            "reference": str(d.get("check") or ""),
        })
    return out


def parse_mythril(data: Any) -> list[dict[str, Any]]:
    """Mythril ``-o json`` output -> findings. Accepts the parsed dict or a JSON string."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return []
    if not isinstance(data, dict):
        return []
    issues = data.get("issues") or []
    out: list[dict[str, Any]] = []
    for it in issues:
        if not isinstance(it, dict):
            continue
        fname = it.get("filename") or it.get("sourceMap") or ""
        lineno = it.get("lineno")
        ref = f"{fname}:{lineno}" if fname and lineno else (str(fname) or "")
        swc = str(it.get("swc-id") or it.get("swcID") or "").strip()
        out.append({
            "tool": "mythril",
            "vuln_class": str(it.get("title") or "").strip(),
            "severity": _norm_sev(it.get("severity"), _MYTHRIL_SEV),
            "confidence": "",
            "title": str(it.get("title") or "").strip()[:220],
            "source_refs": [ref] if ref else [],
            "reference": f"SWC-{swc}" if swc else "",
        })
    return out


def parse_echidna(data: Any) -> list[dict[str, Any]]:
    """Echidna ``--format json`` output -> findings (one per FALSIFIED property)."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return []
    tests = data.get("tests") if isinstance(data, dict) else data
    out: list[dict[str, Any]] = []
    for t in tests or []:
        if not isinstance(t, dict):
            continue
        status = str(t.get("status") or t.get("result") or "").strip().lower()
        # a passed/fuzzing property is not a finding — only a falsified invariant is
        if status not in ("failed", "false", "falsified", "solved"):
            continue
        name = str(t.get("name") or t.get("contract") or "property").strip()
        out.append({
            "tool": "echidna",
            "vuln_class": "broken-invariant",
            "severity": "high",
            "confidence": "high",
            "title": f"Echidna falsified invariant: {name}"[:220],
            "source_refs": [],
            "reference": name,
        })
    return out


_PARSERS = {"slither": parse_slither, "mythril": parse_mythril, "echidna": parse_echidna}


def parse_output(tool: str, raw: Any) -> list[dict[str, Any]]:
    """Dispatch to the right parser for a tool's pasted output. Unknown tool -> []."""
    fn = _PARSERS.get((tool or "").strip().lower())
    return fn(raw) if fn else []
