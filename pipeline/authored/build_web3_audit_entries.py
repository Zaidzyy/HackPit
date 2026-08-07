"""Build the web3 smart-contract audit methodology entries and merge them into
`authored_entries.jsonl`.

WHY A BUILDER AND NOT A HAND-EDITED JSONL
`authored_entries.jsonl` is one JSON object per line with embedded markdown. Hand-editing that is
how you get an unparseable line or a silently duplicated `id`. This script holds the entries as
ordinary Python, validates each through the canonical `schema.Entry`, and replaces by `id` — so it
is re-runnable and running it twice is a no-op rather than a duplication.

WHERE THESE THREE ENTRIES CAME FROM (D21 — DISTIL, NEVER PARROT)
The `claude-bug-bounty` (cbb-*) source already put the web3-audit skill's DeFi/Solidity/Solana-token
bug-class lists, grep arsenal and Foundry reference into the KB (17 web3 entries). Triage against
those found the skill's *content* well-covered but three things NOT covered, and each grounds one
of the new /code-scan web3 audit playbooks:

  * the EXTERNAL-FLOW ANALYSIS methodology — enumerate entrypoints, trace flows, verify one flow
    at a time (the decomposition open·kritt's Blockian team used for $1.5M in bounties). The cbb
    entries list bug classes; none teaches the map-once/verify-per-flow decomposition.
  * the COSMOS ABCI CONSENSUS-HALT review — the four-panic-class method (open·kritt's "Cosmos ABCI
    Panic Halt Review"). The KB's web3 entries are DeFi/Solidity/Solana-token; consensus halt on a
    Cosmos-SDK chain was ZERO.
  * the ANCHOR/SOLANA ACCOUNT-MODEL audit — missing owner check / signer spoof / CPI confusion /
    unchecked arithmetic. cbb-11 covers SPL *token* security; the general Anchor account-model
    audit methodology was thin.

Written from scratch from the vuln taxonomy in the `web3-audit` skill, open·kritt's public
built-in-workflow descriptions, and the official docs cited in each entry's references — no
sentence is copied from any of them. The tags carry the exact vuln_class strings the audit
playbooks emit (reentrancy, access-control, oracle-manipulation, consensus-halt, missing-owner-
check, signer-spoof, cpi-confusion, integer-overflow) so the fan-out's KB grounding retrieves them.

Run:  backend/.venv/Scripts/python.exe pipeline/authored/build_web3_audit_entries.py
      ... then ingest_authored.py and embed.py, as the module docstrings there describe.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schema import Entry  # noqa: E402 - path shim above must run first

AUTHORED = Path(__file__).with_name("authored_entries.jsonl")

ENTRIES: list[dict] = [
    {
        "id": "authored-web3-external-flow-analysis",
        "title": "External-Flow Analysis — Mapping Contract Entrypoints to Loss-of-Funds",
        "category": "web3",
        "subcategory": "solidity-audit",
        "source": "hackpit-authored",
        "tier": 1,
        "tags": ["web3", "solidity", "evm", "smart-contract", "audit", "external-flow",
                 "loss-of-funds", "reentrancy", "access-control", "oracle-manipulation",
                 "flash-loan", "unchecked-math", "checks-effects-interactions"],
        "tools": ["slither", "mythril", "echidna", "foundry", "cast"],
        "summary": "The decomposition to audit an EVM contract set for loss-of-funds without "
                   "drowning: map the externally-reachable entrypoints ONCE, then verify one flow "
                   "at a time. Each external/public function is where attacker calldata and value "
                   "first land; each flow is one path through it — a value transfer, a state "
                   "change, an external call, an oracle read, or an authorization branch. Verify "
                   "each in isolation against source rather than reasoning about the whole contract "
                   "at once. This is the method behind most paid Solidity findings and the "
                   "evm-external-flow /code-scan playbook.",
        "steps": [
            {"n": 1, "text": "Enumerate entrypoints: every external/public function plus "
                             "fallback()/receive(). These are the only places attacker input "
                             "enters. List each contract and its externally-reachable functions."},
            {"n": 2, "text": "For each entrypoint, trace its materially-different flows: value "
                             "transfers (call/transfer/send), accounting/state writes, external "
                             "calls and delegatecall, oracle reads, and authorization branches."},
            {"n": 3, "text": "Reentrancy: does a flow make an external value-bearing call BEFORE "
                             "it zeroes the caller's balance/updates state? Checks-effects-"
                             "interactions violated → re-enter from receive()/fallback() and drain."},
            {"n": 4, "text": "Access control — THE ONE RULE: read all sibling functions of a "
                             "family. If withdraw() has onlyOwner, check rescue()/sweep()/"
                             "initialize()/upgradeTo(). The missing modifier on the sibling IS the "
                             "bug (≈19% of Criticals). Also flag tx.origin auth and uninitialized "
                             "proxies."},
            {"n": 5, "text": "Oracle: is a price read (latestAnswer/latestRoundData) used without "
                             "an updatedAt/answeredInRound staleness check? Is the price a spot "
                             "value from reserves/slot0 (flash-loan manipulable in one block)? Is "
                             "the TWAP window too short?"},
            {"n": 6, "text": "Arithmetic: any `unchecked { }` block on attacker-sized input wraps "
                             "a balance/supply counter. Pre-0.8 code has no built-in overflow "
                             "guard at all."},
            {"n": 7, "text": "Confirm with a Foundry fork PoC: fork mainnet at a block, deploy/"
                             "load the target, run the exploit as the attacker, assertGt the "
                             "attacker balance. A finding without a passing PoC is a hypothesis."},
        ],
        "body_md": (
            "## External-flow analysis\n\n"
            "Auditing a contract by reading it top-to-bottom does not scale and misses the paths "
            "that matter. Map the **attack surface once** — the external/public functions plus "
            "`fallback`/`receive` — then spend your whole attention on **one flow at a time**. A "
            "flow is a single path an attacker's transaction takes: a value transfer, a state "
            "write, an external call, an oracle read, or an authorization decision.\n\n"
            "### The highest-payout classes, in order\n"
            "- **Reentrancy** (SWC-107): an external value call before the state update. The "
            "canonical drain — re-enter from the recipient's `receive()` and the balance is still "
            "non-zero. Fix is checks-effects-interactions or a `nonReentrant` guard.\n"
            "- **Access control** (SWC-105): a privileged function (mint, ownership transfer, "
            "upgrade, rescue) that is `external`/`public` with no owner/role modifier. Apply THE "
            "ONE RULE — audit the whole sibling family, the missing modifier is on the sibling.\n"
            "- **Oracle manipulation**: a price used without a staleness check, or a single-block "
            "spot price from AMM reserves that a flash loan skews and repays in the same tx.\n"
            "- **Unchecked arithmetic**: an `unchecked` block that wraps a balance around zero.\n"
            "- **delegatecall / selfdestruct**: attacker-influenced target runs code in this "
            "contract's storage context or destroys it.\n\n"
            "### Proving it\n"
            "Every finding gets a Foundry PoC (`forge test --match-test test_exploit -vvvv "
            "--fork-url $RPC`) that reproduces the loss on a fork. Tool passes (slither, mythril, "
            "echidna) corroborate but do not replace the manual flow verification — they are the "
            "approve-each tool pass, run in the sandbox, never from the analysis."
        ),
        "references": [
            "https://swcregistry.io/",
            "https://scs.owasp.org/",
            "https://book.getfoundry.sh/forge/fork-testing",
            "https://docs.chain.link/data-feeds/api-reference",
            "https://github.com/crytic/slither/wiki/Detector-Documentation",
        ],
        "meta": {
            "authored_batch": "web3-smartcontract-audit",
            "grounds_playbook": "evm-external-flow",
            "kb_gap": "cbb-* list bug classes; none teaches the map-once/verify-per-flow "
                      "decomposition the paid findings actually use",
        },
    },
    {
        "id": "authored-web3-cosmos-abci-halt",
        "title": "Cosmos ABCI Consensus-Halt Review — the Four Panic Classes",
        "category": "web3",
        "subcategory": "cosmos-audit",
        "source": "hackpit-authored",
        "tier": 1,
        "tags": ["web3", "cosmos", "cosmos-sdk", "abci", "tendermint", "cometbft",
                 "consensus-halt", "panic", "denial-of-service", "chain-halt", "audit", "golang"],
        "tools": ["gosec", "go"],
        "summary": "How to review a Cosmos-SDK chain for a consensus halt. Code inside an ABCI "
                   "method (BeginBlock/EndBlock/DeliverTx/CheckTx/ProcessProposal) runs inside "
                   "consensus on every validator, so a panic there is not a caught error — it "
                   "aborts block production chain-wide. Enumerate the wired ABCI methods and phase "
                   "handlers, then fan out FOUR panic classes per method: explicit panic, "
                   "arithmetic panic, Must*-helper panic, and bounds/type panic. A finding is a "
                   "panic that is BOTH production-reachable in a consensus phase AND triggerable by "
                   "attacker-controlled input. This is the cosmos-abci-halt /code-scan playbook.",
        "steps": [
            {"n": 1, "text": "Enumerate the wired ABCI methods and the module BeginBlocker/"
                             "EndBlocker/msg handlers they call — the code consensus runs every "
                             "block. That is the reachable surface; a panic anywhere on it halts "
                             "the chain."},
            {"n": 2, "text": "Class 1 — explicit panic: a `panic(...)` on a condition an attacker "
                             "sets via a crafted message/proposal field (e.g. an unknown denom). "
                             "In a consensus phase this is a halt, not an error return."},
            {"n": 3, "text": "Class 2 — arithmetic: cosmos-sdk `Int.Sub` panics on a negative "
                             "result and `Quo`/`QuoInt` panics on a zero divisor. A message that "
                             "drives an amount negative or a divisor to zero halts the block."},
            {"n": 4, "text": "Class 3 — Must* helpers: `MustUnmarshal`, `MustMarshal`, mustGet* "
                             "panic instead of returning an error. Attacker-shaped bytes or a "
                             "missing key turns the panic into a halt."},
            {"n": 5, "text": "Class 4 — bounds/type: a slice/map indexed by an attacker-chosen "
                             "position, or a type assertion `x.(*T)` without the comma-ok form. "
                             "Out-of-range or wrong-type panics inside the ABCI method."},
            {"n": 6, "text": "Reachability filter: keep ONLY panics that are both (a) inside a "
                             "consensus phase (not a query/CLI/genesis-only path) and (b) reachable "
                             "with attacker-controlled input. An operator-only panic is not a "
                             "finding."},
            {"n": 7, "text": "Confirm: submit the crafted message against a local node "
                             "(`go test ./...` with the trigger, or a devnet) and observe block "
                             "production stop. Severity is a full chain halt."},
        ],
        "body_md": (
            "## Why a panic is a chain halt\n\n"
            "CometBFT/Tendermint runs the application's ABCI methods — `BeginBlock`, `DeliverTx`, "
            "`EndBlock`, `PrepareProposal`, `ProcessProposal`, `Commit` — as part of committing a "
            "block. The cosmos-sdk BaseApp does **not** recover panics raised inside these paths on "
            "a validator the way it recovers a panic inside a single tx's message handler for "
            "gas-metering. A panic in `EndBlock` or in proposal processing propagates out and the "
            "node stops; because every validator runs the same deterministic code on the same "
            "input, they all stop — the chain halts until a coordinated patched restart.\n\n"
            "### The four classes to fan out\n"
            "1. **Explicit `panic()`** on attacker-controlled state.\n"
            "2. **Arithmetic** — `sdk.Int.Sub` underflow panic, `Quo` divide-by-zero panic; "
            "`sdk.Dec` the same.\n"
            "3. **`Must*` / `mustGet*` helpers** that panic on absent keys or malformed "
            "(un)marshal input.\n"
            "4. **Bounds/type** — slice index out of range, nil-pointer deref, failed type "
            "assertion without `, ok`.\n\n"
            "### The discriminator\n"
            "Most panics in a chain are unreachable by an attacker (genesis, migrations, operator "
            "CLI) or are behind validation that already returns an error. Report only the ones a "
            "**crafted message or proposal an attacker can broadcast** drives into a **consensus "
            "phase**. That is what turns a `panic` into a submittable denial-of-service."
        ),
        "references": [
            "https://docs.cosmos.network/main/build/building-modules/beginblock-endblock",
            "https://docs.cometbft.com/v0.38/spec/abci/abci++_methods",
            "https://docs.cosmos.network/main/build/building-modules/msg-services",
            "https://pkg.go.dev/cosmossdk.io/math",
        ],
        "meta": {
            "authored_batch": "web3-smartcontract-audit",
            "grounds_playbook": "cosmos-abci-halt",
            "kb_gap": "consensus halt on a Cosmos-SDK chain was ZERO in the KB (web3 entries were "
                      "DeFi/Solidity/Solana-token)",
        },
    },
    {
        "id": "authored-web3-anchor-account-model",
        "title": "Anchor / Solana Program Audit — the Account-Model Bug Classes",
        "category": "web3",
        "subcategory": "solana-audit",
        "source": "hackpit-authored",
        "tier": 1,
        "tags": ["web3", "solana", "anchor", "rust", "account-model", "smart-contract", "audit",
                 "missing-owner-check", "signer-spoof", "cpi-confusion", "integer-overflow",
                 "unchecked-account", "pda"],
        "tools": ["anchor", "cargo", "clippy"],
        "summary": "How to audit an Anchor (Solana) program. Solana passes ALL accounts in with "
                   "the instruction, so most bugs are the program trusting an account it never "
                   "validated. Enumerate the instruction handlers, then per instruction check four "
                   "things: account validation (typed Account<T> with owner/discriminator vs a raw "
                   "UncheckedAccount/AccountInfo), signer checks (Signer<'info> vs an unchecked "
                   "authority), CPI target-program-id assertion, and unchecked integer arithmetic "
                   "on lamports/amounts. This is the anchor-solana /code-scan playbook.",
        "steps": [
            {"n": 1, "text": "Enumerate instructions: each `pub fn name(ctx: Context<Accs>)` in "
                             "the #[program] module, with its Accounts struct. The struct is the "
                             "validation contract — read it as carefully as the handler."},
            {"n": 2, "text": "Missing owner check: a field typed `UncheckedAccount`/`AccountInfo` "
                             "with no #[account(owner = ...)]/has_one/seeds constraint. Anchor "
                             "skips owner + discriminator checks, so an attacker passes an account "
                             "they control where a program-owned one is expected."},
            {"n": 3, "text": "Signer spoof: an `authority`/`admin` account trusted for a "
                             "privileged action but typed AccountInfo/UncheckedAccount instead of "
                             "`Signer<'info>` and never asserted `is_signer`. The attacker supplies "
                             "the real authority's pubkey without its signature."},
            {"n": 4, "text": "CPI confusion: an `invoke`/`invoke_signed` whose target program is "
                             "not asserted (e.g. `token_program.key == token::ID`). A look-alike "
                             "program the attacker passes receives the call."},
            {"n": 5, "text": "Integer overflow: raw `+`/`-`/`*` on lamports/amounts instead of "
                             "checked_add/checked_sub/checked_mul. Release builds wrap silently, so "
                             "an attacker-sized amount underflows a balance to a huge value."},
            {"n": 6, "text": "Account confusion / type cosplay: two accounts of different types "
                             "with the same layout, or a missing #[account(mut)]/close constraint "
                             "that lets state be reused across instructions."},
            {"n": 7, "text": "Confirm with `anchor test`: write a test that passes the malicious "
                             "account/omits the signature/overflows the amount and asserts the "
                             "unauthorized state change. A failing invariant test is the PoC."},
        ],
        "body_md": (
            "## The Solana account model, and why it bites\n\n"
            "A Solana instruction does not fetch its accounts — the caller **passes every account "
            "in**, and the program must validate each one. Anchor automates the two checks that "
            "matter when you use a typed `Account<'info, T>`: it verifies the account is owned by "
            "the expected program and that its 8-byte discriminator matches `T`. The moment you "
            "drop to `UncheckedAccount` or `AccountInfo`, you opt OUT of both — and an attacker "
            "supplies an account they fully control.\n\n"
            "### The four classes\n"
            "- **Missing owner check** — `UncheckedAccount`/`AccountInfo` where a program-owned, "
            "typed account was meant. Account substitution.\n"
            "- **Signer spoof** — an authority not typed `Signer<'info>` (or `is_signer` never "
            "asserted). Privileged instruction runs for someone who never signed.\n"
            "- **CPI confusion** — `invoke`/`invoke_signed` to a program whose id is not pinned. "
            "A malicious look-alike program is called.\n"
            "- **Unchecked arithmetic** — `+`/`-`/`*` on balances instead of `checked_*`. Wraps in "
            "release builds; clippy's `arithmetic_side_effects` lint surfaces it.\n\n"
            "### Method\n"
            "Read the Accounts struct as the security boundary. Every constraint absent from it is "
            "a check the handler is trusting the caller to have done. Prove the finding with an "
            "`anchor test` that passes the bad account or omits the signature."
        ),
        "references": [
            "https://www.anchor-lang.com/docs/account-constraints",
            "https://book.anchor-lang.com/anchor_in_depth/the_accounts_struct.html",
            "https://solana.com/developers/courses/program-security",
            "https://github.com/coral-xyz/sealevel-attacks",
        ],
        "meta": {
            "authored_batch": "web3-smartcontract-audit",
            "grounds_playbook": "anchor-solana",
            "kb_gap": "cbb-11 covers SPL token security; the general Anchor account-model audit "
                      "(owner/signer/CPI/arithmetic) was thin",
        },
    },
]


def main() -> None:
    for row in ENTRIES:
        Entry.model_validate(row)  # abort loudly rather than write a bad row

    existing: list[dict] = []
    if AUTHORED.exists():
        with AUTHORED.open(encoding="utf-8") as fh:
            existing = [json.loads(line) for line in fh if line.strip()]

    new_ids = {r["id"] for r in ENTRIES}
    kept = [r for r in existing if r.get("id") not in new_ids]
    replaced = len(existing) - len(kept)
    merged = kept + [Entry.model_validate(r).model_dump() for r in ENTRIES]

    with AUTHORED.open("w", encoding="utf-8") as fh:
        for row in merged:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"authored entries: {len(existing)} before -> {len(merged)} after")
    print(f"  {len(ENTRIES) - replaced} added, {replaced} replaced by id")
    for row in ENTRIES:
        print(f"  - {row['id']}  [{row['category']}]  {len(row['steps'])} steps")
    print("NEXT: pipeline/ingest_authored.py, then pipeline/embed.py")


if __name__ == "__main__":
    main()
