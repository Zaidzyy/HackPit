// SYNTHETIC deliberately-vulnerable Cosmos SDK module — the fixture the `cosmos-abci-halt`
// playbook maps. This is NOT real chain code. It exists only so the /code-scan web3 audit demo
// has a small, public, synthetic Cosmos-Go target to fan out over. Each ABCI phase handler carries
// one maliciously-triggerable, production-reachable halt path — one per class:
// explicit-panic / arithmetic / Must-helper / bounds-type. Do not run this against a live chain.
package rewards

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// EndBlocker runs inside consensus on every validator. A panic here is a chain halt, not a
// caught error — so every attacker-influenced condition below aborts block production.
func EndBlocker(ctx sdk.Context, k Keeper) {
	req := k.GetPendingClaims(ctx)

	// EXPLICIT PANIC: a crafted claim with an unknown denom drives an explicit panic.
	for _, claim := range req {
		if !k.HasDenom(ctx, claim.Denom) {
			panic("unknown denom in pending claim")
		}
	}

	// ARITHMETIC PANIC: sdk.Int.Sub panics on a negative result; a claim amount larger than the
	// pool underflows and halts the block. Quo panics on a zero divisor supplied by the message.
	pool := k.GetPool(ctx)
	for _, claim := range req {
		pool.Balance = pool.Balance.Sub(claim.Amount)
		share := pool.Balance.Quo(claim.Weight)
		k.SetShare(ctx, claim.Addr, share)
	}
}

// ProcessProposal validates a block proposal. It processes proposer-supplied bytes directly.
func (k Keeper) ProcessProposal(ctx sdk.Context, req ProposalRequest) sdk.ResponseProcessProposal {
	// MUST-HELPER PANIC: MustUnmarshal panics on malformed proposer bytes instead of erroring.
	var payload RewardPayload
	k.cdc.MustUnmarshal(req.Txs[0], &payload)

	// BOUNDS/TYPE PANIC: indexes a slice by an attacker-chosen position and type-asserts without
	// the comma-ok form — an out-of-range index or wrong dynamic type panics inside consensus.
	target := payload.Targets[req.Index]
	acc := target.(*ModuleAccount)
	k.Credit(ctx, acc, payload.Amount)

	return sdk.ResponseProcessProposal{Status: 1}
}
