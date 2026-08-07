// SYNTHETIC deliberately-vulnerable Anchor (Solana) program — the fixture the `anchor-solana`
// playbook maps. This is NOT a real program. It exists only so the /code-scan web3 audit demo has
// a small, public, synthetic Rust/Anchor target to fan out over. Each instruction carries one
// classic, attacker-reachable bug: missing owner check / signer spoof / integer overflow / CPI
// confusion. Do not deploy this.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;

declare_id!("Fixture1111111111111111111111111111111111111");

#[program]
pub mod vault {
    use super::*;

    // MISSING OWNER CHECK + INTEGER OVERFLOW: `vault_state` is unvalidated and the credit uses raw
    // wrapping arithmetic on an attacker-sized amount.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let state = &mut ctx.accounts.vault_state;
        state.total = state.total + amount;
        Ok(())
    }

    // SIGNER SPOOF: `authority` is trusted but never constrained to a Signer — an attacker passes
    // the real authority's pubkey without its signature.
    pub fn set_admin(ctx: Context<SetAdmin>, new_admin: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.admin = new_admin;
        Ok(())
    }

    // CPI CONFUSION: invokes a token transfer without asserting the program id, so a look-alike
    // program supplied by the attacker receives the CPI.
    pub fn payout(ctx: Context<Payout>, amount: u64) -> Result<()> {
        let ix = spl_token::instruction::transfer(
            ctx.accounts.token_program.key,
            ctx.accounts.vault.key,
            ctx.accounts.dest.key,
            ctx.accounts.authority.key,
            &[],
            amount,
        )?;
        invoke_signed(&ix, &ctx.accounts.to_account_infos(), &[])?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    /// CHECK: unvalidated — no owner constraint, no typed Account<T> wrapper.
    #[account(mut)]
    pub vault_state: UncheckedAccount<'info>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetAdmin<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub authority: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Payout<'info> {
    /// CHECK: unchecked destination.
    pub dest: UncheckedAccount<'info>,
    pub vault: UncheckedAccount<'info>,
    pub authority: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
}
