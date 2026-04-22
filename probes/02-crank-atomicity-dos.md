# Probe 02 — Crank atomicity / DoS

**Date**: 2026-04-23
**Category**: Ordering/MEV (#27 crank reward farming, #6 keeper grief)
**Verdict**: PARTIALLY COVERED — one empirical edge to test

## Hypothesis (user-suggested)

Force the Crank to fail (bloat tx with account lookups or hit compute
limit), stall the market, trap other users' liquidity. DoS against the
market's internal housekeeping.

## What's already in place

**D35 (scan cursor starvation)**: cursor is modular, all slots
eventually visited. `word_cursor = (word_cursor + 1) % BITMAP_WORDS`.

**D56 (fee sweep cursor infinite loop)**: outer loop bounded by
`words_scanned < BITMAP_WORDS` (64). Each word visited at most once per
crank.

**D52 (empty-market crank)**: crank on `num_used_accounts=0` is a safe
no-op. No reward, no mutation beyond accrue.

**Permissionless by default**: `decide_crank` (Kani proof 36) proves
crank accepts if `permissionless ∨ (idx_exists ∧ stored == signer)`. Any
user can crank; cannot be monopolized.

**Crank reward gate**: line ~5327 — reward only pays out if
`sweep_delta > 0`. No reward, no incentive for attacker, no net loss
for anyone honest.

**Permissionless resolution fallback**: if the market goes un-cranked
for `permissionless_resolve_stale_slots` (432,000 = ~48h on mainnet),
*any* user can call `ResolvePermissionless` to settle. So even a
successful DoS of the crank auto-resolves within 48h — funds are
recoverable.

## Attack paths still to verify

1. **Compute-unit budget**: does a crank at `num_used_accounts = 4096`
   (max) exceed Solana's 1.4M CU default? If so, crank is un-callable at
   max capacity until the fee-sweep budget (128 accounts per call) drains
   to a manageable count. Attacker could artificially inflate the account
   count to push into this regime. But each account init costs
   `new_account_fee` (57M lamports = ~$5 on mainnet), so filling 4096
   slots costs the attacker ~$20k. Economic cost > any expected gain
   from DoS.

2. **Bloat-the-tx via LUTs**: attacker submits a crank tx with many
   unnecessary account references via Address Lookup Tables. Solana limits
   tx size. But the crank handler only *processes* the accounts it was
   designed to process (slab, clock, maybe authority). Extra accounts in
   the tx are overhead but don't extend the handler's work.

3. **Economic grief**: attacker cranks selectively to maximise their
   own reward capture. D9 already covered — attacker pays the fees they
   later sweep, net loss 50%.

## Residual probe — worth empirical check

**CU budget at 4096 accounts**: measure actual CU usage of KeeperCrank
on a fully-populated slab. Compute unit measurement happens via
`measure-cu-scaling.sh` in the CLI repo — re-run against a max-slab
scenario. If CU is near the 1.4M ceiling, the crank becomes a bandwidth
bottleneck: only one crank per slot can fit, and attacker-crafted
conditions (e.g., many accounts at maintenance-fee boundary) could push
over the edge.

Not a fund-theft exploit, but a ship-blocker for production if CU
scaling is tight.

## Status

- Scan cursor DoS: CLOSED (D35, D56)
- Empty-market crank: CLOSED (D52)
- Keeper reward grief: CLOSED (D9)
- Auto-fallback to permissionless-resolve: CLOSED (design)
- CU saturation at max accounts: **UNVERIFIED** — empirical only
