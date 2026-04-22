# F1 — Oracle circuit-breaker DISABLED on deployed mainnet market

**Date**: 2026-04-23
**Status**: **LIVE FINDING — economic attack path against the deployed 5-SOL bounty**

## What I found

Via direct Solana mainnet RPC read of the deployed slab
(`5ZamUkAiXtvYQijNiRcuGaea66TVbbTPusHfwMX1kTqB`):

```
maintenance_margin_bps     = 1000 (10.00%)
initial_margin_bps         = 2000 (20.00%)   → max 5x leverage
oracle_price_cap_e2bps     = 0              → CIRCUIT BREAKER DISABLED
min_oracle_price_cap_e2bps = 0
conf_filter_bps            = 50 (0.5%)
max_staleness_secs         = 60
invert                     = 1
last_effective_price_e6    = 11433
```

Cross-referenced against `clamp_oracle_price` at
`percolator-prog/src/percolator.rs:2761`:

```rust
pub fn clamp_oracle_price(last_price: u64, raw_price: u64, max_change_e2bps: u64) -> u64 {
    if max_change_e2bps == 0 || last_price == 0 {
        return raw_price;              // ← no clamping, raw price through
    }
    // ... normal clamp path
}
```

Kani proof 76 (`kani_clamp_oracle_price_universal`) confirms:
> *"(a) max_change==0 ⇒ raw"*

Kani verifies this is the mathematical behaviour of the clamp
function, but the fact that the *deployed production market* has
`max_change = 0` has been set for the live instance — the engine has
no per-slot oracle-gap protection.

## Attack path

**Pre-conditions**:
- Attacker deploys their own matcher (the explicit invitation)
- Attacker opens an LP + user account pair
- Market has active users holding leveraged positions (long or short)
- Pyth publishes a large single-slot oracle move (≥ 10%)

**Execution**:

1. Attacker monitors Pyth Pull feed for the target feed
   (`ef0d8b6f...c280b56d`).
2. When a large genuine move is imminent (macro event, CEX outage,
   coordinated liquidation), attacker pre-positions: via own matcher,
   LP + user pair takes the *opposite* side of the expected move.
3. Oracle publishes the large update to Pyth Receiver account
   `7UVimff...pjLiE`.
4. Attacker submits TradeCpi or KeeperCrank IMMEDIATELY in the slot
   after publish. `clamp_external_price` reads the new price with no
   clamp → `last_effective_price_e6` jumps to the real post-move price.
5. Every max-leveraged victim on the losing side is now deep
   underwater. With IM=20% / MM=10%, a 15%+ move pushes positions
   past MM into insurance-eating territory.
6. For each such victim: `settle_losses` drains their capital;
   `use_insurance_buffer` absorbs the residual from the 5-SOL seed.
7. Attacker's counterparty (LP or user) now holds corresponding
   positive PnL. After warmup + haircut conversion, attacker extracts
   gains.

**Per-victim insurance drain arithmetic** at max leverage (5×):

| Oracle gap | Victim loss / capital | Per-victim insurance drain |
|---|---|---|
| 10% | 50% | 0 (covered by capital) |
| 12% | 60% | 0.10 × victim_capital |
| 15% | 75% | 0.25 × victim_capital |
| 20% | 100% | 0.50 × victim_capital |
| 25% | 125% | 0.75 × victim_capital |

Insurance is 5 SOL. To fully drain: ~7 max-leveraged victims with
1 SOL capital each on the wrong side of a 25% gap. Or fewer victims
on a larger gap.

## Why this was probably not flagged by the author

The `oracle_price_cap_e2bps = 0` is a DEPLOYMENT-TIME parameter. The
engine code for `clamp_oracle_price` is defensively correct. The Kani
proof is defensively correct. But the deployer (Anatoly) chose to
disable the clamp for this specific market.

Possible reasons:
1. The market is a *test* of the engine's margin safety without the
   clamp as a safety net
2. Intentional to show that 20%/10% margin config suffices
3. Operational simplicity — no need to tune cap per feed
4. Expectation that Pyth updates are mostly sub-10% per slot in normal
   market conditions

The author may consider this "operational choice, not protocol bug" —
aligned with D57's framing of admin-configurable parameters. However:
- Admin is BURNED, so the config is now immutable
- The 5 SOL is at genuine risk in a large oracle-gap event
- This isn't user-trust-based (like LP matcher choice) — every user
  of the market is exposed, not just those who signed up with this
  specific LP

## Attack feasibility analysis

**Required**: a real-world oracle gap ≥ 10%, or the ability to induce one.

Organic sources of large Pyth moves:
- Market crashes (March 2020, May 2022 Terra, November 2022 FTX)
- Exchange outages (stale prices catch up in one publish)
- Liquidation cascades on CEX affecting reference prices

**Attacker's edge** (the AI part):
- Build a pipeline that monitors Pyth off-chain
- Pre-position automatically when volatility spikes
- Submit TradeCpi/crank immediately on large-move detection
- Race other keepers to be first post-publish

This is EXACTLY the kind of AI-driven extraction the tweet rewards.

## What I'd submit to the repo

A GitHub issue titled:

> *"Deployed mainnet market `5ZamU...kTqB` has `oracle_price_cap_e2bps = 0`,
> disabling the circuit breaker and exposing the 5-SOL insurance
> buffer to oracle-gap-driven drains beyond the ~10% margin safety.
> Attacker strategy: pre-position opposite to an expected Pyth move,
> front-run the post-publish crank, extract counterparty winnings
> while insurance absorbs victim shortfalls."*

With concrete RPC decode + the arithmetic table above.

## What's needed to actually execute (if pursuing the bounty)

1. Deploy own matcher on mainnet (small SOL for deployment fees)
2. Build an off-chain Pyth monitor that triggers trades when
   `|Δ price| > 10%` is imminent
3. Either wait for organic volatility OR find a small-liquidity pair
   where the engine's Pyth feed can be moved by a modest real trade
4. Time the trade to land in the same slot as the big Pyth publish
5. Capture the counterparty winnings and withdraw

Realistic capital requirement: probably $10k–100k of provisional
positions, waiting for the trigger event. Patience > capital.

## Risk / ethics

This is a whitehat submission. Do NOT actually execute the drain —
submit the finding to the repo per Anatoly's instructions. The
reward structure explicitly rewards finding, not exploiting.

## Next steps

1. Re-verify the RPC reads (commit the exact request/response for
   reproducibility)
2. Compute the exact insurance-drain expected value across historical
   SOL/related-pair Pyth moves
3. Draft the GitHub issue with all supporting data
4. File it
