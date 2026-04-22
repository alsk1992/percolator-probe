# A2 — Extended analysis after re-examination

**Date**: 2026-04-23
**Re-examined**: yes, after explicit prompt to push harder

## What I re-walked

1. `ins_before` capture at wrapper:5304 — confirmed captured BEFORE
   both candidate syncs and bitmap sweep. `sweep_delta` therefore
   captures ALL maintenance-fee-driven insurance growth in the crank.

2. Author's own comment at wrapper:5293–5302 — earlier revisions had
   `ins_before` capture between phases, which silently zeroed rewards.
   The fix was deliberate to make cranker compensation real.

3. Post-`keeper_crank_not_atomic` insurance growth (liquidation fees,
   uninsured-loss absorption) — EXCLUDED from reward via the pre-crank
   `sweep_delta` snapshot. Comment at 5384–5388 makes this explicit.

4. `use_insurance_buffer` + `record_uninsured_protocol_loss` (engine:2318–2332) —
   the forgiveness mechanism when losses exceed insurance. The doc
   comment is enlightening:

   > *"Alice +100, Bob -100, V = 50, insurance = 0. Forgiving Bob
   > leaves matured = 100, residual = 50 → h = 0.5, Alice gets 50.
   > If we also drained V by 50, residual would drop to 0 → Alice
   > gets 0."*

   So when insurance runs dry, LOSER debt is FORGIVEN (no further
   vault reduction) and WINNER gets haircut proportional to residual
   vault coverage.

## The real insurance-drain scenario

Tracing tokens carefully:

Setup: Attacker accounts A (intended winner) + B (intended loser).
Insurance = 5 SOL. A_cap = 100, B_cap = 1.

1. B opens max-leveraged position (say 20 SOL notional at 5% IM).
2. A opens counter position.
3. Oracle moves adversely to B.
4. B liquidated. `settle_losses` drains B.capital = 0. Residual loss = L.
5. `use_insurance_buffer(L)` absorbs up to 5 SOL of residual loss.
6. `record_uninsured_protocol_loss(remaining)` is a NO-OP — any loss
   beyond insurance is forgiven at ledger level.
7. A has PnL equal to gross trade PnL (no haircut yet applied).
8. Residual = V − (C_tot + I) at this point.
9. A converts released PnL: y = floor(PnL × residual/pnl_matured_pos_tot).
10. A withdraws A_cap + y.

**Net token flow**:
- A deposited A_cap, extracted A_cap + y
- B deposited B_cap, extracted 0
- Vault delta = y − B_cap (from the 5 SOL insurance if y > B_cap)

Attacker (controlling both A and B) net gain = y − B_cap.

For y to exceed B_cap meaningfully (the goal being the 5 SOL), we
need PnL transfer to exceed B_cap by an amount eaten from insurance.

## Why it STILL doesn't work against the live market

The attack requires an oracle move large enough to push B from
margin-healthy into deep-loss territory WITHOUT liquidation firing at
the MM boundary.

- Circuit breaker caps per-slot movement at `oracle_price_cap_e2bps`
- Each slot, engine's internal price moves at most `cap` percent
- `is_above_maintenance_margin` is checked on every trade and crank
- A max-leveraged position at IM starts margin-healthy; it hits MM
  after a small move; liquidation fires at MM

**For insurance drain**, we need: liquidation fires at a price where
B's residual loss EXCEEDS B.capital. In the clamped regime, each
slot's price movement is tiny, so liquidation fires BEFORE cumulative
loss exceeds capital. The MM buffer (IM − MM ≈ 200 bps typical) is
the safety margin.

The only way to skip past MM without liquidation is if no crank fires
in the intervening slots. Crank is permissionless — ANY keeper can
crank, including the victim (B) themselves to self-liquidate at a
favourable-to-them boundary. The live-touch on any trade also
auto-liquidates via `touch_account_live_local`.

So the insurance drain scenario requires: (a) large oracle move, (b)
nobody cranks during the move, (c) attacker controls both sides.
Conditions (b) is defeated by permissionless cranking in a competitive
keeper landscape.

## Residual concrete attempt

The one remaining variable is **the exact MM vs IM spread** in the
deployed mainnet config. If MM is very close to IM (low margin
buffer), less room to liquidate before loss exceeds capital. Need to
read deployed params via RPC to confirm. If MM is set aggressively
close to IM (e.g., 300 vs 500 bps), a fast oracle move could genuinely
drain insurance. Author's `initial_margin_bps > maintenance_margin_bps`
assert only enforces `<=`, not a minimum spread.

**This is the one actionable follow-up that could still land on mainnet**:
fetch deployed `MarketConfig` and check the MM vs IM spread. If it's
suspiciously tight, the insurance-drain scenario above becomes
plausible against a single large-gap event.

## Verdict

A2 as originally formulated (crank-reward direct-drain): closed.
A2 extended (adversarial counterparty-pair forcing insurance absorb):
  theoretically possible but defeated by permissionless cranking and
  the circuit-breaker clamp unless MM/IM spread is aggressively tight.

Next concrete action: RPC-fetch the slab, decode `MarketConfig`,
check `initial_margin_bps - maintenance_margin_bps`. If small, the
scenario is live.
