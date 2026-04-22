# Observation — ADL multiplier truncation residual dropped

**Date**: 2026-04-23
**Status**: NOT A THEFT EXPLOIT. Worth flagging as a precision observation.

## Location

`percolator/src/percolator.rs:2547`

```rust
let (a_candidate_u256, a_trunc_rem) = mul_div_floor_u256_with_rem(
    a_old_u256,
    oi_post_u256,
    oi_u256,
);
```

`a_trunc_rem` is declared in the destructuring pattern. Grep confirms
**it appears nowhere else in the file** — the remainder is captured
then dropped.

Compare with the second call site at line 5786:

```rust
let (q, r) = mul_div_floor_u256_with_rem(abs_size_u256, abs_price_u256, ps_u256);
if result_negative {
    // mag = q + 1 if r != 0, else q (floor toward -inf)
```

There, `r` is used to floor-toward-negative-infinity for signed
arithmetic. So the helper is clearly designed to support precision-
aware callers. The ADL multiplier caller at 2547 chose not to use it.

## Math

On every liquidation (or OI-decrease event), the ADL multiplier for
the opposite side is recomputed as:

```
a_new = floor(a_old * oi_post / oi)
```

Mathematically the true value is `a_old * oi_post / oi` (possibly
non-integer). The floor loses up to `(oi - 1) / oi` of a unit each
time.

Iterating over N liquidations, cumulative floor loss on `a_new` is
bounded by N units, and `a_new < MIN_A_SIDE` triggers `DrainOnly`
mode (line 2570). So the side is auto-retired once precision is
exhausted.

## Why this is not a fund-theft exploit

Conservation `V ≥ C_tot + I` is preserved because `a_side` is a
ratio used in PnL distribution, not a token quantity. The vault
tokens don't move. The floor simply redistributes very small
fractions *within* the accounting.

Who loses the dropped fraction? Holders on the opposite side — their
effective position `floor(|basis| * a_side / a_basis)` is recomputed
with the slightly-lower `a_side`, so their effective position and
notional are very slightly smaller than the continuous-math ideal.

But "effective position smaller than ideal" means:
- Lower margin requirement (favours the holder)
- Lower PnL sensitivity (hurts winners, helps losers)

So the direction of the drift is ambiguous, not unilaterally
protocol-profitable or attacker-profitable.

## Why this is still worth noting

1. **Inconsistent use of the helper**: the author clearly knows to
   use the remainder for signed rounding (line 5786). Choosing to
   drop it at line 2547 is a defensible but unexplained asymmetry.
2. **DrainOnly-mode acceleration**: if an attacker can force OI
   decrease events (via their own self-liquidations), they can
   accelerate the ADL multiplier's decay toward `MIN_A_SIDE`,
   pushing a side into DrainOnly mode and degrading market health.
   Not theft, but a denial-of-service vector against a specific side
   of a market. Cost: attacker must actually lose positions to
   trigger liquidations.
3. **Fair-weather correctness bias**: under normal conditions the
   drift is immaterial. Under sustained high-liquidation conditions
   (volatile markets, attackers griefing), the drift compounds. The
   existing `MIN_A_SIDE` floor catches this before it becomes
   arithmetically pathological, but it does *accelerate* entry into
   the degraded mode.

## Author's likely response

*"Intentional precision trade-off. The DrainOnly floor is the
intended backstop. The dropped remainder would cost compute units to
carry forward and doesn't change the conservation property."*

That's a reasonable defense. Filing as OBSERVATION, not
VULNERABILITY. Worth raising as a GitHub issue anyway to see if the
author wants to preserve the residual for symmetry with line 5786's
usage.
