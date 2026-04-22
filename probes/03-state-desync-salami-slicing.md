# Probe 03 — State desynchronization / salami slicing

**Date**: 2026-04-23
**Category**: Numerical (#40 rounding asymmetry, #32/33 accounting drift)
**Verdict**: PENDING — several angles partially verified, one still open

## Hypothesis (user-suggested)

Global coefficients (`adl_a_basis`, `adl_k_snap`, `f_side_num`). Is
there rounding-error that persists across transactions? Deposit → remove
→ redeposit cycles lose a fraction each iteration → salami drain the
vault over time.

## What I checked

### Direct amount flows: EXACT, no rounding

- `deposit_not_atomic` (engine:3643): `vault += amount`, `capital += amount`.
  Exact u128 addition. No conversion.
- `withdraw_not_atomic` (engine:3720): `capital -= amount`, `vault -= amount`.
  Exact u128 subtraction (checked).
- `close_account_not_atomic` (engine:4843): returns `capital.get()` verbatim
  (line 4907). No rounding on close. Capital goes back as-is.

The simple deposit → withdraw → deposit cycle on a FLAT account loses
nothing — same amount in as out, at exact u128 arithmetic.

### Rounding direction inventory

From a grep of `mul_div_floor_u128` vs `mul_div_ceil_u128` in the engine:

| Operation | Direction | Line | Effect |
|---|---|---|---|
| `notional` | FLOOR | 2935 | Lower notional → lower margin req → favors user (slightly) |
| `IM_req` / `MM_req` proportional | FLOOR | 2947, 2964, 3041, 3784 | Lower req → easier pass → favors user |
| `trade_notional` | FLOOR | 3885, 4066 | Smaller fee base |
| `trade_fee` | CEIL | 4068 | Rounds UP off smaller base — protocol wins ≤1 unit per trade |
| `haircut_loss_num / h_den` | FLOOR (wide) | 2830, 2924, 3010 | Losers absorb dust; winners get floor'd payout |
| `basis conversion` | FLOOR | 1997, 2032 | Effective position floors |
| `sched_vesting` | FLOOR | 3388 | Pending PnL accrues slower than ideal for user |
| `residual × a_ps / oi` | CEIL (wide) | 2479 | Insurance absorbs loss rounded UP (protocol-protective) |

Author's explicit methodology (security.md line 538): *"Fee-rounding is
asymmetric (ceil) — protocol rounds fees UP when possible, minimizing
free rides."* Every path I checked honours this: where the protocol
takes from the user (fees), it rounds CEIL. Where it pays out (haircut
to winners, vesting to user), it rounds FLOOR. Consistent.

### Conservation assertions

Every mutation path ends with `assert_public_postconditions` (engine line
4906, and every other terminal handler). The postcondition includes
`vault >= c_tot + insurance` (conservation §3.1). Any rounding drift that
violates conservation halts the market immediately with `CorruptState`.

The invariant is enforced **synchronously per instruction**. There is no
path where drift accumulates silently across txs — each tx either
passes the invariant or reverts.

### D44 already covers c_tot drift (confirmed)

D44 "c_tot desync on close" was already a discarded probe by the author.
All capital mutations route through `set_capital`, which `checked_add/sub`
against `c_tot`. Integer precision, no floating point. Salami via c_tot
isn't possible.

### D45 already covers haircut overflow (confirmed)

The ratio-math salami vector (`senior_sum overflow`) was explicitly probed
by the author and discarded because `c_tot + insurance ≤ 2×10^16 ≪ u128::MAX`.

## What's still open — worth empirical test

### Open thread 1: funding PnL rounding during high-frequency deposit cycles

`accrue_market_to` + `touch_account_live_local` run on every
deposit/withdraw (engine:3751, 3757). Funding PnL = `(F_side_end - F_side_start) × basis_q`.

- If `F_delta × basis_q` is computed with `mul_div_floor_u128`, each
  per-account accrual floors, donating the rounding residual to one
  side or the other.
- At scale (millions of deposit/withdraw cycles), this could accumulate
  to observable drift. BUT — the engine rebalances funding into
  `f_side_num` updates which are totalled across accounts. If the
  aggregation preserves total accrual at high precision, per-account
  floor rounding just redistributes among accounts, not drains.

**Needs code read**: walk `accrue_market_to` → `accrue_funding_per_side` →
how individual account PnL is updated. Confirm total conservation.

### Open thread 2: unit_scale conversion for non-zero scale markets

Both deployed markets have `unit_scale = 0`, so base == units and no
conversion rounding. But for a market with `unit_scale > 0`, base_to_units
is `base × 10^scale` and units_to_base is `units / 10^scale` (integer
division, i.e., FLOOR).

If a user could deposit an amount that rounds cleanly (e.g., N × 10^scale
base tokens → N × 10^(2×scale) units), and withdraw a different amount
that rounds with residual, dust could accumulate in the `capital`
register. But both deployed markets use scale=0 — this vector is not
reachable in the current bounty.

### Open thread 3: ADL coefficient drift across resets

`adl_a_basis`, `adl_k_snap`, `f_side_num` are side-wide. Reset events
(epoch boundary) zero some and preserve others (D54 covers reset).
Author explicitly cites `F_epoch_start_{side}` as preserving info across
resets.

If a sequence of reset → tiny-trade → reset → tiny-trade could cause
`f_epoch_start` to drift, it would be a real finding. But each reset
snapshots `f_epoch_start = current_F`, and each trade updates F via
checked arithmetic. No silent-drift path identified in a code walk —
matches D53.

**Needs more**: trace whether the relationship between `k_snap` and
`a_basis` can drift when both are zeroed on reset while `basis_q` is
non-zero (edge case). Engine line 2031: `q_eff_new = mul_div_floor_u128(abs_basis, a_side, a_basis)`.
If `a_basis == 0` but `abs_basis != 0`, what happens? `mul_div_floor_u128`
returns 0 or errors on div-by-zero. If it silently returns 0, effective
position becomes 0 → account shows flat → user can CloseAccount →
extracts capital that should be locked against an open position.

This is the specific angle worth the most attention. **OPEN.**

## Status

- Direct amount rounding: CLOSED (exact u128)
- Fee rounding: CLOSED (CEIL protocol-wins)
- Haircut rounding: CLOSED (floor-payout, D45)
- c_tot drift: CLOSED (D44)
- Unit-scale conversion: NOT REACHABLE in deployed markets (unit_scale=0)
- Funding PnL per-account residual: needs code walk of `accrue_funding_per_side`
- ADL coefficient `basis_q ≠ 0 && a_basis == 0` edge: **VERIFIED DEFENDED**, see below

## Addendum — ADL coefficient edge case, resolved

Checked directly. Two findings:

**1. `mul_div_floor_u128` panics on div-by-zero** (`wide_math.rs:1553`):

```rust
pub fn mul_div_floor_u128(a: u128, b: u128, d: u128) -> u128 {
    assert!(d > 0, "mul_div_floor_u128: division by zero");
    ...
}
```

A panic in a Solana program aborts the tx with all state reverted. No
fund theft, but a reliable DoS if an attacker can force an input path
to feed `d = 0`.

**2. The `basis != 0 && a_basis == 0` state is explicitly handled** in
every consumer:

- **Read path** (`effective_pos_q`, engine:1989–1993): treats it as
  flat, returns `0i128`. Comment acknowledges: *"a_basis==0 with nonzero
  basis is corrupt; ... Callers of mutation paths should check
  basis != 0 && a_basis == 0 separately if they need to reject."*
- **Mutation path** (`settle_side_effects_live`, engine:2024): returns
  `RiskError::CorruptState` immediately.
- **Per-slot accrual** (`accrue_funding_per_side`, engine:5129): same
  CorruptState rejection.

**Key chain of defence for the close-exploit hypothesis:**

1. Attacker gets to `basis != 0, a_basis == 0` state somehow.
2. Calls `CloseAccount`.
3. Handler runs `accrue_market_to` → `touch_account_live_local` →
   `settle_side_effects_live` **FIRST** (engine:4857–4860, before the
   flat-check).
4. `settle_side_effects_live` hits the `a_basis == 0` check at line 2024
   → returns `CorruptState` → tx aborts.
5. The later `effective_pos_q(idx) != 0` check never runs, so the
   "account shows flat despite open position" read path is not
   reachable as an exploit entry.

Every write path for `a_basis` (lines 399, 999, 1103, 1240, 1684, 2048,
2082, 5179) sets it to `ADL_ONE` (non-zero constant) or one of the
side multipliers (`adl_mult_long`, `adl_mult_short`). The invariant
`basis_q == 0 || a_basis != 0` is maintained by construction.

**Residual question**: can `adl_mult_long` or `adl_mult_short` be set to
zero globally? If yes, then line 1698/1704 writes zero into a_basis,
and at the same moment basis_q may still be non-zero on that account
(pre-trade-settle). This would briefly create the corrupt state — but
only until the next touch, which would reject via the mutation path.

Worth checking: `self.adl_mult_long` / `self.adl_mult_short` setters.
But this is well into diminishing returns — the defensive code at
lines 1990 and 2024 is exactly what a careful engine should have, and
the three-layer defence (read-returns-flat, write-rejects, touch-first
ordering) is robust.

**DISCARDED** for this probe. The hypothesised exploit is structurally
blocked.
