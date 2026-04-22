# Precision observations from deep salami-slice sweep

**Date**: 2026-04-23
**Scope**: Walked every rounding site in the engine reachable from
deposit / withdraw / trade / convert / close paths.

## Observation 1 — `a_trunc_rem` dropped at line 2547

See `precision-loss-adl-mult.md`.

**Impact**: Precision loss in ADL multiplier after OI-decrease events.
Accelerates entry into `DrainOnly` mode for the opposite side. Not
fund theft (multiplier is a ratio, not tokens).

## Observation 2 — Asymmetric `compute_trade_pnl` floor direction

**Location**: `percolator/src/percolator.rs:5766–5809`.

Positive PnL branch (line 5803–5807): returns `q = floor(|size × price| / POS_SCALE)`.
Negative PnL branch (line 5788–5794): returns `-(q + 1)` when `r != 0`,
else `-q`. Floor-toward-negative-infinity for signed arithmetic.

**Caller invariant preserved**: at line 4041–4042, `trade_pnl_a` is
computed from scratch; `trade_pnl_b = -trade_pnl_a`. Sum is exactly
zero regardless of the floor direction. Zero-sum trade property holds.

**Real impact**: The reported `trade_pnl_a` can differ from the
mathematical ideal by up to 1 unit (absolute). Both counterparties'
ledger entries are off by the same magnitude in opposite directions.
When either side closes, vault conservation still holds because both
closes net out to the starting deposit pool.

**Exploit potential**: Zero. The asymmetry is a ledger-precision
quirk, not a token-transfer channel. Attacker cannot extract value.

## Observation 3 — Stressed-market PnL conversion haircut floor

**Location**: `percolator/src/percolator.rs:4798`.

```rust
let y: u128 = wide_mul_div_floor_u128(x_req, h_num, h_den);
```

When `h_num < h_den` (stressed market, residual vault insufficient to
cover all matured positive PnL), users converting released PnL to
capital receive a floor'd haircut.

**User foot-gun**: converting in tiny chunks `x_req = 1` when haircut
is 50% yields `y = floor(0.5) = 0` per call. The 1 unit of released
PnL is consumed but the user gets 0 capital. All the PnL can be burned
this way.

**Exploit potential**: Zero as fund theft, because:
- Conversion is user-initiated; attackers don't convert to harm
  themselves
- No path allows an attacker to force a VICTIM's conversion
- At close, `finalize_touched_accounts_post_live` (line 3594) does
  whole-only auto-conversion, which only fires when the market is
  healthy (`h_num == h_den`). In stressed state, auto-convert is
  skipped; user must explicitly convert — which they do at their
  own pace

**UX note**: the flat-conversion safety cap
`max_safe_flat_conversion_released` (line 2917) uses `wide_mul_div_floor_u128`
to compute the maximum safe conversion amount. Floor direction here is
conservative (CAP rounded DOWN), so it never allows a conversion that
would over-credit. Consistent with the rest of the haircut math.

## What was ruled out

- **Deposit → withdraw → deposit cycles**: exact u128 arithmetic, no
  residual (probe 03).
- **Close account capital return**: returns `capital.get()` verbatim
  (engine:4907), no rounding.
- **Fee computation**: trade fees use `mul_div_ceil_u128` (engine:4068),
  protocol rounds UP. Attacker pays slightly more than ideal, never less.
- **`a_basis == 0` corrupt state**: structurally unreachable. Every
  write to `adl_a_basis` is `ADL_ONE` or from `set_a_side(side, v)`,
  and `set_a_side` is only called with `v > 0` (engine:2554 guard).
- **Self-trade fee manipulation** (D6): blocked by engine's `a == b`
  check at engine:3900.

## What's still unverified (requires devnet infra)

- **Chainlink oracle path parity with Pyth** — the 4/22 monotonicity
  fix applies to both, but Chainlink has no `conf` validation and
  different timestamp semantics. A disparity might exist. Mainnet
  uses Pyth so any Chainlink-only find is devnet-only unless the
  author later deploys a Chainlink mainnet market.
- **`mul_div_floor_u128` div-by-zero reachability** — 37 call sites
  in the engine. Most have guards; one or two niche paths haven't been
  walked exhaustively. Not fund theft (just tx revert), but reliable
  grief vector if reachable.
- **Funding PnL per-account residual** — I flagged but didn't
  exhaustively walk `accrue_funding_per_side`. Per-account floor
  residual aggregation needs verification.

## Honest status

After 3 probes + 3 precision observations + ~4 hours of focused code
review, **no vault-theft path identified**. The code is tight:

- 369 Kani proofs (wrapper + engine) cover decision gates, ABI,
  monotonicity, oracle clamping, insurance packing, fee EWMA bounding
- 75+ discarded attacks in author's security.md — every reasonable
  angle I've tried overlaps with an existing D-finding
- The author's ongoing DPRK-style R&D loop is iterating the same
  49-category list I'm working from

The precision observations above are worth raising as GitHub issues
(they're defensible as "intentional trade-offs" but the asymmetric
handling is noteworthy). They are not bug-bounty-eligible under the
stated criteria (hack the engine to steal the 5 SOL).

**What would actually win the bounty** is either:
1. An empirical find from running a live matcher against the deployed
   mainnet market with adversarial parameters at the 1% band edge
2. A multi-block coordinated attack across many txs, exploiting
   leader sequencing and oracle update timing
3. A genuinely new class of vulnerability the author hasn't considered

None of those are code-review-from-a-laptop attacks. They need
devnet/mainnet test infrastructure.
