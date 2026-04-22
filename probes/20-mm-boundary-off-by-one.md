# Probe 20 — MM / IM boundary off-by-one

**Date**: 2026-04-23
**Category**: Margin (#20 in author's 49-category checklist)
**Verdict**: DISCARDED

## Hypothesis

`>=` vs `>` on liquidation thresholds is a classic bug class. If the
boundary is inclusive where it should be exclusive (or vice versa),
accounts can either be insta-liquidated on open or trade at below-IM
equity.

## Code path

Engine `is_above_maintenance_margin` at `percolator/src/percolator.rs:2938–2951`:

```rust
/// is_above_maintenance_margin (spec §9.1): Eq_net_i > MM_req_i
...
eq_net > mm_req_i128    // line 2950 — strict
```

Engine `is_above_initial_margin_trade_open` at 3031–3045:

```rust
eq >= im_req_i128       // line 3044 — inclusive
```

So:
- Healthy / above MM ⟺ `eq_net > mm_req` (strict)
- Liquidatable ⟺ `eq_net <= mm_req` (inclusive boundary)
- Trade open allowed ⟺ `eq >= im_req` (inclusive boundary)

## Consistency check

Init asserts at 717–747:

- `maintenance_margin_bps <= initial_margin_bps` (non-strict)
- `min_nonzero_mm_req < min_nonzero_im_req` (STRICT)

For any position:
- `mm_req = max(prop_mm, min_nonzero_mm_req)`
- `im_req = max(prop_im, min_nonzero_im_req)`

Case analysis covering the four combinations of proportional-vs-floor:
1. Both above floor: `mm_req = prop_mm <= prop_im = im_req`. Equality possible iff `mm_bps == im_bps`.
2. Both below floor: `mm_req = min_mm < min_im = im_req` (strict, by assert 745).
3. mm above floor, im below floor: `mm_req = prop_mm <= prop_im < min_im = im_req` → strict.
4. mm below floor, im above floor: `mm_req = min_mm < min_im <= prop_im = im_req` → strict.

## Edge case identified

In case 1, if the operator sets `mm_bps == im_bps`, then `mm_req == im_req`
for positions where proportional dominates the floor.

A trade opening at exactly `eq == im_req` passes IM (`eq >= im_req`).
Immediately after, `is_above_maintenance_margin = eq > mm_req = eq > im_req = false`.
The account is liquidatable the moment it opens.

**Is this a protocol bug?** No — it's operator misconfiguration.

- Spec §1.4 explicitly allows `MM <= IM` (equality permitted at bps level).
- The `min_nonzero_*` floors ensure the minimum-position case is always
  distinct.
- For this to happen in practice, an operator would deliberately set
  `initial_margin_bps == maintenance_margin_bps` AND pick a notional
  large enough to push proportional above both floors. Insta-liq at
  open is an immediately-visible operational defect — new user
  deposits zero before any real exposure.

## Exploitability against the deployed market

Mainnet market 5ZamUkAiXtvYQijNiRcuGaea66TVbbTPusHfwMX1kTqB would only
be vulnerable if Anatoly's init parameters set `mm_bps == im_bps`.
Per the deployed `mainnet-market.json` and the Engine's assert at
line 719 (which allows, not requires, equality), this has to be
verified via RPC slab read. Even if set equal, the exploit would be:

1. Open a maximum-IM-req-sized position
2. Get insta-liquidated
3. Pay the liquidation fee

Attacker cost > any gain — the liquidator gets the fee, the position
is force-closed, and the opener is out the fee. Not profitable unless
the attacker also controls the liquidator. Even then, the net is
`liquidation_fee - 2 × fees_paid < 0` in expectation because the
attacker pays fees on both sides.

## Verdict

DISCARDED. The strict `>` on MM and inclusive `>=` on IM are correct
per spec §9.1. The only way to construct a same-boundary state is
operator misconfiguration (`mm_bps == im_bps`), which is immediately
self-revealing as insta-liquidation at open and is not economically
exploitable.

## What WOULD be a bug

- MM check using `>=` (inclusive healthy): would make `eq == mm_req`
  safe, meaning accounts could trade at exactly the liquidation line
  and never get liquidated at the boundary. Conservation-violating.
- IM check using `>` (exclusive allowed): would require `eq > im_req`,
  which means accounts at exactly IM threshold couldn't open. Benign
  but spec-inconsistent.

Neither is the case.
