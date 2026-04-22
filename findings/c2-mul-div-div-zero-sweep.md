# C2 — mul_div_floor_u128 div-zero reachability sweep

**Date**: 2026-04-23
**Category**: Numerical
**Verdict**: DISCARDED — all 37 call sites guarded

## Approach

Enumerated every call to `mul_div_floor_u128` /
`mul_div_ceil_u128` / `wide_mul_div_floor_u128` / `mul_div_floor_u256*`
in `percolator/src/percolator.rs`. For each, identified the denominator
and traced whether it can reach the helper as zero.

Helpers panic on `d == 0` (see `wide_math.rs:1553, 1560, 1569`).

## Denominator classification

Denominators in use fall into 6 buckets:

| Denominator | Source | Zero possible? | Guard |
|---|---|---|---|
| `POS_SCALE` | compile-time const | no | N/A |
| `10_000` | compile-time const | no | N/A |
| `a_basis` | account.adl_a_basis | only if memory-corrupt | line 1989 (read-path returns 0), 2024 (write-path rejects) |
| `oi` | `self.get_oi_eff(side)` | yes, when no exposure on side | line 2432 early return |
| `h_den` | `haircut_ratio()`, = `pnl_matured_pos_tot` or `resolved_payout_h_den` | yes | explicit `if h_den == 0` checks at 2827, 4787, 5256 |
| `haircut_loss_num` | `h_den - h_num` | yes when no haircut | line 2921 `if h_num == h_den { return x_cap }` |
| `sched_horizon` | account.sched_horizon | only if account data corrupt | line 3382 rejects |
| `pnl_pos_tot_trade_open` | counterfactual aggregate | yes when no positive PnL in market | line 3001 branches to non-helper path |

## Each call site verified

```
1998, 2032: abs_basis / a_side / a_basis — 1989 read-guard, 2024 write-guard
2479:       d_rem * a_ps / oi — 2432 early return on oi=0, plus 2477 d_rem!=0 gate
2547:       a_old * oi_post / oi — same guard chain
2830:       released * h_num / h_den — 2827 early return on h_den=0
2924:       e_before * h_den / haircut_loss_num — 2921 early return on h_num==h_den
2935, 3885, 3975, 3979, 4066, 4238, 4304, 4451, 4488, 4691, 4720, 5786:
            various * POS_SCALE — compile-time constant, non-zero
2947, 2964, 3041, 3784, 3944, 3951, 4068, 4240, 4295, 4307, 4452, 4489, 4692, 4721:
            various * 10_000 — compile-time constant, non-zero
3010:       pos_pnl_trade_open * g_num / pnl_pos_tot_trade_open — 3001 early return on 0
3041, 3784: notional * initial_margin_bps / 10_000 — 10_000 constant
3388:       sched_anchor_q * elapsed / sched_horizon — 3382 rejects sched_horizon=0
4798:       x_req * h_num / h_den — 4787 rejects h_den=0
5259:       released * resolved_payout_h_num / resolved_payout_h_den — 5256 rejects
```

## Result

Every site has an explicit guard on its denominator either at the
immediate call site or in the local control flow. No reachable
division-by-zero from user-influenceable input.

The panic safety-net is defensive programming against memory
corruption; it cannot be triggered by any legal instruction sequence.

## Discarded. Not an exploit vector.
