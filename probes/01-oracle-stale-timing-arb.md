# Probe 01 — Oracle-dependency gap (stale-price timing arbitrage)

**Date**: 2026-04-23
**Category**: Oracle (#14 stale read, #18 stale-matured race in author's checklist)
**Verdict**: PARTIALLY COVERED — empirical probe needed for residual

## Hypothesis (user-suggested)

The RiskEngine is hermetic but takes external prices. Is there a stale
window the attacker can exploit? Time a tx to trade against a price that
is 1 second stale, creating free arb.

## What's already in place

**Circuit-breaker clamp** (engine config `oracle_price_cap_e2bps`):
Every external observation is clamped to `last_effective_price ± cap%`
per slot. Kani proof 76 (`kani_clamp_oracle_price_universal`) proves
the clamp universally. Attacker cannot drive the baseline arbitrarily
in a single observation.

**Staleness check** (wrapper line 2569–2572):
`age = now_unix_ts - publish_time`, rejects if `age > max_staleness_secs`.
Config typically sets this at 30–60s. Pyth publishes ~every 400ms.

**Monotonicity fix (4/22, commit `8da5dd9`)**:
Wrapper now stores `last_oracle_publish_time`. Observations older than
this are accepted but return the stored baseline unchanged — baseline
cannot rewind. Closes the cherry-pick attack where a caller submits a
stale-but-valid Pyth account to nudge baseline in a favorable direction.

**Minimum band** (wrapper lines 6119–6137):
The anti-off-market band on matcher `exec_price` is `max(2 × trading_fee_bps, 100)`
— minimum 1% regardless of fee config. So even when an attacker picks
the worst-favorable oracle within the clamp, they can only skim within
the 1% band after paying 2× fees.

## What the attack would need

Given those defenses, a profitable oracle-stale attack would require:

1. A Pyth publish with a FRESHER `publish_time` than `last_oracle_publish_time`
2. A price in the Pyth message that is *favorable* to the attacker's pending trade
3. Movement within `oracle_price_cap_e2bps` (so the clamp doesn't bound it out)
4. Attacker's trade landing atomically with the Pyth update post

This is MEV-style front-running of oracle updates. Anatoly's stance (D32,
D57) is that matcher-controlled pricing *within the band* is LP-delegation
trust, not a protocol bug. Oracle front-running is structurally similar:
it's an economic surface bounded by the per-slot cap.

## Residual probe — worth empirical check

**Specific edge**: Chainlink path (devnet uses this, not Pyth). Chainlink
OCR2 accounts have a `timestamp` that's off-chain-signed, but the
verification / ordering semantics differ from Pyth.

- Does `read_chainlink_price_e6` enforce the same `publish_time`
  monotonicity as `read_pyth_price_e6`?
- `security.md` session 2026-04-22 mentions "Chainlink doesn't have
  confidence intervals, so conf_bps is not used" (wrapper line 2619).
  Are there other Chainlink-specific paths where the 4/22 fix doesn't
  apply symmetrically?

Check wrapper lines 2619–2700 (Chainlink reader) and compare gate-by-gate
against Pyth reader at 2509–2605.

## Status

- Pyth stale-cherry-pick: CLOSED (monotonicity fix)
- MEV front-run on fresh Pyth update: WITHIN TRUST MODEL (bounded by cap)
- Chainlink monotonicity: **UNVERIFIED** — next step
