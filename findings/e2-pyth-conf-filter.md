# E2 — Pyth conf_bps = 0 edge case

**Date**: 2026-04-23
**Category**: Oracle
**Verdict**: DISCARDED (mainnet-protected)

## Hypothesis

If `config.conf_filter_bps == 0`, the wrapper's confidence check at
`read_pyth_price_e6` (wrapper:2577–2583) is skipped:

```rust
if conf_bps != 0 {
    let lhs = (conf as u128) * 10_000;
    let rhs = price_u * (conf_bps as u128);
    if lhs > rhs { return Err(OracleConfTooWide); }
}
```

With `conf_bps = 0`, any Pyth update is accepted regardless of how
wide the confidence interval is. During volatile events, Pyth
publishes wide-conf updates; a `conf_bps=0` market trusts them
blindly.

## Deployed mainnet check

`percolator-cli/scripts/setup-mainnet-market.ts:192`:

```typescript
confFilterBps:        50,  // mainnet
```

Mainnet market uses 50 bps = 0.5% conf filter. An attacker CANNOT
exploit wide-conf Pyth updates on mainnet — the check is active and
tight.

## Devnet

`percolator-cli/scripts/setup-devnet-market.ts:157`:

```typescript
confFilterBps:        0,   // devnet
```

Devnet has conf filter disabled, BUT devnet uses Chainlink
(`oracleType: "chainlink"`), and `read_chainlink_price_e6` comment
at wrapper:2619 explicitly notes:

> *"Chainlink doesn't have confidence intervals, so conf_bps is not
> used."*

So devnet's conf_bps=0 is structurally unused.

## Conclusion

The bounty target (mainnet 5 SOL) is not reachable via this vector.
The mainnet deployer knew to set a tight conf filter.

Discarded.
