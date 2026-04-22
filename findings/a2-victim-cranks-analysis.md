# A2 — Victim-cranks, attacker-collects — analysis

**Date**: 2026-04-23
**Category**: Economic / multi-party
**Verdict**: REAL INCOME STREAM, NOT THE BOUNTY-TARGET FUND THEFT

## What I found

The cranker reward logic at wrapper lines 5396–5430:

```rust
if !permissionless
    && config.maintenance_fee_per_slot > 0
    && sweep_delta > 0
    && engine.is_used(caller_idx as usize)
{
    let mut reward = sweep_delta
        .saturating_mul(crate::constants::CRANK_REWARD_BPS)
        / 10_000u128;
    let ins_now = engine.insurance_fund.balance.get();
    if reward > ins_now { reward = ins_now; }
    if reward > 0 {
        // insurance -= reward, caller.capital += reward, c_tot += reward
        ...
    }
}
```

Where `CRANK_REWARD_BPS = 5000` (50%) and `sweep_delta` is the total
amount added to insurance from the maintenance fee sweep across ALL
accounts scanned in this crank call.

## D9's dismissal vs reality

D9 in author's `security.md` says:

> *"The attacker's dummy accounts ARE the ones paying the swept fees.
> Net flow: attacker pays N × fee_per_slot × dt → 50% back to attacker
> (their own sweep), 50% to insurance. Net LOSS of 50% on their
> dummy-account fees. Not profitable."*

This is correct for a SELF-DEALING attacker (N dummy accounts, no
other users). But it does NOT cover the case of an attacker with ONE
account in a MULTI-USER market with honest fee-paying counterparties.

Scenario at scale:
- Mainnet: 4,096 max accounts, $5/day maintenance fee each
- Full load = $20,480/day in fees
- Attacker has 1 account (cost: 1 × new_account_fee = ~$5 + initial deposit)
- Attacker wins crank race once (MEV): captures ~$10,000 in 50%
  reward, while having paid ~$5 in their own fee that day

Net: attacker gains ~$9,995. Author's "not profitable" framing doesn't
hold in the multi-user case.

## Why this is NOT the bounty target

Re-reading the reward cap at line 5407:

```rust
if reward > ins_now { reward = ins_now; }
```

`ins_now` = `ins_before + sweep_delta` (insurance AFTER the maintenance
fee sweep). Solving for when `reward > ins_now`:

- `reward = sweep_delta / 2`
- `sweep_delta / 2 > ins_before + sweep_delta`
- `-sweep_delta / 2 > ins_before`

Since `ins_before` is u128 (unsigned, non-negative), this is unreachable
except when both are zero. In all practical cases, `reward = sweep_delta / 2`.

The original 5 SOL insurance is NOT drained by this mechanism. The
cranker captures 50% of NEW fee income, not any of the pre-existing
insurance seed.

## Economic significance

This is not worthless — it's a legitimate income stream that scales
with the market's TVL and activity. If the market runs at full load
with many competing keepers, the reward stream is a professional
keeper opportunity. But it doesn't steal the 5 SOL.

## Why the author probably dismissed it too narrowly

D9 was written during the author's audit with specific framing: "an
attacker tries to drain insurance." The self-dealing model is the
natural first hypothesis, and it correctly comes out non-profitable.
The multi-user case isn't an insurance drain at all — it's a keeper
fee capture, which is precisely what the reward mechanism is DESIGNED
to do.

So D9 isn't wrong. It's just answering a different question than
"can a well-positioned keeper earn income from this market," because
that second question isn't a vulnerability in the first place.

## Worth submitting as GitHub issue?

Borderline. The finding is:
- Real (not refuted by D9)
- Consistent with protocol design (keeper fees are intended)
- Not a vulnerability per the bounty charter
- But possibly worth documenting as "D9's wording should note the
  multi-user case isn't a vuln either, for clarity"

I'd submit it only if no other finding lands. It's a documentation
improvement, not a bug.

## Next target

A2 eliminated. Moving to **E2** (Pyth conf_bps = 0 edge) — this
requires reading the deployed market's `conf_filter_bps` value via
RPC to confirm whether the confidence check is actually disabled on
mainnet.
