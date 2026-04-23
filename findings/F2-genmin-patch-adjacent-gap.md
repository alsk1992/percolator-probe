# F2 — Genmin's same-owner patch (#37) leaves a trivial bypass via dual keypairs

**Date**: 2026-04-23
**Relationship to prior work**: Extension of Genmin's finding in [#35](https://github.com/aeyakovenko/percolator-prog/issues/35) + PR [#37](https://github.com/aeyakovenko/percolator-prog/pull/37).
**Status**: Adjacent-gap finding. Not a dismissal of Genmin's work — a refinement.

## Summary

Genmin's PR #37 rejects trades where `accounts[user_idx].owner == accounts[lp_idx].owner`. Because "owner" is an on-chain 32-byte Ed25519 pubkey, the check distinguishes KEYS, not CONTROLLERS. An attacker with two distinct keypairs K1 ≠ K2 — which is a trivially-generatable resource — reproduces the exact same insurance-drain attack Genmin documented in #35, with the patch applied and cleared.

## Exact bypass

Genmin's reproduction parameters from #35:

```
p1 = 11_494 (SOL ≈ $87)
p2 = 16_000 (SOL ≈ $62.50)
user_dep = 7_500_000_000 (7.5 SOL)
lp_dep   = 7_500_000_000 (7.5 SOL)
size = 3_000_000
exec_bps_from_oracle = -100
→ withdrew_total = 19_973_499_735
→ attacker_profit = 4_973_499_735 (≈ 5 SOL)
→ insurance_drained = 5_000_000_000 (full insurance)
```

Replication under the patched version:

1. Attacker generates two fresh keypairs `K1` and `K2` (cost: ≈ 0). Both are attacker-controlled.
2. `K1` deposits 7.5 SOL → user slot with `stored_owner = K1`.
3. `K2` deposits 7.5 SOL → LP slot with `stored_owner = K2`.
4. `K2` registers the attacker's own matcher program at the LP slot.
5. Oracle moves from p1 → p2 (28% drop — 15 slots at 1% clamp, or 1 slot with current mainnet config where `oracle_price_cap_e2bps = 0`).
6. Attacker triggers the same liquidation-first-then-convert sequence.
7. Patch check: `K1 != K2` → **passes**. Trade proceeds exactly as before.
8. `K1` withdraws winning side. `K2` has been fully liquidated; insurance absorbed the shortfall.
9. Attacker aggregates funds from `K1` and `K2` off-chain. Net profit identical to Genmin's reproduction.

The patch adds **zero** practical resistance to a motivated attacker.

## Why this was inevitable

The intended security property is *"one economic actor cannot be on both sides of a trade that socialises losses."* But "economic actor" is an off-chain concept — Solana cannot observe that two pubkeys share a human operator. The on-chain representation of ownership IS the pubkey. Any fix phrased as "reject if owner fields match" is fundamentally bypassable by using distinct keypairs.

## What would actually close the attack

The attack exploits three protocol invariants jointly:

1. **Insurance is communal**: any account's losses beyond capital draw from a shared pool.
2. **Asymmetric liquidation**: the losing side's residual loss is absorbed by insurance, while the winning side's PnL is paid out (subject to haircut).
3. **No per-actor insurance accounting**: insurance doesn't track which user contributed how much, so any user who can *force* insurance usage on their own position extracts from the pool of all users' contributions.

Real fixes, in increasing order of design cost:

**Tactical (high-bar for attacker, not a true fix):**
- Lower max leverage (smaller margin buffer × attack position size)
- Tighter oracle circuit breaker (smaller per-slot moves → smaller per-slot drain)
- Higher minimum deposit (larger attacker capital at risk per cycle)
- Per-ix cooldown on user close-after-trade

**Structural (actually closes the attack class):**
- **Per-owner insurance contributions** tracked as a ledger. An account's losses first draw from that owner's own contribution; insurance-pool access only after personal contribution is exhausted. This makes the attack cost the attacker their own insurance quota before externalising anything.
- **Winner-side haircut scaled to insurance consumed**: if a trade's losing counterparty drew from insurance, reduce the winning counterparty's payout by the amount of insurance consumed, regardless of the winner's owner. (Effectively: two sides of a trade are jointly responsible for insurance consumption.) This makes the attack a wash in expectation.
- **Permissioned LP registration**: LP slots require approval from a burnable-but-not-yet-burned registration authority that can blacklist known-attacker keys. Centralising but effective.

None of these can be patched into the deployed immutable market. They'd apply to future deployments only — same constraint Genmin's patch already faces.

## Implications for the bounty

The deployed mainnet market (`5ZamU...kTqB`) has admin burned, so neither Genmin's patch nor any of the structural fixes above can be applied. The attack surface remains LIVE on that market for its lifetime, executable by any attacker with two keypairs and the requisite capital.

Under the bounty criterion *"steal the 5 SOL"*:
- Genmin's finding + PR gets credit for first-disclosure.
- The attack described in #35 IS executable on the deployed market using the dual-keypair variant documented here.
- The PR merge would close the class for FUTURE deployments but not for the current one.
- If the bounty requires demonstrated extraction, neither Genmin nor we have executed yet; the tool + parameters are both now public.

## Should this be a new bounty submission?

Unsure. Arguments for:
- The dual-keypair bypass is a meaningful extension — Genmin's PR would be merged believing the patch closes the attack. Documenting the bypass prevents that false sense of security.
- It reframes the fix space from "add a check" to "redesign insurance accounting."

Arguments against:
- It's building on Genmin's work, not an independent discovery.
- The author may already be aware that same-owner checks are bypassable via dual keypairs.

My vote: post it as a REVIEW COMMENT on PR #37, not a separate bounty claim. That way Genmin gets full attribution for the finding class, and the adjacent observation strengthens rather than competes.

## Validation plan

Running the exact Genmin parameters in LiteSVM but with distinct keypairs for user and LP would mechanically confirm the bypass. Task #57 (multi-ix state-split probe) has LiteSVM harness work that can be adapted. Small addition — not reinventing the wheel.
