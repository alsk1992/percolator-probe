# Next probe queue

Ranked by promise and verifiability from code review alone (no devnet infra yet).

## Code-reviewable now

- [ ] **#12 Zero-OI funding boundary** — what happens when one side has no open interest? Funding rate division by zero? Check `accrue_funding` / rate computation in engine.
- [ ] **#30 Resolved-market writes** — after `ResolveMarket` / `ResolvePermissionless`, are there any instruction paths that mutate state they shouldn't? Walk the post-resolve locks.
- [ ] **#36 Fee debt → positive** — `fee_credits` is supposed to be `<= 0` (debt). Any path that could drive it positive (silent corruption)?
- [ ] **#45 Double init** — what if an attacker calls `InitMarket` twice on the same slab? Magic-byte check at 4768 should reject, but confirm the re-init guard.
- [ ] **#28 Authority rotation race** — when an authority is rotated to `[0;32]` (burned) mid-instruction, is there a path where the previous key is still consulted?
- [ ] **#44 Haircut precision** — rounding direction bias in `haircut_ratio` during distressed-close. Already D45 + D48 covered; re-check for any non-haircut path that also applies a ratio.
- [ ] **#34 OI imbalance** — `oi_eff_long_q - oi_eff_short_q` drift from net positions. Engine should enforce.

## Requires empirical test (devnet matcher)

- [ ] **#7 Self-liquidation profit** — same owner on liquidator + target. D21 covers cross-market reentrancy; self-liq specifically not in D1-D75.
- [ ] **#24 Liquidation front-running** — see a liquidatable account, price-push, liquidate, revert. On-chain behavior depends on oracle cache semantics.
- [ ] **#26 Cross-tx race in same block** — multiple txs from different users in the same block, leader-order-dependent attack.
- [ ] **#10 Funding snapshot race** — `accrue_market_to` timing with concurrent `UpdateConfig`. Requires live leader sequencing.
- [ ] **Precision sweep**: parametric matcher returning `exec_price` just inside the 1% anti-off-market band under varying oracle conditions. Fuzzer against deployed market.

## Infrastructure prerequisites for empirical probes

1. `matcher-attacker/` crate — deploys a Solana program that exposes configurable `exec_price`, `exec_size`, `flags` via a state PDA.
2. `harness/` — TypeScript or Rust CLI that: registers an LP pointing at our matcher, performs `DepositCollateral`, triggers `TradeCpi` scenarios, tears down cleanly.
3. Devnet funds — ~2 SOL for fees/deposits across iterations.
4. Abliterated LLM pipeline — local MLX reading `src/percolator.rs` in 200-line windows, prompted with the 49-category taxonomy, emitting ranked hypotheses. Feed output back as probe candidates.
