# Advanced attack plan — devious angles aligned to the tweet

## Re-reading the bounty charter

> *"Figure out how to hack it **or manipulate the engine** and steal
> the 5 sol, and I will do my best to land you a job or an angel
> investment. **Especially if you can figure out how to get AI to hack
> it instead of doing it yourself.**"*
> — Anatoly Yakovenko, 2026-04-22

Two reframes this forces:

1. **"Manipulate the engine"** ≠ "find a classical code bug". The
   author invites *game-theoretic* attacks within the rules — any
   action that drains vault tokens to the attacker counts, even if the
   protocol considers it "intended LP-delegation trust." The
   discarded-findings log (D32 in particular) classifies matcher
   adversarial pricing as "operational risk, not bug" — **but the
   attacker doesn't care about that classification**.

2. **"AI to hack it"** — AI-driven discovery is an explicit bonus
   criterion. Solo LLM code review is the weakest form. Winning
   move: a pipeline where the LLM generates hypotheses, a harness
   executes them against devnet, results feed back into the LLM's
   context. This is the frontier the tweet literally points at.

## Categorisation of attack surfaces

Ranked by the intersection of *novelty vs the 75+ discarded findings*,
*technical depth*, and *realistic AI-assisted exploitability*.

---

## A. Game-theoretic / multi-party drains

### A1. Three-party sandwich via attacker-LP + own user + independent user

**Hypothesis**: zero-sum invariant in `execute_trade_not_atomic` only
holds between `trade_pnl_a` and `trade_pnl_b` (same trade). If the
attacker operates a matcher AND a user account under a DIFFERENT
independent LP, they can:

1. User A (attacker) trades through LP-1 (attacker's own matcher).
   Matcher returns exec_price 1% unfavourable to A → A instantly loses
   1% of notional. LP-1's counterparty (the matcher's own hedge) gains
   it — but that's the attacker's own side, so circular.

2. Simultaneously (or adjacent tx), User B (attacker) trades through
   LP-2 (independent, honest matcher). Exec near oracle. B opens the
   opposite position to A at near-fair pricing.

3. Combined A+B are delta-neutral. But A's 1% slippage loss went to
   LP-1's counterparty slot — which is another attacker account or
   wallet.

4. Attacker's LP also takes maker fees from the trades routed through
   it, and a slice of crank rewards if they time a crank right after.

**Why promising**: the zero-sum is *per-trade*, not *per-owner*.
Delegating the matcher lets the attacker steer where the 1% slippage
goes. If it goes to a third attacker-controlled sink, it's a real
extraction route bounded only by willing counterparty volume.

**Code to walk**: `execute_trade_not_atomic` at engine:3856 —
specifically which fields update for A, B, and whether any state
writes implicitly credit a third party (LP). If LPs never become
balance-holding participants, this exists only at the application/UX
layer, not the engine. But the **maker rebate / fee split** to LP
might open a third-party channel.

**AI-assist leverage**: prompt model with the full `execute_trade`
source + "find every third party whose balance changes during the
trade." Fuzz parameters.

---

### A2. Victim-cranks-zero, attacker-cranks-sum

**Hypothesis**: D9 rejected crank-reward griefing on "attacker pays
own fees." But crank sweeps EVERY account's accrued fees. If victims
have accumulated fees (waiting to be swept) and the attacker cranks
first, attacker captures 50% of *all* fees — including the victims'.

D9 author framed this as "economic impossibility: the attacker is
also paying fees." But in a MULTI-USER market with other traders
generating fees, the attacker isn't the only fee-payer. Their 50%
share scales with total fee volume, not just their own contribution.

**Why promising**: the deployed mainnet has `maintenance_fee_per_slot = 265`
and `expectedDailyFee ≈ $5/account`. With 4096 max accounts at full
capacity, daily fee pool is ~$20,000. Cranker takes 50% = ~$10,000/day
if they can consistently win the crank race. Over 30 days that's
$300k, dwarfing the 5 SOL bounty.

**Code to walk**: crank reward logic at engine ~line 5327 (gate
`sweep_delta > 0`). Confirm that cranker's reward is funded from
*swept fees (all accounts)*, not just cranker's own contribution.

**AI-assist**: prompt with crank handler + ask for "whose balance
decreases, whose increases, by what proportion."

---

### A3. Liquidation-cascade positioning

**Hypothesis**: attacker positions a healthy account on the SAME side
as a cascade of victims about to be liquidated. When liquidations
fire, liquidator fees go to insurance and the cascade drives the ADL
multiplier down on the *opposite* side. If attacker is on the right
side, their effective position is preserved while opposite-side
holders get written down.

Author's D57 (admin-key funding abuse) covers adversarial config
changes. But a *non-admin* attacker can still engineer cascades by
providing liquidity that encourages victims into positions that
become cascade-vulnerable.

**Why promising**: the ADL mechanism specifically writes down the
winning side to match the drained loser side. A clever attacker
positioned to absorb the write-down asymmetrically could profit.

**Code to walk**: ADL reset mechanics at engine lines 2553–2574 and
the `adl_mult_long/short` decay path. Specifically the A-candidate
computation at line 2547 where truncation residual is dropped.

---

## B. CPI and reentrancy angles (beyond D1/D21)

### B1. 3-hop reentrancy via intermediate program

**Hypothesis**: D21 discarded *direct* matcher reentry to a second
Percolator market. But what if the matcher CPIs into an *intermediate*
program, which then CPIs into a second Percolator instance or back
into the same Percolator? The reentrancy guard (`FLAG_CPI_IN_PROGRESS`)
is scoped to the slab — does it persist across a 3-hop call chain?

Specifically: attacker's matcher calls program X; X calls attacker's
second program Y; Y does something with Percolator state.

**Code to walk**: `state::set_cpi_in_progress` at wrapper line 5976
and corresponding `is_cpi_in_progress` check at slab_guard line 3759.
Trace whether the flag is cleared ONLY on the CPI return path, or
whether a panic / error mid-chain could leave it set and brick the
market (DoS, not theft, but still damaging).

### B2. Matcher_context shape manipulation mid-CPI

**Hypothesis**: matcher program is the owner of matcher_context
account. During its CPI execution, can it realloc the account to a
different size, shrink below `ctx_len_ok` threshold, or reassign
ownership? Solana allows account mutation by owner within an
instruction. If the wrapper's post-CPI `read_matcher_return` runs
against a modified matcher_context, the read could go wrong.

**Code to walk**: after `invoke_signed_trade` returns (line 5980),
does `read_matcher_return` re-validate the matcher_context shape, or
rely on the pre-CPI validation? If only pre-validated, shape
manipulation during CPI is a gap.

### B3. Tail account aliasing with SystemProgram or sysvars

**Hypothesis**: what if a tail AccountInfo aliases the Clock sysvar
or the SystemProgram pubkey? The wrapper explicitly validates the
Clock key in the fixed position (line 5791ish) but the tail is
attacker-controlled. If the matcher processes the tail as "treat as
clock" based on pubkey, and the engine later re-reads clock, could the
clock be stale/manipulated?

Probably not exploitable because sysvars are read by key, not by
passed-in AccountInfo. But worth walking.

---

## C. Numerical / precision angles (deeper than probe 03)

### C1. Kani BOUNDED proof gap exploitation

The Kani proofs 55, 59, 63, 65, 69–73, 78–81 are explicitly BOUNDED
(e.g. u8×u8 or KANI_MAX_SCALE=64) for SAT tractability. Production
bounds are vastly larger (e.g. MAX_UNIT_SCALE = 1e9).

**Hypothesis**: behaviour is *proven* correct up to the Kani bound,
but between the Kani bound and the production bound, the logic might
silently diverge due to intermediate overflow or an edge case SAT
didn't have to enumerate.

**Concrete targets**:
- `scale_price_e6` with unit_scale = 1e9 (production max) on prices
  near MAX_ORACLE_PRICE = 1e12. Kani bound is 64. The 1e9 case is
  never proven universally.
- `clamp_oracle_price` with `mark = 1e12`, `cap = 1e8`. Kani bound
  is u8×u8.
- EWMA fee-weighted updates with extreme price/fee combinations.

**AI-assist**: prompt model to generate specific input vectors at the
production boundary and compute expected vs actual outputs by hand.
Compare.

### C2. `mul_div_floor_u128` denominator-zero reachability

The helper panics on `d == 0`. 37 call sites in the engine. Most have
explicit `a_basis != 0` / `h_den != 0` guards; some don't.

**Targets to walk** (non-exhaustive):
- Haircut computations where `h_den = pnl_matured_pos_tot`. If the
  matured pool ever hits 0 mid-instruction but the caller didn't
  pre-check, panic.
- Funding rate computations using `oi` as denominator. Zero-OI
  boundary (author's #12).
- Scale conversions where unit_scale could be 0 from a corrupt path.

**AI-assist**: enumerate all 37 call sites, for each identify the
denominator source, trace backward to confirm non-zero invariant.

### C3. `i128::MIN` propagation beyond proof 75

Kani proof 75 regression-tests exactly the pair `(exec=i128::MIN, req=i128::MIN+1)`. That's ONE point in the input space. What about:
- `i128::MIN` introduced via accumulated PnL (pnl + trade_pnl = i128::MIN exactly)?
- `i128::MIN` in intermediate arithmetic inside `compute_kf_pnl_delta`
  or `set_pnl_with_reserve`?

**Code to walk**: every `checked_neg()` site and every `unsigned_abs()`
site. `i128::MIN.checked_neg() == None`, `i128::MIN.unsigned_abs()`
returns `i128::MAX as u128 + 1`. If a caller uses `unwrap_or` or
`.expect()`, boom.

---

## D. Cross-tx / multi-block coordinated attacks

*These are the author's explicitly-admitted blind spot.*

### D1. Funding-rate-boundary sniping

**Hypothesis**: funding accrues on a per-slot basis. At the exact
slot where `funding_rate_e9` changes (via some event, even natural
market dynamics), the attacker front-runs with a trade that crystallises
a favourable funding snapshot.

**Why promising**: `accrue_market_to` updates funding once per slot.
The timing of *when within a slot* a tx lands determines which rate
applies. With priority fees, an attacker can win the race.

### D2. Oracle cap-step harvesting

**Hypothesis**: oracle cap per slot (e.g. 1%). If real price jumps
5% in one slot, the engine's `last_effective_price` only moves 1% per
slot. For 5 slots, the engine's price lags reality.

An attacker with the real price signal (Pyth pulled off-chain) can:
1. See real price = $105, engine price = $100
2. Open long at engine price (via matcher at ~$100 × 1.01 = $101)
3. Wait for cap-steps to pull engine price up
4. Close at engine price = $105
5. Profit ~4% regardless of real market direction afterwards

This is latent arbitrage against the circuit breaker. The author's
D32 covers "matcher adversarial pricing" but not "matcher racing the
cap step."

**Why promising**: every oracle-based market with circuit breaker
has this latent surface. Bounds are set for volatility protection,
but the flip side is arbitrage opportunity for informed actors.

**AI-assist**: simulate price sequences + attacker trades, compute
realised P&L, compare to random-baseline.

### D3. Keeper-crank manipulation for stake-reclaim timing

**Hypothesis**: dust reclaim and fee sweeps depend on crank timing.
If an attacker can influence WHEN a crank fires (by crowding or
starving the crank tx), they can:
- Delay crank until a victim's account decays below `min_initial_deposit`,
  then crank + reclaim → victim's dust to insurance → crank reward
- Accelerate crank right after their own large trade to capture
  freshly-generated fee sweep rewards

---

## E. Oracle-specific devious angles

### E1. Chainlink vs Pyth asymmetry (4/22 fix parity)

The monotonicity fix (commit `8da5dd9`) added `last_oracle_publish_time`
storage. Both readers emit a `(price, timestamp)` pair. But:
- Pyth: `publish_time` is inside the signed Pyth message — forge-proof
- Chainlink: `timestamp` is inside the account data — signed by
  Chainlink OCR2 reporters

Question: are the monotonicity gates applied symmetrically? Or does
one path have a subtle bypass?

**Target**: side-by-side diff of `read_pyth_price_e6` (wrapper 2509–2605)
and `read_chainlink_price_e6` (wrapper 2619–2700), then both against
`clamp_external_price` and its callers.

### E2. Pyth confidence-interval edge case

`read_pyth_price_e6` at line 2577–2583:
```rust
if conf_bps != 0 {
    let lhs = (conf as u128) * 10_000;
    let rhs = price_u * (conf_bps as u128);
    if lhs > rhs { return Err(OracleConfTooWide); }
}
```

What if `conf_bps == 0` (feature disabled)? The check is skipped and
*any* conf is accepted, including `conf > price` (infinite
uncertainty). The deployed mainnet market's `conf_filter_bps` was not
listed in the JSON — if it's 0, the conf filter is disabled and Pyth
updates with wide intervals are accepted. A Pyth update with tight
`price` but huge `conf` could be valid-in-schema but meaningless-in-market.

**Hypothesis**: during a known volatility event, Pyth publishes with
wide conf. If `conf_bps == 0`, engine ignores it and uses the
possibly-unreliable price. Attacker who timed their trade to that
moment benefits from the engine's failure to flag the uncertainty.

### E3. Pyth PriceUpdateV2 account reallocation

Pyth Pull receiver program allows anyone to post an update. What
happens if attacker posts a MALFORMED update that passes the `data.len() >= PRICE_UPDATE_V2_MIN_LEN` check but has garbage after the header? The borsh deserialize at line 2543 should fail gracefully, but if there's a parse path that succeeds on garbage, it could result in acceptance of a bogus PriceFeedMessage.

---

## F. Solana-runtime specific

### F1. Address Lookup Table smuggling

Attacker's tx uses ALTs to reference the slab, matcher_ctx, and oracle
from an on-chain table rather than inline. Does the wrapper's
AccountInfo-based validation catch this? Usually yes (AccountInfo
carries the pubkey regardless of reference source), but worth
verifying the SIMD-0123 runtime semantics.

### F2. Sysvar read-after-CPI staleness

`LastRestartSlot::get()` is called in InitMarket and checked
elsewhere. If this sysvar is read once and cached, a cluster restart
mid-transaction (vanishingly rare but theoretically possible) would
leave a stale value. Per D65 the author classifies this as "cannot
span a restart" but SIMD-0047 semantics can be subtle.

### F3. Compute-unit exhaustion mid-instruction

If a particular input causes an engine path to use >1.4M CU, the tx
fails. **BUT** — does the engine write state BEFORE the CU-exhausting
arithmetic? If yes, a partial state mutation could occur, leaving an
inconsistent state. Transaction rollback should prevent this (Solana
reverts account changes on failed tx), but worth confirming no
writes occur outside the owned-account space.

---

## G. Matcher-program design space

### G1. Matcher-signed PDA collision

The LP registers `matcher_program` and `matcher_context`. If an
attacker deploys a matcher whose program ID happens to collide (via
PDA chicanery) with another known program (e.g., SystemProgram, Token
program, Clock sysvar), does the wrapper's identity check let it
through? Highly unlikely but checkable.

### G2. Matcher that re-enters via different instruction

D21 covers cross-market re-entry via TradeCpi. What about the matcher
re-entering via `KeeperCrank`? Crank is permissionless. Matcher
during its CPI could invoke Percolator's crank on the same slab. The
reentrancy guard blocks it on the slab level — but only if crank
handler also sets/checks the flag. If crank DOESN'T set the flag,
crank is re-entrant during a trade. Does this matter? Crank sweeps
fees, which changes capital state while a trade is in progress.

**Code to walk**: does `KeeperCrank` handler set `FLAG_CPI_IN_PROGRESS`?

---

## H. Init and lifecycle angles

### H1. Double-init via low-level account create

InitMarket's magic-byte check (wrapper line 4768, `MAGIC = "PERCOLAT"`)
rejects re-init if magic is present. But what if an attacker closes
the slab account via Solana's account close (transferring lamports
out and zeroing data), then re-initialises? Close requires
`close_authority` — BURNED on mainnet. So this is blocked. But the
sequence is worth confirming.

### H2. LP identity reuse post-close

Author's 49-list item #49. LP closes (freeing its slot), another LP
inits in the same slot. Old matcher's stored `matcher_program`/
`matcher_context` might match the new one if the attacker registered
their matcher with the same pubkeys. Stale signed data from old LP
could replay against new LP.

D20 covers this with generation counter (`mat_counter`). Confirm the
counter increments on EVERY materialisation without any skip path.

---

## Priority ranking for next execution

Top-5 to execute next, in order:

1. **A2** (victim-cranks, attacker-collects) — walk the crank reward
   flow, confirm whose balance funds the cranker reward. If OTHER
   users' fees are redistributable via cranking, the 50% capture at
   scale is a real extraction surface and may not be "intended LP
   trust" territory.

2. **E2** (Pyth conf_bps = 0 edge) — check deployed market's
   `conf_filter_bps` via RPC. If zero, then during market stress the
   engine accepts unreliable prices. Combined with matcher-adversarial
   pricing, this widens the 1% band beyond the author's modeled
   envelope.

3. **C2** (mul_div_floor_u128 div-zero reachability) — systematic
   enumeration of 37 call sites. Even one reachable path means a
   grief vector. Not fund theft but publishable finding.

4. **D2** (oracle cap-step harvesting) — build a simulation of price
   sequences + matcher trades + cap-step progression. Compute attacker
   P&L vs baseline. If positive expected value after fees, it's a
   real-money extraction path against the engine's intended circuit
   breaker behaviour.

5. **A1** (3-party sandwich) — walk `execute_trade` looking for any
   third-party (LP-pubkey) whose state is credited during the trade.

## AI-assist pipeline design (the "bonus" angle)

Real move: build a pipeline where a local MLX-abliterated model runs
against 200-line windows of engine source, primed with:
- The 49-category taxonomy from commit `5933576`
- The 75+ discarded findings as "already-rejected" negative examples
- The above advanced-angle categorisation as "hypothesis seeds"

For each window, model emits ranked hypotheses with a template:
```
Window: <file>:<lines>
Hypothesis: <single sentence>
Code path: <exact lines involved>
Why not already discarded: <reference to nearest D#>
Test sequence: <concrete steps>
```

Human reviews hypotheses; devnet harness executes the test sequences.
Results feed back as context to the model for next window.

This is the genuine "AI hacks it" entry — not one-shot conversation,
but a persistent research loop.

---

## Final realism check

The bounty is hard on purpose. The author has:
- 369 Kani proofs
- 75+ discarded findings
- Run his own DPRK-style R&D loop
- Published his threat taxonomy

Expected value of any single angle finding a bug: probably < 5%.
Expected value across all 20+ above: maybe 20–30% after a week of
focused work. The PORTFOLIO VALUE of the artifacts produced is the
more reliable outcome — this plan itself, plus a working AI-assist
harness, plus documented probe discipline, is hireable-engineer-level
work regardless of whether the 5 SOL lands.
