# Deployed mainnet market: oracle circuit breaker disabled (`cap=0`), exposes 5 SOL insurance to gap-driven drain

## Summary

The deployed mainnet market slab `5ZamUkAiXtvYQijNiRcuGaea66TVbbTPusHfwMX1kTqB`
has `oracle_price_cap_e2bps = 0`, which per `clamp_oracle_price`
(`src/percolator.rs:2761`) disables the external-oracle circuit breaker
entirely. Combined with `min_oracle_price_cap_e2bps = 0` and the
burned admin authority, the breaker cannot be re-enabled through any
instruction path and is permanently off for the lifetime of this
market.

This exposes the 5 SOL insurance seed to a gap-driven drain: any
unclamped Pyth update causes the engine's `last_effective_price_e6`
to jump in a single slot, marking max-leveraged positions to the new
price without the usual per-slot attenuation. Victims whose loss
exceeds their capital have their shortfall absorbed from insurance
per `use_insurance_buffer`.

Not claiming this is a protocol bug — the engine code and the Kani
proofs are consistent — but it is a concrete economic attack path
against the stated bounty target (*"steal the 5 sol"*), so filing per
the tweet's instructions.

## Verification

```bash
curl -sS -X POST https://api.mainnet-beta.solana.com \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":
      ["5ZamUkAiXtvYQijNiRcuGaea66TVbbTPusHfwMX1kTqB",
       {"encoding":"base64","dataSlice":{"offset":0,"length":584}}]}' \
  | python3 -c '
import sys, json, base64, struct
r = json.load(sys.stdin)
d = base64.b64decode(r["result"]["value"]["data"][0])
assert d[0:8] == b"TALOCREP"  # "PERCOLAT" LE
mm = struct.unpack("<Q", d[568:576])[0]
im = struct.unpack("<Q", d[576:584])[0]
off = 136+32+32+32 + 8+2+1+1+4 + 8+8+8+8 + 32 + 8+8
opcap = struct.unpack("<Q", d[off:off+8])[0]
mincap = struct.unpack("<Q", d[off+16:off+24])[0]
print(f"MM={mm} IM={im} cap={opcap} min_cap={mincap}")
'
```

Output at slot 415012537:
```
MM=1000 IM=2000 cap=0 min_cap=0
```

- `MM = 1000 bps` (10% maintenance margin)
- `IM = 2000 bps` (20% initial margin — max 5× leverage)
- `oracle_price_cap_e2bps = 0`
- `min_oracle_price_cap_e2bps = 0`

## Code path

**`clamp_oracle_price` returns raw when cap=0** (`src/percolator.rs:2761`):

```rust
pub fn clamp_oracle_price(last_price: u64, raw_price: u64, max_change_e2bps: u64) -> u64 {
    if max_change_e2bps == 0 || last_price == 0 {
        return raw_price;
    }
    // ...
}
```

Kani proof 76 case (a) formally verifies this branch.

**`InitMarket` allows cap=0 on non-Hyperp markets** (`src/percolator.rs:4538-4544`):

```rust
oracle_price_cap_e2bps: if is_hyperp {
    DEFAULT_HYPERP_PRICE_CAP_E2BPS.max(min_oracle_price_cap_e2bps)
} else {
    // Non-Hyperp: start at the immutable floor so the circuit
    // breaker is active from genesis. 0 floor = no breaker.
    min_oracle_price_cap_e2bps
},
```

(Comment is the author's own.)

**`UpdateConfig` cannot re-enable** because admin is burned, but even
if it weren't, the guard at `src/percolator.rs:7142-7147` only
forbids runtime `cap=0` when `min_cap != 0`. With `min_cap=0`, no
runtime transition can restore the breaker.

## Attack arithmetic

Per max-leveraged (5×) victim with 1 SOL capital:

| Oracle gap | Position loss / capital | Insurance drain |
|---|---|---|
| 10% | 50% | 0 (covered by capital) |
| 15% | 75% | 0.25 SOL |
| 20% | 100% | 0.50 SOL |
| 25% | 125% | 0.75 SOL |
| 50% | 250% | 2.0 SOL |

Drain of 5 SOL requires ~7 victims at 25% gap, ~3 at 50%, or fewer at
larger gaps / larger per-victim capital.

## Attack path

1. Deploy attacker-controlled matcher on mainnet (explicitly invited
   by the tweet).
2. Route user flow through the attacker's LP; counterparty exposure
   accumulates on the matcher-backed side.
3. Off-chain Pyth monitor watches feed
   `ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d`
   for published updates exceeding a volatility threshold.
4. On detection of a large imminent move, attacker submits
   `TradeCpi` (or `KeeperCrank` targeting liquidatable accounts) in
   the same slot as the Pyth publish.
5. `read_price_clamped` reads the raw new price; `clamp_external_price`
   returns it unchanged; `config.last_effective_price_e6` jumps to
   the new value.
6. Engine re-marks all positions at the jumped price. Max-leveraged
   victims breach MM. `settle_losses` + `use_insurance_buffer` absorb
   the shortfall from the 5 SOL seed.
7. Attacker's counterparty position holds the corresponding positive
   PnL. After warmup + haircut (`wide_mul_div_floor_u128(x_req, h_num, h_den)`),
   attacker extracts value.

## The AI angle the tweet specifically rewarded

> *"Especially if you can figure out how to get AI to hack it instead
> of doing it yourself."*

The execution above is exactly the kind of pipeline where AI beats a
human: a local MLX-inference loop watching Pyth + market state and
triggering pre-positioned transactions at the speed of one-slot
Solana inclusion. No human is fast enough to race published updates.
A small model running on consumer hardware can.

## Root cause classification

The engine's `clamp_oracle_price`, `read_price_clamped`, and
`use_insurance_buffer` functions are correct for their specified
behaviour. The 83 wrapper + 286 engine Kani proofs all hold. So the
root cause is not a spec violation — it's a deployment-time
parameter choice (`min_oracle_price_cap_e2bps = 0`) that the burned
admin key has now made immutable.

Consistent with D57's framing in `security.md`, admin-configurable
parameters are usually classified as operational risk. The
distinction matters less than it might seem here, because:

- The bounty charter is *"steal the 5 SOL"*, not *"prove a spec
  violation"*. The attack path above accomplishes the former given
  a real volatility event, regardless of how the underlying
  configuration is classified.
- Admin is burned. Users entering the market can observe the config
  by reading the slab, but cannot rely on any future re-enabling of
  the breaker. The decision is immutable, so the risk is permanent.
- The attack pattern generalises: any future deployer who follows the
  `setup-mainnet-market.ts` template inherits the same disabled-
  breaker default (the script does not set `minOraclePriceCapE2bps`
  explicitly; it defaults to 0 via `prodInitMarketArgs`). Absent a
  follow-up commit that either sets a non-zero default or adds an
  InitMarket guard that requires `min_cap > 0` for non-Hyperp
  markets, future live markets repeat this surface.

## Reproducibility

Verification script, finding write-up, and attack-path notes in
[research repo link — TBD before filing].

Happy to walk through the on-chain state, the attack simulation
against devnet, or the LLM-driven monitor/pre-position pipeline
design.

---

Filed per the tweet's instructions. Whitehat — not executing the
drain. Classification of the root cause is your call, but the
5-SOL bounty target is economically reachable by the attack above,
so filing for completeness and in the interest of either (a)
collecting the bounty if you consider this sufficient, or (b) your
classification giving me a clearer picture of what does count,
which would shape whether I continue the research.

Available for direct dialogue on the "AI hacks it" angle; the
execution pipeline described is exactly the kind of agentic
exploitation infrastructure I think your framing is optimising
for rewarding.
