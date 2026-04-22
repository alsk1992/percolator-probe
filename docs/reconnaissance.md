# Reconnaissance — target state as of 2026-04-23

## Deployed instances

### Mainnet (the bounty target)

- Program: `BCGNFw6vDinWTF9AybAbi8vr69gx5nk5w8o2vEWgpsiw`
- Slab: `5ZamUkAiXtvYQijNiRcuGaea66TVbbTPusHfwMX1kTqB`
- Vault: `AcJsfpbuUKHHdoqPuLccRsK794nHecM1XKySE6Umefvr`
- Oracle: `7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE` (Pyth pull PriceUpdateV2)
- Feed ID: `ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d`
- Mint: wSOL (So11111111111111111111111111111111111111112), unit_scale=0
- Inverted: yes
- Insurance: 5,000,000,000 lamports (= 5 SOL, ≈ $437)
- TVL cap multiplier: 20× insurance (max c_tot = 100 SOL)
- Maintenance fee per slot: 265 (e9 units)
- New-account fee: 57_000_000 lamports (~$5)
- Permissionless-resolve-stale: 432000 slots (~48h)
- Force-close delay: 432000 slots (~48h)
- **All 4 authorities burned** (admin, insurance, operator, hyperp)
- **No matcher deployed** — third parties provision their own (the invitation)

### Devnet (test surface)

- Program: `2SSnp35m7FQ7cRLNKGdW5UzjYFF6RBUNq7d3m5mqNByp`
- Matcher program: `4HcGCsyjAqnFua5ccuXyt8KRRQzKFbGTJkVChpS7Yfzy` (already deployed, someone's test matcher)
- Slab: `dtrNVk7otCtcmPvrARnLxi5nWoNFYQYS7b9vC1Yjnt2`
- Oracle: Chainlink (different from mainnet — Pyth)
- Initial LP exists at idx 0 with 1 SOL deposited
- All authorities burned

## Key differences between mainnet and devnet

- Mainnet uses Pyth pull oracle, devnet uses Chainlink. **Two different oracle code paths** — the 4/22 monotonicity fix covers both but is phrased slightly differently per oracle.
- Devnet has a permissive matcher already deployed, convenient for testing. But the bounty is on mainnet, so exploits must ultimately work against the Pyth/mainnet path.
- Devnet has a live LP at idx 0 — mainnet does not. The first real trader must register an LP.

## Audit artifacts inventory

- Wrapper Kani proofs: 83/83 passing (`percolator-prog/kani_audit.md`)
- Engine Kani proofs: 286/286 passing (per commit `3f55f87`)
- Integration tests: 674+ across tiers
- Proptest fuzzers: 19
- Discarded security findings: 75+ documented in `percolator-prog/security.md` (D1–D75 across 3 rounds + DPRK R&D loop)
- Fresh threat taxonomy: 49-category perp-DEX failure checklist (commit `5933576`, 2026-04-22)

## Author's admitted blind spots

From `security.md` §"Residual review scope" and "Next sweep targets":

1. Funding rate at `MAX_ABS_FUNDING_E9_PER_SLOT` with OI at `MAX_VAULT_TVL` on both sides — exact arithmetic stress at the envelope boundary. Author cites test-infrastructure gap.
2. Multi-block coordinated attacks (keeper-timing collusion, miner+attacker).
3. The 49-category checklist — explicitly noted as "iterate through these when nothing else jumps out."

These are the targets. #1 and #3 are code-reviewable with care. #2 requires empirical infra.

## Deployment context notes

- Build SHA256 of mainnet BPF binary: `3f78e2f279dc29aa373fca57cfc56a56d70b8a5e85a16e5a090a2f2d5d9efbcc`
- Wrapper commit: `06f86fb125525af81c0bfd19a295095dda102c07`
- Engine commit: `3f55f871a3aa29d7b582fc2641d2106cbac0c32e`
- **Upgrade authority burned (`--final`)** — bytecode is immutable forever

The immutability is a double-edged sword: any bug currently in the deployed binary is *also* immutable. Discovery of a real bug in the wrapper or engine as it stands is a permanent find.
