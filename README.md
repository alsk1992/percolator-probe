# percolator-probe

Whitehat research project targeting the Percolator immutable risk-engine
market deployed by Anatoly Yakovenko on Solana mainnet. Insurance vault
seeded with ~5 SOL, admin keys burned, public invitation to hack.

Refs:
- Challenge: https://x.com/aeyakovenko (public post, Apr 2026)
- Target program: https://github.com/aeyakovenko/percolator-prog
- Engine: https://github.com/aeyakovenko/percolator
- Author's own security log: `percolator-prog/security.md` (75+ discarded findings)

## Methodology

1. **Respect the prior work.** The author has run three audit rounds plus
   an ongoing DPRK-style R&D loop. 369 Kani formal proofs pass across
   wrapper + engine. 75+ hypotheses are already rejected in `security.md`
   with code-path rationales. Every probe starts by confirming it is not
   already covered.

2. **Code review first, empirics second.** Each probe begins with a code
   walk of the relevant handler + engine paths. If the walk identifies a
   concrete exploit, a test is written; if it confirms the exploit is
   blocked, the probe is committed as a discarded finding with the exact
   lines that block it. No probe is deleted — even discards have value
   because they map untested territory.

3. **Focus on the author's admitted gaps.** He himself flags three blind
   spots: funding-rate at envelope edge, multi-block coordinated attacks,
   and the 49-category perp-DEX failure checklist he is iterating
   through. Probes target these in priority order.

4. **Empirical path when code review is inconclusive.** A devnet
   attacker-matcher program in `matcher-attacker/` returns parametrised
   adversarial data. A harness in `harness/` runs scenarios and logs
   outcomes. Use this when a code path's correctness depends on runtime
   state that can't be statically proven.

5. **LLM-assisted hypothesis generation.** Local MLX-abliterated model
   is prompted with specific code slices + the 49-category taxonomy to
   generate attack hypotheses. Output is a ranked candidate list; each
   candidate is then code-walked per step 2.

## Probe catalogue

Each probe is a file in `probes/` named `NN-short-slug.md` with:
- Hypothesis
- Code path
- Test sequence (if applicable)
- Verdict (`LIVE` / `DISCARDED` / `PENDING`)
- Discovery date

See `probes/` for the live list.

## CV / portfolio intent

This repo is a serious research attempt regardless of whether the bounty
lands. The artifacts demonstrate (a) ability to reason about a 17k-line
Rust DeFi codebase, (b) integration of LLM tooling into security
workflow, (c) methodical documentation discipline.
