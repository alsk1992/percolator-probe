# percolator-re

Reverse-engineering harness for immutable Solana programs with
formal-verification claims. Built because skimmode's drainer-oriented
heuristics don't apply to live hardened programs — this tool targets
programs that have passed Kani proofs and looks for things formal
verification can't model.

## What it does

- **Proper SBF decoder** — full opcode coverage including LDDW
  (16-byte), JMP32 class, ALU64, BPF_ST vs BPF_STX, all the jcc
  variants, syscall vs internal-call distinction.
- **Dispatch extraction** — scans for Rust-generated `match tag` jcc
  cascades, returns tag → handler-PC mapping.
- **Source-truth correlation** — the dispatch output cross-references
  against the source `match tag` decoder so heuristic false positives
  are filtered out automatically.
- **Handler inventory** — per-tag size/call/syscall/load/store/alu
  counts (linear walk until first `exit`; approximate).

## Usage

```bash
cargo build --release
./target/release/percolator-re info <binary.so>
./target/release/percolator-re dispatch <binary.so>
./target/release/percolator-re handlers <binary.so>
```

## Target-binary acquisition

```bash
solana program dump \
  BCGNFw6vDinWTF9AybAbi8vr69gx5nk5w8o2vEWgpsiw \
  percolator.so -u mainnet-beta
```

## Findings from running against the deployed Percolator binary

- SHA-256 of dumped binary: `502088e9cf5e1b38cccd31bbab2df18d4958712fb9456d48669241aaddf4cc93`
- `.text` section: 371,488 bytes, 45,288 SBF instructions
- Entry point: `0x00026a18`
- All 27 source-valid instruction tags present in dispatch, zero hidden
  or extra instructions. The binary faithfully implements the
  percolator-prog `Instruction` enum as defined at `src/percolator.rs:1464`.

## Limitations / known work left

- Handler size walk uses linear-to-first-`exit` heuristic, which
  under-counts handlers whose primary exit is on an error path (most
  handlers). Proper size measurement requires control-flow reachability
  analysis.
- No symbolic execution yet (skimmode's symex engine would be the
  starting point — extract authority-check graph + CPI boundaries).
- No Kani-coverage overlay yet (would require parsing the author's
  Kani proof identifiers and mapping them to handler PC ranges).

These are tractable follow-ups if this tool continues to get built out.
