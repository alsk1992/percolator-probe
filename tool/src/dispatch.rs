// Dispatch-table extraction.
//
// Rust's `match` over a small integer discriminator usually compiles to
// a cascade of `jeq r<x>, imm, +N` instructions, one per variant,
// falling through to the default arm. Anchor programs use an 8-byte
// borsh discriminator (not relevant here — percolator is a pinocchio
// program with single-byte Instruction tags 0..=32).
//
// This module scans the decoded .text for such cascades and emits a
// mapping from discriminator value → handler PC.

use serde::Serialize;
use crate::sbf::{Insn, JMP_JEQ, JMP_JNE, CLASS_JMP, CLASS_JMP32, SRC_K, alu_or_jmp_op, class_of, src_bit};

/// One (discriminator, handler-pc) binding from the dispatch table.
#[derive(Debug, Clone, Serialize)]
pub struct DispatchEntry {
    pub discriminator: u64,
    pub target_pc: usize,
    /// Slot index at which the jeq/jne was emitted (for locality analysis).
    pub source_pc: usize,
    /// Register being tested at this site.
    pub test_reg: u8,
}

/// Heuristic dispatch finder.
///
/// Approach:
///   1. For each `jeq r<x>, imm, +N` (BPF_K source), record a candidate
///      `(discriminator=imm, target_pc=pc+1+N, source_pc=pc, test_reg=x)`.
///   2. Group candidates by `test_reg` into clusters (runs where the
///      same register is being compared in a small PC window).
///   3. Return the largest cluster — that is the dispatch cascade.
///
/// This is robust against simple compiler reorderings: the tool still
/// picks up all `jeq` sites, just potentially over-includes. The user
/// can filter by PC range in the report.
pub fn find_dispatch(insns: &[Insn]) -> Vec<DispatchEntry> {
    // Collect every jeq-immediate site.
    let mut candidates: Vec<DispatchEntry> = Vec::new();
    for i in insns.iter() {
        let class = class_of(i.opcode);
        if class != CLASS_JMP && class != CLASS_JMP32 { continue; }
        if alu_or_jmp_op(i.opcode) != JMP_JEQ { continue; }
        if src_bit(i.opcode) != SRC_K { continue; }
        let target = i.pc as isize + 1 + i.off as isize;
        if target < 0 { continue; }
        candidates.push(DispatchEntry {
            discriminator: i.imm as u64,
            target_pc: target as usize,
            source_pc: i.pc,
            test_reg: i.dst,
        });
    }

    if candidates.is_empty() { return Vec::new(); }

    // Cluster by (test_reg, approximate PC window).
    // Two candidates are in the same cluster if they compare the same
    // register and are within WINDOW slots of each other.
    const WINDOW: usize = 400;
    candidates.sort_by_key(|c| (c.test_reg, c.source_pc));

    let mut clusters: Vec<Vec<DispatchEntry>> = Vec::new();
    for c in candidates {
        let mut placed = false;
        for cluster in clusters.iter_mut() {
            let same_reg = cluster[0].test_reg == c.test_reg;
            let near = cluster
                .iter()
                .any(|x| x.source_pc.abs_diff(c.source_pc) <= WINDOW);
            if same_reg && near {
                cluster.push(c.clone());
                placed = true;
                break;
            }
        }
        if !placed {
            clusters.push(vec![c]);
        }
    }

    // Pick the cluster with the most distinct discriminators.
    let best = clusters
        .into_iter()
        .max_by_key(|c| {
            let mut seen = std::collections::BTreeSet::new();
            for e in c { seen.insert(e.discriminator); }
            seen.len()
        })
        .unwrap_or_default();

    // Deduplicate by discriminator (first occurrence wins).
    let mut seen = std::collections::BTreeMap::new();
    for e in best {
        seen.entry(e.discriminator).or_insert(e);
    }
    let mut out: Vec<DispatchEntry> = seen.into_values().collect();
    out.sort_by_key(|e| e.discriminator);
    out
}

/// Map the numeric tag to the percolator-prog instruction name.
/// Source-of-truth: the `match tag` decoder in percolator-prog
/// `src/percolator.rs` line 1464–1766. Tags NOT listed here are
/// rejected by the decoder's `_ => InvalidInstructionData` fallback.
pub fn percolator_tag_name(tag: u64) -> Option<&'static str> {
    // Source-authoritative list. Gaps (11, 12, 15, 16, 22, 24) are
    // INVALID — the decoder rejects these as InvalidInstructionData.
    match tag {
        0  => Some("InitMarket"),
        1  => Some("InitUser"),
        2  => Some("InitLP"),
        3  => Some("DepositCollateral"),
        4  => Some("WithdrawCollateral"),
        5  => Some("KeeperCrank"),
        6  => Some("TradeNoCpi"),
        7  => Some("LiquidateAtOracle"),
        8  => Some("CloseAccount"),
        9  => Some("TopUpInsurance"),
        10 => Some("TradeCpi"),
        13 => Some("SlashCreationDeposit"),
        14 => Some("UpdateConfig"),
        17 => Some("CloseSlab"),
        18 => Some("SettleAccount"),
        19 => Some("ResolveMarket"),
        20 => Some("WithdrawInsurance"),
        21 => Some("AdminForceCloseAccount"),
        23 => Some("WithdrawInsuranceLimited"),
        25 => Some("ReclaimEmptyAccount"),
        26 => Some("SettleFlatNegativePnl"),
        27 => Some("DepositFeeCredits"),
        28 => Some("ConvertReleasedPnl"),
        29 => Some("ResolvePermissionless"),
        30 => Some("ForceCloseResolved"),
        31 => Some("CatchupAccrue"),
        32 => Some("UpdateAuthority"),
        _  => None,
    }
}

/// True if `tag` is a valid instruction tag accepted by the source decoder.
/// Anything else found in the binary is either a nested-match comparison
/// (false positive for the main dispatch heuristic) or dead code.
pub fn is_valid_source_tag(tag: u64) -> bool {
    percolator_tag_name(tag).is_some()
}
