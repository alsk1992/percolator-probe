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

/// Proper dispatch-cascade detector.
///
/// A Rust `match tag { 0 => ..., 1 => ..., 2 => ..., ... }` with a
/// dense integer domain compiles to a sequence of `jeq r<x>, imm, +N`
/// instructions in rapid succession. The key signal is DENSITY: many
/// jcc's against different immediates targeting the same test register,
/// clustered in a small number of consecutive slots.
///
/// Algorithm:
///   1. Collect every `(jeq | jne) r<x>, imm, +off` site (src=K).
///   2. For each starting position i, find the maximal run of j such
///      that all sites in [i..j] test the same register, are within
///      `MAX_STRIDE` slots of the previous site, and have distinct
///      immediates.
///   3. Pick the longest run as the dispatch cascade.
///
/// Rationale: standalone jeq's (like boolean-conversion helpers) are
/// isolated; the dispatch cascade is dozens of jeq's in a row with
/// stride 1-4 slots.
pub fn find_dispatch(insns: &[Insn]) -> Vec<DispatchEntry> {
    // Collect every jeq/jne-against-imm site in PC order.
    let mut sites: Vec<DispatchEntry> = Vec::new();
    for i in insns.iter() {
        let class = class_of(i.opcode);
        if class != CLASS_JMP && class != CLASS_JMP32 { continue; }
        let op = alu_or_jmp_op(i.opcode);
        if op != JMP_JEQ && op != JMP_JNE { continue; }
        if src_bit(i.opcode) != SRC_K { continue; }
        let target = i.pc as isize + 1 + i.off as isize;
        if target < 0 { continue; }
        sites.push(DispatchEntry {
            discriminator: i.imm as u64,
            target_pc: target as usize,
            source_pc: i.pc,
            test_reg: i.dst,
        });
    }
    if sites.is_empty() { return Vec::new(); }

    // Find the longest run of consecutive jcc-on-imm sites testing the
    // same register with bounded stride.
    const MAX_STRIDE: usize = 8; // slots between consecutive jcc's in cascade
    const MIN_RUN: usize = 8;    // minimum length to be considered dispatch

    sites.sort_by_key(|s| s.source_pc);

    let mut best_run_start = 0usize;
    let mut best_run_len = 0usize;
    let mut i = 0usize;
    while i < sites.len() {
        let mut j = i + 1;
        let test_reg = sites[i].test_reg;
        let mut seen_imms: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        seen_imms.insert(sites[i].discriminator);
        while j < sites.len() {
            if sites[j].test_reg != test_reg { break; }
            if sites[j].source_pc - sites[j - 1].source_pc > MAX_STRIDE { break; }
            if seen_imms.contains(&sites[j].discriminator) { break; }
            seen_imms.insert(sites[j].discriminator);
            j += 1;
        }
        let run_len = j - i;
        if run_len > best_run_len {
            best_run_start = i;
            best_run_len = run_len;
        }
        i = j.max(i + 1);
    }

    if best_run_len < MIN_RUN {
        return Vec::new();
    }

    let run = &sites[best_run_start..best_run_start + best_run_len];

    // For a jeq cascade, the target is the arm body (taken when equal).
    // For a jne cascade, the target is the NEXT-arm check (taken when
    // not equal) — the arm body is actually the FALL-THROUGH. Detect
    // which we have by looking at the first instruction:
    //   - If opcode at pc == JMP_JEQ: taken target = arm body → correct as-is
    //   - If opcode at pc == JMP_JNE: taken target = skip over fall-through
    //     (typically to the NEXT jne), fall-through is arm body.
    let first_op = alu_or_jmp_op(
        insns.iter().find(|i| i.pc == run[0].source_pc).map(|i| i.opcode).unwrap_or(0)
    );
    let is_jne_cascade = first_op == JMP_JNE;

    let mut out: Vec<DispatchEntry> = if is_jne_cascade {
        // For jne cascade, the handler is the FALL-THROUGH: next slot
        // after each jne. But the discriminator accepted at that arm
        // IS the tested value (taken-not-equal means skipping when
        // != imm, so falling through means == imm).
        run.iter()
            .map(|e| DispatchEntry {
                discriminator: e.discriminator,
                target_pc: e.source_pc + 1, // fall-through
                source_pc: e.source_pc,
                test_reg: e.test_reg,
            })
            .collect()
    } else {
        run.to_vec()
    };
    out.sort_by_key(|e| e.discriminator);
    out.dedup_by_key(|e| e.discriminator);
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
