// Authority-check auditor.
//
// For each handler identified by the dispatch map, extract the opening
// prologue and look for signs of an is_signer check. In Solana programs
// built on Pinocchio / solana-program, the canonical signer-check
// pattern is:
//
//   ldxb r?, [r?+0x0008]      ; AccountInfo layout has is_signer at +8
//                             ; (the exact offset depends on library
//                             ;  version; we scan for the common ones)
//   jeq/jne r?, 0, <reject>   ; if not signer, branch to reject
//
// We widen this to: any `ldxb` / `ldxh` / `ldxw` in the first N
// instructions that is followed by a conditional jump against an
// immediate is evidence of some form of input validation. A handler
// that does NO input validation before reaching its first CPI or
// memory-write is a strong red flag — it's either permissionless by
// design (rare, worth confirming) or missing an auth check.
//
// This does NOT prove an auth bypass on its own — signer checks can
// be inlined into subroutine calls, and Pinocchio's `expect_signer`
// is often a short internal call. But it produces a ranked shortlist
// of handlers worth a deeper manual look.

use serde::Serialize;
use crate::sbf::{Insn, CLASS_LDX, CLASS_STX, class_of};
use crate::dispatch::{DispatchEntry, percolator_tag_name};

#[derive(Debug, Clone, Serialize)]
pub struct AuthAudit {
    pub tag: u64,
    pub name: String,
    pub pc_start: usize,
    /// Number of load instructions in the first WINDOW slots.
    pub prologue_loads: usize,
    /// Number of conditional branches (against imm) in the first WINDOW slots.
    pub prologue_branches: usize,
    /// Number of syscalls reached before any conditional branch.
    pub syscalls_before_any_branch: usize,
    /// Number of stores reached before any conditional branch.
    pub stores_before_any_branch: usize,
    /// True if the prologue shows evidence of at least one validation
    /// pattern (load + branch within a small window).
    pub prologue_validates: bool,
    /// Slot index (within handler) of the first syscall, if any.
    pub first_syscall_at: Option<usize>,
    /// Slot index (within handler) of the first internal call, if any.
    pub first_internal_call_at: Option<usize>,
}

pub fn audit_handlers(
    insns: &[Insn],
    dispatch: &[DispatchEntry],
    follow_calls: bool,
) -> Vec<AuthAudit> {
    let max_pc = insns.last().map(|i| i.pc).unwrap_or(0);
    let mut pc_to_idx: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::with_capacity(insns.len());
    for (i, insn) in insns.iter().enumerate() {
        pc_to_idx.insert(insn.pc, i);
    }

    const PROLOGUE: usize = 80; // slots
    const ARM_SCAN: usize = 200; // how far into the arm we look for the first internal call
    let mut out = Vec::with_capacity(dispatch.len());

    for e in dispatch {
        // Optionally follow the first internal call from the match arm to
        // the real handler body. The match-arm stub typically does:
        //   - extract variant fields from the Instruction enum
        //   - build an account-info slice
        //   - internal-call into the actual handler function
        //   - return
        // The real handler is the target of that first internal call.
        let effective_start_pc = if follow_calls {
            let Some(&arm_idx) = pc_to_idx.get(&e.target_pc) else { continue; };
            let mut resolved = e.target_pc;
            for step in 0..ARM_SCAN {
                let idx = arm_idx + step;
                if idx >= insns.len() { break; }
                let insn = &insns[idx];
                if insn.is_exit() { break; }
                if insn.is_internal_call() {
                    if let Some(target) = insn.call_target() {
                        resolved = target;
                    }
                    break;
                }
            }
            resolved
        } else {
            e.target_pc
        };

        let Some(&start_idx) = pc_to_idx.get(&effective_start_pc) else {
            continue;
        };

        let mut prologue_loads = 0usize;
        let mut prologue_branches = 0usize;
        let mut syscalls_before_branch = 0usize;
        let mut stores_before_branch = 0usize;
        let mut first_branch_slot: Option<usize> = None;
        let mut first_syscall_at: Option<usize> = None;
        let mut first_internal_call_at: Option<usize> = None;
        let mut saw_load_then_branch = false;
        let mut saw_load_at: Option<usize> = None;

        for step in 0..PROLOGUE {
            let idx = start_idx + step;
            if idx >= insns.len() { break; }
            let insn = &insns[idx];
            if insn.is_exit() { break; }

            if class_of(insn.opcode) == CLASS_LDX {
                prologue_loads += 1;
                saw_load_at = Some(step);
            }
            if insn.is_conditional_jump() {
                prologue_branches += 1;
                if first_branch_slot.is_none() {
                    first_branch_slot = Some(step);
                }
                // If we loaded earlier in the prologue and now branch, the
                // handler has at least attempted some sort of validation.
                if let Some(_) = saw_load_at {
                    saw_load_then_branch = true;
                }
            }
            if insn.is_syscall() {
                if first_syscall_at.is_none() {
                    first_syscall_at = Some(step);
                }
                if first_branch_slot.is_none() {
                    syscalls_before_branch += 1;
                }
            }
            if insn.is_internal_call() && first_internal_call_at.is_none() {
                first_internal_call_at = Some(step);
            }
            if class_of(insn.opcode) == CLASS_STX {
                if first_branch_slot.is_none() {
                    stores_before_branch += 1;
                }
            }
        }

        out.push(AuthAudit {
            tag: e.discriminator,
            name: percolator_tag_name(e.discriminator)
                .unwrap_or("<unknown>")
                .to_string(),
            pc_start: effective_start_pc,
            prologue_loads,
            prologue_branches,
            syscalls_before_any_branch: syscalls_before_branch,
            stores_before_any_branch: stores_before_branch,
            prologue_validates: saw_load_then_branch,
            first_syscall_at,
            first_internal_call_at,
        });
    }
    let _ = max_pc;

    out.sort_by_key(|r| r.tag);
    out
}
