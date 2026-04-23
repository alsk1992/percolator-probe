// BST dispatch extractor.
//
// The real Percolator dispatcher at vaddr 0x51b70 compiles to a
// balanced binary search tree of `jsgt/jeq` on a tag register,
// culminating in leaf blocks that set `r6` to an encoded handler
// identifier and jump to a common exit. This is what rustc emits
// for a `match` over a dense integer range with many arms.
//
// Algorithm:
//   1. Find the dispatcher prologue signature:
//        ldxdw r2, [r1+0]
//        lddw  r4, 0x8000000000000000
//        mov64 r3, r2
//        xor64 r3, r4
//        jlt   r3, <MAX_TAG>, +1
//        mov64 r3, <INVALID_TAG>
//   2. From the first jsgt after that prologue, walk the BST:
//      each node is `jsgt r3, <mid>, +N` (split) or
//      `jeq r3, <value>, +N` (leaf branch-taken → arm).
//      Fall-through of a jsgt = left subtree; taken = right.
//   3. Collect (tag_value → arm_body_vaddr) pairs. Arm bodies are
//      the targets of `jeq r3, tag, +N` leaves and fall-through
//      of the last `jeq` in a leaf cluster.
//
// This module doesn't execute the BST — it just parses it
// statically.

use serde::Serialize;
use crate::sbf::{Insn, CLASS_JMP, CLASS_JMP32, JMP_JEQ, JMP_JSGT, JMP_JLT, JMP_JA,
                  alu_or_jmp_op, class_of, src_bit, SRC_K};

#[derive(Debug, Clone, Serialize)]
pub struct BstDispatchEntry {
    pub tag: u64,
    /// The PC (slot) reached when this tag matches. This is the arm
    /// body — typically a short block that sets r6 and `ja`s to the
    /// common exit. The caller's next job is to parse the arm body.
    pub arm_body_pc: usize,
}

/// Find the main dispatcher by pattern-matching the prologue.
/// Returns the slot index where the first `jsgt` (root of BST) sits.
///
/// Signature required (in order, allowing arbitrary intermediate
/// instructions within `WINDOW` slots):
///   A. ldxdw r?, [r1+0]                          (class 1, size DW, ldx-mem, off=0, src=r1)
///   B. lddw r?, 0x8000_0000_0000_0000
///   C. xor64 rX, rY  where rX is the register later used by the BST
///   D. jlt rX, <imm>, +1                         (bounds check — imm is the max valid tag + 1)
///   E. mov64 rX, <imm>                           (default fall-through)
/// F. jsgt rX, <imm>, +N                          ← root of BST
///
/// This exact sequence is distinctive enough to only match the real
/// dispatcher, not unrelated i64::MIN uses elsewhere.
pub fn find_dispatcher_root(insns: &[Insn]) -> Option<usize> {
    use crate::sbf::{CLASS_LDX, MODE_MEM, SIZE_DW, ALU_XOR, ALU_MOV, CLASS_ALU64};
    const WINDOW: usize = 20;
    let beacon = 0x8000_0000_0000_0000u64 as i64;

    for (i, insn_a) in insns.iter().enumerate() {
        // A: ldxdw r?, [r1+0]
        if class_of(insn_a.opcode) != CLASS_LDX { continue; }
        if (insn_a.opcode & 0x18) != SIZE_DW { continue; }
        if (insn_a.opcode & 0xE0) != MODE_MEM { continue; }
        if insn_a.src != 1 || insn_a.off != 0 { continue; }

        // B: lddw with beacon value, within WINDOW
        let mut saw_beacon = false;
        for j in 1..WINDOW {
            let idx = i + j;
            if idx >= insns.len() { break; }
            if insns[idx].is_lddw && insns[idx].imm == beacon {
                saw_beacon = true;
                break;
            }
        }
        if !saw_beacon { continue; }

        // C: xor64 within WINDOW
        let mut xor_reg: Option<u8> = None;
        for j in 1..WINDOW {
            let idx = i + j;
            if idx >= insns.len() { break; }
            let n = &insns[idx];
            if class_of(n.opcode) == CLASS_ALU64 && alu_or_jmp_op(n.opcode) == ALU_XOR {
                xor_reg = Some(n.dst);
                break;
            }
        }
        let Some(xreg) = xor_reg else { continue; };

        // D: jlt of same reg
        let mut saw_jlt = false;
        for j in 1..WINDOW {
            let idx = i + j;
            if idx >= insns.len() { break; }
            let n = &insns[idx];
            if (class_of(n.opcode) == CLASS_JMP || class_of(n.opcode) == CLASS_JMP32)
                && alu_or_jmp_op(n.opcode) == JMP_JLT
                && n.dst == xreg
            {
                saw_jlt = true;
                break;
            }
        }
        if !saw_jlt { continue; }

        // E: mov64 of same reg (default)
        let mut saw_mov = false;
        for j in 1..WINDOW {
            let idx = i + j;
            if idx >= insns.len() { break; }
            let n = &insns[idx];
            if class_of(n.opcode) == CLASS_ALU64
                && alu_or_jmp_op(n.opcode) == ALU_MOV
                && n.dst == xreg
            {
                saw_mov = true;
                break;
            }
        }
        if !saw_mov { continue; }

        // F: first jsgt on xreg = BST root
        for j in 1..WINDOW + 10 {
            let idx = i + j;
            if idx >= insns.len() { break; }
            let n = &insns[idx];
            if (class_of(n.opcode) == CLASS_JMP || class_of(n.opcode) == CLASS_JMP32)
                && alu_or_jmp_op(n.opcode) == JMP_JSGT
                && n.dst == xreg
            {
                return Some(n.pc);
            }
        }
    }
    None
}

/// Recursively walk the BST starting at `root_pc` and collect leaves.
/// The register under test is inferred from the first jcc at root.
pub fn walk_bst(insns: &[Insn], root_pc: usize) -> Vec<BstDispatchEntry> {
    let mut out = Vec::new();
    let pc_to_idx: std::collections::HashMap<usize, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, x)| (x.pc, i))
        .collect();

    // Infer test register from first instruction at root.
    let root_insn = match pc_to_idx.get(&root_pc).and_then(|&i| insns.get(i)) {
        Some(x) => x,
        None => return out,
    };
    let test_reg = root_insn.dst;

    let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut stack: Vec<(usize, Option<(u64, bool)>, Option<(u64, bool)>)> = vec![(root_pc, None, None)];
    // Triple = (node_pc, lo_constraint, hi_constraint)
    //   lo = (value, inclusive) means r >= value or r > value-1
    //   hi = (value, inclusive) means r <= value

    while let Some((pc, _lo, _hi)) = stack.pop() {
        if !visited.insert(pc) { continue; }
        let Some(&idx) = pc_to_idx.get(&pc) else { continue; };
        let insn = &insns[idx];

        let class = class_of(insn.opcode);
        if class != CLASS_JMP && class != CLASS_JMP32 {
            // Not a BST node — stop walking this branch.
            continue;
        }
        if src_bit(insn.opcode) != SRC_K { continue; }
        if insn.dst != test_reg { continue; }

        let op = alu_or_jmp_op(insn.opcode);
        let Some(target_pc_i) = insn.jump_target() else { continue; };
        if target_pc_i < 0 { continue; }
        let taken_target = target_pc_i as usize;
        let fall_through = pc + 1;

        match op {
            JMP_JSGT => {
                // taken = right subtree (r > imm)
                // fall-through = left subtree (r <= imm)
                stack.push((taken_target, None, None));
                stack.push((fall_through, None, None));
            }
            JMP_JLT => {
                stack.push((taken_target, None, None));
                stack.push((fall_through, None, None));
            }
            JMP_JEQ => {
                // Leaf: taken = arm body for tag=imm.
                out.push(BstDispatchEntry {
                    tag: insn.imm as u64,
                    arm_body_pc: taken_target,
                });
                // Fall-through continues the tree walk.
                stack.push((fall_through, None, None));
            }
            JMP_JA => {
                // Skip unconditional jumps — they chain leaves to an arm
                // epilogue.
                if let Some(t) = insn.jump_target() {
                    if t >= 0 { stack.push((t as usize, None, None)); }
                }
            }
            _ => {
                // Other jcc — probably not part of the BST.
            }
        }
    }

    out.sort_by_key(|e| e.tag);
    out.dedup_by_key(|e| e.tag);
    out
}

/// For a BST leaf arm body, extract the handler-code encoding.
/// The pattern is typically `lddw r6, <tag << 32>` followed by `ja
/// <common_exit>`. Returns the immediate loaded into r6, which tells
/// us the dispatch identifier the rest of the entrypoint uses.
pub fn extract_arm_r6_encoding(insns: &[Insn], arm_pc: usize) -> Option<u64> {
    let pc_to_idx: std::collections::HashMap<usize, usize> = insns
        .iter()
        .enumerate()
        .map(|(i, x)| (x.pc, i))
        .collect();
    let idx = *pc_to_idx.get(&arm_pc)?;
    for step in 0..8 {
        let i = idx + step;
        if i >= insns.len() { return None; }
        let insn = &insns[i];
        if insn.is_lddw && insn.dst == 6 {
            return Some(insn.imm as u64);
        }
        if insn.is_exit() { return None; }
    }
    None
}

/// Alternative extraction: enumerate every `lddw r6, <(tag+1) << 32>`
/// instruction in a PC window and decode the tag. The dispatcher's
/// per-arm convention is that r6 is set to (tag+1) << 32 right before
/// jumping to the common exit, so each such LDDW maps 1-to-1 to a tag.
///
/// Returns (tag, arm_body_pc, r6_encoding) tuples. The arm_body_pc is
/// the PC of the LDDW itself (not the jeq that targets it) — this is
/// what the dispatcher sets r6 on before the common-exit jump.
pub fn enumerate_r6_arms(
    insns: &[Insn],
    search_start: usize,
    search_end: usize,
) -> Vec<BstDispatchEntry> {
    let mut out = Vec::new();
    for insn in insns.iter() {
        if insn.pc < search_start || insn.pc > search_end { continue; }
        if !insn.is_lddw { continue; }
        if insn.dst != 6 { continue; }
        // Encoded as (tag+1) << 32. Extract.
        let enc = insn.imm as u64;
        if enc & 0xffff_ffff != 0 { continue; }            // low 32 must be zero
        let high = enc >> 32;
        if high == 0 { continue; }                          // tag+1 > 0
        if high > 64 { continue; }                          // sanity: tags are small
        let tag = high - 1;
        out.push(BstDispatchEntry {
            tag,
            arm_body_pc: insn.pc,
        });
    }
    out.sort_by_key(|e| e.tag);
    out.dedup_by_key(|e| e.tag);
    out
}
