// Per-handler analysis. For each dispatch entry, walk forward from the
// handler PC accumulating:
//   - approximate byte size (until `exit` in dominant linear trace)
//   - call count (internal + syscall)
//   - syscall count
//   - load/store count
//   - checked arithmetic operations (64-bit mul/div/mod/add/sub are
//     the common checked-math lowering — we count all of them and let
//     the human compare ratios)
//
// This walk is INTENTIONALLY NOT a full control-flow reachability
// analysis. It follows the linear extent of a handler (start PC →
// first `exit`) which for Rust match-arm compilations is a reasonable
// proxy for handler size. Cross-handler jumps back into shared helpers
// are expected; we don't try to discount them.

use serde::Serialize;
use crate::dispatch::{DispatchEntry, percolator_tag_name};
use crate::sbf::Insn;

#[derive(Debug, Clone, Serialize)]
pub struct HandlerReport {
    pub tag: u64,
    pub name: String,
    pub pc_start: usize,
    pub approx_size_bytes: usize,
    pub call_count: usize,
    pub syscall_count: usize,
    pub load_count: usize,
    pub store_count: usize,
    pub alu_count: usize,
    /// Most-frequent syscall hashes found in the handler, with counts.
    pub top_syscalls: Vec<(u32, usize)>,
}

pub fn analyze_handlers(insns: &[Insn], dispatch: &[DispatchEntry]) -> Vec<HandlerReport> {
    let mut out = Vec::with_capacity(dispatch.len());

    // Build pc-indexed view.
    let max_pc = insns.last().map(|i| i.pc).unwrap_or(0);
    let mut pc_to_idx: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::with_capacity(insns.len());
    for (i, insn) in insns.iter().enumerate() {
        pc_to_idx.insert(insn.pc, i);
    }

    for e in dispatch {
        let Some(&start_idx) = pc_to_idx.get(&e.target_pc) else {
            continue;
        };

        let mut end_idx = start_idx;
        let mut call_count = 0usize;
        let mut syscall_count = 0usize;
        let mut load_count = 0usize;
        let mut store_count = 0usize;
        let mut alu_count = 0usize;
        let mut syscall_hist: std::collections::HashMap<u32, usize> =
            std::collections::HashMap::new();

        // Walk forward until we hit `exit` or run out of instructions.
        // We pessimistically bail after a large number of slots to avoid
        // infinite walking through shared helper tails.
        const MAX_WALK: usize = 50_000;
        for step in 0..MAX_WALK {
            let idx = start_idx + step;
            if idx >= insns.len() { break; }
            end_idx = idx;
            let insn = &insns[idx];

            if insn.is_syscall() {
                syscall_count += 1;
                call_count += 1;
                *syscall_hist.entry(insn.imm as u32).or_insert(0) += 1;
            } else if insn.is_internal_call() {
                call_count += 1;
            } else if insn.is_load() {
                load_count += 1;
            } else if insn.is_store() {
                store_count += 1;
            } else if insn.is_alu() {
                alu_count += 1;
            }

            if insn.is_exit() { break; }
        }

        let pc_end = insns.get(end_idx).map(|i| i.pc).unwrap_or(max_pc);
        let size_bytes = (pc_end - e.target_pc + 1) * 8;

        let mut top_syscalls: Vec<(u32, usize)> = syscall_hist.into_iter().collect();
        top_syscalls.sort_by_key(|x| std::cmp::Reverse(x.1));
        top_syscalls.truncate(5);

        out.push(HandlerReport {
            tag: e.discriminator,
            name: percolator_tag_name(e.discriminator)
                .unwrap_or("<unknown>")
                .to_string(),
            pc_start: e.target_pc,
            approx_size_bytes: size_bytes,
            call_count,
            syscall_count,
            load_count,
            store_count,
            alu_count,
            top_syscalls,
        });
    }

    out.sort_by_key(|r| r.tag);
    out
}
