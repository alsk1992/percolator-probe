// percolator-re — reverse-engineering harness for immutable Solana programs
// with formal-verification claims.
//
// Anti-thesis of skimmode: skimmode hunts ABANDONED programs with
// authorization gaps. This tool targets LIVE HARDENED programs and
// looks for things Kani-proofs can't model:
//   - Compiled ≠ intended (compiler artefacts, inlining, dead code)
//   - Dispatch table integrity
//   - CPI graph shape — who can re-enter whom, through which path
//   - Arithmetic operation inventory (checked vs unchecked)
//   - Sysvar access audit
//   - Authority-check presence per handler

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use goblin::elf::Elf;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

mod sbf;
mod dispatch;
mod report;
mod audit;
mod bst;

#[derive(Parser)]
#[command(name = "percolator-re")]
#[command(about = "Reverse-engineer immutable Solana program binaries")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print ELF header summary + .text size + SHA-256 of ELF
    Info {
        /// Path to .so file
        binary: PathBuf,
    },

    /// Extract and print the instruction dispatch table by scanning
    /// `ldw ... r<X>, imm` + `jeq/jne` patterns against a discriminator
    /// register. For Solana programs built around
    /// `Instruction::try_from(first_byte)` the dispatch is a cascade of
    /// `jeq imm, target` on r0 or r1 — this walks the cascade.
    Dispatch {
        binary: PathBuf,
        /// Optional JSON output path
        #[arg(long)]
        json: Option<PathBuf>,
    },

    /// For each handler identified from the dispatch map, emit an
    /// inventory: (offset, size, calls, syscalls invoked).
    Handlers {
        binary: PathBuf,
        #[arg(long)]
        json: Option<PathBuf>,
    },

    /// Audit each handler's prologue for evidence of input validation
    /// (load-then-branch pattern). Handlers reaching syscalls/stores
    /// without a preceding branch are flagged for manual review.
    AuthAudit {
        binary: PathBuf,
        #[arg(long)]
        json: Option<PathBuf>,
        /// Follow the first internal call from each match-arm to the
        /// real handler body before auditing. Default: true.
        #[arg(long, default_value_t = true)]
        follow_calls: bool,
    },

    /// Disassemble N instructions starting at the given PC (hex byte
    /// offset). Useful for manual inspection of a handler prologue.
    Disasm {
        binary: PathBuf,
        /// Start PC in bytes (e.g., `0x525b8`).
        #[arg(long)]
        pc: String,
        /// Number of instructions to decode.
        #[arg(long, default_value_t = 30)]
        n: usize,
    },

    /// Find and parse the BST-style dispatcher at the deserializer
    /// entry. Emits (tag → arm_body_vaddr, r6_encoding) for each leaf.
    BstDispatch {
        binary: PathBuf,
        #[arg(long)]
        json: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Info { binary } => cmd_info(&binary),
        Cmd::Dispatch { binary, json } => cmd_dispatch(&binary, json.as_deref()),
        Cmd::Handlers { binary, json } => cmd_handlers(&binary, json.as_deref()),
        Cmd::AuthAudit { binary, json, follow_calls } => {
            cmd_auth_audit(&binary, json.as_deref(), follow_calls)
        }
        Cmd::Disasm { binary, pc, n } => cmd_disasm(&binary, &pc, n),
        Cmd::BstDispatch { binary, json } => cmd_bst_dispatch(&binary, json.as_deref()),
    }
}

fn cmd_bst_dispatch(path: &std::path::Path, json_out: Option<&std::path::Path>) -> Result<()> {
    let (_bytes, text, text_vaddr) = load_elf(path)?;
    let insns = sbf::decode_text(&text);

    let Some(root_pc) = bst::find_dispatcher_root(&insns) else {
        println!("BST dispatcher root not found — is this the right binary?");
        return Ok(());
    };
    println!(
        "BST dispatcher root at slot {} (vaddr 0x{:x})",
        root_pc,
        slot_to_vaddr(root_pc, text_vaddr)
    );

    // First try the BST walker. If it misses many tags, fall back to
    // the direct r6-enumeration which scans for `lddw r6, (tag+1)<<32`
    // patterns in a PC window around the dispatcher.
    let bst_entries = bst::walk_bst(&insns, root_pc);
    let window_start = root_pc;
    let window_end = root_pc + 600; // dispatcher region
    let r6_entries = bst::enumerate_r6_arms(&insns, window_start, window_end);

    // Merge — use the union (r6 has more coverage because defaults are implicit).
    let mut combined: std::collections::BTreeMap<u64, usize> =
        bst_entries.iter().map(|e| (e.tag, e.arm_body_pc)).collect();
    for e in &r6_entries {
        combined.entry(e.tag).or_insert(e.arm_body_pc);
    }

    let entries: Vec<bst::BstDispatchEntry> = combined
        .into_iter()
        .map(|(tag, arm_body_pc)| bst::BstDispatchEntry { tag, arm_body_pc })
        .collect();

    println!("\nBST walker: {} tags, r6 enumeration: {} tags, union: {} tags",
        bst_entries.len(), r6_entries.len(), entries.len());
    println!("Leaf entries:");
    println!(
        "{:>4} {:32} {:>10} {:>20}",
        "tag", "name", "arm_vaddr", "r6_encoding"
    );
    println!("{}", "-".repeat(70));

    #[derive(serde::Serialize)]
    struct Out {
        tag: u64,
        name: String,
        arm_vaddr: u64,
        r6_encoding: Option<u64>,
    }

    let mut rows = Vec::with_capacity(entries.len());
    for e in &entries {
        let r6 = bst::extract_arm_r6_encoding(&insns, e.arm_body_pc);
        let vaddr = slot_to_vaddr(e.arm_body_pc, text_vaddr);
        let name = dispatch::percolator_tag_name(e.tag)
            .unwrap_or("<unknown>")
            .to_string();
        println!(
            "{:>4} {:32} 0x{:08x} {}",
            e.tag,
            name,
            vaddr,
            r6.map(|v| format!("0x{:x}", v)).unwrap_or_else(|| "-".to_string())
        );
        rows.push(Out {
            tag: e.tag,
            name,
            arm_vaddr: vaddr,
            r6_encoding: r6,
        });
    }

    // Coverage check.
    let found: std::collections::BTreeSet<u64> = entries.iter().map(|e| e.tag).collect();
    let expected: Vec<u64> = (0..=32)
        .filter(|t| dispatch::is_valid_source_tag(*t as u64))
        .map(|t| t as u64)
        .collect();
    let missing: Vec<u64> = expected.iter().copied().filter(|t| !found.contains(t)).collect();
    let extra: Vec<u64> = entries
        .iter()
        .map(|e| e.tag)
        .filter(|t| !dispatch::is_valid_source_tag(*t))
        .collect();

    if missing.is_empty() {
        println!("\n[OK] all 27 source-valid tags present in BST");
    } else {
        println!("\n[MISSING from BST] tags: {:?}", missing);
    }
    if !extra.is_empty() {
        println!("[EXTRA in BST (not source-valid)] tags: {:?}", extra);
    }

    if let Some(out) = json_out {
        fs::write(out, serde_json::to_string_pretty(&rows)?)?;
        println!("\nJSON written to {}", out.display());
    }
    Ok(())
}

fn parse_hex(s: &str) -> Result<usize> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    Ok(usize::from_str_radix(s, 16).with_context(|| format!("parsing hex pc: {s}"))?)
}

fn cmd_disasm(path: &std::path::Path, pc_str: &str, n: usize) -> Result<()> {
    let (_bytes, text, text_vaddr) = load_elf(path)?;
    let insns = sbf::decode_text(&text);
    let vaddr = parse_hex(pc_str)? as u64;
    let target_slot = vaddr_to_slot(vaddr, text_vaddr)
        .with_context(|| format!("vaddr 0x{:x} is not in .text (base 0x{:x})", vaddr, text_vaddr))?;
    let start_idx = insns
        .iter()
        .position(|i| i.pc == target_slot)
        .with_context(|| format!("no instruction at vaddr=0x{:x} (slot {})", vaddr, target_slot))?;

    println!("disasm @ vaddr=0x{:x} (.text slot {}, {} instructions):", vaddr, target_slot, n);
    for step in 0..n {
        let idx = start_idx + step;
        if idx >= insns.len() { break; }
        let insn = &insns[idx];
        let abs_vaddr = slot_to_vaddr(insn.pc, text_vaddr);
        let marker = if insn.is_exit() {
            " <exit>"
        } else if insn.is_syscall() {
            " <syscall>"
        } else if insn.is_internal_call() {
            " <call>"
        } else if insn.is_conditional_jump() {
            " <jcc>"
        } else if insn.is_unconditional_jump() {
            " <ja>"
        } else {
            ""
        };
        // For calls + jumps, compute the absolute target vaddr.
        let target_annot = if insn.is_internal_call() {
            insn.call_target()
                .map(|t| format!("  → 0x{:x}", slot_to_vaddr(t, text_vaddr)))
                .unwrap_or_default()
        } else if let Some(t) = insn.jump_target() {
            if t >= 0 {
                format!("  → 0x{:x}", slot_to_vaddr(t as usize, text_vaddr))
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        println!("  0x{:06x}  {}{}{}", abs_vaddr, insn, marker, target_annot);
        if insn.is_exit() { break; }
    }
    Ok(())
}

fn cmd_auth_audit(
    path: &std::path::Path,
    json_out: Option<&std::path::Path>,
    follow_calls: bool,
) -> Result<()> {
    let (_bytes, text, text_vaddr) = load_elf(path)?;
    let insns = sbf::decode_text(&text);
    let dispatch = dispatch::find_dispatch(&insns);
    // Only audit source-valid tags.
    let dispatch: Vec<_> = dispatch
        .into_iter()
        .filter(|e| dispatch::is_valid_source_tag(e.discriminator))
        .collect();
    let audits = audit::audit_handlers(&insns, &dispatch, follow_calls);

    println!(
        "auth-audit over {} source-valid handlers. follow_calls={}. PROLOGUE WINDOW = 80 slots.\n",
        audits.len(), follow_calls
    );
    println!(
        "{:>4} {:28} {:>4} {:>4} {:>6} {:>6} {:>6} {:>8}",
        "tag", "name", "ldx", "br", "syB", "stB", "vldat", "firstSC"
    );
    println!("{}", "-".repeat(80));
    for a in &audits {
        let valid_mark = if a.prologue_validates { " yes  " } else { "  NO  " };
        println!(
            "{:4} {:28} vaddr=0x{:06x} {:>4} {:>4} {:>6} {:>6} {:>6} {:>8}",
            a.tag,
            a.name,
            slot_to_vaddr(a.pc_start, text_vaddr),
            a.prologue_loads,
            a.prologue_branches,
            a.syscalls_before_any_branch,
            a.stores_before_any_branch,
            valid_mark,
            a.first_syscall_at
                .map(|s| format!("+{}", s))
                .unwrap_or_else(|| "-".to_string())
        );
    }

    println!("\nFlagged handlers (no load+branch in prologue):");
    let flagged: Vec<_> = audits.iter().filter(|a| !a.prologue_validates).collect();
    if flagged.is_empty() {
        println!("  (none — every handler shows at least one load+branch validation)");
    } else {
        for a in flagged {
            println!(
                "  tag={:3} {:28} vaddr=0x{:x}  loads={} branches={}",
                a.tag,
                a.name,
                slot_to_vaddr(a.pc_start, text_vaddr),
                a.prologue_loads,
                a.prologue_branches
            );
        }
    }

    println!("\nHandlers with syscall or store BEFORE any branch (deep red flag):");
    let red: Vec<_> = audits
        .iter()
        .filter(|a| a.syscalls_before_any_branch > 0 || a.stores_before_any_branch > 0)
        .collect();
    if red.is_empty() {
        println!("  (none — every handler branches at least once before mutating)");
    } else {
        for a in red {
            println!(
                "  tag={:3} {:28} syB={} stB={}",
                a.tag, a.name, a.syscalls_before_any_branch, a.stores_before_any_branch
            );
        }
    }

    if let Some(out) = json_out {
        fs::write(out, serde_json::to_string_pretty(&audits)?)?;
        println!("\nJSON written to {}", out.display());
    }

    Ok(())
}

/// Returns (full file bytes, .text bytes, .text base virtual address).
/// PCs throughout the tool are VIRTUAL ADDRESSES so they line up with
/// dynsym entries and source-level debugging.
fn load_elf(path: &std::path::Path) -> Result<(Vec<u8>, Vec<u8>, u64)> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let elf = Elf::parse(&bytes).with_context(|| "parsing ELF")?;
    let text = elf
        .section_headers
        .iter()
        .find(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map(|n| n == ".text")
                .unwrap_or(false)
        })
        .with_context(|| "no .text section")?;
    let start = text.sh_offset as usize;
    let end = start + text.sh_size as usize;
    anyhow::ensure!(end <= bytes.len(), ".text extends past file");
    let text_bytes = bytes[start..end].to_vec();
    let text_vaddr = text.sh_addr;
    Ok((bytes, text_bytes, text_vaddr))
}

/// Convert slot index within .text to virtual address.
fn slot_to_vaddr(slot: usize, text_vaddr: u64) -> u64 {
    text_vaddr + (slot as u64) * 8
}

/// Convert virtual address to slot index within .text.
fn vaddr_to_slot(vaddr: u64, text_vaddr: u64) -> Option<usize> {
    if vaddr < text_vaddr { return None; }
    let byte_off = vaddr - text_vaddr;
    if byte_off % 8 != 0 { return None; }
    Some((byte_off / 8) as usize)
}

fn cmd_info(path: &std::path::Path) -> Result<()> {
    let (bytes, text, text_vaddr) = load_elf(path)?;
    let elf = Elf::parse(&bytes)?;
    let hash = Sha256::digest(&bytes);

    println!("file          : {}", path.display());
    println!("file_size     : {} bytes", bytes.len());
    println!("file_sha256   : {}", hex::encode(hash));
    println!("e_machine     : 0x{:04x} (SBF = 0x0107)", elf.header.e_machine);
    println!("e_type        : 0x{:04x}", elf.header.e_type);
    println!("e_entry       : 0x{:x} (virtual)", elf.header.e_entry);
    println!(".text vaddr   : 0x{:x}", text_vaddr);
    println!(".text size    : {} bytes", text.len());
    println!(".text sha256  : {}", hex::encode(Sha256::digest(&text)));
    println!("section count : {}", elf.section_headers.len());
    for sh in elf.section_headers.iter() {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            println!(
                "  {:20} offset=0x{:08x} size={:>8} flags=0x{:x}",
                name, sh.sh_offset, sh.sh_size, sh.sh_flags
            );
        }
    }
    Ok(())
}

fn cmd_dispatch(path: &std::path::Path, json_out: Option<&std::path::Path>) -> Result<()> {
    let (_bytes, text, text_vaddr) = load_elf(path)?;
    let insns = sbf::decode_text(&text);

    println!("decoded {} SBF instructions from .text", insns.len());

    let entries = dispatch::find_dispatch(&insns);
    let valid: Vec<_> = entries
        .iter()
        .filter(|e| dispatch::is_valid_source_tag(e.discriminator))
        .collect();
    let invalid: Vec<_> = entries
        .iter()
        .filter(|e| !dispatch::is_valid_source_tag(e.discriminator))
        .collect();

    println!(
        "\ndispatch entries — {} valid, {} heuristic false-positives (jcc against imm not in source decoder)",
        valid.len(),
        invalid.len()
    );
    println!("\n[VALID — accepted by source decoder at percolator.rs:1464]");
    for e in &valid {
        let name = dispatch::percolator_tag_name(e.discriminator).unwrap();
        println!(
            "  tag={:3} (0x{:02x}) {:32} → vaddr=0x{:08x}",
            e.discriminator, e.discriminator, name,
            slot_to_vaddr(e.target_pc, text_vaddr),
        );
    }

    // Cross-check completeness. Source has 27 valid tags.
    let expected_tags: Vec<u64> = (0..=32)
        .filter(|t| dispatch::is_valid_source_tag(*t as u64))
        .map(|t| t as u64)
        .collect();
    let found_set: std::collections::BTreeSet<u64> =
        valid.iter().map(|e| e.discriminator).collect();
    let missing: Vec<u64> = expected_tags
        .iter()
        .copied()
        .filter(|t| !found_set.contains(t))
        .collect();
    if !missing.is_empty() {
        println!("\n[MISSING from binary dispatch — not detected by heuristic]");
        for t in &missing {
            println!(
                "  tag={:3} (0x{:02x}) {}",
                t,
                t,
                dispatch::percolator_tag_name(*t).unwrap()
            );
        }
    } else {
        println!("\n[OK] all 27 source-valid tags detected in binary.");
    }

    if !invalid.is_empty() {
        println!(
            "\n[FALSE POSITIVES — {} unlikely-dispatch jcc sites, filtered]",
            invalid.len()
        );
        for e in &invalid {
            println!(
                "  discriminator=0x{:x} @ src_vaddr=0x{:x}",
                e.discriminator,
                slot_to_vaddr(e.source_pc, text_vaddr),
            );
        }
    }

    if let Some(out) = json_out {
        let j = serde_json::to_string_pretty(&entries)?;
        fs::write(out, j)?;
        println!("\nJSON written to {}", out.display());
    }
    Ok(())
}

fn cmd_handlers(path: &std::path::Path, json_out: Option<&std::path::Path>) -> Result<()> {
    let (_bytes, text, text_vaddr) = load_elf(path)?;
    let insns = sbf::decode_text(&text);
    let dispatch = dispatch::find_dispatch(&insns);

    let reports = report::analyze_handlers(&insns, &dispatch);
    println!("handler inventory (N={}):\n", reports.len());
    println!(
        "{:>4} {:32} {:>10} {:>8} {:>6} {:>6}",
        "tag", "name", "vaddr", "size_b", "calls", "syscal"
    );
    for r in &reports {
        println!(
            "0x{:02x} {:32} 0x{:08x} {:>8} {:>6} {:>6}",
            r.tag,
            r.name,
            slot_to_vaddr(r.pc_start, text_vaddr),
            r.approx_size_bytes,
            r.call_count,
            r.syscall_count,
        );
    }

    if let Some(out) = json_out {
        let j = serde_json::to_string_pretty(&reports)?;
        fs::write(out, j)?;
        println!("\nJSON written to {}", out.display());
    }
    Ok(())
}
