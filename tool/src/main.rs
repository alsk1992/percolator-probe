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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Info { binary } => cmd_info(&binary),
        Cmd::Dispatch { binary, json } => cmd_dispatch(&binary, json.as_deref()),
        Cmd::Handlers { binary, json } => cmd_handlers(&binary, json.as_deref()),
    }
}

fn load_elf(path: &std::path::Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let elf = Elf::parse(&bytes).with_context(|| "parsing ELF")?;
    // Find .text section
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
    Ok((bytes, text_bytes))
}

fn cmd_info(path: &std::path::Path) -> Result<()> {
    let (bytes, text) = load_elf(path)?;
    let elf = Elf::parse(&bytes)?;
    let hash = Sha256::digest(&bytes);

    println!("file          : {}", path.display());
    println!("file_size     : {} bytes", bytes.len());
    println!("file_sha256   : {}", hex::encode(hash));
    println!("e_machine     : 0x{:04x} (SBF = 0x0107)", elf.header.e_machine);
    println!("e_type        : 0x{:04x}", elf.header.e_type);
    println!("e_entry       : 0x{:x}", elf.header.e_entry);
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
    let (_bytes, text) = load_elf(path)?;
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
            "  tag={:3} (0x{:02x}) {:32} → pc=0x{:08x}",
            e.discriminator, e.discriminator, name, e.target_pc * 8
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
                "  discriminator=0x{:x} @ src_pc=0x{:x}",
                e.discriminator,
                e.source_pc * 8
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
    let (_bytes, text) = load_elf(path)?;
    let insns = sbf::decode_text(&text);
    let dispatch = dispatch::find_dispatch(&insns);

    let reports = report::analyze_handlers(&insns, &dispatch);
    println!("handler inventory (N={}):\n", reports.len());
    println!(
        "{:>4} {:32} {:>8} {:>8} {:>6} {:>6}",
        "tag", "name", "pc_start", "size_b", "calls", "syscal"
    );
    for r in &reports {
        println!(
            "0x{:02x} {:32} 0x{:06x} {:>8} {:>6} {:>6}",
            r.tag,
            r.name,
            r.pc_start * 8,
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
