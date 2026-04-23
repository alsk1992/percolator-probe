// SBF (Solana BPF) instruction decoder — full opcode coverage.
//
// SBF is a fork of eBPF. Each instruction is 8 bytes; LDDW occupies 16
// bytes (two slots). Opcode encoding:
//
//   bits 0-2: class (LD, LDX, ST, STX, ALU, JMP, JMP32, ALU64)
//   bits 3-4: size  (W=0, H=1, B=2, DW=3)  — for load/store
//   bits 5-7: mode  (IMM=0, ABS=1, IND=2, MEM=3, LEN=4, MSH=5, XADD=6, ATOMIC=6 in SBF)
//
//   For ALU / JMP classes:
//     bit 3  : source (K=0 immediate, X=1 register)
//     bits 4-7: op code (ADD/SUB/MUL/... or JEQ/JGT/...)
//
// SBF-specific:
//   - LDDW (class=LD, size=DW, mode=IMM) — 16-byte instruction with
//     second half carrying high 32 bits of 64-bit immediate
//   - CALL (class=JMP, op=CALL): src=0 = syscall via hash in imm;
//                                src=1 = internal call by rel offset;
//                                src=2 = internal call by absolute target
//   - JMP32 class (0x06) = 32-bit comparison variants of JMP
//
// References:
//   https://docs.kernel.org/bpf/instruction-set.html
//   https://github.com/solana-labs/rbpf/blob/main/src/ebpf.rs
//   https://github.com/solana-labs/solana/blob/master/sdk/program/src/bpf_loader.rs

use serde::Serialize;
use std::fmt;

// ===== Class constants =====
pub const CLASS_LD:    u8 = 0x00;
pub const CLASS_LDX:   u8 = 0x01;
pub const CLASS_ST:    u8 = 0x02;
pub const CLASS_STX:   u8 = 0x03;
pub const CLASS_ALU:   u8 = 0x04;
pub const CLASS_JMP:   u8 = 0x05;
pub const CLASS_JMP32: u8 = 0x06;
pub const CLASS_ALU64: u8 = 0x07;

// ===== Size constants (class LD/LDX/ST/STX) =====
pub const SIZE_W:  u8 = 0x00; // 32-bit word
pub const SIZE_H:  u8 = 0x08; // 16-bit half
pub const SIZE_B:  u8 = 0x10; // 8-bit byte
pub const SIZE_DW: u8 = 0x18; // 64-bit doubleword

// ===== Mode constants =====
pub const MODE_IMM:    u8 = 0x00;
pub const MODE_ABS:    u8 = 0x20;
pub const MODE_IND:    u8 = 0x40;
pub const MODE_MEM:    u8 = 0x60;
pub const MODE_ATOMIC: u8 = 0xC0;

// ===== ALU / JMP op codes (in high nibble, shifted >> 4) =====
pub const ALU_ADD: u8 = 0x0;
pub const ALU_SUB: u8 = 0x1;
pub const ALU_MUL: u8 = 0x2;
pub const ALU_DIV: u8 = 0x3;
pub const ALU_OR:  u8 = 0x4;
pub const ALU_AND: u8 = 0x5;
pub const ALU_LSH: u8 = 0x6;
pub const ALU_RSH: u8 = 0x7;
pub const ALU_NEG: u8 = 0x8;
pub const ALU_MOD: u8 = 0x9;
pub const ALU_XOR: u8 = 0xA;
pub const ALU_MOV: u8 = 0xB;
pub const ALU_ARSH: u8 = 0xC;
pub const ALU_END:  u8 = 0xD;

pub const JMP_JA:   u8 = 0x0;
pub const JMP_JEQ:  u8 = 0x1;
pub const JMP_JGT:  u8 = 0x2;
pub const JMP_JGE:  u8 = 0x3;
pub const JMP_JSET: u8 = 0x4;
pub const JMP_JNE:  u8 = 0x5;
pub const JMP_JSGT: u8 = 0x6;
pub const JMP_JSGE: u8 = 0x7;
pub const JMP_CALL: u8 = 0x8;
pub const JMP_EXIT: u8 = 0x9;
pub const JMP_JLT:  u8 = 0xA;
pub const JMP_JLE:  u8 = 0xB;
pub const JMP_JSLT: u8 = 0xC;
pub const JMP_JSLE: u8 = 0xD;

// Source bit (ALU / JMP): 0 = immediate, 1 = register.
pub const SRC_K: u8 = 0x00;
pub const SRC_X: u8 = 0x08;

#[inline] pub fn class_of(op: u8) -> u8 { op & 0x07 }
#[inline] pub fn size_of(op: u8) -> u8  { op & 0x18 }
#[inline] pub fn mode_of(op: u8) -> u8  { op & 0xE0 }
#[inline] pub fn alu_or_jmp_op(op: u8) -> u8 { op >> 4 }
#[inline] pub fn src_bit(op: u8) -> u8 { op & SRC_X }

/// Decoded SBF instruction (one slot = 8 bytes, LDDW = two slots = 16 bytes).
#[derive(Debug, Clone, Serialize)]
pub struct Insn {
    /// Slot index (each slot is 8 bytes of raw bytecode).
    pub pc: usize,
    pub opcode: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    /// Immediate. For LDDW this holds the full 64-bit value; otherwise
    /// the i32 immediate zero-extended / sign-extended into i64 as
    /// appropriate for the operation.
    pub imm: i64,
    /// True iff this is LDDW (occupies 2 slots).
    pub is_lddw: bool,
}

impl Insn {
    pub fn class(&self) -> u8  { class_of(self.opcode) }
    pub fn size(&self) -> u8   { size_of(self.opcode) }
    pub fn mode(&self) -> u8   { mode_of(self.opcode) }
    pub fn op_high(&self) -> u8 { alu_or_jmp_op(self.opcode) }
    pub fn src_mode_bit(&self) -> u8 { src_bit(self.opcode) }

    /// Is this any jump-class instruction (JMP or JMP32)?
    pub fn is_jmp(&self) -> bool {
        matches!(self.class(), CLASS_JMP | CLASS_JMP32)
    }

    /// Is this a conditional jump (not JA, not CALL, not EXIT)?
    pub fn is_conditional_jump(&self) -> bool {
        self.is_jmp() && !matches!(self.op_high(), JMP_JA | JMP_CALL | JMP_EXIT)
    }

    /// Is this the unconditional jump?
    pub fn is_unconditional_jump(&self) -> bool {
        self.is_jmp() && self.op_high() == JMP_JA
    }

    /// For jump instructions: compute the target PC (next-slot based).
    /// Target = current-pc + 1 (fall-through) + off.
    pub fn jump_target(&self) -> Option<isize> {
        if self.is_jmp() && !matches!(self.op_high(), JMP_CALL | JMP_EXIT) {
            Some(self.pc as isize + 1 + self.off as isize)
        } else {
            None
        }
    }

    /// Syscall: CALL with src=0. Imm is the syscall hash.
    pub fn is_syscall(&self) -> bool {
        self.is_jmp() && self.op_high() == JMP_CALL && self.src == 0
    }

    /// Internal call: CALL with src=1 (relative) or src=2 (absolute).
    pub fn is_internal_call(&self) -> bool {
        self.is_jmp() && self.op_high() == JMP_CALL && (self.src == 1 || self.src == 2)
    }

    /// For internal calls, compute absolute target PC.
    pub fn call_target(&self) -> Option<usize> {
        if !self.is_internal_call() { return None; }
        match self.src {
            1 => {
                // Relative: target = pc + 1 + imm
                let t = self.pc as isize + 1 + self.imm as isize;
                if t >= 0 { Some(t as usize) } else { None }
            }
            2 => Some(self.imm as usize),
            _ => None,
        }
    }

    pub fn is_exit(&self) -> bool {
        self.is_jmp() && self.op_high() == JMP_EXIT
    }

    /// Load operations (LD/LDX class).
    pub fn is_load(&self) -> bool {
        matches!(self.class(), CLASS_LD | CLASS_LDX)
    }

    /// Store operations (ST/STX class).
    pub fn is_store(&self) -> bool {
        matches!(self.class(), CLASS_ST | CLASS_STX)
    }

    /// ALU operation (any width).
    pub fn is_alu(&self) -> bool {
        matches!(self.class(), CLASS_ALU | CLASS_ALU64)
    }
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_lddw {
            return write!(f, "lddw r{}, 0x{:x}", self.dst, self.imm as u64);
        }
        let mnem = mnemonic(self.opcode);
        let class = self.class();
        match class {
            CLASS_ALU | CLASS_ALU64 => {
                if self.src_mode_bit() == SRC_X {
                    write!(f, "{} r{}, r{}", mnem, self.dst, self.src)
                } else {
                    write!(f, "{} r{}, {}", mnem, self.dst, self.imm)
                }
            }
            CLASS_JMP | CLASS_JMP32 => {
                let op = self.op_high();
                if op == JMP_EXIT {
                    return write!(f, "exit");
                }
                if op == JMP_CALL {
                    if self.src == 0 {
                        return write!(f, "syscall 0x{:08x}", self.imm as u32);
                    }
                    return write!(f, "call +{} (abs src={})", self.imm, self.src);
                }
                if op == JMP_JA {
                    return write!(f, "ja +{}", self.off);
                }
                if self.src_mode_bit() == SRC_X {
                    write!(f, "{} r{}, r{}, +{}", mnem, self.dst, self.src, self.off)
                } else {
                    write!(f, "{} r{}, {}, +{}", mnem, self.dst, self.imm, self.off)
                }
            }
            CLASS_LD | CLASS_LDX => {
                if self.mode() == MODE_MEM {
                    write!(f, "{} r{}, [r{}{:+}]", mnem, self.dst, self.src, self.off)
                } else {
                    write!(f, "{} r{}, {}", mnem, self.dst, self.imm)
                }
            }
            CLASS_ST | CLASS_STX => {
                if self.src_mode_bit() == SRC_X || class == CLASS_STX {
                    write!(f, "{} [r{}{:+}], r{}", mnem, self.dst, self.off, self.src)
                } else {
                    write!(f, "{} [r{}{:+}], {}", mnem, self.dst, self.off, self.imm)
                }
            }
            _ => write!(f, "opcode=0x{:02x} dst=r{} src=r{} off={} imm={}",
                       self.opcode, self.dst, self.src, self.off, self.imm),
        }
    }
}

fn mnemonic(op: u8) -> &'static str {
    let class = class_of(op);
    match class {
        CLASS_LD | CLASS_LDX => match size_of(op) {
            SIZE_W  => "ldxw",
            SIZE_H  => "ldxh",
            SIZE_B  => "ldxb",
            SIZE_DW => if mode_of(op) == MODE_IMM { "lddw" } else { "ldxdw" },
            _ => "ld?",
        },
        CLASS_ST | CLASS_STX => match size_of(op) {
            SIZE_W  => if class == CLASS_STX { "stxw"  } else { "stw"  },
            SIZE_H  => if class == CLASS_STX { "stxh"  } else { "sth"  },
            SIZE_B  => if class == CLASS_STX { "stxb"  } else { "stb"  },
            SIZE_DW => if class == CLASS_STX { "stxdw" } else { "stdw" },
            _ => "st?",
        },
        CLASS_ALU | CLASS_ALU64 => {
            let op_h = alu_or_jmp_op(op);
            let w = if class == CLASS_ALU64 { "64" } else { "" };
            match op_h {
                ALU_ADD => if w == "64" { "add64"  } else { "add"  },
                ALU_SUB => if w == "64" { "sub64"  } else { "sub"  },
                ALU_MUL => if w == "64" { "mul64"  } else { "mul"  },
                ALU_DIV => if w == "64" { "div64"  } else { "div"  },
                ALU_OR  => if w == "64" { "or64"   } else { "or"   },
                ALU_AND => if w == "64" { "and64"  } else { "and"  },
                ALU_LSH => if w == "64" { "lsh64"  } else { "lsh"  },
                ALU_RSH => if w == "64" { "rsh64"  } else { "rsh"  },
                ALU_NEG => if w == "64" { "neg64"  } else { "neg"  },
                ALU_MOD => if w == "64" { "mod64"  } else { "mod"  },
                ALU_XOR => if w == "64" { "xor64"  } else { "xor"  },
                ALU_MOV => if w == "64" { "mov64"  } else { "mov"  },
                ALU_ARSH => if w == "64" { "arsh64" } else { "arsh" },
                ALU_END => "end",
                _ => "alu?",
            }
        },
        CLASS_JMP | CLASS_JMP32 => {
            let op_h = alu_or_jmp_op(op);
            let suff = if class == CLASS_JMP32 { "32" } else { "" };
            match op_h {
                JMP_JA   => "ja",
                JMP_JEQ  => if suff == "32" { "jeq32"  } else { "jeq"  },
                JMP_JGT  => if suff == "32" { "jgt32"  } else { "jgt"  },
                JMP_JGE  => if suff == "32" { "jge32"  } else { "jge"  },
                JMP_JSET => if suff == "32" { "jset32" } else { "jset" },
                JMP_JNE  => if suff == "32" { "jne32"  } else { "jne"  },
                JMP_JSGT => if suff == "32" { "jsgt32" } else { "jsgt" },
                JMP_JSGE => if suff == "32" { "jsge32" } else { "jsge" },
                JMP_CALL => "call",
                JMP_EXIT => "exit",
                JMP_JLT  => if suff == "32" { "jlt32"  } else { "jlt"  },
                JMP_JLE  => if suff == "32" { "jle32"  } else { "jle"  },
                JMP_JSLT => if suff == "32" { "jslt32" } else { "jslt" },
                JMP_JSLE => if suff == "32" { "jsle32" } else { "jsle" },
                _ => "jmp?",
            }
        },
        _ => "unk",
    }
}

/// Decode the entire .text section into a sequence of SBF instructions.
pub fn decode_text(text: &[u8]) -> Vec<Insn> {
    let mut out = Vec::with_capacity(text.len() / 8);
    let mut pc = 0usize;
    while pc * 8 + 8 <= text.len() {
        let base = pc * 8;
        let opcode = text[base];
        let regs = text[base + 1];
        let dst = regs & 0x0f;
        let src = (regs >> 4) & 0x0f;
        let off = i16::from_le_bytes(text[base + 2..base + 4].try_into().unwrap());
        let imm32 = i32::from_le_bytes(text[base + 4..base + 8].try_into().unwrap());

        // LDDW — class=LD, size=DW, mode=IMM → opcode 0x18
        if opcode == (CLASS_LD | SIZE_DW | MODE_IMM) && pc * 8 + 16 <= text.len() {
            let hi32 = i32::from_le_bytes(text[base + 12..base + 16].try_into().unwrap());
            let lo = imm32 as u32 as u64;
            let hi = hi32 as u32 as u64;
            let imm64 = ((hi << 32) | lo) as i64;
            out.push(Insn {
                pc,
                opcode,
                dst,
                src,
                off,
                imm: imm64,
                is_lddw: true,
            });
            pc += 2;
            continue;
        }

        // For ALU/JMP with BPF_K source, sign-extend imm32 into imm64.
        // For mem-ops, imm32 is also sign-extended (offset-like semantics).
        // LDDW handled above; other LD-class use imm32 zero-ext (not used here).
        let imm = imm32 as i64;

        out.push(Insn {
            pc,
            opcode,
            dst,
            src,
            off,
            imm,
            is_lddw: false,
        });
        pc += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_decodes() {
        // 0x95 = JMP class + EXIT
        let mut bytes = vec![0u8; 8];
        bytes[0] = 0x95;
        let v = decode_text(&bytes);
        assert_eq!(v.len(), 1);
        assert!(v[0].is_exit());
    }

    #[test]
    fn lddw_consumes_two_slots() {
        // LDDW r0, 0x0000_0001_dead_beef
        let mut bytes = vec![0u8; 16];
        bytes[0] = 0x18;
        bytes[1] = 0x00; // dst=0 src=0
        // low 32 = 0xdeadbeef
        bytes[4..8].copy_from_slice(&0xdead_beefi32.to_le_bytes());
        // high 32 = 0x00000001 (in slot 2)
        bytes[12..16].copy_from_slice(&1i32.to_le_bytes());
        let v = decode_text(&bytes);
        assert_eq!(v.len(), 1);
        assert!(v[0].is_lddw);
        assert_eq!(v[0].dst, 0);
        assert_eq!(v[0].imm as u64, 0x0000_0001_dead_beef);
    }

    #[test]
    fn jeq_target_computes() {
        // jeq r1, 5, +3  →  pc=0, off=3, target = 0 + 1 + 3 = 4
        let mut bytes = vec![0u8; 8];
        bytes[0] = 0x15; // JMP | JEQ | BPF_K
        bytes[1] = 0x01;
        bytes[2..4].copy_from_slice(&3i16.to_le_bytes());
        bytes[4..8].copy_from_slice(&5i32.to_le_bytes());
        let v = decode_text(&bytes);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].jump_target(), Some(4));
    }

    #[test]
    fn syscall_vs_internal_call() {
        let mut syscall = vec![0u8; 8];
        syscall[0] = 0x85;
        syscall[1] = 0x00; // src=0 -> syscall
        let s = &decode_text(&syscall)[0];
        assert!(s.is_syscall());
        assert!(!s.is_internal_call());

        let mut internal = vec![0u8; 8];
        internal[0] = 0x85;
        internal[1] = 0x10; // src=1 -> internal
        let i = &decode_text(&internal)[0];
        assert!(i.is_internal_call());
        assert!(!i.is_syscall());
    }
}
