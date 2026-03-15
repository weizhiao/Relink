//! RISC-V 64-bit architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides RISC-V 64-bit specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.
//!
//! Implementation based on LLVM JITLink RISC-V support (EdgeKind_riscv and applyFixup).

use crate::{
    elf::ElfRelType,
    relocation::{
        RelocHelper, RelocValue, RelocationHandler, StaticReloc, SymbolLookup, reloc_error,
    },
    segment::section::{GotEntry, PltEntry, PltGotSection},
};
use elf::abi::*;
use hashbrown::HashMap;
/// The ELF machine type for RISC-V architecture.
pub const EM_ARCH: u16 = EM_RISCV;
/// Offset for TLS Dynamic Thread Vector.
/// In our software-based TLS implementation, we use 0 offset for simplicity.
pub const TLS_DTV_OFFSET: usize = 0;

/// Relative relocation type - add base address to relative offset.
pub const REL_RELATIVE: u32 = R_RISCV_RELATIVE;
/// GOT entry relocation type - set GOT entry to symbol address.
pub const REL_GOT: u32 = R_RISCV_64;
/// TLS DTPMOD relocation type - set to TLS module ID.
pub const REL_DTPMOD: u32 = R_RISCV_TLS_DTPMOD64;
/// Symbolic relocation type - set to absolute symbol address.
pub const REL_SYMBOLIC: u32 = R_RISCV_64;
/// PLT jump slot relocation type - set PLT entry to symbol address.
pub const REL_JUMP_SLOT: u32 = R_RISCV_JUMP_SLOT;
/// TLS DTPOFF relocation type - set to TLS offset relative to DTV.
pub const REL_DTPOFF: u32 = R_RISCV_TLS_DTPREL64;
/// IRELATIVE relocation type - call function to get address.
pub const REL_IRELATIVE: u32 = R_RISCV_IRELATIVE;
/// COPY relocation type - copy data from shared object.
pub const REL_COPY: u32 = R_RISCV_COPY;
/// TLS TPOFF relocation type - set to TLS offset relative to thread pointer.
pub const REL_TPOFF: u32 = R_RISCV_TLS_TPREL64;
/// TLSDESC relocation type - set to a function pointer and an argument.
pub const REL_TLSDESC: u32 = 0;

/// Size of each PLT entry in bytes.
pub(crate) const PLT_ENTRY_SIZE: usize = 16;

/// Template for PLT entries on RISC-V 64.
///
/// Layout:
/// - auipc t3, %pcrel_hi(GOT_ENTRY)
/// - ld    t3, %pcrel_lo(GOT_ENTRY)(t3)
/// - jalr  t1, t3, 0
/// - nop
pub(crate) const PLT_ENTRY: [u8; PLT_ENTRY_SIZE] = [
    0x17, 0x0e, 0x00, 0x00, // auipc t3, 0
    0x03, 0x3e, 0x0e, 0x00, // ld t3, 0(t3)
    0x67, 0x03, 0x0e, 0x00, // jalr t1, t3, 0
    0x13, 0x00, 0x00, 0x00, // nop
];

/// Get the current thread pointer using architecture-specific register.
#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) tp);
    }
    tp
}

/// Offset in GOT for dynamic library handle.
pub(crate) const DYLIB_OFFSET: usize = 1;
/// Offset in GOT for resolver function pointer.
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 0;

/// Dynamic linker runtime resolver for RISC-V 64-bit PLT entries.
///
/// This function is called when a PLT entry needs to resolve a symbol address
/// at runtime. It saves the current register state including floating-point
/// registers, calls the dynamic linker resolution function, and then restores
/// the state before jumping to the resolved function.
///
/// The function preserves all caller-saved integer registers (a0-a7, ra)
/// and optionally floating-point registers depending on the target features.
///
/// # Safety
/// This function uses naked assembly and must be called with the correct
/// stack layout set up by the PLT stub code.
#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
        // 保存整数参数寄存器
        // 18 * 8 = 144 bytes, 保持 16 字节对齐
        addi sp,sp,-18*8
        sd ra,8*0(sp)
        sd a0,8*1(sp)
        sd a1,8*2(sp)
        sd a2,8*3(sp)
        sd a3,8*4(sp)
        sd a4,8*5(sp)
        sd a5,8*6(sp)
        sd a6,8*7(sp)
        sd a7,8*8(sp)
        ",
        #[cfg(target_feature = "d")]
        "
        fsd fa0,8*9(sp)
        fsd fa1,8*10(sp)
        fsd fa2,8*11(sp)
        fsd fa3,8*12(sp)
        fsd fa4,8*13(sp)
        fsd fa5,8*14(sp)
        fsd fa6,8*15(sp)
        fsd fa7,8*16(sp)
        ",
        #[cfg(all(target_feature = "f", not(target_feature = "d")))]
        "
        fsw fa0,8*9(sp)
        fsw fa1,8*10(sp)
        fsw fa2,8*11(sp)
        fsw fa3,8*12(sp)
        fsw fa4,8*13(sp)
        fsw fa5,8*14(sp)
        fsw fa6,8*15(sp)
        fsw fa7,8*16(sp)
        ",
        "
        // 这两个是plt代码设置的
        mv a0,t0
        srli a1,t1,3
        // 调用重定位函数
        call {0}
        // 恢复参数寄存器
        mv t1,a0
        ld ra,8*0(sp)
        ld a0,8*1(sp)
        ld a1,8*2(sp)
        ld a2,8*3(sp)
        ld a3,8*4(sp)
        ld a4,8*5(sp)
        ld a5,8*6(sp)
        ld a6,8*7(sp)
        ld a7,8*8(sp)
        ",
        #[cfg(target_feature = "d")]
        "
        fld fa0,8*9(sp)
        fld fa1,8*10(sp)
        fld fa2,8*11(sp)
        fld fa3,8*12(sp)
        fld fa4,8*13(sp)
        fld fa5,8*14(sp)
        fld fa6,8*15(sp)
        fld fa7,8*16(sp)
        ",
        #[cfg(all(target_feature = "f", not(target_feature = "d")))]
        "
        flw fa0,8*9(sp)
        flw fa1,8*10(sp)
        flw fa2,8*11(sp)
        flw fa3,8*12(sp)
        flw fa4,8*13(sp)
        flw fa5,8*14(sp)
        flw fa6,8*15(sp)
        flw fa7,8*16(sp)
        ",
        "
        addi sp,sp,18*8
        // 执行真正的函数
        jr t1
        ",
        sym crate::relocation::dl_fixup,
    )
}
/// Static TLSDESC resolver dummy for RISC-V 64.
pub(crate) extern "C" fn tlsdesc_resolver_static() {
    unimplemented!("TLSDESC is not supported on RISC-V 64 yet");
}
/// Dynamic TLSDESC resolver dummy for RISC-V 64.
pub(crate) extern "C" fn tlsdesc_resolver_dynamic() {
    unimplemented!("TLSDESC is not supported on RISC-V 64 yet");
}
/// Map riscv64 relocation types to human readable names
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_RISCV_NONE => "R_RISCV_NONE",
        R_RISCV_32 => "R_RISCV_32",
        R_RISCV_64 => "R_RISCV_64",
        R_RISCV_RELATIVE => "R_RISCV_RELATIVE",
        R_RISCV_COPY => "R_RISCV_COPY",
        R_RISCV_JUMP_SLOT => "R_RISCV_JUMP_SLOT",
        R_RISCV_IRELATIVE => "R_RISCV_IRELATIVE",
        R_RISCV_BRANCH => "R_RISCV_BRANCH",
        R_RISCV_JAL => "R_RISCV_JAL",
        R_RISCV_CALL => "R_RISCV_CALL",
        R_RISCV_CALL_PLT => "R_RISCV_CALL_PLT",
        R_RISCV_GOT_HI20 => "R_RISCV_GOT_HI20",
        R_RISCV_PCREL_HI20 => "R_RISCV_PCREL_HI20",
        R_RISCV_PCREL_LO12_I => "R_RISCV_PCREL_LO12_I",
        R_RISCV_PCREL_LO12_S => "R_RISCV_PCREL_LO12_S",
        R_RISCV_HI20 => "R_RISCV_HI20",
        R_RISCV_LO12_I => "R_RISCV_LO12_I",
        R_RISCV_LO12_S => "R_RISCV_LO12_S",
        R_RISCV_ADD8 => "R_RISCV_ADD8",
        R_RISCV_ADD16 => "R_RISCV_ADD16",
        R_RISCV_ADD32 => "R_RISCV_ADD32",
        R_RISCV_ADD64 => "R_RISCV_ADD64",
        R_RISCV_SUB8 => "R_RISCV_SUB8",
        R_RISCV_SUB16 => "R_RISCV_SUB16",
        R_RISCV_SUB32 => "R_RISCV_SUB32",
        R_RISCV_SUB64 => "R_RISCV_SUB64",
        R_RISCV_SUB6 => "R_RISCV_SUB6",
        R_RISCV_SET6 => "R_RISCV_SET6",
        R_RISCV_SET8 => "R_RISCV_SET8",
        R_RISCV_SET16 => "R_RISCV_SET16",
        R_RISCV_SET32 => "R_RISCV_SET32",
        R_RISCV_32_PCREL => "R_RISCV_32_PCREL",
        R_RISCV_RVC_BRANCH => "R_RISCV_RVC_BRANCH",
        R_RISCV_RVC_JUMP => "R_RISCV_RVC_JUMP",
        _ => "UNKNOWN",
    }
}

/// RISC-V 64 ELF relocator implementation.
/// 
/// Stores a cache of HI20 relocations for efficient LO12 pairing lookup.
pub(crate) struct Riscv64Relocator {
    /// Cache for PCREL_HI20/GOT_HI20 relocations.
    /// Key: ABSOLUTE virtual address of the AUIPC instruction.
    /// Value: (symbol_idx, addend, relocation_type)
    hi20_cache: HashMap<usize, (usize, i64, u32)>,
}

trait WrappingRelocWord: Copy {
    fn trunc_from_usize(val: usize) -> Self;
    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;
}

impl WrappingRelocWord for u8 {
    #[inline]
    fn trunc_from_usize(val: usize) -> Self {
        val as u8
    }

    #[inline]
    fn wrapping_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }

    #[inline]
    fn wrapping_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
}

impl WrappingRelocWord for u16 {
    #[inline]
    fn trunc_from_usize(val: usize) -> Self {
        val as u16
    }

    #[inline]
    fn wrapping_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }

    #[inline]
    fn wrapping_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
}

impl WrappingRelocWord for u32 {
    #[inline]
    fn trunc_from_usize(val: usize) -> Self {
        val as u32
    }

    #[inline]
    fn wrapping_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }

    #[inline]
    fn wrapping_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
}

impl WrappingRelocWord for u64 {
    #[inline]
    fn trunc_from_usize(val: usize) -> Self {
        val as u64
    }

    #[inline]
    fn wrapping_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }

    #[inline]
    fn wrapping_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
}

/// Helper functions for RISC-V instruction encoding
impl Riscv64Relocator {
    #[inline]
    fn apply_wrapping_arith<T>(ptr: *mut T, value: usize, is_add: bool)
    where
        T: WrappingRelocWord,
    {
        let old = unsafe { ptr.read_unaligned() };
        let rhs = T::trunc_from_usize(value);
        let new = if is_add {
            old.wrapping_add(rhs)
        } else {
            old.wrapping_sub(rhs)
        };
        unsafe { ptr.write_unaligned(new) };
    }

    /// Resolve the lo12 value for PCREL_LO12_I/S relocations.
    ///
    /// This finds the paired HI20 relocation (PCREL_HI20 or GOT_HI20) at the
    /// AUIPC instruction address, recomputes the full PC-relative offset, and
    /// returns the lo12 portion.
    fn resolve_pcrel_lo12<D, PreS, PostS, PreH, PostH>(
        & self,
        helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
        rel: &ElfRelType,
        r_sym: usize,
        pltgot: &mut PltGotSection,
    ) -> crate::Result<i64>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        // r_sym points to the label at the AUIPC instruction address
        let auipc_vaddr = helper
            .find_symbol(r_sym)
            .ok_or_else(|| reloc_error(rel, "Could not resolve AUIPC address", helper.core))?
            .0;
        let base = helper.core.base();

        // Query the pre-built HI20 cache using ABSOLUTE virtual address
        let (target_sym_idx, target_addend, hi20_type) = self
            .hi20_cache
            .get(&auipc_vaddr)
            .copied()
            .ok_or_else(|| {
                reloc_error(rel, "Could not find paired HI20 relocation", helper.core)
            })?;

        // For GOT_HI20, per RISC-V psABI, addends should be 0.
        // We ignore addends for GOT relocations to avoid misaligned GOT reads.
        let off = if hi20_type == R_RISCV_GOT_HI20 {
            // For GOT_HI20, the AUIPC+LD pair loads from the GOT entry.
            // We need the GOT entry address, not the symbol address.
            let sym = helper
                .find_symbol(target_sym_idx)
                .ok_or_else(|| reloc_error(rel, "Could not resolve target symbol from GOT_HI20", helper.core))?;
            let got_entry = pltgot.add_got_entry(target_sym_idx);
            let got_entry_addr = match got_entry {
                GotEntry::Occupied(addr) => addr,
                GotEntry::Vacant(mut got) => {
                    got.update(sym);
                    got.get_addr()
                }
            };
            // Ignore target_addend and lo12_addend for GOT_HI20 to prevent misaligned access
            (got_entry_addr.0 as i64).wrapping_sub(auipc_vaddr as i64)
        } else {
            // For PCREL_HI20, offset = (S + A) - AUIPC_PC
            let target_val = helper
                .find_symbol(target_sym_idx)
                .ok_or_else(|| reloc_error(rel, "Could not resolve target symbol from PCREL_HI20", helper.core))?
                .0;
            let target_final = (target_val as isize + target_addend as isize) as usize;
            let lo12_addend = rel.r_addend(base);
            let final_target = (target_final as isize + lo12_addend as isize) as usize;
            (final_target as i64).wrapping_sub(auipc_vaddr as i64)
        };

        // Split into hi20 + lo12
        let hi20 = (off + 0x800) >> 12;
        let lo12 = off - (hi20 << 12);
        Ok(lo12)
    }

    /// Encode immediate value into a RISC-V instruction
    #[inline]
    fn encode_imm(insn: u32, val: i64, ty: ImmType) -> u32 {
        match ty {
            ImmType::U => (insn & 0xfff) | ((val as u32) << 12),
            ImmType::I => (insn & 0xfffff) | (((val & 0xfff) as u32) << 20),
            ImmType::S => {
                let imm11_5 = ((val >> 5) & 0x7f) as u32;
                let imm4_0 = (val & 0x1f) as u32;
                (insn & 0x1fff07f) | (imm11_5 << 25) | (imm4_0 << 7)
            }
            ImmType::B => {
                let imm12 = ((val >> 12) & 0x1) as u32;
                let imm10_5 = ((val >> 5) & 0x3f) as u32;
                let imm4_1 = ((val >> 1) & 0xf) as u32;
                let imm11 = ((val >> 11) & 0x1) as u32;
                (insn & 0x1fff07f) | (imm12 << 31) | (imm10_5 << 25) | (imm4_1 << 8) | (imm11 << 7)
            }
            ImmType::J => {
                let imm20 = ((val >> 20) & 0x1) as u32;
                let imm10_1 = ((val >> 1) & 0x3ff) as u32;
                let imm11 = ((val >> 11) & 0x1) as u32;
                let imm19_12 = ((val >> 12) & 0xff) as u32;
                (insn & 0xfff) | (imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) | (imm19_12 << 12)
            }
            ImmType::CB => {
                let imm8 = ((val >> 8) & 0x1) as u16;
                let imm4_3 = ((val >> 3) & 0x3) as u16;
                let imm7_6 = ((val >> 6) & 0x3) as u16;
                let imm2_1 = ((val >> 1) & 0x3) as u16;
                let imm5 = ((val >> 5) & 0x1) as u16;
                (((insn as u16) & 0xe383)
                    | ((imm8 << 12) | (imm4_3 << 10) | (imm7_6 << 5) | (imm2_1 << 3) | (imm5 << 2)))
                    as u32
            }
            ImmType::CJ => {
                let imm11 = ((val >> 11) & 0x1) as u16;
                let imm4 = ((val >> 4) & 0x1) as u16;
                let imm9_8 = ((val >> 8) & 0x3) as u16;
                let imm10 = ((val >> 10) & 0x1) as u16;
                let imm6 = ((val >> 6) & 0x1) as u16;
                let imm7 = ((val >> 7) & 0x1) as u16;
                let imm3_1 = ((val >> 1) & 0x7) as u16;
                let imm5 = ((val >> 5) & 0x1) as u16;
                (((insn as u16) & 0xe003)
                    | ((imm11 << 12)
                        | (imm4 << 11)
                        | (imm9_8 << 9)
                        | (imm10 << 8)
                        | (imm6 << 7)
                        | (imm7 << 6)
                        | (imm3_1 << 3)
                        | (imm5 << 2))) as u32
            }
        }
    }
}

/// Immediate encoding types for RISC-V instructions
#[derive(Copy, Clone)]
enum ImmType {
    U,  // Upper immediate (lui, auipc)
    I,  // I-type immediate
    S,  // S-type immediate (store)
    B,  // B-type immediate (branch)
    J,  // J-type immediate (jal)
    CB, // Compressed branch
    CJ, // Compressed jump
}

impl StaticReloc for Riscv64Relocator {
    fn new(_relocs: &[&'static [ElfRelType]]) -> Self {
        Self {
            hi20_cache: HashMap::new(),
        }
    }

    fn prepare<D, PreS, PostS, PreH, PostH>(
        &mut self,
        relocs: &[&'static [ElfRelType]],
        helper: &RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
    ) where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        // Build HI20 cache: scan all relocations for PCREL_HI20 and GOT_HI20
        let base = helper.core.base();
        self.hi20_cache.clear();
        
        for reloc_section in relocs {
            for r in *reloc_section {
                let rtype = r.r_type() as u32;
                if rtype == R_RISCV_PCREL_HI20 || rtype == R_RISCV_GOT_HI20 {
                    // Key: ABSOLUTE virtual address (base + r_offset)
                    let key = base.wrapping_add(r.r_offset());
                    let addend = if rtype == R_RISCV_GOT_HI20 {
                        0i64 // GOT_HI20 must have zero addend per psABI
                    } else {
                        r.r_addend(base) as i64
                    };
                    self.hi20_cache.insert(key, (r.r_symbol(), addend, rtype));
                }
            }
        }
    }

    fn relocate<D, PreS, PostS, PreH, PostH>(
        &mut self,
        helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
        rel: &ElfRelType,
        pltgot: &mut PltGotSection,
    ) -> crate::Result<()>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        let r_sym = rel.r_symbol();
        let r_type = rel.r_type();
        let base = helper.core.base();
        let segments = helper.core.segments();
        let addend = rel.r_addend(base);
        let offset = rel.r_offset();
        let p = base + offset;
        let boxed_error = || reloc_error(rel, "unknown symbol", helper.core);

        match r_type as u32 {
            // Absolute 64-bit relocation: S + A
            R_RISCV_64 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                segments.write(offset, sym + addend);
            }
            // Absolute 32-bit relocation: S + A
            R_RISCV_32 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val: RelocValue<u32> = (sym + addend).try_into().map_err(|_| {
                    reloc_error(
                        rel,
                        "out of range integral type conversion attempted",
                        helper.core,
                    )
                })?;
                segments.write(offset, val);
            }

            // Relative relocation: B + A
            R_RISCV_RELATIVE => {
                let val: RelocValue<usize> = RelocValue::new(base) + addend;
                segments.write(offset, val);
            }

            // PC-relative 32-bit: S + A - P
            R_RISCV_32_PCREL => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val: RelocValue<u32> = (sym + addend - p).try_into().map_err(|_| {
                    reloc_error(rel, "PC-relative offset out of range", helper.core)
                })?;
                segments.write(offset, val);
            }

            // Branch instruction: S + A - P (must be even, within ±4KiB)
            R_RISCV_BRANCH => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let off = (sym + addend - p).0 as i64;
                if off & 1 != 0 || off < -4096 || off >= 4096 {
                    return Err(reloc_error(rel, "branch offset out of range", helper.core));
                }
                let ptr = segments.get_mut_ptr::<u32>(offset);
                let insn = unsafe { ptr.read_unaligned() };
                let new_insn = Self::encode_imm(insn, off, ImmType::B);
                unsafe { ptr.write_unaligned(new_insn) };
            }

            // JAL instruction: S + A - P (must be even, within ±1MiB)
            R_RISCV_JAL => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let off = (sym + addend - p).0 as i64;
                if off & 1 != 0 || off < -(1 << 20) || off >= (1 << 20) {
                    return Err(reloc_error(rel, "JAL offset out of range", helper.core));
                }
                let ptr = segments.get_mut_ptr::<u32>(offset);
                let insn = unsafe { ptr.read_unaligned() };
                let new_insn = Self::encode_imm(insn, off, ImmType::J);
                unsafe { ptr.write_unaligned(new_insn) };
            }

            // CALL: pair of AUIPC + JALR (within ±2GiB)
            R_RISCV_CALL => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let off = (sym + addend - p).0 as i64;

                // Check if offset is within ±2GiB range for CALL instruction
                if off < -(1i64 << 31) || off >= (1i64 << 31) {
                    return Err(reloc_error(
                        rel,
                        "CALL offset out of ±2GiB range",
                        helper.core,
                    ));
                }

                let hi20 = (off + 0x800) >> 12;
                let lo12 = off & 0xfff;

                let ptr = segments.get_mut_ptr::<u32>(offset);
                let auipc = unsafe { ptr.read_unaligned() };
                let jalr = unsafe { ptr.add(1).read_unaligned() };

                let new_auipc = Self::encode_imm(auipc, hi20, ImmType::U);
                let new_jalr = Self::encode_imm(jalr, lo12, ImmType::I);

                unsafe {
                    ptr.write_unaligned(new_auipc);
                    ptr.add(1).write_unaligned(new_jalr);
                }
            }

            // CALL_PLT: pair of AUIPC + JALR with PLT fallback
            R_RISCV_CALL_PLT => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };

                let off = (sym + addend - p).0 as i64;
                // Check if direct call is within ±2GiB range
                let target_addr = if off >= -(1i64 << 31) && off < (1i64 << 31) {
                    sym
                } else {
                    // Distance too far, use PLT entry
                    let plt_entry = pltgot.add_plt_entry(r_sym);
                    let plt_entry_addr = match plt_entry {
                        PltEntry::Occupied(plt_entry_addr) => plt_entry_addr,
                        PltEntry::Vacant { plt, mut got } => {
                            let plt_entry_addr = RelocValue::new(plt.as_ptr() as usize);
                            // Set up PLT entry - copy template
                            plt.copy_from_slice(&PLT_ENTRY);

                            // Create corresponding GOT entry
                            got.update(sym);
                            let got_addr = got.get_addr();

                            // Patch PLT entry to point to GOT
                            let plt_ptr = plt_entry_addr.0;
                            let got_off = (got_addr - plt_ptr).0 as i64;
                            let got_hi20 = (got_off + 0x800) >> 12;
                            let got_lo12 = got_off & 0xfff;

                            // Patch AUIPC instruction (offset 0) - use safe byte order handling
                            let plt_ptr = plt.as_mut_ptr() as *mut u32;
                            let auipc = unsafe { plt_ptr.read_unaligned() };
                            let new_auipc = Self::encode_imm(auipc, got_hi20, ImmType::U);
                            unsafe { plt_ptr.write_unaligned(new_auipc) };

                            // Patch LD instruction (offset 4) - use safe byte order handling
                            let ld = unsafe { plt_ptr.add(1).read_unaligned() };
                            let new_ld = Self::encode_imm(ld, got_lo12, ImmType::I);
                            unsafe { plt_ptr.add(1).write_unaligned(new_ld) };

                            plt_entry_addr
                        }
                    };
                    plt_entry_addr
                };

                let final_off = (target_addr + addend - p).0 as i64;
                let hi20 = (final_off + 0x800) >> 12;
                let lo12 = final_off & 0xfff;

                let ptr = segments.get_mut_ptr::<u32>(offset);
                let auipc = unsafe { ptr.read_unaligned() };
                let jalr = unsafe { ptr.add(1).read_unaligned() };

                let new_auipc = Self::encode_imm(auipc, hi20, ImmType::U);
                let new_jalr = Self::encode_imm(jalr, lo12, ImmType::I);

                unsafe {
                    ptr.write_unaligned(new_auipc);
                    ptr.add(1).write_unaligned(new_jalr);
                }
            }

            // GOT_HI20: high 20 bits of GOT entry offset
            R_RISCV_GOT_HI20 => {
                // Per RISC-V psABI, GOT_HI20 must have addend == 0
                if addend != 0 {
                    return Err(reloc_error(
                        rel,
                        "R_RISCV_GOT_HI20 with non-zero addend is invalid",
                        helper.core,
                    ));
                }
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                // Create GOT entry for the symbol
                let got_entry = pltgot.add_got_entry(r_sym);
                let got_entry_addr = match got_entry {
                    GotEntry::Occupied(got_entry_addr) => got_entry_addr,
                    GotEntry::Vacant(mut got) => {
                        got.update(sym);
                        got.get_addr()
                    }
                };
                // Calculate offset to GOT entry (no addend for GOT_HI20)
                let off = (got_entry_addr - p).0 as i64;
                let hi20 = (off + 0x800) >> 12;

                let ptr = segments.get_mut_ptr::<u32>(offset);
                let insn = unsafe { ptr.read_unaligned() };
                let new_insn = Self::encode_imm(insn, hi20, ImmType::U);
                unsafe { ptr.write_unaligned(new_insn) };
            }

            // PCREL_HI20: high 20 bits of PC-relative offset
            R_RISCV_PCREL_HI20 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let off = (sym + addend - p).0 as i64;
                let hi20 = (off + 0x800) >> 12;

                let ptr = segments.get_mut_ptr::<u32>(offset);
                let insn = unsafe { ptr.read_unaligned() };
                let new_insn = Self::encode_imm(insn, hi20, ImmType::U);
                unsafe { ptr.write_unaligned(new_insn) };
            }

            // PCREL_LO12_I: low 12 bits for I-type instruction (paired with PCREL_HI20 or GOT_HI20)
            R_RISCV_PCREL_LO12_I => {
                let lo12 = self.resolve_pcrel_lo12(helper, rel, r_sym, pltgot)?;
                let ptr = segments.get_mut_ptr::<u32>(offset);
                let insn = unsafe { ptr.read_unaligned() };
                let new_insn = Self::encode_imm(insn, lo12, ImmType::I);
                unsafe { ptr.write_unaligned(new_insn) };
            }

            // PCREL_LO12_S: low 12 bits for S-type instruction (paired with PCREL_HI20 or GOT_HI20)
            R_RISCV_PCREL_LO12_S => {
                let lo12 = self.resolve_pcrel_lo12(helper, rel, r_sym, pltgot)?;
                let ptr = segments.get_mut_ptr::<u32>(offset);
                let insn = unsafe { ptr.read_unaligned() };
                let new_insn = Self::encode_imm(insn, lo12, ImmType::S);
                unsafe { ptr.write_unaligned(new_insn) };
            }

            // HI20: absolute high 20 bits
            R_RISCV_HI20 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val = (sym + addend).0 as i64;
                let hi20 = (val + 0x800) >> 12;

                let ptr = segments.get_mut_ptr::<u32>(offset);
                let insn = unsafe { ptr.read_unaligned() };
                let new_insn = Self::encode_imm(insn, hi20, ImmType::U);
                unsafe { ptr.write_unaligned(new_insn) };
            }

            // LO12_I: absolute low 12 bits for I-type
            R_RISCV_LO12_I => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val = (sym + addend).0 as i64;
                let lo12 = val & 0xfff;

                let ptr = segments.get_mut_ptr::<u32>(offset);
                let insn = unsafe { ptr.read_unaligned() };
                let new_insn = Self::encode_imm(insn, lo12, ImmType::I);
                unsafe { ptr.write_unaligned(new_insn) };
            }

            // LO12_S: absolute low 12 bits for S-type
            R_RISCV_LO12_S => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val = (sym + addend).0 as i64;
                let lo12 = val & 0xfff;

                let ptr = segments.get_mut_ptr::<u32>(offset);
                let insn = unsafe { ptr.read_unaligned() };
                let new_insn = Self::encode_imm(insn, lo12, ImmType::S);
                unsafe { ptr.write_unaligned(new_insn) };
            }

            // ADD*/SUB*: *(uN*)P = *(uN*)P +/- (S + A)
            R_RISCV_ADD8 | R_RISCV_ADD16 | R_RISCV_ADD32 | R_RISCV_ADD64 | R_RISCV_SUB8
            | R_RISCV_SUB16 | R_RISCV_SUB32 | R_RISCV_SUB64 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let value = (sym + addend).0;
                let is_add = matches!(
                    r_type as u32,
                    R_RISCV_ADD8 | R_RISCV_ADD16 | R_RISCV_ADD32 | R_RISCV_ADD64
                );
                match r_type as u32 {
                    R_RISCV_ADD8 | R_RISCV_SUB8 => {
                        Self::apply_wrapping_arith::<u8>(
                            segments.get_mut_ptr::<u8>(offset),
                            value,
                            is_add,
                        );
                    }
                    R_RISCV_ADD16 | R_RISCV_SUB16 => {
                        Self::apply_wrapping_arith::<u16>(
                            segments.get_mut_ptr::<u16>(offset),
                            value,
                            is_add,
                        );
                    }
                    R_RISCV_ADD32 | R_RISCV_SUB32 => {
                        Self::apply_wrapping_arith::<u32>(
                            segments.get_mut_ptr::<u32>(offset),
                            value,
                            is_add,
                        );
                    }
                    R_RISCV_ADD64 | R_RISCV_SUB64 => {
                        Self::apply_wrapping_arith::<u64>(
                            segments.get_mut_ptr::<u64>(offset),
                            value,
                            is_add,
                        );
                    }
                    _ => unreachable!(),
                }
            }

            // SUB6: 6-bit subtraction (bits 5:0)
            R_RISCV_SUB6 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let ptr = segments.get_mut_ptr::<u8>(offset);
                let old = unsafe { ptr.read_unaligned() };
                let val = ((old & 0x3f).wrapping_sub((sym + addend).0 as u8)) & 0x3f;
                unsafe { ptr.write_unaligned((old & 0xc0) | val) };
            }

            // SET6: set 6-bit value (bits 5:0)
            R_RISCV_SET6 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let ptr = segments.get_mut_ptr::<u8>(offset);
                let old = unsafe { ptr.read_unaligned() };
                let val = ((sym + addend).0 as u8) & 0x3f;
                unsafe { ptr.write_unaligned((old & 0xc0) | val) };
            }
            // SET8: set 8-bit value
            R_RISCV_SET8 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val = (sym + addend).0 as u8;
                segments.write(offset, RelocValue::new(val));
            }
            // SET16: set 16-bit value
            R_RISCV_SET16 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val = (sym + addend).0 as u16;
                segments.write(offset, RelocValue::new(val));
            }
            // SET32: set 32-bit value
            R_RISCV_SET32 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val = (sym + addend).0 as u32;
                segments.write(offset, RelocValue::new(val));
            }

            // RVC_BRANCH: compressed branch instruction (±256B)
            R_RISCV_RVC_BRANCH => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let off = (sym + addend - p).0 as i64;
                if off & 1 != 0 || off < -256 || off >= 256 {
                    return Err(reloc_error(
                        rel,
                        "RVC branch offset out of range",
                        helper.core,
                    ));
                }
                let ptr = segments.get_mut_ptr::<u16>(offset);
                let insn = unsafe { ptr.read_unaligned() } as u32;
                let new_insn = Self::encode_imm(insn, off, ImmType::CB) as u16;
                unsafe { ptr.write_unaligned(new_insn) };
            }
            // RVC_JUMP: compressed jump instruction (±2KiB)
            R_RISCV_RVC_JUMP => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let off = (sym + addend - p).0 as i64;
                if off & 1 != 0 || off < -2048 || off >= 2048 {
                    return Err(reloc_error(
                        rel,
                        "RVC jump offset out of range",
                        helper.core,
                    ));
                }
                let ptr = segments.get_mut_ptr::<u16>(offset);
                let insn = unsafe { ptr.read_unaligned() } as u32;
                let new_insn = Self::encode_imm(insn, off, ImmType::CJ) as u16;
                unsafe { ptr.write_unaligned(new_insn) };
            }

            // RELAX: linker optimization hint - no action needed at runtime
            R_RISCV_RELAX => {
                // This is a hint to the linker that the instruction sequence
                // can be relaxed/optimized. For runtime linking, we simply
                // ignore this relocation as no memory modification is needed.
            }

            _ => {
                return Err(reloc_error(rel, "unsupported relocation type", helper.core));
            }
        }
        Ok(())
    }

    /// Check if a relocation type requires a GOT entry.
    ///
    /// GOT (Global Offset Table) entries are needed for position-independent
    /// references to symbols. On RISC-V, GOT entries are required for:
    /// - R_RISCV_GOT_HI20: PC-relative reference to GOT entry
    /// - R_RISCV_CALL_PLT: PLT entry that may need GOT indirection
    ///
    /// # Arguments
    /// * `rel_type` - The relocation type to check
    ///
    /// # Returns
    /// `true` if the relocation type requires a GOT entry, `false` otherwise
    fn needs_got(rel_type: u32) -> bool {
        matches!(rel_type, R_RISCV_GOT_HI20 | R_RISCV_CALL_PLT)
    }

    /// Check if a relocation type requires a PLT entry.
    ///
    /// PLT (Procedure Linkage Table) entries are needed for function calls
    /// that may need lazy binding. On RISC-V, PLT entries are required for:
    /// - R_RISCV_CALL_PLT: PC-relative call through PLT
    ///
    /// # Arguments
    /// * `rel_type` - The relocation type to check
    ///
    /// # Returns
    /// `true` if the relocation type requires a PLT entry, `false` otherwise
    fn needs_plt(rel_type: u32) -> bool {
        rel_type == R_RISCV_CALL_PLT
    }
}
