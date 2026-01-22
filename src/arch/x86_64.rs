//! x86-64 architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides x86-64 specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

use crate::{
    elf::ElfRelType,
    relocation::{
        RelocHelper, RelocValue, RelocationHandler, StaticReloc, SymbolLookup, reloc_error,
    },
    segment::section::{GotEntry, PltEntry, PltGotSection},
};
use elf::abi::*;

/// The ELF machine type for x86-64 architecture.
pub const EM_ARCH: u16 = EM_X86_64;

/// Offset for TLS Dynamic Thread Vector.
/// For x86-64, this is 0 as the TCB (Thread Control Block) comes first.
pub const TLS_DTV_OFFSET: usize = 0;

/// Relative relocation type - add base address to relative offset.
pub const REL_RELATIVE: u32 = R_X86_64_RELATIVE;
/// GOT entry relocation type - set GOT entry to symbol address.
pub const REL_GOT: u32 = R_X86_64_GLOB_DAT;
/// TLS DTPMOD relocation type - set to TLS module ID.
pub const REL_DTPMOD: u32 = R_X86_64_DTPMOD64;
/// Symbolic relocation type - set to absolute symbol address.
pub const REL_SYMBOLIC: u32 = R_X86_64_64;
/// PLT jump slot relocation type - set PLT entry to symbol address.
pub const REL_JUMP_SLOT: u32 = R_X86_64_JUMP_SLOT;
/// TLS DTPOFF relocation type - set to TLS offset relative to DTV.
pub const REL_DTPOFF: u32 = R_X86_64_DTPOFF64;
/// IRELATIVE relocation type - call function to get address.
pub const REL_IRELATIVE: u32 = R_X86_64_IRELATIVE;
/// COPY relocation type - copy data from shared object.
pub const REL_COPY: u32 = R_X86_64_COPY;
/// TLS TPOFF relocation type - set to TLS offset relative to thread pointer.
pub const REL_TPOFF: u32 = R_X86_64_TPOFF64;

/// Offset in GOT for dynamic library handle.
pub(crate) const DYLIB_OFFSET: usize = 1;
/// Offset in GOT for resolver function pointer.
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 2;
/// Size of each PLT entry in bytes.
pub(crate) const PLT_ENTRY_SIZE: usize = 16;

/// Template for PLT entries.
/// Each PLT entry contains:
/// - endbr64 instruction for CET (Control-flow Enforcement Technology)
/// - jmp instruction to jump through GOT entry
/// - padding bytes
pub(crate) const PLT_ENTRY: [u8; PLT_ENTRY_SIZE] = [
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0xff, 0x25, 0, 0, 0, 0, // jmp *GOTPLT+idx(%rip)
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // (padding)
];

/// Dynamic linker runtime resolver for x86-64 PLT entries.
///
/// This function is called when a PLT entry needs to resolve a symbol address
/// at runtime. It saves the current register state, calls the dynamic linker
/// resolution function, and then restores the state before jumping to the
/// resolved function.
///
/// The function preserves all caller-saved registers and SIMD registers
/// to ensure compatibility with various calling conventions.
///
/// # Safety
/// This function uses naked assembly and must be called with the correct
/// stack layout set up by the PLT stub code.
#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
    // Save caller-saved registers
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11

    // Save xmm registers (arguments can be passed in xmm0-xmm7)
    // We need 128 bytes for xmm0-xmm7 + 8 bytes padding to align stack to 16 bytes
    sub rsp, 136
    movdqu [rsp + 0], xmm0
    movdqu [rsp + 16], xmm1
    movdqu [rsp + 32], xmm2
    movdqu [rsp + 48], xmm3
    movdqu [rsp + 64], xmm4
    movdqu [rsp + 80], xmm5
    movdqu [rsp + 96], xmm6
    movdqu [rsp + 112], xmm7

    // Arguments for dl_fixup(link_map, reloc_idx)
    // link_map was pushed by PLT0, reloc_idx was pushed by PLT entry
    // Stack layout now:
    // [rsp + 0..127]  : xmm0-xmm7
    // [rsp + 128..135]: padding
    // [rsp + 136..199]: r11, r10, r9, r8, rcx, rdx, rsi, rdi (8 * 8 = 64)
    // [rsp + 200]     : link_map
    // [rsp + 208]     : reloc_idx
    // [rsp + 216]     : return address to caller
    mov rdi, [rsp + 200]
    mov rsi, [rsp + 208]

    // Call the resolver
    call {0}

    // Restore xmm registers
    movdqu xmm0, [rsp + 0]
    movdqu xmm1, [rsp + 16]
    movdqu xmm2, [rsp + 32]
    movdqu xmm3, [rsp + 48]
    movdqu xmm4, [rsp + 64]
    movdqu xmm5, [rsp + 80]
    movdqu xmm6, [rsp + 96]
    movdqu xmm7, [rsp + 112]
    add rsp, 136

    // Restore caller-saved registers
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi

    // Clean up link_map and reloc_idx from stack
    add rsp, 16

    // Jump to the resolved function
    jmp rax
    ",
        sym crate::relocation::dl_fixup,
    )
}

/// x86-64 ELF relocator implementation.
///
/// This struct implements the `StaticReloc` trait to provide x86-64 specific
/// relocation processing for ELF files. It handles various relocation types
/// including absolute addresses, PC-relative offsets, GOT entries, and PLT entries.
pub(crate) struct X86_64Relocator;

/// Map x86_64 relocation type value to human readable name.
///
/// This function converts numeric relocation type constants to their
/// corresponding string names for debugging and error reporting purposes.
///
/// # Arguments
/// * `r_type` - The numeric relocation type value
///
/// # Returns
/// A static string containing the relocation type name, or "UNKNOWN" for unrecognized types.
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_X86_64_NONE => "R_X86_64_NONE",
        R_X86_64_64 => "R_X86_64_64",
        R_X86_64_PC32 => "R_X86_64_PC32",
        R_X86_64_GOT32 => "R_X86_64_GOT32",
        R_X86_64_PLT32 => "R_X86_64_PLT32",
        R_X86_64_COPY => "R_X86_64_COPY",
        R_X86_64_GLOB_DAT => "R_X86_64_GLOB_DAT",
        R_X86_64_JUMP_SLOT => "R_X86_64_JUMP_SLOT",
        R_X86_64_RELATIVE => "R_X86_64_RELATIVE",
        R_X86_64_GOTPCREL => "R_X86_64_GOTPCREL",
        R_X86_64_32 => "R_X86_64_32",
        R_X86_64_32S => "R_X86_64_32S",
        R_X86_64_IRELATIVE => "R_X86_64_IRELATIVE",
        _ => "UNKNOWN",
    }
}

impl StaticReloc for X86_64Relocator {
    /// Perform x86-64 specific ELF relocation.
    ///
    /// This method handles various x86-64 relocation types including:
    /// - R_X86_64_64: Absolute 64-bit address
    /// - R_X86_64_PC32: 32-bit PC-relative offset
    /// - R_X86_64_PLT32: 32-bit PLT entry offset
    /// - R_X86_64_GOTPCREL: 32-bit GOT entry offset
    /// - R_X86_64_32/R_X86_64_32S: 32-bit absolute addresses
    ///
    /// # Arguments
    /// * `core` - The ELF core image being relocated
    /// * `rel_type` - The relocation entry to process
    /// * `pltgot` - PLT/GOT section for managing procedure linkage
    /// * `scope` - Array of loaded core images for symbol resolution
    /// * `pre_find` - Pre-resolution symbol lookup
    /// * `post_find` - Post-resolution symbol lookup
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if relocation fails
    fn relocate<D, PreS, PostS, PreH, PostH>(
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
        let append = rel.r_addend(base);
        let offset = rel.r_offset();
        let p = base + rel.r_offset();
        let boxed_error = || reloc_error(rel, "unknown symbol", helper.core);
        match r_type as _ {
            R_X86_64_64 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                segments.write(offset, sym + append);
            }
            R_X86_64_PC32 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val: RelocValue<i32> = (sym + append - p).try_into().map_err(|_| {
                    reloc_error(
                        rel,
                        "out of range integral type conversion attempted",
                        helper.core,
                    )
                })?;
                segments.write(offset, val);
            }
            R_X86_64_PLT32 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val: RelocValue<i32> = if let Ok(val) = (sym + append - p).try_into() {
                    val
                } else {
                    let plt_entry = pltgot.add_plt_entry(r_sym);
                    let plt_entry_addr = match plt_entry {
                        PltEntry::Occupied(plt_entry_addr) => plt_entry_addr,
                        PltEntry::Vacant { plt, mut got } => {
                            let plt_entry_addr = plt.as_ptr() as usize;
                            got.update(sym.into());
                            let call_offset = got.get_addr() - plt_entry_addr - 10;
                            let call_offset_val: RelocValue<i32> = call_offset.try_into().unwrap();
                            plt[6..10].copy_from_slice(&call_offset_val.0.to_ne_bytes());
                            RelocValue::new(plt_entry_addr)
                        }
                    };
                    (plt_entry_addr + append - p).try_into().unwrap()
                };
                segments.write(offset, val);
            }
            R_X86_64_GOTPCREL => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let got_entry = pltgot.add_got_entry(r_sym);
                let got_entry_addr = match got_entry {
                    GotEntry::Occupied(got_entry_addr) => got_entry_addr,
                    GotEntry::Vacant(mut got) => {
                        got.update(sym);
                        got.get_addr()
                    }
                };
                let val: RelocValue<i32> = (got_entry_addr + append - p).try_into().unwrap();
                segments.write(offset, val);
            }
            R_X86_64_32 => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val: RelocValue<u32> = (sym + append).try_into().map_err(|_| {
                    reloc_error(
                        rel,
                        "out of range integral type conversion attempted",
                        helper.core,
                    )
                })?;
                segments.write(offset, val);
            }
            R_X86_64_32S => {
                let Some(sym) = helper.find_symbol(r_sym) else {
                    return Err(boxed_error());
                };
                let val: RelocValue<i32> = (sym + append).try_into().map_err(|_| {
                    reloc_error(
                        rel,
                        "out of range integral type conversion attempted",
                        helper.core,
                    )
                })?;
                segments.write(offset, val);
            }
            _ => {
                return Err(boxed_error());
            }
        }
        Ok(())
    }

    /// Check if a relocation type requires a GOT entry.
    ///
    /// GOT (Global Offset Table) entries are needed for position-independent
    /// references to symbols. On x86-64, GOT entries are required for:
    /// - R_X86_64_GOTPCREL: PC-relative reference to GOT entry
    /// - R_X86_64_PLT32: PLT entry that may need GOT indirection
    ///
    /// # Arguments
    /// * `rel_type` - The relocation type to check
    ///
    /// # Returns
    /// `true` if the relocation type requires a GOT entry, `false` otherwise
    fn needs_got(rel_type: u32) -> bool {
        matches!(rel_type, R_X86_64_GOTPCREL | R_X86_64_PLT32)
    }

    /// Check if a relocation type requires a PLT entry.
    ///
    /// PLT (Procedure Linkage Table) entries are needed for function calls
    /// that may need lazy binding. On x86-64, PLT entries are required for:
    /// - R_X86_64_PLT32: PC-relative call through PLT
    ///
    /// # Arguments
    /// * `rel_type` - The relocation type to check
    ///
    /// # Returns
    /// `true` if the relocation type requires a PLT entry, `false` otherwise
    fn needs_plt(rel_type: u32) -> bool {
        rel_type == R_X86_64_PLT32
    }
}
