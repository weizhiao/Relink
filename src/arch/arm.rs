//! ARM architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides ARM specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

use elf::abi::*;

/// The ELF machine type for ARM architecture.
pub const EM_ARCH: u16 = EM_ARM;
/// Offset for TLS Dynamic Thread Vector.
/// For ARM, this is 0 as the TCB (Thread Control Block) comes first.
pub const TLS_DTV_OFFSET: usize = 0;

/// Relative relocation type - add base address to relative offset.
pub const REL_RELATIVE: u32 = R_ARM_RELATIVE;
/// GOT entry relocation type - set GOT entry to symbol address.
pub const REL_GOT: u32 = R_ARM_GLOB_DAT;
/// TLS DTPMOD relocation type - set to TLS module ID.
pub const REL_DTPMOD: u32 = R_ARM_TLS_DTPMOD32;
/// Symbolic relocation type - set to absolute symbol address.
pub const REL_SYMBOLIC: u32 = R_ARM_ABS32;
/// PLT jump slot relocation type - set PLT entry to symbol address.
pub const REL_JUMP_SLOT: u32 = R_ARM_JUMP_SLOT;
/// TLS DTPOFF relocation type - set to TLS offset relative to DTV.
pub const REL_DTPOFF: u32 = R_ARM_TLS_DTPOFF32;
/// IRELATIVE relocation type - call function to get address.
pub const REL_IRELATIVE: u32 = R_ARM_IRELATIVE;
/// COPY relocation type - copy data from shared object.
pub const REL_COPY: u32 = R_ARM_COPY;
/// TLS TPOFF relocation type - set to TLS offset relative to thread pointer.
pub const REL_TPOFF: u32 = R_ARM_TLS_TPOFF32;
/// TLSDESC relocation type - set to a function pointer and an argument.
pub const REL_TLSDESC: u32 = 0;

/// Get the current thread pointer using architecture-specific register.
#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    // Read TPIDRURO (User Read-Only Thread ID Register) - c13, c0, 3
    // This is the standard TLS register for Linux user space.
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c13, c0, 3", out(reg) tp);
    }
    tp
}

/// Offset in GOT for dynamic library handle.
pub(crate) const DYLIB_OFFSET: usize = 1;
/// Offset in GOT for resolver function pointer.
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 2;

/// Dynamic linker runtime resolver for ARM PLT entries.
///
/// This function is called when a PLT entry needs to resolve a symbol address
/// at runtime. It saves the current register state, calls the dynamic linker
/// resolution function, and then restores the state before jumping to the
/// resolved function.
///
/// The function preserves caller-saved registers and optionally SIMD registers
/// (VFP) depending on the target features.
///
/// # Safety
/// This function uses naked assembly and must be called with the correct
/// stack layout set up by the PLT stub code.
#[cfg(target_feature = "vfp2")]
#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
        // sp has original lr (4 bytes)
        // push r0-r4 (5 regs, 20 bytes). sp aligned to 8 bytes (aligned - 24).
        push {{r0, r1, r2, r3, r4}}
        vpush {{d0, d1, d2, d3, d4, d5, d6, d7}}
        
        // r0 = link_map (GOT[1])
        ldr r0, [lr, #-4]
        
        // r1 = index
        add r1, lr, #4
        sub r1, ip, r1
        lsr r1, r1, #2
        
        blx {0}
        
        mov ip, r0
        
        vpop {{d0, d1, d2, d3, d4, d5, d6, d7}}
        pop {{r0, r1, r2, r3, r4, lr}}
        bx ip
        ",
        sym crate::relocation::dl_fixup,
    )
}

#[cfg(not(target_feature = "vfp2"))]
#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
        push {{r0, r1, r2, r3, r4}}
        
        ldr r0, [lr, #-4]
        
        add r1, lr, #4
        sub r1, ip, r1
        lsr r1, r1, #2
        
        blx {0}
        
        mov ip, r0
        pop {{r0, r1, r2, r3, r4, lr}}
        bx ip
        ",
        sym crate::relocation::dl_fixup,
    )
}

/// Static TLSDESC resolver dummy for ARM.
pub(crate) extern "C" fn tlsdesc_resolver_static() {
    unimplemented!("TLSDESC is not supported on ARM yet");
}

/// Dynamic TLSDESC resolver dummy for ARM.
pub(crate) extern "C" fn tlsdesc_resolver_dynamic() {
    unimplemented!("TLSDESC is not supported on ARM yet");
}

/// Map arm relocation type to human readable name
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_ARM_NONE => "R_ARM_NONE",
        R_ARM_ABS32 => "R_ARM_ABS32",
        R_ARM_GLOB_DAT => "R_ARM_GLOB_DAT",
        R_ARM_JUMP_SLOT => "R_ARM_JUMP_SLOT",
        R_ARM_RELATIVE => "R_ARM_RELATIVE",
        R_ARM_IRELATIVE => "R_ARM_IRELATIVE",
        R_ARM_COPY => "R_ARM_COPY",
        _ => "UNKNOWN",
    }
}
