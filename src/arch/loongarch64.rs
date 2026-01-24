//! LoongArch 64-bit architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides LoongArch 64-bit specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.
//!
//! Reference: https://loongson.github.io/LoongArch-Documentation/LoongArch-ELF-ABI-CN.html

/// Custom relocation type constants for LoongArch 64-bit.
/// These are defined locally as they may not be available in all elf crate versions.
const EM_LARCH: u16 = 258;
const R_LARCH_64: u32 = 2;
const R_LARCH_RELATIVE: u32 = 3;
const R_LARCH_COPY: u32 = 4;
const R_LARCH_JUMP_SLOT: u32 = 5;
const R_LARCH_TLS_DTPMOD64: u32 = 7;
const R_LARCH_TLS_DTPREL64: u32 = 9;
const R_LARCH_TLS_TPREL64: u32 = 11;
const R_LARCH_IRELATIVE: u32 = 12;

/// The ELF machine type for LoongArch architecture.
pub const EM_ARCH: u16 = EM_LARCH;
/// Offset for TLS Dynamic Thread Vector.
/// For LoongArch, this is 0 as the TCB (Thread Control Block) comes first.
pub const TLS_DTV_OFFSET: usize = 0;

/// Symbolic relocation type - set to absolute symbol address.
pub const REL_SYMBOLIC: u32 = R_LARCH_64;
/// Relative relocation type - add base address to relative offset.
pub const REL_RELATIVE: u32 = R_LARCH_RELATIVE;
/// COPY relocation type - copy data from shared object.
pub const REL_COPY: u32 = R_LARCH_COPY;
/// PLT jump slot relocation type - set PLT entry to symbol address.
pub const REL_JUMP_SLOT: u32 = R_LARCH_JUMP_SLOT;
/// TLS DTPMOD relocation type - set to TLS module ID.
pub const REL_DTPMOD: u32 = R_LARCH_TLS_DTPMOD64;
/// TLS DTPOFF relocation type - set to TLS offset relative to DTV.
pub const REL_DTPOFF: u32 = R_LARCH_TLS_DTPREL64;
/// IRELATIVE relocation type - call function to get address.
pub const REL_IRELATIVE: u32 = R_LARCH_IRELATIVE;
/// TLS TPOFF relocation type - set to TLS offset relative to thread pointer.
pub const REL_TPOFF: u32 = R_LARCH_TLS_TPREL64;

/// Get the current thread pointer using architecture-specific register.
#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("move {}, $tp", out(reg) tp);
    }
    tp
}

/// GOT entry relocation type - set GOT entry to symbol address.
pub const REL_GOT: u32 = R_LARCH_64;

pub(crate) const DYLIB_OFFSET: usize = 1;
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 0;

#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
        addi.d  $sp, $sp, -224
        st.d    $ra, $sp, 0
        st.d    $a0, $sp, 8
        st.d    $a1, $sp, 16
        st.d    $a2, $sp, 24
        st.d    $a3, $sp, 32
        st.d    $a4, $sp, 40
        st.d    $a5, $sp, 48
        st.d    $a6, $sp, 56
        st.d    $a7, $sp, 64
        st.d    $t0, $sp, 72
        st.d    $t1, $sp, 80
        // 16 bytes padding to align vr0 to 16 bytes (sp + 96)
        vst     $vr0, $sp, 96
        vst     $vr1, $sp, 112
        vst     $vr2, $sp, 128
        vst     $vr3, $sp, 144
        vst     $vr4, $sp, 160
        vst     $vr5, $sp, 176
        vst     $vr6, $sp, 192
        vst     $vr7, $sp, 208

        move    $a0, $t0
        srli.d  $a1, $t1, 3
        la.local $t2, {0}
        jirl    $ra, $t2, 0

        move    $t2, $a0

        ld.d    $ra, $sp, 0
        ld.d    $a0, $sp, 8
        ld.d    $a1, $sp, 16
        ld.d    $a2, $sp, 24
        ld.d    $a3, $sp, 32
        ld.d    $a4, $sp, 40
        ld.d    $a5, $sp, 48
        ld.d    $a6, $sp, 56
        ld.d    $a7, $sp, 64
        ld.d    $t0, $sp, 72
        ld.d    $t1, $sp, 80
        vld     $vr0, $sp, 96
        vld     $vr1, $sp, 112
        vld     $vr2, $sp, 128
        vld     $vr3, $sp, 144
        vld     $vr4, $sp, 160
        vld     $vr5, $sp, 176
        vld     $vr6, $sp, 192
        vld     $vr7, $sp, 208

        addi.d  $sp, $sp, 224

        jr      $t2
	",
        sym crate::relocation::dl_fixup,
    )
}

/// Map loongarch64 relocation types to human readable names
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_LARCH_64 => "R_LARCH_64",
        R_LARCH_RELATIVE => "R_LARCH_RELATIVE",
        R_LARCH_COPY => "R_LARCH_COPY",
        R_LARCH_JUMP_SLOT => "R_LARCH_JUMP_SLOT",
        R_LARCH_TLS_DTPMOD64 => "R_LARCH_TLS_DTPMOD64",
        R_LARCH_TLS_DTPREL64 => "R_LARCH_TLS_DTPREL64",
        R_LARCH_IRELATIVE => "R_LARCH_IRELATIVE",
        _ => "UNKNOWN",
    }
}
