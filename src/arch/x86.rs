//! x86 (32-bit) architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides x86 32-bit specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

use elf::abi::*;

/// Custom relocation type constants for x86 (32-bit).
/// These are defined locally since they may not be available in all elf crate versions.
const R_386_32: u32 = 1;
const R_386_GLOB_DAT: u32 = 6;
const R_386_JMP_SLOT: u32 = 7;
const R_386_RELATIVE: u32 = 8;
const R_386_COPY: u32 = 5;
const R_386_TLS_DTPMOD32: u32 = 35;
const R_386_TLS_DTPOFF32: u32 = 36;
const R_386_IRELATIVE: u32 = 42;
const R_386_TLS_TPOFF: u32 = 14;

/// The ELF machine type for x86 architecture.
pub const EM_ARCH: u16 = EM_386;
pub const TLS_DTV_OFFSET: usize = 0;

pub const REL_RELATIVE: u32 = R_386_RELATIVE;
pub const REL_GOT: u32 = R_386_GLOB_DAT;
pub const REL_DTPMOD: u32 = R_386_TLS_DTPMOD32;
pub const REL_SYMBOLIC: u32 = R_386_32;
pub const REL_JUMP_SLOT: u32 = R_386_JMP_SLOT;
pub const REL_DTPOFF: u32 = R_386_TLS_DTPOFF32;
pub const REL_IRELATIVE: u32 = R_386_IRELATIVE;
pub const REL_COPY: u32 = R_386_COPY;
pub const REL_TPOFF: u32 = R_386_TLS_TPOFF;

/// Get the current thread pointer using architecture-specific register.
#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("mov {}, gs:0", out(reg) tp);
    }
    tp
}

pub(crate) const DYLIB_OFFSET: usize = 1;
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 2;

#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
    // 保存调用者保存的寄存器
    push eax
    push ecx
    push edx

    // 此时栈布局:
    // [esp]      : edx
    // [esp + 4]  : ecx
    // [esp + 8]  : eax
    // [esp + 12] : link_map (由 PLT0 压入)
    // [esp + 16] : reloc_offset (由 PLT 条目压入)
    // [esp + 20] : 返回地址

    // 准备 dl_fixup(link_map, reloc_idx) 的参数
    // reloc_idx = reloc_offset / 8 (x86 Rel 条目大小为 8)
    mov eax, [esp + 16]
    shr eax, 3
    
    push eax         // 参数 2: reloc_idx
    push dword ptr [esp + 16]  // 参数 1: link_map (原本在 +12，现在因为 push eax 变成了 +16)

    call {0}

    // 清理参数
    add esp, 8

    // eax 现在包含解析后的地址。将其存入栈中原本 reloc_offset 的位置。
    mov [esp + 16], eax

    // 恢复寄存器
    pop edx
    pop ecx
    pop eax

    // 跳过 link_map，此时栈顶是解析后的地址
    add esp, 4

    // 弹出解析后的地址并跳转
    ret
    ",
        sym crate::relocation::dl_fixup,
    )
}

/// Map x86 relocation type to human readable name
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_386_32 => "R_386_32",
        R_386_GLOB_DAT => "R_386_GLOB_DAT",
        R_386_COPY => "R_386_COPY",
        R_386_JMP_SLOT => "R_386_JMP_SLOT",
        R_386_RELATIVE => "R_386_RELATIVE",
        R_386_TLS_DTPMOD32 => "R_386_TLS_DTPMOD32",
        R_386_TLS_DTPOFF32 => "R_386_TLS_DTPOFF32",
        R_386_IRELATIVE => "R_386_IRELATIVE",
        R_386_TLS_TPOFF => "R_386_TLS_TPOFF",
        _ => "UNKNOWN",
    }
}
