//! RISC-V 32-bit architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides RISC-V 32-bit specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

use elf::abi::*;

/// The ELF machine type for RISC-V architecture.
pub const EM_ARCH: u16 = EM_RISCV;
/// Offset for TLS Dynamic Thread Vector.
/// In our software-based TLS implementation, we use 0 offset for simplicity.
pub const TLS_DTV_OFFSET: usize = 0;

/// Relative relocation type - add base address to relative offset.
pub const REL_RELATIVE: u32 = R_RISCV_RELATIVE;
/// GOT entry relocation type - set GOT entry to symbol address.
pub const REL_GOT: u32 = R_RISCV_32;
/// TLS DTPMOD relocation type - set to TLS module ID.
pub const REL_DTPMOD: u32 = R_RISCV_TLS_DTPMOD32;
/// Symbolic relocation type - set to absolute symbol address.
pub const REL_SYMBOLIC: u32 = R_RISCV_32;
/// PLT jump slot relocation type - set PLT entry to symbol address.
pub const REL_JUMP_SLOT: u32 = R_RISCV_JUMP_SLOT;
/// TLS DTPOFF relocation type - set to TLS offset relative to DTV.
pub const REL_DTPOFF: u32 = R_RISCV_TLS_DTPREL32;
/// IRELATIVE relocation type - call function to get address.
pub const REL_IRELATIVE: u32 = R_RISCV_IRELATIVE;
/// COPY relocation type - copy data from shared object.
pub const REL_COPY: u32 = R_RISCV_COPY;
/// TLS TPOFF relocation type - set to TLS offset relative to thread pointer.
pub const REL_TPOFF: u32 = R_RISCV_TLS_TPREL32;

/// Get the current thread pointer using architecture-specific register.
#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) tp);
    }
    tp
}

pub(crate) const DYLIB_OFFSET: usize = 1;
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 0;

macro_rules! riscv32_dl_runtime_resolve {
    ($save_fprs:expr, $restore_fprs:expr) => {
        #[unsafe(naked)]
        pub(crate) extern "C" fn dl_runtime_resolve() {
            core::arch::naked_asm!(
                "
                // 保存整数参数寄存器
                // ra, a0-a7: 9 * 4 = 36 bytes
                // 栈帧总大小设为 112 字节以保持 16 字节对齐
                addi sp,sp,-112
                sw ra,0(sp)
                sw a0,4(sp)
                sw a1,8(sp)
                sw a2,12(sp)
                sw a3,16(sp)
                sw a4,20(sp)
                sw a5,24(sp)
                sw a6,28(sp)
                sw a7,32(sp)
                ",
                $save_fprs,
                "
                // 这两个是plt代码设置的
                mv a0,t0
                srli a1,t1,3
                // 调用重定位函数
                call {0}
                // 恢复参数寄存器
                mv t1,a0
                lw ra,0(sp)
                lw a0,4(sp)
                lw a1,8(sp)
                lw a2,12(sp)
                lw a3,16(sp)
                lw a4,20(sp)
                lw a5,24(sp)
                lw a6,28(sp)
                lw a7,32(sp)
                ",
                $restore_fprs,
                "
                addi sp,sp,112
                // 执行真正的函数
                jr t1
                ",
                sym crate::relocation::dl_fixup,
            )
        }
    };
}

#[cfg(target_feature = "d")]
riscv32_dl_runtime_resolve!(
    "
    fsd fa0,40(sp)
    fsd fa1,48(sp)
    fsd fa2,56(sp)
    fsd fa3,64(sp)
    fsd fa4,72(sp)
    fsd fa5,80(sp)
    fsd fa6,88(sp)
    fsd fa7,96(sp)
    ",
    "
    fld fa0,40(sp)
    fld fa1,48(sp)
    fld fa2,56(sp)
    fld fa3,64(sp)
    fld fa4,72(sp)
    fld fa5,80(sp)
    fld fa6,88(sp)
    fld fa7,96(sp)
    "
);

#[cfg(all(target_feature = "f", not(target_feature = "d")))]
riscv32_dl_runtime_resolve!(
    "
    fsw fa0,40(sp)
    fsw fa1,44(sp)
    fsw fa2,48(sp)
    fsw fa3,52(sp)
    fsw fa4,56(sp)
    fsw fa5,60(sp)
    fsw fa6,64(sp)
    fsw fa7,68(sp)
    ",
    "
    flw fa0,40(sp)
    flw fa1,44(sp)
    flw fa2,48(sp)
    flw fa3,52(sp)
    flw fa4,56(sp)
    flw fa5,60(sp)
    flw fa6,64(sp)
    flw fa7,68(sp)
    "
);

#[cfg(not(target_feature = "f"))]
riscv32_dl_runtime_resolve!("", "");

/// Map riscv32 relocation types to human readable names
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_RISCV_NONE => "R_RISCV_NONE",
        R_RISCV_32 => "R_RISCV_32",
        R_RISCV_RELATIVE => "R_RISCV_RELATIVE",
        R_RISCV_COPY => "R_RISCV_COPY",
        R_RISCV_JUMP_SLOT => "R_RISCV_JUMP_SLOT",
        R_RISCV_IRELATIVE => "R_RISCV_IRELATIVE",
        _ => "UNKNOWN",
    }
}
