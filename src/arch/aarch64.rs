//! AArch64 architecture-specific ELF relocation and dynamic linking support.
//!
//! This module provides AArch64 specific implementations for ELF relocation,
//! dynamic linking, and procedure linkage table (PLT) handling.

use elf::abi::*;

/// The ELF machine type for AArch64 architecture.
pub const EM_ARCH: u16 = EM_AARCH64;
/// Offset for TLS Dynamic Thread Vector.
/// For AArch64, this is 0 as the TCB (Thread Control Block) comes first.
pub const TLS_DTV_OFFSET: usize = 0;

/// Relative relocation type - add base address to relative offset.
pub const REL_RELATIVE: u32 = R_AARCH64_RELATIVE;
/// GOT entry relocation type - set GOT entry to symbol address.
pub const REL_GOT: u32 = R_AARCH64_GLOB_DAT;
/// TLS DTPMOD relocation type - set to TLS module ID.
pub const REL_DTPMOD: u32 = R_AARCH64_TLS_DTPMOD;
/// Symbolic relocation type - set to absolute symbol address.
pub const REL_SYMBOLIC: u32 = R_AARCH64_ABS64;
/// PLT jump slot relocation type - set PLT entry to symbol address.
pub const REL_JUMP_SLOT: u32 = R_AARCH64_JUMP_SLOT;
/// TLS DTPOFF relocation type - set to TLS offset relative to DTV.
pub const REL_DTPOFF: u32 = R_AARCH64_TLS_DTPREL;
/// IRELATIVE relocation type - call function to get address.
pub const REL_IRELATIVE: u32 = R_AARCH64_IRELATIVE;
/// COPY relocation type - copy data from shared object.
pub const REL_COPY: u32 = R_AARCH64_COPY;
/// TLS TPOFF relocation type - set to TLS offset relative to thread pointer.
pub const REL_TPOFF: u32 = R_AARCH64_TLS_TPREL;
/// TLSDESC relocation type - set to a function pointer and an argument.
pub const REL_TLSDESC: u32 = R_AARCH64_TLSDESC;

/// Get the current thread pointer using architecture-specific register.
#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp);
    }
    tp
}

/// Offset in GOT for dynamic library handle.
pub(crate) const DYLIB_OFFSET: usize = 1;
/// Offset in GOT for resolver function pointer.
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 2;

/// Dynamic linker runtime resolver for AArch64 PLT entries.
///
/// This function is called when a PLT entry needs to resolve a symbol address
/// at runtime. It saves the current register state including SIMD registers,
/// calls the dynamic linker resolution function, and then restores the state
/// before jumping to the resolved function.
///
/// The function preserves all caller-saved registers (x0-x8) and SIMD registers
/// (q0-q7) to ensure compatibility with the AArch64 calling convention.
///
/// # Safety
/// This function uses naked assembly and must be called with the correct
/// stack layout set up by the PLT stub code.
#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
    // ==========================================
    // 1. 保存上下文 (Context Save)
    // ==========================================
    // 需要保存:
    // - x0-x7 (整数参数)
    // - x8 (间接返回值地址，必须保存!)
    // - q0-q7 (浮点/向量参数，必须保存!)
    // 总计空间需求:
    // Q regs: 8 * 16 = 128 bytes
    // X regs: 9 * 8  = 72 bytes
    // Padding: 对齐到 16 字节 -> 总共需要 208 字节
    
    sub sp, sp, #208

    // 保存整数寄存器
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    str x8,     [sp, #64]

    // 保存向量寄存器
    stp q0, q1, [sp, #80]
    stp q2, q3, [sp, #112]
    stp q4, q5, [sp, #144]
    stp q6, q7, [sp, #176]

    // ==========================================
    // 2. 准备 dl_fixup 参数
    // ==========================================
    // 目标: dl_fixup(struct link_map *l, ElfW(Word) reloc_index)
    
    // 【参数 1: link_map】
    // 标准 PLT0 保证 x16 指向 GOT[2]。
    // link_map 位于 GOT[1]，即 x16 - 8。
    ldr x0, [x16, #-8]

    // 【参数 2: reloc_index】
    // 计算公式: index = (&GOT[n] - &GOT[3]) / 8
    // - &GOT[n] 存储在 [sp + 208] (PLT0 压入的 x16)
    // - &GOT[3] 等于 x16 + 8 (因为 x16 是 GOT[2])
    
    ldr x10, [sp, #208]   // 从旧栈顶读取 &GOT[n]
    add x11, x16, #8      // 计算 &GOT[3] 的地址
    sub x1, x10, x11      // x1 = 字节偏移量
    lsr x1, x1, #3        // x1 = 偏移量 / 8 (得到索引)

    // 调用解析函数
    bl {dl_fixup}

    // x0 返回解析后的实际函数地址，暂存到 x17 (x17 是 caller-saved,可以随便用)
    mov x17, x0

    // ==========================================
    // 3. 恢复上下文 (Context Restore)
    // ==========================================
    ldp q0, q1, [sp, #80]
    ldp q2, q3, [sp, #112]
    ldp q4, q5, [sp, #144]
    ldp q6, q7, [sp, #176]

    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldr x8,     [sp, #64]

    // ==========================================
    // 4. 栈清理与跳转
    // ==========================================
    // 回收我们分配的 208 字节
    add sp, sp, #208

    // 弹出 PLT0 压入的 pair (x16, lr)
    // 注意：x16 (GOT entry) 已经没用了，但 LR (x30) 必须恢复
    ldp x16, x30, [sp], #16

    // 跳转到解析后的地址
    br x17
        ",
        dl_fixup = sym crate::relocation::dl_fixup,
    )
}

/// Static TLSDESC resolver for AArch64.
///
/// This function is called for TLSDESC relocations when the symbol is
/// resolved to a static offset. It returns the offset stored in the
/// second word of the descriptor.
///
/// According to the AArch64 TLSDESC ABI:
/// - x0: address of the TLSDESC structure
/// - returns: offset in x0
/// - All other registers preserved.
#[unsafe(naked)]
pub(crate) extern "C" fn tlsdesc_resolver_static() {
    core::arch::naked_asm!("ldr x0, [x0, #8]", "ret");
}

/// Dynamic TLSDESC resolver for AArch64.
///
/// According to the AArch64 TLSDESC ABI:
/// - x0: address of the TLSDESC structure
/// - [x0, #8]: pointer to TlsDescDynamicArg
/// - returns: offset in x0 (addr - TP)
/// - All other registers preserved.
#[unsafe(naked)]
pub(crate) extern "C" fn tlsdesc_resolver_dynamic() {
    core::arch::naked_asm!(
        "
        // Save all registers that must be preserved.
        // x0 is the descriptor address, we need it but can clobber it for return.
        // x1-x18 must be preserved.
        // x30 (LR) must be preserved around the call.
        // q0-q7 must be preserved.
        
        sub sp, sp, #288
        stp x1, x2, [sp, #0]
        stp x3, x4, [sp, #16]
        stp x5, x6, [sp, #32]
        stp x7, x8, [sp, #48]
        stp x9, x10, [sp, #64]
        stp x11, x12, [sp, #80]
        stp x13, x14, [sp, #96]
        stp x15, x16, [sp, #112]
        stp x17, x18, [sp, #128]
        str x30,      [sp, #144]
        stp q0, q1, [sp, #160]
        stp q2, q3, [sp, #192]
        stp q4, q5, [sp, #224]
        stp q6, q7, [sp, #256]

        ldr x1, [x0, #8] // Get TlsDescDynamicArg pointer
        ldr x16, [x1]    // Get tls_get_addr pointer
        add x0, x1, #8   // Get pointer to TlsIndex (first arg of tls_get_addr)
        blr x16          // Call tls_get_addr
        
        mrs x1, tpidr_el0
        sub x0, x0, x1
        // x0 now contains the desired offset.
        
        ldp q6, q7, [sp, #256]
        ldp q4, q5, [sp, #224]
        ldp q2, q3, [sp, #192]
        ldp q0, q1, [sp, #160]
        ldr x30,      [sp, #144]
        ldp x17, x18, [sp, #128]
        ldp x15, x16, [sp, #112]
        ldp x13, x14, [sp, #96]
        ldp x11, x12, [sp, #80]
        ldp x9, x10, [sp, #64]
        ldp x7, x8, [sp, #48]
        ldp x5, x6, [sp, #32]
        ldp x3, x4, [sp, #16]
        ldp x1, x2, [sp, #0]
        add sp, sp, #288
        ret
        ",
    )
}

/// Map aarch64 relocation type to human readable name
pub(crate) fn rel_type_to_str(r_type: usize) -> &'static str {
    match r_type as u32 {
        R_AARCH64_NONE => "R_AARCH64_NONE",
        R_AARCH64_ABS64 => "R_AARCH64_ABS64",
        R_AARCH64_GLOB_DAT => "R_AARCH64_GLOB_DAT",
        R_AARCH64_RELATIVE => "R_AARCH64_RELATIVE",
        R_AARCH64_JUMP_SLOT => "R_AARCH64_JUMP_SLOT",
        R_AARCH64_IRELATIVE => "R_AARCH64_IRELATIVE",
        R_AARCH64_COPY => "R_AARCH64_COPY",
        R_AARCH64_TLS_TPREL => "R_AARCH64_TLS_TPREL",
        R_AARCH64_TLSDESC => "R_AARCH64_TLSDESC",
        _ => "UNKNOWN",
    }
}
