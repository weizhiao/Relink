pub(crate) const DYLIB_OFFSET: usize = 1;
pub(crate) const RESOLVE_FUNCTION_OFFSET: usize = 2;

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
