use elf::abi::*;

pub const TLS_DTV_OFFSET: usize = 0;
pub const REL_DTPMOD: u32 = R_X86_64_DTPMOD64;
pub const REL_DTPOFF: u32 = R_X86_64_DTPOFF64;
pub const REL_TPOFF: u32 = R_X86_64_TPOFF64;
pub const REL_TLSDESC: u32 = R_X86_64_TLSDESC;

pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("mov {}, fs:0", out(reg) tp);
    }
    tp
}

#[unsafe(naked)]
pub(crate) extern "C" fn tlsdesc_resolver_static() {
    core::arch::naked_asm!("mov rax, [rax + 8]", "ret");
}

#[unsafe(naked)]
pub(crate) extern "C" fn tlsdesc_resolver_dynamic() {
    core::arch::naked_asm!(
        "
        // Save all registers that might be clobbered
        push rdi
        push rsi
        push rdx
        push rcx
        push r8
        push r9
        push r10
        push r11

        // Save xmm0-xmm7 (arguments in some conventions)
        sub rsp, 128
        movdqu [rsp + 0], xmm0
        movdqu [rsp + 16], xmm1
        movdqu [rsp + 32], xmm2
        movdqu [rsp + 48], xmm3
        movdqu [rsp + 64], xmm4
        movdqu [rsp + 80], xmm5
        movdqu [rsp + 96], xmm6
        movdqu [rsp + 112], xmm7

        mov rsi, [rax + 8]   // Get TlsDescDynamicArg pointer
        mov rdx, [rsi]       // Get tls_get_addr pointer
        lea rdi, [rsi + 8]   // Get pointer to TlsIndex (first arg of tls_get_addr)
        call rdx             // Call tls_get_addr

        // TP is at fs:0
        mov rcx, fs:0
        sub rax, rcx

        // Restore everything
        movdqu xmm0, [rsp + 0]
        movdqu xmm1, [rsp + 16]
        movdqu xmm2, [rsp + 32]
        movdqu xmm3, [rsp + 48]
        movdqu xmm4, [rsp + 64]
        movdqu xmm5, [rsp + 80]
        movdqu xmm6, [rsp + 96]
        movdqu xmm7, [rsp + 112]
        add rsp, 128

        pop r11
        pop r10
        pop r9
        pop r8
        pop rcx
        pop rdx
        pop rsi
        pop rdi
        ret
        ",
    )
}
