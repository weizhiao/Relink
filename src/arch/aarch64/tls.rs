#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp);
    }
    tp
}

#[unsafe(naked)]
pub(crate) extern "C" fn tlsdesc_resolver_static() {
    core::arch::naked_asm!("ldr x0, [x0, #8]", "ret");
}

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
