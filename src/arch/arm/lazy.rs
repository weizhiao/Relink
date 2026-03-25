pub(crate) const DYLIB_OFFSET: usize = 1;
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
#[unsafe(naked)]
pub(crate) extern "C" fn dl_runtime_resolve() {
    core::arch::naked_asm!(
        "
        // sp has original lr (4 bytes)
        // push r0-r4 (5 regs, 20 bytes). sp aligned to 8 bytes (aligned - 24).
        push {{r0, r1, r2, r3, r4}}
        ",
        #[cfg(target_feature = "vfp2")]
        "vpush {{d0, d1, d2, d3, d4, d5, d6, d7}}",
        "
        // r0 = link_map (GOT[1])
        // Case for thumb-1 compatibility: mov + sub + ldr
        mov r0, lr
        subs r0, r0, #4
        ldr r0, [r0]
        
        // r1 = index
        mov r1, lr
        adds r1, r1, #4
        mov r2, ip
        subs r1, r2, r1
        lsrs r1, r1, #2
        
        bl {fixup}
        
        mov ip, r0
        ",
        #[cfg(target_feature = "vfp2")]
        "vpop {{d0, d1, d2, d3, d4, d5, d6, d7}}",
        "
 		pop {{r0, r1, r2, r3, r4, lr}}
        bx ip
        ",
        fixup = sym crate::relocation::dl_fixup,
    )
}
