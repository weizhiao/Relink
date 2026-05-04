#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("move {}, $tp", out(reg) tp);
    }
    tp
}

pub(crate) extern "C" fn tlsdesc_resolver_static() {
    unimplemented!("TLSDESC is not supported on LoongArch64 yet");
}

pub(crate) extern "C" fn tlsdesc_resolver_dynamic() {
    unimplemented!("TLSDESC is not supported on LoongArch64 yet");
}
