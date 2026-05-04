#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("mov {}, gs:0", out(reg) tp);
    }
    tp
}

pub(crate) extern "C" fn tlsdesc_resolver_static() {
    unimplemented!("TLSDESC is not supported on x86 yet");
}

pub(crate) extern "C" fn tlsdesc_resolver_dynamic() {
    unimplemented!("TLSDESC is not supported on x86 yet");
}
