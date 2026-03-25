pub const TLS_DTV_OFFSET: usize = 0;
pub const REL_DTPMOD: u32 = 35;
pub const REL_DTPOFF: u32 = 36;
pub const REL_TPOFF: u32 = 14;
pub const REL_TLSDESC: u32 = 0;

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
