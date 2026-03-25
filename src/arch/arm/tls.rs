pub const TLS_DTV_OFFSET: usize = 0;
pub const REL_DTPMOD: u32 = elf::abi::R_ARM_TLS_DTPMOD32;
pub const REL_DTPOFF: u32 = elf::abi::R_ARM_TLS_DTPOFF32;
pub const REL_TPOFF: u32 = elf::abi::R_ARM_TLS_TPOFF32;
pub const REL_TLSDESC: u32 = 0xffff_ffff;

#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("mrc p15, 0, {}, c13, c0, 3", out(reg) tp);
    }
    tp
}

pub(crate) extern "C" fn tlsdesc_resolver_static() {
    unimplemented!("TLSDESC is not supported on ARM yet");
}

pub(crate) extern "C" fn tlsdesc_resolver_dynamic() {
    unimplemented!("TLSDESC is not supported on ARM yet");
}
