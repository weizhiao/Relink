pub const TLS_DTV_OFFSET: usize = 0;
pub const REL_DTPMOD: u32 = elf::abi::R_RISCV_TLS_DTPMOD32;
pub const REL_DTPOFF: u32 = elf::abi::R_RISCV_TLS_DTPREL32;
pub const REL_TPOFF: u32 = elf::abi::R_RISCV_TLS_TPREL32;
pub const REL_TLSDESC: u32 = 0;

#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    let tp: *mut u8;
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) tp);
    }
    tp
}

pub(crate) extern "C" fn tlsdesc_resolver_static() {
    unimplemented!("TLSDESC is not supported on RISC-V 32 yet");
}

pub(crate) extern "C" fn tlsdesc_resolver_dynamic() {
    unimplemented!("TLSDESC is not supported on RISC-V 32 yet");
}
