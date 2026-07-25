#[inline(always)]
pub(crate) unsafe fn get_thread_pointer() -> *mut u8 {
    unimplemented!("native Xtensa TLS is not supported yet")
}

pub(crate) extern "C" fn tlsdesc_resolver_static() {
    unimplemented!("TLSDESC is not supported on Xtensa yet");
}

pub(crate) extern "C" fn tlsdesc_resolver_undefweak() {
    unimplemented!("TLSDESC is not supported on Xtensa yet");
}

pub(crate) extern "C" fn tlsdesc_resolver_dynamic() {
    unimplemented!("TLSDESC is not supported on Xtensa yet");
}
