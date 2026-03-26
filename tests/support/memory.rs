#![allow(dead_code)]

pub(crate) fn read_native_word(addr: usize) -> u64 {
    unsafe {
        if core::mem::size_of::<usize>() == 8 {
            (addr as *const u64).read_unaligned()
        } else {
            (addr as *const u32).read_unaligned() as u64
        }
    }
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
pub(crate) fn read_u64(ptr: *const u8) -> u64 {
    unsafe { (ptr as *const u64).read_unaligned() }
}

#[cfg(all(feature = "object", target_arch = "x86_64"))]
pub(crate) fn read_i32(ptr: *const u8) -> i32 {
    unsafe { (ptr as *const i32).read_unaligned() }
}
