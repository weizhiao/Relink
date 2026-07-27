#![no_std]

use core::panic::PanicInfo;

#[repr(C)]
pub struct Message {
    bytes: *const u8,
    len: usize,
}

unsafe impl Sync for Message {}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn provider_value() -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn trace(_: *const u8, _: usize) {}

#[unsafe(no_mangle)]
pub static MESSAGE: Message = Message {
    bytes: b"fixture".as_ptr(),
    len: 7,
};

#[unsafe(no_mangle)]
pub static mut value: [u8; 4] = [1, 2, 3, 4];
