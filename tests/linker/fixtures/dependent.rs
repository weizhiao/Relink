#![no_std]

use core::panic::PanicInfo;

#[repr(C)]
struct Message {
    bytes: *const u8,
    len: usize,
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

unsafe extern "C" {
    fn trace(message: *const u8, len: usize);
    fn provider_value() -> i32;
    static MESSAGE: Message;
}

#[unsafe(no_mangle)]
pub extern "C" fn dependent_value() -> i32 {
    unsafe {
        trace(MESSAGE.bytes, MESSAGE.len);
        provider_value() + 1
    }
}
