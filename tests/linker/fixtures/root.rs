#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

unsafe extern "C" {
    fn trace(message: *const u8, len: usize);
    fn dependent_value() -> i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn root_value() -> i32 {
    unsafe {
        trace(b"root".as_ptr(), 4);
        dependent_value() + 1
    }
}
