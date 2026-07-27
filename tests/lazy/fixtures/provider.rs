#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn first() -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn second() -> i32 {
    2
}
