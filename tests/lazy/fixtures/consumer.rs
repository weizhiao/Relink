#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

unsafe extern "C" {
    fn first() -> i32;
    fn second() -> i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn call_first() -> i32 {
    unsafe { first() }
}

#[unsafe(no_mangle)]
pub extern "C" fn call_second() -> i32 {
    unsafe { second() }
}
