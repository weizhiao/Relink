#![no_main]
#![no_std]

use core::panic::PanicInfo;

unsafe extern "C" {
    fn fixture_value() -> i32;
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    core::hint::black_box(unsafe { fixture_value() });
    loop {}
}
