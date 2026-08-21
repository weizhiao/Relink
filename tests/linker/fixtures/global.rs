#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

unsafe extern "C" {
    fn provider_value() -> i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn global_value() -> i32 {
    unsafe { provider_value() + 1 }
}
