#![no_std]
#![crate_type = "cdylib"]
#![crate_name = "leaf"]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

unsafe extern "Rust" {
    fn print(s: &str);
}

unsafe extern "C" {
    fn middle_value() -> i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn leaf_value() -> i32 {
    unsafe {
        print("call leaf_value()");
        middle_value() + 1
    }
}
