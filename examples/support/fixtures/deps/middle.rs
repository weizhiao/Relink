#![no_std]
#![crate_type = "cdylib"]
#![crate_name = "middle"]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

unsafe extern "Rust" {
    fn print(s: &str);
    static HELLO: &'static str;
}

unsafe extern "C" {
    fn base_value() -> i32;
}

#[unsafe(no_mangle)]
pub extern "C" fn middle_value() -> i32 {
    unsafe {
        print("call middle_value()");
        print(HELLO);
        base_value() + 1
    }
}
