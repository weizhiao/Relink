#![no_std]
#![crate_type = "cdylib"]
#![crate_name = "c"]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

unsafe extern "Rust" {
    fn print(s: &str);
    fn b() -> i32;
}

#[unsafe(no_mangle)]
fn c() -> i32 {
    unsafe {
        print("call c()");
        b() + 1
    }
}
