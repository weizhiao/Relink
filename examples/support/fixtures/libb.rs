#![no_std]
#![crate_type = "cdylib"]
#![crate_name = "b"]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

unsafe extern "Rust" {
    fn print(s: &str);
    fn a() -> i32;
    static HELLO: &'static str;
}

#[unsafe(no_mangle)]
fn b() -> i32 {
    unsafe {
        print("call b()");
        print(HELLO);
        a() + 1
    }
}
