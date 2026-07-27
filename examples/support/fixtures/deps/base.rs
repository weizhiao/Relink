#![no_std]
#![crate_type = "cdylib"]
#![crate_name = "base"]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn base_value() -> i32 {
    1
}

#[unsafe(no_mangle)]
pub fn print(_: &str) {}

#[repr(C)]
pub struct S {
    a: u64,
    b: u32,
    c: u16,
    d: u8,
}

#[unsafe(no_mangle)]
pub extern "C" fn test_identity_struct(x: S) -> S {
    x
}

#[unsafe(no_mangle)]
pub static HELLO: &str = "Hello!";

#[unsafe(no_mangle)]
pub static mut value: [u8; 4] = [1, 2, 3, 4];
