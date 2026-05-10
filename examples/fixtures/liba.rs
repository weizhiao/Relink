#![no_std]
#![crate_type = "cdylib"]
#![crate_name = "a"]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
fn a() -> i32 {
    1
}

#[unsafe(no_mangle)]
fn print(_: &str) {}

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
