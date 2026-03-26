#![no_std]

use core::{ffi::c_int, hint::spin_loop};
use syscalls::{Sysno, raw_syscall};
mod arch;

#[inline(always)]
fn write_stdout(bytes: &[u8]) {
    unsafe {
        let _ = raw_syscall!(Sysno::write, 1, bytes.as_ptr(), bytes.len());
    }
}

#[inline]
pub fn print_char(c: char) {
    let mut buffer = [0u8; 4];
    let encoded = c.encode_utf8(&mut buffer);
    write_stdout(encoded.as_bytes());
}

#[inline]
pub fn print_str(s: &str) {
    write_stdout(s.as_bytes());
}

pub fn exit(status: c_int) -> ! {
    unsafe {
        let _ = raw_syscall!(Sysno::exit, status);
    }
    loop {
        spin_loop();
    }
}

pub fn fatal(message: &str) -> ! {
    print_str(message);
    exit(-1);
}
