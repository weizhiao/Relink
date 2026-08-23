//! Minimal syscall-backed helpers used by the `mini-loader` executable.
//!
//! The crate intentionally avoids the standard library and exposes only the
//! output and termination primitives needed while bootstrapping an ELF image.
#![no_std]
#![warn(missing_docs)]

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
/// Writes one UTF-8 encoded character to standard output.
pub fn print_char(c: char) {
    let mut buffer = [0u8; 4];
    let encoded = c.encode_utf8(&mut buffer);
    write_stdout(encoded.as_bytes());
}

#[inline]
/// Writes a string to standard output without allocating.
pub fn print_str(s: &str) {
    write_stdout(s.as_bytes());
}

/// Terminates the process with `status` through the platform syscall ABI.
pub fn exit(status: c_int) -> ! {
    unsafe {
        let _ = raw_syscall!(Sysno::exit, status);
    }
    loop {
        spin_loop();
    }
}

/// Prints `message` and terminates the process with a failure status.
pub fn fatal(message: &str) -> ! {
    print_str(message);
    exit(-1);
}
