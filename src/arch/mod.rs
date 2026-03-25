//! Architecture-specific definitions and relocation logic.
//!
//! This module contains target-specific code for various CPU architectures
//! supported by the ELF loader, including relocation handlers, PLT entry definitions,
//! and instruction-specific fixups.
cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")]{
        mod x86_64;
        pub use x86_64::*;
    }else if #[cfg(target_arch = "riscv64")]{
        mod riscv64;
        pub use riscv64::*;
    }else if #[cfg(target_arch = "riscv32")]{
        mod riscv32;
        pub use riscv32::*;
    }else if #[cfg(target_arch="aarch64")]{
        mod aarch64;
        pub use aarch64::*;
    }else if #[cfg(target_arch="loongarch64")]{
        mod loongarch64;
        pub use loongarch64::*;
    }else if #[cfg(target_arch = "x86")]{
        mod x86;
        pub use x86::*;
    }else if #[cfg(target_arch = "arm")]{
        mod arm;
        pub use arm::*;
    }
}

pub const REL_NONE: u32 = 0;

#[cfg(feature = "object")]
pub(crate) mod object;

#[cfg(feature = "lazy-binding")]
#[inline]
pub(crate) fn prepare_lazy_bind(got: *mut usize, dylib: crate::relocation::RelocAddr) {
    // 这是安全的，延迟绑定时库是存在的
    unsafe {
        got.add(DYLIB_OFFSET).write(dylib.into_inner());
        got.add(RESOLVE_FUNCTION_OFFSET)
            .write(dl_runtime_resolve as *const () as usize);
    }
}
