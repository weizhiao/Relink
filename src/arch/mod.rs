//! Architecture-specific definitions and relocation logic.
//!
//! This module contains target-specific code for various CPU architectures
//! supported by the ELF loader, including relocation handlers, PLT entry definitions,
//! and instruction-specific fixups.
// All architecture submodules are declared unconditionally so that their
// pure-data items (relocation type numbers, `EM_ARCH`, ...) are reachable
// from any host. Platform-specific code inside each submodule (naked
// assembly in `lazy.rs` / `tls.rs`) is gated on `target_arch` at the
// submodule level, so this unconditional declaration is safe.
//
// The `cfg_if!` block below still picks exactly one submodule to re-export
// at the crate-root level, preserving the `crate::arch::EM_ARCH` etc. paths
// and the `crate::arch::NativeArch` host-architecture marker.
// `NativeArch` is the canonical "host relocation backend" name used by
// `Loader`'s default `Arch` parameter and by `elf/defs.rs`.
//
// `#[cfg_attr(not(target_arch = ...), allow(dead_code))]` silences the
// "never used" warnings inside non-native submodules: their items are only
// referenced by the cross-architecture relocation backends in
// `crate::relocation::arch`, which themselves only get used by downstream
// crates that perform cross-arch relocation. From this crate's perspective
// when built for a single host, the items in non-native submodules look
// dead but are intentionally kept available.
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub mod aarch64;
#[cfg_attr(not(target_arch = "arm"), allow(dead_code))]
pub mod arm;
#[cfg_attr(not(target_arch = "loongarch64"), allow(dead_code))]
pub mod loongarch64;
#[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
pub mod riscv32;
#[cfg_attr(not(target_arch = "riscv64"), allow(dead_code))]
pub mod riscv64;
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
pub mod x86;
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub mod x86_64;

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")]{
        pub use x86_64::*;
        // The host's architecture marker is republished as
        // `crate::arch::NativeArch`. Every architecture-specific trait impl
        // (`RelocationArch`, `RelocationValueProvider`, `GotPltTarget`)
        // lives on this single ZST in `arch/<host>/relocation.rs`. Because
        // `SUPPORTS_NATIVE_RUNTIME` on each per-ISA ZST is `cfg!(target_arch
        // = "<isa>")`, this re-export is the only place that turns "host
        // runtime hooks enabled" on.
        pub use x86_64::relocation::X86_64Arch as NativeArch;
    }else if #[cfg(target_arch = "riscv64")]{
        pub use riscv64::*;
        pub use riscv64::relocation::RiscV64Arch as NativeArch;
    }else if #[cfg(target_arch = "riscv32")]{
        pub use riscv32::*;
        pub use riscv32::relocation::RiscV32Arch as NativeArch;
    }else if #[cfg(target_arch="aarch64")]{
        pub use aarch64::*;
        pub use aarch64::relocation::AArch64Arch as NativeArch;
    }else if #[cfg(target_arch="loongarch64")]{
        pub use loongarch64::*;
        pub use loongarch64::relocation::LoongArch64Arch as NativeArch;
    }else if #[cfg(target_arch = "x86")]{
        pub use x86::*;
        pub use x86::relocation::X86Arch as NativeArch;
    }else if #[cfg(target_arch = "arm")]{
        pub use arm::*;
        pub use arm::relocation::ArmArch as NativeArch;
    }
}


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
