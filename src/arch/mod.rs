//! Architecture-specific definitions and relocation logic.
//!
//! This module contains target-specific code for various CPU architectures
//! supported by the ELF loader, including relocation handlers, PLT entry definitions,
//! and instruction-specific fixups.
// All architecture submodules are declared unconditionally so that their
// pure-data items (relocation type numbers, architecture markers, ...) are reachable
// from any host. Platform-specific code inside each submodule (naked
// assembly in `lazy.rs` / `tls.rs`) is gated on `target_arch` at the
// submodule level, so this unconditional declaration is safe.
//
// The `cfg_if!` block below still picks exactly one submodule to re-export
// at the crate-root level, preserving paths such as `crate::arch::NativeArch`
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

use crate::{
    elf::{ElfClass, ElfMachine, ElfTarget},
    relocation::RelocationArch,
};
use elf::abi::{EM_386, EM_AARCH64, EM_ARM, EM_LOONGARCH, EM_RISCV, EM_X86_64, EM_XTENSA};

/// Runtime tag for a supported target architecture.
///
/// `ArchKind` is used when linker state may contain modules from more than one
/// target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArchKind {
    /// x86-64 (`EM_X86_64`).
    X86_64,
    /// AArch64 (`EM_AARCH64`).
    AArch64,
    /// 64-bit RISC-V (`EM_RISCV` with ELF64 layout).
    RiscV64,
    /// 32-bit RISC-V (`EM_RISCV` with ELF32 layout).
    RiscV32,
    /// LoongArch64 (`EM_LOONGARCH` with ELF64 layout).
    LoongArch64,
    /// 32-bit x86 (`EM_386`).
    X86,
    /// 32-bit ARM (`EM_ARM`).
    Arm,
    /// 32-bit Xtensa (`EM_XTENSA`).
    Xtensa,
}

impl ArchKind {
    /// Returns the architecture kind for the current compilation target.
    #[inline]
    pub const fn native() -> Self {
        <NativeArch as RelocationArch>::KIND
    }

    /// Returns whether this architecture is the current compilation target.
    #[inline]
    pub fn is_native(self) -> bool {
        self == Self::native()
    }

    /// Returns the ELF `e_machine` value for this architecture.
    #[inline]
    pub const fn e_machine(self) -> ElfMachine {
        match self {
            Self::X86_64 => ElfMachine::new(EM_X86_64),
            Self::AArch64 => ElfMachine::new(EM_AARCH64),
            Self::RiscV64 | Self::RiscV32 => ElfMachine::new(EM_RISCV),
            Self::LoongArch64 => ElfMachine::new(EM_LOONGARCH),
            Self::X86 => ElfMachine::new(EM_386),
            Self::Arm => ElfMachine::new(EM_ARM),
            Self::Xtensa => ElfMachine::new(EM_XTENSA),
        }
    }

    /// Resolves an ELF machine/class pair into an architecture kind.
    ///
    /// A few architectures share the same `e_machine` across 32-bit and
    /// 64-bit layouts (notably RISC-V), so callers that are decoding a file
    /// header should prefer [`Self::from_elf_bytes`] over checking
    /// [`Self::e_machine`] alone.
    #[inline]
    pub const fn from_e_machine(machine: ElfMachine, class: ElfClass) -> Option<Self> {
        match (machine.raw(), class) {
            (EM_X86_64, ElfClass::ELF64) => Some(Self::X86_64),
            (EM_AARCH64, ElfClass::ELF64) => Some(Self::AArch64),
            (EM_RISCV, ElfClass::ELF64) => Some(Self::RiscV64),
            (EM_RISCV, ElfClass::ELF32) => Some(Self::RiscV32),
            (EM_LOONGARCH, ElfClass::ELF64) => Some(Self::LoongArch64),
            (EM_386, ElfClass::ELF32) => Some(Self::X86),
            (EM_ARM, ElfClass::ELF32) => Some(Self::Arm),
            (EM_XTENSA, ElfClass::ELF32) => Some(Self::Xtensa),
            _ => None,
        }
    }

    /// Resolves an ELF target description into a supported architecture kind.
    #[inline]
    pub const fn from_elf_target(target: ElfTarget) -> Option<Self> {
        Self::from_e_machine(target.machine(), target.class())
    }

    /// Detects the architecture kind from raw ELF header bytes.
    ///
    /// Requires at least 20 bytes, covering `e_ident`, `e_type`, and
    /// `e_machine`.
    pub fn from_elf_bytes(bytes: &[u8]) -> crate::Result<Option<Self>> {
        Ok(Self::from_elf_target(ElfTarget::from_bytes(bytes)?))
    }
}

impl core::fmt::Display for ArchKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::X86_64 => f.write_str("x86_64"),
            Self::AArch64 => f.write_str("aarch64"),
            Self::RiscV64 => f.write_str("riscv64"),
            Self::RiscV32 => f.write_str("riscv32"),
            Self::LoongArch64 => f.write_str("loongarch64"),
            Self::X86 => f.write_str("x86"),
            Self::Arm => f.write_str("arm"),
            Self::Xtensa => f.write_str("xtensa"),
        }
    }
}

pub mod aarch64;
pub mod arm;
pub mod loongarch64;
pub(crate) mod riscv;
pub mod riscv32;
pub mod riscv64;
pub mod x86;
pub mod x86_64;
pub mod xtensa;

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
        pub use x86_64::X86_64Arch as NativeArch;
    }else if #[cfg(target_arch = "riscv64")]{
        pub use riscv64::*;
        pub use riscv64::RiscV64Arch as NativeArch;
    }else if #[cfg(target_arch = "riscv32")]{
        pub use riscv32::*;
        pub use riscv32::RiscV32Arch as NativeArch;
    }else if #[cfg(target_arch="aarch64")]{
        pub use aarch64::*;
        pub use aarch64::AArch64Arch as NativeArch;
    }else if #[cfg(target_arch="loongarch64")]{
        pub use loongarch64::*;
        pub use loongarch64::LoongArch64Arch as NativeArch;
    }else if #[cfg(target_arch = "x86")]{
        pub use x86::*;
        pub use x86::X86Arch as NativeArch;
    }else if #[cfg(target_arch = "arm")]{
        pub use arm::*;
        pub use arm::ArmArch as NativeArch;
    }else if #[cfg(target_arch = "xtensa")]{
        pub use xtensa::*;
        pub use xtensa::XtensaArch as NativeArch;
    }
}

#[cfg(feature = "object")]
pub(crate) mod object;
