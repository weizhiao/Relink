#[cfg(all(feature = "object", target_arch = "x86_64"))]
pub(crate) use super::x86_64::object::{PLT_ENTRY, PLT_ENTRY_SIZE};

#[cfg(all(feature = "object", target_arch = "riscv64"))]
pub(crate) use super::riscv64::object::{PLT_ENTRY, PLT_ENTRY_SIZE};

#[cfg(all(
    feature = "object",
    not(any(target_arch = "x86_64", target_arch = "riscv64"))
))]
pub(crate) const PLT_ENTRY_SIZE: usize = 16;

#[cfg(all(
    feature = "object",
    not(any(target_arch = "x86_64", target_arch = "riscv64"))
))]
pub(crate) const PLT_ENTRY: [u8; PLT_ENTRY_SIZE] = [
    0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25, 0, 0, 0, 0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];
