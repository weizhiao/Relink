use crate::{ParseEhdrError, Result, elf::ElfMachine};
use elf::abi::*;

#[inline]
pub(crate) fn validate_native_float_abi(machine: ElfMachine, flags: u32) -> Result<()> {
    if flags & EF_RISCV_FLOAT_ABI_MASK != native_float_abi() {
        return invalid_flags(
            machine,
            flags,
            "floating-point ABI does not match native target",
        );
    }
    Ok(())
}

#[inline]
const fn native_float_abi() -> u32 {
    if cfg!(riscv_float_abi = "q") {
        EF_RISCV_FLOAT_ABI_QUAD
    } else if cfg!(riscv_float_abi = "d") {
        EF_RISCV_FLOAT_ABI_DOUBLE
    } else if cfg!(riscv_float_abi = "f") {
        EF_RISCV_FLOAT_ABI_SINGLE
    } else {
        EF_RISCV_FLOAT_ABI_SOFT
    }
}

#[cold]
pub(crate) fn invalid_flags<T>(machine: ElfMachine, flags: u32, detail: &'static str) -> Result<T> {
    Err(ParseEhdrError::InvalidFlags {
        machine,
        flags,
        detail,
    }
    .into())
}
