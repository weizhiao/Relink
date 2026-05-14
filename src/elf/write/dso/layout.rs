use crate::{Result, custom_error, elf::ElfLayout};
use core::mem::size_of;

pub(super) const DEFAULT_PAGE_SIZE: usize = 0x1000;
pub(super) const DEFAULT_TEXT_ALIGN: usize = 16;
pub(super) const TEXT_SECTION_INDEX: u16 = 1;

#[inline]
pub(super) const fn is_64<L: ElfLayout>() -> bool {
    L::E_CLASS == crate::elf::abi::ELFCLASS64
}

#[inline]
pub(super) const fn sym_size(is_64: bool) -> usize {
    if is_64 { 24 } else { 16 }
}

#[inline]
pub(super) const fn dyn_size(is_64: bool) -> usize {
    if is_64 { 16 } else { 8 }
}

#[inline]
pub(super) fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align > 0);
    value.div_ceil(align) * align
}

#[inline]
pub(super) fn align_up_checked(value: usize, align: usize) -> Result<usize> {
    let rounded = value
        .checked_add(align - 1)
        .ok_or_else(|| custom_error("generated DSO alignment overflow"))?;
    Ok((rounded / align) * align)
}

#[inline]
pub(super) fn checked_add(lhs: usize, rhs: usize, message: &'static str) -> Result<usize> {
    lhs.checked_add(rhs).ok_or_else(|| custom_error(message))
}

#[inline]
pub(super) fn check_word_range<L: ElfLayout>(value: usize) -> Result<()> {
    if size_of::<L::Word>() == 4 && value > u32::MAX as usize {
        return Err(custom_error("generated DSO value exceeds ELF32 range"));
    }
    Ok(())
}
