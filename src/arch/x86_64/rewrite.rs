use super::Architecture;
use crate::{LinkerError, Result, elf::ElfRelocationType};
use core::mem::size_of;
use elf::abi::{R_X86_64_GOTPCREL, R_X86_64_PLT32};

impl crate::linker::GotPltTarget for Architecture {
    fn got_plt_target(
        target_bytes: &[u8],
        relocation_type: ElfRelocationType,
        symbol_is_undef: bool,
        section_offset: usize,
        source_place: usize,
        addend: isize,
    ) -> Result<Option<usize>> {
        match relocation_type.raw() {
            // These relocation types target an already-created GOT/PLT slot. For
            // undefined symbols, st_value is zero until the dynamic relocation pass
            // fills that slot, so recover the slot address from the original
            // encoded displacement.
            R_X86_64_GOTPCREL => {}
            R_X86_64_PLT32 if symbol_is_undef => {}
            _ => return Ok(None),
        }

        let end = section_offset
            .checked_add(size_of::<i32>())
            .ok_or_else(|| {
                LinkerError::metadata_rewrite("retained relocation read range overflowed")
            })?;
        let bytes = target_bytes.get(section_offset..end).ok_or_else(|| {
            LinkerError::metadata_rewrite("retained relocation read range exceeds section")
        })?;

        let mut encoded = [0u8; size_of::<i32>()];
        encoded.copy_from_slice(bytes);
        let displacement = i32::from_ne_bytes(encoded) as i128;
        let target = source_place as i128 + displacement - addend as i128;
        usize::try_from(target).map(Some).map_err(|_| {
            LinkerError::metadata_rewrite("retained relocation encoded target is out of range")
                .into()
        })
    }
}
