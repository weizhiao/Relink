use core::ops::Range;

use crate::{
    elf::{ElfLayout, ElfPhdr, ElfProgramFlags, ElfProgramType},
    input::FileBacking,
    logging,
    memory::{VmAddr, VmOffset, rounddown},
    os::{MadviseAdvice, Mmap, PageSize},
};

/// Applies caller-provided THP preferences to directly mapped file contents.
pub(super) struct FileThp {
    page_size: usize,
    backing: FileBacking,
}

impl FileThp {
    pub(super) fn new(
        page_size: Option<PageSize>,
        backing: Option<FileBacking>,
        base_page_size: usize,
    ) -> Option<Self> {
        let page_size = page_size?.bytes();
        if !page_size.is_power_of_two() || page_size <= base_page_size {
            return None;
        }
        Some(Self {
            page_size,
            backing: backing?,
        })
    }

    pub(super) fn preferred_alignment<L: ElfLayout>(&self, phdrs: &[ElfPhdr<L>]) -> Option<usize> {
        phdrs
            .iter()
            .find_map(|phdr| self.range(phdr).map(|_| self.page_size))
    }

    /// Select complete huge pages inside a readable, non-writable LOAD's file contents.
    /// Overlapping LOADs are left to the backend's advice handling.
    fn range<L: ElfLayout>(&self, phdr: &ElfPhdr<L>) -> Option<Range<usize>> {
        if phdr.program_type() != ElfProgramType::LOAD
            || !phdr.flags().contains(ElfProgramFlags::READ)
            || phdr.flags().contains(ElfProgramFlags::WRITE)
        {
            return None;
        }
        let huge = self.page_size;
        let vaddr = phdr.p_vaddr().get();
        let start = align_up_checked(vaddr, huge)?;
        let end = rounddown(vaddr.checked_add(phdr.p_filesz())?, huge);
        if start >= end || phdr.p_offset().checked_add(phdr.p_filesz())? > self.backing.len {
            return None;
        }
        // FileBacking may describe an ELF embedded in a larger file. Both the
        // eventual VA and the actual file offset must align, not just p_offset.
        let offset = self
            .backing
            .offset
            .checked_add(phdr.p_offset())?
            .checked_add(start - vaddr)?;
        if !offset.is_multiple_of(huge) {
            return None;
        }
        Some(start..end)
    }

    pub(super) fn advise<L: ElfLayout, M: Mmap + ?Sized>(
        &self,
        phdrs: &[ElfPhdr<L>],
        mapper: &M,
        base: VmAddr,
    ) {
        for phdr in phdrs {
            let Some(range) = self.range(phdr) else {
                continue;
            };
            let addr = base + VmOffset::new(range.start);
            let len = range.end - range.start;
            // SAFETY: the selected interval is wholly inside a populated LOAD
            // range owned by this mapper. HUGEPAGE preserves its contents.
            let result = unsafe { mapper.madvise(addr, len, MadviseAdvice::HugePage) };
            match result {
                Ok(()) => logging::debug!(
                    "[THP] advice accepted for {addr}, length {len}; huge-page backing is not guaranteed"
                ),
                Err(error) => {
                    logging::debug!("[THP] advice ignored for {addr}, length {len}: {error}")
                }
            }
        }
    }
}

fn align_up_checked(value: usize, align: usize) -> Option<usize> {
    value
        .checked_add(align - 1)
        .map(|value| rounddown(value, align))
}
