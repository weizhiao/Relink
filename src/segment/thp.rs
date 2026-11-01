use core::ops::Range;

use crate::{
    elf::{ElfLayout, ElfPhdr, ElfProgramFlags, ElfProgramType},
    input::FileBacking,
    logging,
    memory::{VmAddr, VmOffset, rounddown, roundup},
    os::{MadviseAdvice, Mmap, SpaceLayout, ThpPolicy},
};

/// Applies THP preferences to file-mapped images, including anonymous BSS.
/// LOAD file bounds and virtual address ranges are validated by `load_segments`.
pub(super) struct Thp {
    page_size: usize,
    file_offset: usize,
    policy: ThpPolicy,
}

impl Thp {
    pub(super) fn new(
        policy: Option<ThpPolicy>,
        backing: Option<FileBacking>,
        base_page_size: usize,
    ) -> Option<Self> {
        let policy = policy?;
        let page_size = match policy {
            ThpPolicy::Advise(size) | ThpPolicy::Collapse(size) => size.bytes(),
        };
        if !page_size.is_power_of_two() || page_size <= base_page_size {
            return None;
        }
        Some(Self {
            page_size,
            file_offset: backing?.offset,
            policy,
        })
    }

    /// Prefer the load bias covering the most executable file bytes, then the
    /// most total read-only bytes. Every candidate preserves ELF alignment.
    pub(super) fn adjust_layout<L: ElfLayout>(
        &self,
        phdrs: &[ElfPhdr<L>],
        layout: &mut SpaceLayout,
    ) {
        // ELF alignment already fixes the bias modulo the huge-page size.
        if layout.align >= self.page_size {
            return;
        }
        let mut best = (0, 0);
        let mut bias = 0;
        for phdr in phdrs {
            let Some(file) = self.file_range(phdr) else {
                continue;
            };
            // B + p_vaddr must be congruent to the actual file offset modulo H.
            let candidate = file.start.wrapping_sub(phdr.p_vaddr().get()) & (self.page_size - 1);
            if !candidate.is_multiple_of(layout.align) {
                continue;
            }
            let mut score = (0usize, 0usize);
            for other in phdrs {
                if let Some(range) = self.range(other, candidate) {
                    let len = range.end - range.start;
                    if other.flags().contains(ElfProgramFlags::EXEC) {
                        score.0 = score.0.saturating_add(len);
                    }
                    score.1 = score.1.saturating_add(len);
                }
            }
            if score > best {
                best = score;
                bias = candidate;
            }
        }
        if best.1 != 0 {
            layout.align = self.page_size;
            layout.offset = layout.offset.wrapping_add(bias) & (layout.align - 1);
        }
    }

    fn file_range<L: ElfLayout>(&self, phdr: &ElfPhdr<L>) -> Option<Range<usize>> {
        if phdr.program_type() != ElfProgramType::LOAD
            || !phdr.flags().contains(ElfProgramFlags::READ)
            || phdr.flags().contains(ElfProgramFlags::WRITE)
            || phdr.p_filesz() == 0
        {
            return None;
        }
        let start = self.file_offset + phdr.p_offset();
        Some(start..start + phdr.p_filesz())
    }

    /// Select complete file huge pages whose runtime addresses are also aligned.
    /// Return ELF-relative addresses; overlapping LOADs use the final mappings.
    fn range<L: ElfLayout>(&self, phdr: &ElfPhdr<L>, bias: usize) -> Option<Range<usize>> {
        let file = self.file_range(phdr)?;
        let vaddr = phdr.p_vaddr().get();
        if !bias
            .wrapping_add(vaddr)
            .wrapping_sub(file.start)
            .is_multiple_of(self.page_size)
        {
            return None;
        }
        let file_start = roundup(file.start, self.page_size);
        let file_end = rounddown(file.end, self.page_size);
        if file_start >= file_end {
            return None;
        }
        let start = vaddr + (file_start - file.start);
        Some(start..start + (file_end - file_start))
    }

    /// Select complete huge pages in declared BSS, returning ELF-relative addresses.
    /// Overlapping LOADs use the final mappings.
    fn bss_range<L: ElfLayout>(&self, phdr: &ElfPhdr<L>, base: VmAddr) -> Option<Range<usize>> {
        if phdr.program_type() != ElfProgramType::LOAD
            || !phdr.flags().contains(ElfProgramFlags::WRITE)
        {
            return None;
        }
        let addr = (base + phdr.p_vaddr()).get();
        let start = roundup(addr + phdr.p_filesz(), self.page_size);
        let end = rounddown(addr + phdr.p_memsz(), self.page_size);
        if start >= end {
            return None;
        }
        Some(start - base.get()..end - base.get())
    }

    pub(super) fn advise<L: ElfLayout, M: Mmap + ?Sized>(
        &self,
        phdrs: &[ElfPhdr<L>],
        mapper: &M,
        base: VmAddr,
    ) {
        for phdr in phdrs {
            let (range, advice, description) = if let Some(range) = self.range(phdr, base.get()) {
                let (advice, description) = match self.policy {
                    ThpPolicy::Advise(_) => (MadviseAdvice::HugePage, "file MADV_HUGEPAGE"),
                    ThpPolicy::Collapse(_) => (MadviseAdvice::Collapse, "file MADV_COLLAPSE"),
                };
                (range, advice, description)
            } else if let Some(range) = self.bss_range(phdr, base) {
                (range, MadviseAdvice::HugePage, "BSS MADV_HUGEPAGE")
            } else {
                continue;
            };
            let addr = base + VmOffset::new(range.start);
            let len = range.end - range.start;
            // SAFETY: the interval lies within final LOAD mappings owned by
            // this mapper, including when another LOAD replaced part of it.
            // Declared BSS receives non-faulting, content-preserving advice.
            // File advice also preserves contents, including synchronous collapse.
            let result = unsafe { mapper.madvise(addr, len, advice) };
            match result {
                Ok(()) => {
                    logging::debug!("[THP] {description} accepted for {addr}, length {len}")
                }
                Err(error) => {
                    logging::debug!("[THP] {description} ignored for {addr}, length {len}: {error}")
                }
            }
        }
    }
}
