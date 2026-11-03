use core::ops::Range;

use crate::{
    elf::{ElfLayout, ElfPhdr, ElfProgramFlags, ElfProgramType},
    logging,
    memory::{VmAddr, VmOffset, rounddown, roundup},
    os::{MadviseAdvice, Mmap, PageSize, SpaceLayout, ThpPolicy},
};

/// Applies THP preferences to directly mapped and copied images.
/// LOAD file bounds and virtual address ranges are validated by `load_segments`.
pub(super) struct Thp {
    page_size: usize,
    policy: ThpPolicy,
}

impl Thp {
    pub(super) fn new(policy: ThpPolicy, page_size: PageSize) -> Self {
        Self {
            page_size: page_size.bytes(),
            policy,
        }
    }

    /// Prefer the load bias covering the most executable file bytes, then the
    /// most total non-writable bytes. Every candidate preserves ELF alignment.
    pub(super) fn adjust_layout<L: ElfLayout>(
        &self,
        phdrs: &[ElfPhdr<L>],
        layout: &mut SpaceLayout,
        file_offset: Option<usize>,
    ) {
        // ELF alignment already fixes the bias modulo the huge-page size.
        if layout.align >= self.page_size {
            return;
        }
        // Copied images have no file-offset congruence requirement. Align their
        // load bias while preserving the original ELF image origin.
        let Some(file_offset) = file_offset else {
            if layout.len >= self.page_size {
                layout.align = self.page_size;
            }
            return;
        };
        let mut best = (0, 0);
        let mut bias = 0;
        for phdr in phdrs {
            let Some(file) = Self::file_range(phdr, file_offset) else {
                continue;
            };
            // B + p_vaddr must be congruent to the actual file offset modulo H.
            let candidate = file.start.wrapping_sub(phdr.p_vaddr().get()) & (self.page_size - 1);
            if !candidate.is_multiple_of(layout.align) {
                continue;
            }
            let mut score = (0usize, 0usize);
            for other in phdrs {
                if let Some(range) = self.aligned_file_range(other, candidate, file_offset) {
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

    fn file_range<L: ElfLayout>(phdr: &ElfPhdr<L>, file_offset: usize) -> Option<Range<usize>> {
        if phdr.program_type() != ElfProgramType::LOAD
            || phdr.flags().contains(ElfProgramFlags::WRITE)
            || phdr.p_filesz() == 0
        {
            return None;
        }
        let start = file_offset + phdr.p_offset();
        Some(start..start + phdr.p_filesz())
    }

    /// Select complete file huge pages whose runtime addresses are also aligned.
    /// Return ELF-relative addresses; overlapping LOADs use the final mappings.
    fn aligned_file_range<L: ElfLayout>(
        &self,
        phdr: &ElfPhdr<L>,
        bias: usize,
        file_offset: usize,
    ) -> Option<Range<usize>> {
        let file = Self::file_range(phdr, file_offset)?;
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
        let addr = phdr.p_vaddr().get();
        self.memory_range(addr + phdr.p_filesz()..addr + phdr.p_memsz(), base.get())
    }

    fn memory_range(&self, range: Range<usize>, bias: usize) -> Option<Range<usize>> {
        let start = roundup(bias + range.start, self.page_size);
        let end = rounddown(bias + range.end, self.page_size);
        if start >= end {
            return None;
        }
        Some(start - bias..end - bias)
    }

    /// Enable huge-page allocation on first write, including for untouched BSS.
    pub(super) fn prepare_copy<L: ElfLayout, M: Mmap + ?Sized>(
        &self,
        phdrs: &[ElfPhdr<L>],
        mapper: &M,
        base: VmAddr,
    ) {
        self.advise_copy(phdrs, mapper, base, MadviseAdvice::HugePage);
    }

    /// Collapse initialized anonymous contents before removing write permission.
    pub(super) fn finish_copy<L: ElfLayout, M: Mmap + ?Sized>(
        &self,
        phdrs: &[ElfPhdr<L>],
        mapper: &M,
        base: VmAddr,
    ) {
        if matches!(self.policy, ThpPolicy::Collapse) {
            self.advise_copy(phdrs, mapper, base, MadviseAdvice::Collapse);
        }
    }

    fn advise_copy<L: ElfLayout, M: Mmap + ?Sized>(
        &self,
        phdrs: &[ElfPhdr<L>],
        mapper: &M,
        base: VmAddr,
        advice: MadviseAdvice,
    ) {
        for phdr in phdrs {
            if phdr.program_type() != ElfProgramType::LOAD {
                continue;
            }
            let start = phdr.p_vaddr().get();
            let len = match advice {
                MadviseAdvice::HugePage => phdr.p_memsz(),
                MadviseAdvice::Collapse => phdr.p_filesz(),
                _ => unreachable!("THP only uses huge-page advice"),
            };
            if let Some(range) = self.memory_range(start..start + len, base.get()) {
                self.apply(mapper, base, range, advice);
            }
        }
    }

    /// Advise final file mappings and their anonymous BSS after all replacements.
    pub(super) fn advise_file<L: ElfLayout, M: Mmap + ?Sized>(
        &self,
        phdrs: &[ElfPhdr<L>],
        mapper: &M,
        base: VmAddr,
        file_offset: usize,
    ) {
        for phdr in phdrs {
            let (range, advice) =
                if let Some(range) = self.aligned_file_range(phdr, base.get(), file_offset) {
                    let advice = match self.policy {
                        ThpPolicy::Advise => MadviseAdvice::HugePage,
                        ThpPolicy::Collapse => MadviseAdvice::Collapse,
                    };
                    (range, advice)
                } else if let Some(range) = self.bss_range(phdr, base) {
                    (range, MadviseAdvice::HugePage)
                } else {
                    continue;
                };
            self.apply(mapper, base, range, advice);
        }
    }

    fn apply<M: Mmap + ?Sized>(
        &self,
        mapper: &M,
        base: VmAddr,
        range: Range<usize>,
        advice: MadviseAdvice,
    ) {
        let addr = base + VmOffset::new(range.start);
        let len = range.end - range.start;
        // SAFETY: the interval lies within LOAD mappings owned by this mapper.
        // Both advice types preserve contents. Collapse only covers initialized
        // contents; untouched anonymous memory receives non-faulting advice.
        let result = unsafe { mapper.madvise(addr, len, advice) };
        match result {
            Ok(()) => logging::debug!("[THP] {advice:?} accepted for {addr}, length {len}"),
            Err(error) => {
                logging::debug!("[THP] {advice:?} ignored for {addr}, length {len}: {error}")
            }
        }
    }
}
