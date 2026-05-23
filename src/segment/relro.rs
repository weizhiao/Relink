use crate::{
    Result,
    elf::{ElfLayout, ElfPhdr},
    os::{Mapper, ProtFlags, VmAddr, VmOffset},
};

/// RELRO (RELocation Read-Only) segment information
///
/// This structure holds information about a RELRO segment,
/// which is used to make certain segments read-only after
/// relocation to improve security.
#[allow(unused)]
pub(crate) struct ELFRelro {
    /// Virtual address of the RELRO segment
    addr: VmAddr,
    /// Size of the RELRO segment
    len: usize,
    /// Page size used to align the protected range.
    page_size: usize,
    /// Mapping backend used for protection changes.
    mapper: Mapper,
}

impl ELFRelro {
    /// Create a new RELRO segment
    ///
    /// # Arguments
    /// * `phdr` - The program header describing the segment
    /// * `base` - The base address to which the segment is loaded
    ///
    /// # Returns
    /// A new ELFRelro instance
    pub(crate) fn new<L: ElfLayout>(
        phdr: &ElfPhdr<L>,
        base: VmAddr,
        page_size: usize,
        mapper: Mapper,
    ) -> ELFRelro {
        ELFRelro {
            addr: base + phdr.p_vaddr(),
            len: phdr.p_memsz(),
            page_size,
            mapper,
        }
    }

    /// Apply RELRO protection to the segment
    ///
    /// This method makes the RELRO segment read-only to improve security.
    ///
    /// # Returns
    /// * `Ok(())` - If RELRO protection is applied successfully
    /// * `Err(Error)` - If RELRO protection fails
    #[inline]
    pub(crate) fn relro(&self) -> Result<()> {
        let start = self.addr.rounddown(self.page_size);
        let end = (self.addr + VmOffset::new(self.len)).roundup(self.page_size);
        let len = end
            .checked_offset_from(start)
            .expect("RELRO rounded range end precedes its start")
            .get();
        unsafe {
            self.mapper.mprotect(start, len, ProtFlags::PROT_READ)?;
        }
        Ok(())
    }
}
