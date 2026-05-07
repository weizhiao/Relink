use crate::{
    Result,
    elf::{ElfLayout, ElfPhdr},
    os::{Mmap, ProtFlags},
    relocation::RelocAddr,
};
use core::ffi::c_void;

use super::{rounddown, roundup};

/// RELRO (RELocation Read-Only) segment information
///
/// This structure holds information about a RELRO segment,
/// which is used to make certain segments read-only after
/// relocation to improve security.
#[allow(unused)]
pub(crate) struct ELFRelro {
    /// Virtual address of the RELRO segment
    addr: RelocAddr,
    /// Size of the RELRO segment
    len: usize,
    /// Page size used to align the protected range.
    page_size: usize,
    /// Function pointer to the mprotect function
    mprotect: unsafe fn(*mut c_void, usize, ProtFlags) -> Result<()>,
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
    pub(crate) fn new<M: Mmap, L: ElfLayout>(
        phdr: &ElfPhdr<L>,
        base: RelocAddr,
        page_size: usize,
    ) -> ELFRelro {
        ELFRelro {
            addr: base.offset(phdr.p_vaddr()),
            len: phdr.p_memsz(),
            page_size,
            mprotect: M::mprotect,
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
        let addr = self.addr.into_inner();
        let end = roundup(addr + self.len, self.page_size);
        let start = rounddown(addr, self.page_size);
        let start_addr = start as *mut c_void;
        unsafe {
            (self.mprotect)(start_addr, end - start, ProtFlags::PROT_READ)?;
        }
        Ok(())
    }
}
