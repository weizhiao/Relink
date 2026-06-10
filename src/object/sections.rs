use crate::elf::{ElfLayout, ElfSectionId, ElfShdr, NativeElfLayout};
use alloc::vec::Vec;
use core::ffi::CStr;

/// Object section headers paired with their section-name string table.
pub(crate) struct ObjectSections<L: ElfLayout = NativeElfLayout> {
    shdrs: Vec<ElfShdr<L>>,
    shstrtab: Vec<u8>,
}

impl<L: ElfLayout> ObjectSections<L> {
    #[inline]
    pub(crate) fn new(shdrs: Vec<ElfShdr<L>>, shstrtab: Vec<u8>) -> Self {
        Self { shdrs, shstrtab }
    }

    #[inline]
    pub(crate) fn into_headers(self) -> Vec<ElfShdr<L>> {
        self.shdrs
    }

    #[inline]
    pub(crate) fn headers(&self) -> &[ElfShdr<L>] {
        &self.shdrs
    }

    #[inline]
    pub(crate) fn headers_mut(&mut self) -> &mut [ElfShdr<L>] {
        &mut self.shdrs
    }

    #[inline]
    pub(crate) fn section(&self, id: ElfSectionId) -> &ElfShdr<L> {
        &self.shdrs[id.index()]
    }

    #[inline]
    pub(crate) fn section_mut(&mut self, id: ElfSectionId) -> &mut ElfShdr<L> {
        &mut self.shdrs[id.index()]
    }

    #[inline]
    pub(crate) fn name_table(&self) -> &[u8] {
        &self.shstrtab
    }

    #[inline]
    pub(crate) fn section_name(&self, id: ElfSectionId) -> &CStr {
        let shdr = self.section(id);
        let bytes = &self.shstrtab[shdr.sh_name() as usize..];
        CStr::from_bytes_until_nul(bytes).expect("validated section name must be NUL-terminated")
    }

    #[inline]
    pub(crate) fn find_section(&self, name: &str) -> Option<ElfSectionId> {
        self.shdrs.iter().enumerate().find_map(|(index, _)| {
            let id = ElfSectionId::new(index);
            (self.section_name(id).to_bytes() == name.as_bytes()).then_some(id)
        })
    }
}
