use super::layout::SectionPlacement;
use crate::elf::{ElfLayout, ElfSectionId, ElfShdr, NativeElfLayout};
use alloc::{boxed::Box, vec::Vec};
use core::ffi::CStr;

/// Object section headers paired with their section-name string table and
/// optional layout metadata.
pub struct ObjectSections<L: ElfLayout = NativeElfLayout> {
    shdrs: Vec<ElfShdr<L>>,
    shstrtab: Vec<u8>,
    section_mapped: Option<Box<[bool]>>,
}

impl<L: ElfLayout> ObjectSections<L> {
    #[inline]
    pub(crate) fn new(shdrs: Vec<ElfShdr<L>>, shstrtab: Vec<u8>) -> Self {
        Self {
            shdrs,
            shstrtab,
            section_mapped: None,
        }
    }

    #[inline]
    pub fn headers(&self) -> &[ElfShdr<L>] {
        &self.shdrs
    }

    #[inline]
    pub(crate) fn headers_mut(&mut self) -> &mut [ElfShdr<L>] {
        &mut self.shdrs
    }

    #[inline]
    pub fn section(&self, id: ElfSectionId) -> &ElfShdr<L> {
        &self.shdrs[id.index()]
    }

    #[inline]
    pub(crate) fn section_mut(&mut self, id: ElfSectionId) -> &mut ElfShdr<L> {
        &mut self.shdrs[id.index()]
    }

    pub(crate) fn push_section(&mut self, name: &str, mut shdr: ElfShdr<L>) -> ElfSectionId {
        let name_offset = self.shstrtab.len();
        self.shstrtab.extend_from_slice(name.as_bytes());
        self.shstrtab.push(0);
        shdr.set_sh_name(name_offset as u32);

        let id = ElfSectionId::new(self.shdrs.len());
        self.shdrs.push(shdr);
        id
    }

    #[inline]
    pub(crate) fn set_layout_metadata(&mut self, placements: &[SectionPlacement]) {
        debug_assert_eq!(placements.len(), self.shdrs.len());
        self.section_mapped = Some(
            placements
                .iter()
                .copied()
                .map(|placement| !matches!(placement, SectionPlacement::Skip))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
    }

    #[inline]
    pub(crate) fn section_is_mapped(&self, id: ElfSectionId) -> bool {
        self.section_mapped
            .as_ref()
            .expect("object section layout metadata must be set")
            .get(id.index())
            .copied()
            .unwrap_or(false)
    }

    #[inline]
    pub fn name_table(&self) -> &[u8] {
        &self.shstrtab
    }

    #[inline]
    pub fn section_name(&self, id: ElfSectionId) -> &CStr {
        let shdr = self.section(id);
        let bytes = &self.shstrtab[shdr.sh_name() as usize..];
        CStr::from_bytes_until_nul(bytes).expect("validated section name must be NUL-terminated")
    }

    #[inline]
    pub fn find_section(&self, name: &str) -> Option<ElfSectionId> {
        self.shdrs.iter().enumerate().find_map(|(index, _)| {
            let id = ElfSectionId::new(index);
            (self.section_name(id).to_bytes() == name.as_bytes()).then_some(id)
        })
    }
}
