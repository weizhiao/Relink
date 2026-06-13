use crate::{
    elf::{
        ElfHeader, ElfLayout, ElfSectionId, ElfSectionType, ElfShdr, NativeElfLayout,
        SymbolTableView,
    },
    image::{ElfCore, RawObject, SymbolExports, exports_handle},
    input::{ElfReader, ElfReaderExt, Path},
    memory::{HostRegion, RegionAccess},
    object::{
        CustomHash, ObjectExports, ObjectSections,
        layout::{SectionGroup, SectionGroups, SectionLifetime, SectionPlacement},
    },
    relocation::{ObjectRelocationArch, RelocationArch},
    sync::Arc,
};
use alloc::vec::Vec;
use core::ffi::CStr;

/// Relocatable-object layout event emitted before section addresses are assigned.
pub struct SectionLayoutEvent<'event, L: ElfLayout = NativeElfLayout> {
    sections: &'event mut ObjectSections<L>,
    groups: SectionGroups,
    placements: Vec<Option<SectionPlacement>>,
}

impl<'event, L: ElfLayout> SectionLayoutEvent<'event, L> {
    #[inline]
    pub(crate) fn new(sections: &'event mut ObjectSections<L>) -> Self {
        let mut placements = Vec::new();
        placements.resize(sections.headers().len(), None);
        Self {
            sections,
            groups: SectionGroups::default(),
            placements,
        }
    }

    #[inline]
    pub(crate) fn into_overrides(self) -> (SectionGroups, Vec<Option<SectionPlacement>>) {
        (self.groups, self.placements)
    }

    /// Returns all section ids in table order.
    #[inline]
    pub fn section_ids(&self) -> impl Iterator<Item = ElfSectionId> + '_ {
        (0..self.sections.headers().len()).map(ElfSectionId::new)
    }

    /// Defines or replaces one layout group.
    pub fn define_group(
        &mut self,
        group: SectionGroup,
        prot: crate::os::ProtFlags,
        order: usize,
        lifetime: SectionLifetime,
    ) {
        self.groups.define(group, prot, order, lifetime);
    }

    /// Places `id` in `group`.
    #[inline]
    pub fn place(&mut self, id: ElfSectionId, group: SectionGroup) {
        self.placements[id.index()] = Some(SectionPlacement::Place(group));
    }

    /// Excludes `id` from object section layout.
    #[inline]
    pub fn skip(&mut self, id: ElfSectionId) {
        self.placements[id.index()] = Some(SectionPlacement::Skip);
    }

    /// Returns the explicit group override for `id`, if one was set.
    #[inline]
    pub fn group(&self, id: ElfSectionId) -> Option<SectionGroup> {
        match self.placements[id.index()] {
            Some(SectionPlacement::Place(group)) => Some(group),
            Some(SectionPlacement::Stage | SectionPlacement::Skip) | None => None,
        }
    }

    /// Returns the validated section headers.
    #[inline]
    pub fn sections(&self) -> &[ElfShdr<L>] {
        self.sections.headers()
    }

    /// Returns mutable validated section headers.
    #[inline]
    pub fn sections_mut(&mut self) -> &mut [ElfShdr<L>] {
        self.sections.headers_mut()
    }

    /// Returns one section header by id.
    #[inline]
    pub fn section(&self, id: ElfSectionId) -> &ElfShdr<L> {
        self.sections.section(id)
    }

    /// Returns one mutable section header by id.
    #[inline]
    pub fn section_mut(&mut self, id: ElfSectionId) -> &mut ElfShdr<L> {
        self.sections.section_mut(id)
    }

    /// Returns the raw section-name string table bytes.
    #[inline]
    pub fn section_name_table(&self) -> &[u8] {
        self.sections.name_table()
    }

    /// Returns one validated section name as a NUL-terminated byte string.
    #[inline]
    pub fn section_name(&self, id: ElfSectionId) -> &CStr {
        self.sections.section_name(id)
    }

    /// Finds the first section whose name equals `name`.
    #[inline]
    pub fn find_section(&self, name: &str) -> Option<ElfSectionId> {
        self.sections.find_section(name)
    }
}

/// Relocatable-object event emitted after an object has been mapped and parsed,
/// before relocation.
pub struct AfterObjectLoadEvent<
    'event,
    D: 'static,
    Arch: ObjectRelocationArch,
    R: RegionAccess = HostRegion,
> {
    raw: &'event mut RawObject<D, Arch, R>,
}

impl<'event, D: 'static, Arch, R> AfterObjectLoadEvent<'event, D, Arch, R>
where
    Arch: ObjectRelocationArch,
    R: RegionAccess,
{
    #[inline]
    pub(crate) const fn new(raw: &'event mut RawObject<D, Arch, R>) -> Self {
        Self { raw }
    }

    /// Returns the loaded relocatable object.
    #[inline]
    pub const fn raw(&self) -> &RawObject<D, Arch, R> {
        self.raw
    }

    /// Returns the mutable loaded relocatable object.
    #[inline]
    pub fn raw_mut(&mut self) -> &mut RawObject<D, Arch, R> {
        self.raw
    }
}

/// Relocated-object event emitted after relocation and before memory protection
/// and initialization.
///
/// The event exposes relocated section headers and the object symbol table.
/// Observers may install any [`SymbolExports`] implementation, including a
/// backend derived from custom metadata such as kernel export tables. If no
/// exports are installed, the object loader builds the default exports after
/// observers return.
pub struct ObjectRelocatedEvent<
    'event,
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess = HostRegion,
> {
    core: &'event ElfCore<D, Arch, R>,
    shdrs: &'event [ElfShdr<Arch::Layout>],
    symtab: SymbolTableView<'event, Arch::Layout, CustomHash>,
    exports: Option<Arc<dyn SymbolExports<Arch>>>,
}

impl<'event, D: 'static, Arch: RelocationArch, R: RegionAccess>
    ObjectRelocatedEvent<'event, D, Arch, R>
{
    #[inline]
    pub(crate) fn new(
        core: &'event ElfCore<D, Arch, R>,
        shdrs: &'event [ElfShdr<Arch::Layout>],
        symtab: SymbolTableView<'event, Arch::Layout, CustomHash>,
    ) -> Self {
        Self {
            core,
            shdrs,
            symtab,
            exports: None,
        }
    }

    /// Returns the relocated object core.
    #[inline]
    pub const fn core(&self) -> &ElfCore<D, Arch, R> {
        self.core
    }

    /// Returns relocated section headers in table order.
    #[inline]
    pub const fn sections(&self) -> &'event [ElfShdr<Arch::Layout>] {
        self.shdrs
    }

    /// Returns one relocated section header by id.
    #[inline]
    pub fn section(&self, id: ElfSectionId) -> &ElfShdr<Arch::Layout> {
        &self.shdrs[id.index()]
    }

    /// Returns the relocated object symbol table view.
    #[inline]
    pub const fn symtab(&self) -> SymbolTableView<'event, Arch::Layout, CustomHash> {
        self.symtab
    }

    /// Replaces runtime exports with a custom backend.
    #[inline]
    pub fn set_exports<E>(&mut self, exports: E)
    where
        E: SymbolExports<Arch> + 'static,
    {
        self.exports = Some(exports_handle(exports));
    }

    /// Clears all runtime exports.
    #[inline]
    pub fn clear_exports(&mut self) {
        self.set_exports(ObjectExports::<Arch::Layout>::empty());
    }

    #[inline]
    pub(crate) fn into_exports(self) -> Option<Arc<dyn SymbolExports<Arch>>> {
        self.exports
    }
}

/// Event emitted after relocatable-object section headers are validated and
/// before section contents are mapped.
pub struct BeforeObjectLoadEvent<'event, D: 'static, L: ElfLayout = NativeElfLayout> {
    ehdr: &'event ElfHeader<L>,
    sections: &'event mut ObjectSections<L>,
    object: &'event dyn ElfReader,
    user_data: &'event mut D,
}

impl<'event, D: 'static, L: ElfLayout> BeforeObjectLoadEvent<'event, D, L> {
    #[inline]
    pub(crate) fn new(
        ehdr: &'event ElfHeader<L>,
        sections: &'event mut ObjectSections<L>,
        object: &'event dyn ElfReader,
        user_data: &'event mut D,
    ) -> Self {
        Self {
            ehdr,
            sections,
            object,
            user_data,
        }
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub fn path(&self) -> &Path {
        self.object.path()
    }

    /// Returns the parsed ELF header.
    #[inline]
    pub const fn ehdr(&self) -> &ElfHeader<L> {
        self.ehdr
    }

    /// Returns the validated section headers.
    #[inline]
    pub fn sections(&self) -> &[ElfShdr<L>] {
        self.sections.headers()
    }

    /// Returns one section header by index.
    #[inline]
    pub fn section(&self, id: ElfSectionId) -> &ElfShdr<L> {
        self.sections.section(id)
    }

    /// Returns mutable validated section headers.
    #[inline]
    pub fn sections_mut(&mut self) -> &mut [ElfShdr<L>] {
        self.sections.headers_mut()
    }

    /// Returns one mutable section header by index.
    #[inline]
    pub fn section_mut(&mut self, id: ElfSectionId) -> &mut ElfShdr<L> {
        self.sections.section_mut(id)
    }

    /// Returns the raw section-name string table bytes.
    #[inline]
    pub fn section_name_table(&self) -> &[u8] {
        self.sections.name_table()
    }

    /// Returns one validated section name as a NUL-terminated byte string.
    #[inline]
    pub fn section_name(&self, id: ElfSectionId) -> &CStr {
        self.sections.section_name(id)
    }

    /// Finds the first section whose name equals `name`.
    #[inline]
    pub fn find_section(&self, name: &str) -> Option<ElfSectionId> {
        self.sections.find_section(name)
    }

    /// Borrows one section's file-backed contents when the reader is backed by
    /// memory.
    ///
    /// Returns `Ok(None)` when the reader cannot provide a borrowed view.
    /// `SHT_NOBITS` and zero-sized sections return `Ok(Some(&[]))`.
    pub fn borrow_section_bytes(&self, id: ElfSectionId) -> crate::Result<Option<&[u8]>> {
        let Some((offset, len)) = self.section_content_range(id) else {
            return Ok(Some(&[]));
        };
        self.object.borrow_bytes(offset, len)
    }

    /// Reads one section's file-backed contents and passes them to `f`.
    ///
    /// Memory-backed readers pass a borrowed slice directly. Other readers
    /// reuse `scratch` as temporary storage.
    pub fn with_section_bytes<T>(
        &mut self,
        id: ElfSectionId,
        scratch: &mut Vec<u8>,
        f: impl FnOnce(&[u8]) -> crate::Result<T>,
    ) -> crate::Result<T> {
        let Some((offset, len)) = self.section_content_range(id) else {
            return f(&[]);
        };
        self.object.with_bytes::<u8, _, _>(offset, len, scratch, f)
    }

    /// Returns immutable user data for this object image.
    #[inline]
    pub const fn user_data(&self) -> &D {
        self.user_data
    }

    /// Returns mutable user data for this object image.
    #[inline]
    pub fn user_data_mut(&mut self) -> &mut D {
        self.user_data
    }

    fn section_content_range(&self, id: ElfSectionId) -> Option<(usize, usize)> {
        let shdr = self.section(id);
        let len = shdr.sh_size();
        if len == 0 || shdr.section_type() == ElfSectionType::NOBITS {
            return None;
        }
        Some((shdr.sh_offset(), len))
    }
}
