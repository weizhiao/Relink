use crate::{
    elf::{
        ElfHeader, ElfLayout, ElfSectionId, ElfSectionType, ElfShdr, Lifecycle, NativeElfLayout,
        SymbolTableView,
    },
    image::{ElfCore, RawObject, SymbolExports, exports_handle},
    input::{ElfReader, ElfReaderExt, Path},
    memory::{HostRegion, ImageMemory, RegionAccess, VmAddr},
    object::{
        CustomHash, ObjectExports, ObjectSections, ObjectSegmentView,
        layout::{SectionGroup, SectionPlacement},
    },
    relocation::{ObjectRelocationArch, RelocationArch},
    sync::Arc,
};
use alloc::vec::Vec;
use core::{ffi::CStr, ptr::NonNull};

use super::lifecycle::{Finalizer, FiniEvent};

type ObjectExportsHandle<L> = Option<Arc<dyn SymbolExports<L>>>;

/// Relocatable-object layout event emitted before section addresses are assigned.
pub struct SectionLayoutEvent<'event, L: ElfLayout = NativeElfLayout> {
    sections: &'event mut ObjectSections<L>,
    placements: Vec<Option<SectionPlacement>>,
}

impl<'event, L: ElfLayout> SectionLayoutEvent<'event, L> {
    #[inline]
    pub(crate) fn new(sections: &'event mut ObjectSections<L>) -> Self {
        let mut placements = Vec::new();
        placements.resize(sections.headers().len(), None);
        Self {
            sections,
            placements,
        }
    }

    #[inline]
    pub(crate) fn into_placements(self) -> Vec<Option<SectionPlacement>> {
        self.placements
    }

    /// Returns all section ids in table order.
    #[inline]
    pub fn section_ids(&self) -> impl Iterator<Item = ElfSectionId> + '_ {
        (0..self.sections.headers().len()).map(ElfSectionId::new)
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
            Some(SectionPlacement::Skip) | None => None,
        }
    }

    /// Returns the validated object sections.
    #[inline]
    pub fn sections(&self) -> &ObjectSections<L> {
        self.sections
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
/// The event exposes relocated section headers, object memory, and the object
/// symbol table.
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
    sections: &'event ObjectSections<Arch::Layout>,
    symtab: SymbolTableView<'event, Arch::Layout, CustomHash>,
    memory: ObjectSegmentView<'event, R>,
    exports: ObjectExportsHandle<Arch::Layout>,
    finalizer: Finalizer<Arch>,
}

impl<'event, D: 'static, Arch: RelocationArch, R: RegionAccess>
    ObjectRelocatedEvent<'event, D, Arch, R>
{
    #[inline]
    pub(crate) fn new(
        core: &'event ElfCore<D, Arch, R>,
        sections: &'event ObjectSections<Arch::Layout>,
        symtab: SymbolTableView<'event, Arch::Layout, CustomHash>,
        memory: ObjectSegmentView<'event, R>,
        finalizer: Finalizer<Arch>,
    ) -> Self {
        Self {
            core,
            sections,
            symtab,
            memory,
            exports: None,
            finalizer,
        }
    }

    /// Returns the relocated object core.
    #[inline]
    pub const fn core(&self) -> &ElfCore<D, Arch, R> {
        self.core
    }

    /// Returns relocated object section metadata.
    #[inline]
    pub const fn sections(&self) -> &'event ObjectSections<Arch::Layout> {
        self.sections
    }

    /// Returns whether one section participates in the runtime object layout.
    #[inline]
    pub fn section_is_mapped(&self, id: ElfSectionId) -> bool {
        self.sections.section_is_mapped(id)
    }

    /// Returns the relocated object symbol table view.
    #[inline]
    pub const fn symtab(&self) -> SymbolTableView<'event, Arch::Layout, CustomHash> {
        self.symtab
    }

    /// Returns relocated object memory.
    #[inline]
    pub const fn memory(&self) -> ObjectSegmentView<'event, R> {
        self.memory
    }

    /// Returns the relocated VM address of one mapped section.
    #[inline]
    pub fn section_addr(&self, id: ElfSectionId) -> Option<VmAddr> {
        self.section_is_mapped(id)
            .then(|| VmAddr::new(self.sections.section(id).sh_addr()))
    }

    /// Returns the size of one section.
    #[inline]
    pub fn section_size(&self, id: ElfSectionId) -> usize {
        self.sections.section(id).sh_size()
    }

    /// Translates the beginning of one relocated section into a host pointer.
    #[inline]
    pub fn section_host_ptr(&self, id: ElfSectionId) -> Option<NonNull<u8>> {
        self.section_host_ptr_range(id, self.section_size(id))
    }

    /// Translates the beginning of one relocated section range into a host
    /// pointer.
    pub fn section_host_ptr_range(&self, id: ElfSectionId, len: usize) -> Option<NonNull<u8>> {
        let addr = self.section_addr(id)?;
        if len > self.section_size(id) {
            return None;
        }
        self.memory.host_ptr_range(addr, len)
    }

    /// Replaces runtime exports with a custom backend.
    #[inline]
    pub fn set_exports<E>(&mut self, exports: E)
    where
        E: SymbolExports<Arch::Layout> + 'static,
    {
        self.exports = Some(exports_handle(exports));
    }

    /// Clears all runtime exports.
    #[inline]
    pub fn clear_exports(&mut self) {
        self.set_exports(ObjectExports::<Arch::Layout>::empty());
    }

    /// Returns the finalization lifecycle that will be run when the initialized
    /// object is dropped.
    #[inline]
    pub fn fini(&self) -> &Lifecycle {
        self.finalizer.lifecycle()
    }

    /// Returns mutable finalization lifecycle addresses.
    #[inline]
    pub fn fini_mut(&mut self) -> &mut Lifecycle {
        self.finalizer.lifecycle_mut()
    }

    /// Installs a hook that runs immediately before finalization functions.
    #[inline]
    pub fn set_fini_hook<F>(&mut self, hook: F)
    where
        F: for<'fini> Fn(&mut FiniEvent<'fini>) -> crate::Result<()> + Send + Sync + 'static,
    {
        self.finalizer.set_hook(hook);
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (ObjectExportsHandle<Arch::Layout>, Finalizer<Arch>) {
        (self.exports, self.finalizer)
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
