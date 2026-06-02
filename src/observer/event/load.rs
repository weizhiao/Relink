use crate::{
    arch::{ArchKind, NativeArch},
    elf::{
        ElfHeader, ElfLayout, ElfPhdr, ElfSectionId, ElfSectionType, ElfSections, ElfShdr,
        NativeElfLayout,
    },
    image::RawDynamic,
    input::{ElfReader, ElfReaderExt, Path},
    os::{HostRegion, RegionAccess},
    relocation::RelocationArch,
    segment::ElfSegments,
};
use alloc::vec::Vec;
use core::ffi::CStr;

/// Program-header event emitted while an ELF image is being loaded.
pub struct ProgramHeaderEvent<'a, L: ElfLayout = NativeElfLayout, R: RegionAccess = HostRegion> {
    path: &'a Path,
    phdr: &'a ElfPhdr<L>,
    segments: &'a ElfSegments<R>,
}

impl<'a, L: ElfLayout, R: RegionAccess> ProgramHeaderEvent<'a, L, R> {
    #[inline]
    pub(crate) const fn new(
        path: &'a Path,
        phdr: &'a ElfPhdr<L>,
        segments: &'a ElfSegments<R>,
    ) -> Self {
        Self {
            path,
            phdr,
            segments,
        }
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub const fn path(&self) -> &Path {
        self.path
    }

    /// Returns the program header being processed.
    #[inline]
    pub const fn phdr(&self) -> &ElfPhdr<L> {
        self.phdr
    }

    /// Returns the ELF segments built for this image.
    #[inline]
    pub const fn segments(&self) -> &ElfSegments<R> {
        self.segments
    }
}

/// Relocatable-object metadata observed after section-header validation and
/// before section contents are mapped.
pub struct ObjectMetadataEvent<'event, 'sections, D: 'static, L: ElfLayout = NativeElfLayout> {
    ehdr: &'event ElfHeader<L>,
    sections: &'event mut ElfSections<'sections, L>,
    object: &'event dyn ElfReader,
    user_data: &'event mut D,
}

impl<'event, 'sections, D: 'static, L: ElfLayout> ObjectMetadataEvent<'event, 'sections, D, L> {
    #[inline]
    #[cfg_attr(not(feature = "object"), allow(dead_code))]
    pub(crate) fn new(
        ehdr: &'event ElfHeader<L>,
        sections: &'event mut ElfSections<'sections, L>,
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
        let Some((offset, len)) = self.section_content_range(id)? else {
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
        let Some((offset, len)) = self.section_content_range(id)? else {
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

    fn section_content_range(&self, id: ElfSectionId) -> crate::Result<Option<(usize, usize)>> {
        let shdr = self.section(id);
        let len = shdr.sh_size();
        if len == 0 || shdr.section_type() == ElfSectionType::NOBITS {
            return Ok(None);
        }
        Ok(Some((shdr.sh_offset(), len)))
    }
}

/// A dynamic image that has been mapped and parsed, before relocation.
pub struct DynamicLoadedEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    raw: &'a mut RawDynamic<D, Arch, R>,
}

impl<'a, D: 'static, Arch, R> DynamicLoadedEvent<'a, D, Arch, R>
where
    Arch: RelocationArch,
    R: RegionAccess,
{
    #[inline]
    pub(crate) const fn new(raw: &'a mut RawDynamic<D, Arch, R>) -> Self {
        Self { raw }
    }

    /// Returns the dynamic image.
    #[inline]
    pub const fn raw(&self) -> &RawDynamic<D, Arch, R> {
        self.raw
    }

    /// Returns the mutable dynamic image.
    #[inline]
    pub fn raw_mut(&mut self) -> &mut RawDynamic<D, Arch, R> {
        self.raw
    }
}

/// A mapped but unrelocated dynamic image observed during a link operation.
pub struct StagedDynamic<
    'a,
    K,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    key: &'a K,
    raw: &'a RawDynamic<D, Arch, R>,
}

impl<'a, K, D: 'static, Arch, R> StagedDynamic<'a, K, D, Arch, R>
where
    Arch: RelocationArch,
    R: RegionAccess,
{
    #[inline]
    pub(crate) const fn new(key: &'a K, raw: &'a RawDynamic<D, Arch, R>) -> Self {
        Self { key, raw }
    }

    /// Returns the key of the staged module.
    #[inline]
    pub const fn key(&self) -> &'a K {
        self.key
    }

    /// Returns the architecture kind of the staged module.
    #[inline]
    pub const fn arch_kind(&self) -> ArchKind {
        Arch::KIND
    }

    /// Returns the mapped byte length of the staged module.
    #[inline]
    pub fn mapped_len(&self) -> usize {
        self.raw.mapped_len()
    }

    /// Returns the unrelocated dynamic image.
    #[inline]
    pub const fn raw(&self) -> &'a RawDynamic<D, Arch, R> {
        self.raw
    }
}
