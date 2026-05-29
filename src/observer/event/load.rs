use crate::{
    arch::{ArchKind, NativeArch},
    elf::{ElfLayout, ElfPhdr, NativeElfLayout},
    image::RawDynamic,
    input::Path,
    os::{HostRegion, RegionAccess},
    relocation::RelocationArch,
    segment::ElfSegments,
};

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
