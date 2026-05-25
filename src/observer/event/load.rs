use crate::{
    arch::{ArchKind, NativeArch},
    elf::{ElfLayout, ElfPhdr, NativeElfLayout},
    image::RawDynamic,
    input::Path,
    relocation::RelocationArch,
    segment::ElfSegments,
};

/// Program-header event emitted while an ELF image is being loaded.
pub struct ProgramHeaderEvent<'a, L: ElfLayout = NativeElfLayout> {
    path: &'a Path,
    phdr: &'a ElfPhdr<L>,
    segments: &'a ElfSegments,
}

impl<'a, L: ElfLayout> ProgramHeaderEvent<'a, L> {
    #[inline]
    pub(crate) const fn new(
        path: &'a Path,
        phdr: &'a ElfPhdr<L>,
        segments: &'a ElfSegments,
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
    pub const fn segments(&self) -> &ElfSegments {
        self.segments
    }
}

/// A mapped but unrelocated dynamic image observed during a link operation.
pub struct StagedDynamic<'a, K, D: 'static, Arch: RelocationArch = NativeArch> {
    key: &'a K,
    raw: &'a RawDynamic<D, Arch>,
}

impl<'a, K, D: 'static, Arch> StagedDynamic<'a, K, D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) const fn new(key: &'a K, raw: &'a RawDynamic<D, Arch>) -> Self {
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
    pub const fn raw(&self) -> &'a RawDynamic<D, Arch> {
        self.raw
    }
}
