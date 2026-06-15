use crate::{
    arch::{ArchKind, NativeArch},
    elf::{ElfHeader, ElfLayout, ElfPhdr, NativeElfLayout},
    image::RawDynamic,
    input::Path,
    memory::{HostRegion, RegionAccess},
    relocation::RelocationArch,
};

/// Event emitted after dynamic-image program headers are available and before
/// `PT_LOAD` segments are mapped.
pub struct BeforeDynamicLoadEvent<'a, D: 'static, L: ElfLayout = NativeElfLayout> {
    path: &'a Path,
    ehdr: &'a ElfHeader<L>,
    phdrs: &'a [ElfPhdr<L>],
    user_data: &'a mut D,
}

impl<'a, D: 'static, L: ElfLayout> BeforeDynamicLoadEvent<'a, D, L> {
    #[inline]
    pub(crate) const fn new(
        path: &'a Path,
        ehdr: &'a ElfHeader<L>,
        phdrs: &'a [ElfPhdr<L>],
        user_data: &'a mut D,
    ) -> Self {
        Self {
            path,
            ehdr,
            phdrs,
            user_data,
        }
    }

    /// Returns the loader source path or caller-provided source identifier.
    #[inline]
    pub const fn path(&self) -> &Path {
        self.path
    }

    /// Returns the parsed ELF header.
    #[inline]
    pub const fn ehdr(&self) -> &ElfHeader<L> {
        self.ehdr
    }

    /// Returns the parsed program headers.
    #[inline]
    pub const fn phdrs(&self) -> &[ElfPhdr<L>] {
        self.phdrs
    }

    /// Returns immutable user data for this image.
    #[inline]
    pub const fn user_data(&self) -> &D {
        self.user_data
    }

    /// Returns mutable user data for this image.
    #[inline]
    pub fn user_data_mut(&mut self) -> &mut D {
        self.user_data
    }
}

/// Event emitted after a dynamic image has been mapped and parsed, before relocation.
pub struct AfterDynamicLoadEvent<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    raw: &'a mut RawDynamic<D, Arch, R>,
}

impl<'a, D: 'static, Arch, R> AfterDynamicLoadEvent<'a, D, Arch, R>
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

    /// Returns the unrelocated dynamic image.
    #[inline]
    pub const fn raw(&self) -> &'a RawDynamic<D, Arch, R> {
        self.raw
    }
}
