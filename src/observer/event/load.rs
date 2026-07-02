use crate::{
    arch::NativeArch,
    elf::{ElfHeader, ElfLayout, ElfPhdr, NativeElfLayout},
    image::RawDynamic,
    input::{ElfReader, Path},
    memory::{HostRegion, RegionAccess},
    relocation::RelocationArch,
    tls::TlsResolver,
};

/// Event emitted after dynamic-image program headers are available and before
/// `PT_LOAD` segments are mapped.
pub struct BeforeDynamicLoadEvent<'a, D: 'static, L: ElfLayout = NativeElfLayout> {
    path: &'a Path,
    reader: &'a dyn ElfReader,
    ehdr: &'a ElfHeader<L>,
    phdrs: &'a [ElfPhdr<L>],
    user_data: &'a mut D,
}

impl<'a, D: 'static, L: ElfLayout> BeforeDynamicLoadEvent<'a, D, L> {
    #[inline]
    pub(crate) const fn new(
        path: &'a Path,
        reader: &'a dyn ElfReader,
        ehdr: &'a ElfHeader<L>,
        phdrs: &'a [ElfPhdr<L>],
        user_data: &'a mut D,
    ) -> Self {
        Self {
            path,
            reader,
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

    /// Returns the ELF reader for the source object.
    #[inline]
    pub const fn reader(&self) -> &dyn ElfReader {
        self.reader
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
    Tls: TlsResolver<Arch> = (),
> {
    raw: &'a mut RawDynamic<D, Arch, R, Tls>,
}

impl<'a, D: 'static, Arch, R, Tls> AfterDynamicLoadEvent<'a, D, Arch, R, Tls>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) const fn new(raw: &'a mut RawDynamic<D, Arch, R, Tls>) -> Self {
        Self { raw }
    }

    /// Returns the dynamic image.
    #[inline]
    pub const fn raw(&self) -> &RawDynamic<D, Arch, R, Tls> {
        self.raw
    }

    /// Returns the mutable dynamic image.
    #[inline]
    pub fn raw_mut(&mut self) -> &mut RawDynamic<D, Arch, R, Tls> {
        self.raw
    }
}
