//! Pre-mapping ELF descriptions and lazily readable section data.

use crate::{
    AlignedBytes, ParseDynamicError, ParsePhdrError, Result,
    arch::ArchKind,
    elf::{
        Elf32Layout, Elf64Layout, ElfDyn, ElfHeader, ElfLayout, ElfPhdr, ElfProgramType,
        ElfSectionFlags, ElfSectionIndex, ElfSectionType, ElfShdr, ElfStringTable, NativeElfLayout,
        parse_dynamic_entries,
    },
    entity::entity_ref,
    input::{ElfReader, ElfReaderExt},
    loader::ScanBuilder,
};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{fmt, mem::size_of, num::NonZeroUsize, ptr};
use elf::abi::{DF_1_NOW, DF_BIND_NOW, DF_STATIC_TLS};

struct DynamicScanParts {
    dynamic: ScannedDynamicInfo,
    strtab: Box<[u8]>,
    needed_libs: Box<[usize]>,
    rpath: Option<usize>,
    runpath: Option<usize>,
}

impl DynamicScanParts {
    fn new<L: ElfLayout>(object: &mut dyn ElfReader, phdrs: &[ElfPhdr<L>]) -> Result<Self> {
        let dynamic_phdr = phdrs
            .iter()
            .find(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
            .ok_or(ParsePhdrError::MissingDynamicSection)?;
        if dynamic_phdr.p_filesz() % size_of::<ElfDyn<L>>() != 0 {
            return Err(ParsePhdrError::MalformedProgramHeaders.into());
        }

        let dyns = object.read_to_vec::<ElfDyn<L>>(
            dynamic_phdr.p_offset(),
            dynamic_phdr.p_filesz() / core::mem::size_of::<ElfDyn<L>>(),
        )?;
        let parsed = parse_dynamic_entries(
            dyns.into_iter()
                .map(|dynamic| (dynamic.tag(), dynamic.value())),
        );

        let strtab_vaddr =
            NonZeroUsize::new(parsed.strtab_off).ok_or(ParseDynamicError::AddressOverflow)?;
        let strtab_file_off = vaddr_to_file_offset(strtab_vaddr.get(), phdrs)?;
        let strtab_size = parsed
            .strtab_size
            .ok_or(ParseDynamicError::MissingRequiredTag { tag: "DT_STRSZ" })?
            .get();
        let strtab = object.read_to_vec(strtab_file_off, strtab_size)?;

        let needed_libs = parsed
            .needed_libs
            .into_iter()
            .map(|offset| offset.get())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let rpath = parsed.rpath_off.map(|offset| offset.get());
        let runpath = parsed.runpath_off.map(|offset| offset.get());

        Ok(Self {
            dynamic: ScannedDynamicInfo::new(
                parsed.flags & DF_BIND_NOW as usize != 0 || parsed.flags_1 & DF_1_NOW as usize != 0,
                parsed.flags & DF_STATIC_TLS as usize != 0,
            ),
            strtab: strtab.into_boxed_slice(),
            needed_libs,
            rpath,
            runpath,
        })
    }
}

struct SectionTable<L: ElfLayout = NativeElfLayout> {
    sections: Box<[ElfShdr<L>]>,
    shstrtab: Box<[u8]>,
}

impl<L: ElfLayout> SectionTable<L> {
    fn new(object: &mut dyn ElfReader, ehdr: &ElfHeader<L>) -> Result<Option<Self>> {
        if ehdr.e_shnum() == 0 {
            return Ok(None);
        }

        let Some((start, _)) = ehdr.checked_shdr_layout()? else {
            return Ok(None);
        };

        let shdrs = object.read_to_vec::<ElfShdr<L>>(start, ehdr.e_shnum())?;
        let shstrndx = ehdr.e_shstrndx();
        let shstrtab = match shdrs.get(shstrndx) {
            Some(shdr) if shdr.section_type() != ElfSectionType::NOBITS => {
                object.read_to_vec(shdr.sh_offset(), shdr.sh_size())?
            }
            _ => return Ok(None),
        };

        Ok(Some(SectionTable {
            sections: shdrs.into_boxed_slice(),
            shstrtab: shstrtab.into_boxed_slice(),
        }))
    }
}

/// The planning capability exposed by one scanned module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModuleCapability {
    /// The module has no usable section-table view for planning.
    Opaque,
    /// The module exposes section metadata/data, but not enough retained
    /// relocation inputs to support section reordering repair.
    SectionData,
    /// The module exposes enough retained relocation inputs for section-level
    /// reordering and repair.
    SectionReorderable,
}

impl ModuleCapability {
    /// Returns whether this module exposes section metadata/data.
    #[inline]
    pub const fn has_section_data(self) -> bool {
        !matches!(self, Self::Opaque)
    }

    /// Returns whether this module supports section reordering repair.
    #[inline]
    pub const fn supports_reorder_repair(self) -> bool {
        matches!(self, Self::SectionReorderable)
    }
}

/// Dynamic-library metadata collected before the object is mapped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScannedDynamicInfo {
    bind_now: bool,
    static_tls: bool,
}

impl ScannedDynamicInfo {
    #[inline]
    pub(crate) const fn new(bind_now: bool, static_tls: bool) -> Self {
        Self {
            bind_now,
            static_tls,
        }
    }

    /// Returns whether the object requests eager binding.
    #[inline]
    pub fn bind_now(&self) -> bool {
        self.bind_now
    }

    /// Returns whether the object requests static TLS.
    #[inline]
    pub fn static_tls(&self) -> bool {
        self.static_tls
    }
}

/// A dynamic ELF image that has been parsed but not yet mapped into memory.
pub struct ScannedDynamic<L: ElfLayout = NativeElfLayout> {
    name: String,
    ehdr: ElfHeader<L>,
    phdrs: Box<[ElfPhdr<L>]>,
    interp: Option<Box<[u8]>>,
    _strtab_bytes: Box<[u8]>,
    strtab: ElfStringTable,
    section_table: Option<SectionTable<L>>,
    rpath: Option<usize>,
    runpath: Option<usize>,
    needed_libs: Box<[usize]>,
    capability: ModuleCapability,
    reader: Box<dyn ElfReader + 'static>,
    dynamic: ScannedDynamicInfo,
}

/// A static executable that has been parsed but not yet mapped into memory.
pub struct ScannedExec<L: ElfLayout = NativeElfLayout> {
    name: String,
    ehdr: ElfHeader<L>,
    phdrs: Box<[ElfPhdr<L>]>,
    interp: Option<Box<[u8]>>,
    section_table: Option<SectionTable<L>>,
    reader: Box<dyn ElfReader + 'static>,
}

/// A scanned ELF image classified by the metadata available before mapping.
#[derive(Debug)]
pub enum ScannedElf<L: ElfLayout = NativeElfLayout> {
    /// An image with `PT_DYNAMIC` metadata.
    Dynamic(ScannedDynamic<L>),
    /// An executable without `PT_DYNAMIC` metadata.
    StaticExec(ScannedExec<L>),
}

pub(crate) struct ScannedDynamicLoadParts<L: ElfLayout = NativeElfLayout> {
    pub(crate) ehdr: ElfHeader<L>,
    pub(crate) phdrs: Box<[ElfPhdr<L>]>,
    pub(crate) reader: Box<dyn ElfReader + 'static>,
}

/// A stable identifier for one scanned section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ScannedSectionId(usize);
entity_ref!(ScannedSectionId);

impl From<usize> for ScannedSectionId {
    #[inline]
    fn from(index: usize) -> Self {
        Self::new(index)
    }
}

impl From<ScannedSectionId> for usize {
    #[inline]
    fn from(id: ScannedSectionId) -> Self {
        id.index()
    }
}

impl ScannedSectionId {
    /// Converts a symbol `st_shndx` value into a scanned section id when it
    /// names a real section table entry.
    #[inline]
    pub const fn from_symbol_shndx(index: ElfSectionIndex) -> Option<Self> {
        if index.is_undef() || index.is_abs() {
            None
        } else {
            Some(Self::new(index.index()))
        }
    }
}

/// A readable view over one scanned section and its metadata.
pub struct ScannedSection<'a, L: ElfLayout = NativeElfLayout> {
    id: ScannedSectionId,
    name: &'a str,
    header: &'a ElfShdr<L>,
}

impl<L: ElfLayout> Copy for ScannedSection<'_, L> {}

impl<L: ElfLayout> Clone for ScannedSection<'_, L> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

/// Iterator over the usable section-table entries of a scanned module.
pub struct ScannedSections<'a, L: ElfLayout = NativeElfLayout> {
    sections: &'a [ElfShdr<L>],
    shstrtab: *const u8,
    index: usize,
}

/// Layout-erased scanned dynamic image used by heterogeneous planning.
pub enum AnyScannedDynamic {
    X86_64(ScannedDynamic<Elf64Layout>),
    AArch64(ScannedDynamic<Elf64Layout>),
    RiscV64(ScannedDynamic<Elf64Layout>),
    RiscV32(ScannedDynamic<Elf32Layout>),
    LoongArch64(ScannedDynamic<Elf64Layout>),
    X86(ScannedDynamic<Elf32Layout>),
    Arm(ScannedDynamic<Elf32Layout>),
}

/// Layout-erased section metadata exposed by planned-load passes.
#[derive(Clone, Copy)]
pub struct AnyScannedSection<'a> {
    id: ScannedSectionId,
    name: &'a str,
    section_type: ElfSectionType,
    flags: ElfSectionFlags,
    address: usize,
    file_offset: usize,
    size: usize,
    alignment: usize,
    linked_section: Option<ScannedSectionId>,
    info_section: Option<ScannedSectionId>,
}

/// Layout-erased view of a scanned section-header table.
pub enum AnySectionHeaders<'a> {
    Elf32(&'a [ElfShdr<Elf32Layout>]),
    Elf64(&'a [ElfShdr<Elf64Layout>]),
}

impl<'a, L: ElfLayout> ScannedSections<'a, L> {
    #[inline]
    fn new(sections: &'a [ElfShdr<L>], shstrtab: *const u8) -> Self {
        Self {
            sections,
            shstrtab,
            index: 0,
        }
    }

    #[inline]
    fn section_name(&self, section: &ElfShdr<L>) -> &'a str {
        let table = ElfStringTable::new(self.shstrtab);
        table.get_str(section.sh_name() as usize)
    }
}

impl<'a, L: ElfLayout> Iterator for ScannedSections<'a, L> {
    type Item = ScannedSection<'a, L>;

    fn next(&mut self) -> Option<Self::Item> {
        let header = self.sections.get(self.index)?;
        let id = ScannedSectionId::new(self.index);
        self.index += 1;
        Some(ScannedSection::new(id, self.section_name(header), header))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.sections.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl<L: ElfLayout> ExactSizeIterator for ScannedSections<'_, L> {}

impl<'a, L: ElfLayout> From<ScannedSection<'a, L>> for AnyScannedSection<'a> {
    #[inline]
    fn from(section: ScannedSection<'a, L>) -> Self {
        Self {
            id: section.id(),
            name: section.name(),
            section_type: section.section_type(),
            flags: section.flags(),
            address: section.address(),
            file_offset: section.file_offset(),
            size: section.size(),
            alignment: section.alignment(),
            linked_section: section.linked_section_id(),
            info_section: section.info_section_id(),
        }
    }
}

impl<'a> AnyScannedSection<'a> {
    /// Returns the stable section id.
    #[inline]
    pub const fn id(&self) -> ScannedSectionId {
        self.id
    }

    /// Returns the section name.
    #[inline]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// Returns the parsed section type.
    #[inline]
    pub const fn section_type(&self) -> ElfSectionType {
        self.section_type
    }

    /// Returns the parsed section flags.
    #[inline]
    pub const fn flags(&self) -> ElfSectionFlags {
        self.flags
    }

    /// Returns the section address.
    #[inline]
    pub const fn address(&self) -> usize {
        self.address
    }

    /// Returns the section file offset.
    #[inline]
    pub const fn file_offset(&self) -> usize {
        self.file_offset
    }

    /// Returns the section size in bytes.
    #[inline]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the section alignment in bytes.
    #[inline]
    pub const fn alignment(&self) -> usize {
        self.alignment
    }

    /// Returns whether the section contributes to the loaded memory image.
    #[inline]
    pub fn is_allocated(&self) -> bool {
        self.flags().contains(ElfSectionFlags::ALLOC)
    }

    /// Returns whether the section is writable after mapping.
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.flags().contains(ElfSectionFlags::WRITE)
    }

    /// Returns whether the section is executable.
    #[inline]
    pub fn is_executable(&self) -> bool {
        self.flags().contains(ElfSectionFlags::EXECINSTR)
    }

    /// Returns whether the section belongs to TLS storage.
    #[inline]
    pub fn is_tls(&self) -> bool {
        self.flags().contains(ElfSectionFlags::TLS)
    }

    /// Returns whether the section is zero-fill only (`SHT_NOBITS`).
    #[inline]
    pub fn is_nobits(&self) -> bool {
        self.section_type() == ElfSectionType::NOBITS
    }

    /// Returns whether the section stores retained relocations.
    #[inline]
    pub fn is_relocation_section(&self) -> bool {
        matches!(
            self.section_type(),
            ElfSectionType::REL | ElfSectionType::RELA
        )
    }

    /// Returns the linked section id referenced by `sh_link`, when non-zero.
    #[inline]
    pub const fn linked_section_id(&self) -> Option<ScannedSectionId> {
        self.linked_section
    }

    /// Returns the info section id referenced by `sh_info`, when non-zero.
    #[inline]
    pub const fn info_section_id(&self) -> Option<ScannedSectionId> {
        self.info_section
    }
}

impl fmt::Debug for AnyScannedSection<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyScannedSection")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("type", &self.section_type)
            .field("size", &self.size)
            .field("align", &self.alignment)
            .finish()
    }
}

impl AnySectionHeaders<'_> {
    /// Returns the number of section headers.
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Elf32(headers) => headers.len(),
            Self::Elf64(headers) => headers.len(),
        }
    }

    /// Returns whether the table is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for AnySectionHeaders<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnySectionHeaders")
            .field("len", &self.len())
            .finish()
    }
}

impl fmt::Debug for AnyScannedDynamic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyScannedDynamic")
            .field("arch", &self.arch_kind())
            .field("name", &self.name())
            .field("needed_libs", &self.needed_libs().collect::<Vec<_>>())
            .field("capability", &self.capability())
            .field("bind_now", &self.dynamic().bind_now())
            .field("static_tls", &self.dynamic().static_tls())
            .finish()
    }
}

macro_rules! any_scanned_dynamic {
    ($($variant:ident => $kind:ident),+ $(,)?) => {
        impl AnyScannedDynamic {
            /// Returns the relocation backend selected for this scanned module.
            #[inline]
            pub const fn arch_kind(&self) -> ArchKind {
                match self {
                    $(Self::$variant(_) => ArchKind::$kind,)+
                }
            }

            /// Returns the file name or path selected for this image.
            #[inline]
            pub fn name(&self) -> &str {
                match self {
                    $(Self::$variant(module) => module.name(),)+
                }
            }

            /// Returns the short image name.
            #[inline]
            pub fn short_name(&self) -> &str {
                match self {
                    $(Self::$variant(module) => module.short_name(),)+
                }
            }

            /// Returns the PT_INTERP string when present.
            #[inline]
            pub fn interp(&self) -> Option<&str> {
                match self {
                    $(Self::$variant(module) => module.interp(),)+
                }
            }

            /// Returns the DT_RPATH string when present.
            #[inline]
            pub fn rpath(&self) -> Option<&str> {
                match self {
                    $(Self::$variant(module) => module.rpath(),)+
                }
            }

            /// Returns the DT_RUNPATH string when present.
            #[inline]
            pub fn runpath(&self) -> Option<&str> {
                match self {
                    $(Self::$variant(module) => module.runpath(),)+
                }
            }

            /// Returns one `DT_NEEDED` entry by index.
            #[inline]
            pub fn needed_lib(&self, index: usize) -> Option<&str> {
                match self {
                    $(Self::$variant(module) => module.needed_lib(index),)+
                }
            }

            /// Returns the number of `DT_NEEDED` entries.
            #[inline]
            pub fn needed_len(&self) -> usize {
                match self {
                    $(Self::$variant(module) => module.needed_libs().len(),)+
                }
            }

            /// Iterates over the `DT_NEEDED` entries.
            #[inline]
            pub fn needed_libs(&self) -> impl Iterator<Item = &str> + '_ {
                (0..self.needed_len()).map(|index| {
                    self.needed_lib(index)
                        .expect("AnyScannedDynamic DT_NEEDED index out of bounds")
                })
            }

            /// Returns the planning capability of this module.
            #[inline]
            pub fn capability(&self) -> ModuleCapability {
                match self {
                    $(Self::$variant(module) => module.capability(),)+
                }
            }

            /// Returns whether the module exposes a usable section-table view.
            #[inline]
            pub fn has_sections(&self) -> bool {
                match self {
                    $(Self::$variant(module) => module.has_sections(),)+
                }
            }

            /// Returns one scanned section by id.
            #[inline]
            pub fn section(&self, id: impl Into<ScannedSectionId>) -> Option<AnyScannedSection<'_>> {
                let id = id.into();
                match self {
                    $(Self::$variant(module) => module.section(id).map(Into::into),)+
                }
            }

            /// Iterates over all scanned sections together with stable ids.
            #[inline]
            pub fn sections(&self) -> Box<dyn Iterator<Item = AnyScannedSection<'_>> + '_> {
                match self {
                    $(Self::$variant(module) => Box::new(module.sections().map(Into::into)),)+
                }
            }

            /// Iterates over sections that contribute to the loaded memory image.
            #[inline]
            pub fn alloc_sections(&self) -> Box<dyn Iterator<Item = AnyScannedSection<'_>> + '_> {
                match self {
                    $(Self::$variant(module) => Box::new(module.alloc_sections().map(Into::into)),)+
                }
            }

            /// Captures one section's backing bytes.
            pub fn section_data(
                &mut self,
                id: impl Into<ScannedSectionId>,
            ) -> Result<Option<AlignedBytes>> {
                let id = id.into();
                match self {
                    $(Self::$variant(module) => module.section_data(id),)+
                }
            }

            /// Returns the dynamic binding and TLS policy flags discovered during scan.
            #[inline]
            pub fn dynamic(&self) -> &ScannedDynamicInfo {
                match self {
                    $(Self::$variant(module) => module.dynamic(),)+
                }
            }
        }
    };
}

any_scanned_dynamic!(
    X86_64 => X86_64,
    AArch64 => AArch64,
    RiscV64 => RiscV64,
    RiscV32 => RiscV32,
    LoongArch64 => LoongArch64,
    X86 => X86,
    Arm => Arm,
);

impl AnyScannedDynamic {
    /// Returns the raw ELF section headers, when the section table is usable.
    #[inline]
    pub fn section_headers(&self) -> Option<AnySectionHeaders<'_>> {
        match self {
            Self::X86_64(module)
            | Self::AArch64(module)
            | Self::RiscV64(module)
            | Self::LoongArch64(module) => module.section_headers().map(AnySectionHeaders::Elf64),
            Self::RiscV32(module) | Self::X86(module) | Self::Arm(module) => {
                module.section_headers().map(AnySectionHeaders::Elf32)
            }
        }
    }
}

impl<'a, L: ElfLayout> ScannedSection<'a, L> {
    #[inline]
    fn new(id: ScannedSectionId, name: &'a str, header: &'a ElfShdr<L>) -> Self {
        Self { id, name, header }
    }

    /// Returns the stable section id.
    #[inline]
    pub const fn id(&self) -> ScannedSectionId {
        self.id
    }

    /// Returns the section name.
    #[inline]
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Returns the underlying ELF section header.
    #[inline]
    pub fn header(&self) -> &'a ElfShdr<L> {
        self.header
    }

    /// Returns the parsed section type.
    #[inline]
    pub fn section_type(&self) -> ElfSectionType {
        self.header.section_type()
    }

    /// Returns the parsed section flags.
    #[inline]
    pub fn flags(&self) -> ElfSectionFlags {
        self.header.flags()
    }

    /// Returns the section address.
    #[inline]
    pub fn address(&self) -> usize {
        self.header.sh_addr()
    }

    /// Returns the section file offset.
    #[inline]
    pub fn file_offset(&self) -> usize {
        self.header.sh_offset()
    }

    /// Returns the section size in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        self.header.sh_size()
    }

    /// Returns the section alignment in bytes.
    #[inline]
    pub fn alignment(&self) -> usize {
        self.header.sh_addralign()
    }

    /// Returns whether the section contributes to the loaded memory image.
    #[inline]
    pub fn is_allocated(&self) -> bool {
        self.flags().contains(ElfSectionFlags::ALLOC)
    }

    /// Returns whether the section is writable after mapping.
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.flags().contains(ElfSectionFlags::WRITE)
    }

    /// Returns whether the section is executable.
    #[inline]
    pub fn is_executable(&self) -> bool {
        self.flags().contains(ElfSectionFlags::EXECINSTR)
    }

    /// Returns whether the section belongs to TLS storage.
    #[inline]
    pub fn is_tls(&self) -> bool {
        self.flags().contains(ElfSectionFlags::TLS)
    }

    /// Returns whether the section is zero-fill only (`SHT_NOBITS`).
    #[inline]
    pub fn is_nobits(&self) -> bool {
        self.section_type() == ElfSectionType::NOBITS
    }

    /// Returns whether the section stores retained relocations.
    #[inline]
    pub fn is_relocation_section(&self) -> bool {
        matches!(
            self.section_type(),
            ElfSectionType::REL | ElfSectionType::RELA
        )
    }

    /// Returns the linked section id referenced by `sh_link`, when non-zero.
    #[inline]
    pub fn linked_section_id(&self) -> Option<ScannedSectionId> {
        (self.header.sh_link() != 0)
            .then_some(ScannedSectionId::new(self.header.sh_link() as usize))
    }

    /// Returns the info section id referenced by `sh_info`, when non-zero.
    #[inline]
    pub fn info_section_id(&self) -> Option<ScannedSectionId> {
        (self.header.sh_info() != 0)
            .then_some(ScannedSectionId::new(self.header.sh_info() as usize))
    }
}

impl<'a, L: ElfLayout> fmt::Debug for ScannedSection<'a, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedSection")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("type", &self.section_type())
            .field("size", &self.size())
            .field("align", &self.alignment())
            .finish()
    }
}

impl<L: ElfLayout> fmt::Debug for ScannedDynamic<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedDynamic")
            .field("name", &self.name)
            .field("needed_libs", &self.needed_libs().collect::<Vec<_>>())
            .field(
                "sections",
                &self
                    .section_table
                    .as_ref()
                    .map_or(0, |table| table.sections.len()),
            )
            .field("capability", &self.capability)
            .field("bind_now", &self.dynamic.bind_now)
            .field("static_tls", &self.dynamic.static_tls)
            .finish()
    }
}

impl<L: ElfLayout> fmt::Debug for ScannedExec<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScannedExec")
            .field("name", &self.name)
            .field(
                "sections",
                &self
                    .section_table
                    .as_ref()
                    .map_or(0, |table| table.sections.len()),
            )
            .finish()
    }
}

impl<L: ElfLayout> ScannedElf<L> {
    /// Returns the file name or path selected for this image.
    #[inline]
    pub fn name(&self) -> &str {
        match self {
            Self::Dynamic(image) => image.name(),
            Self::StaticExec(image) => image.name(),
        }
    }

    /// Returns the short image name.
    #[inline]
    pub fn short_name(&self) -> &str {
        match self {
            Self::Dynamic(image) => image.short_name(),
            Self::StaticExec(image) => image.short_name(),
        }
    }

    /// Returns the parsed ELF header.
    #[inline]
    pub fn ehdr(&self) -> &ElfHeader<L> {
        match self {
            Self::Dynamic(image) => image.ehdr(),
            Self::StaticExec(image) => image.ehdr(),
        }
    }

    /// Returns the parsed program headers.
    #[inline]
    pub fn phdrs(&self) -> &[ElfPhdr<L>] {
        match self {
            Self::Dynamic(image) => image.phdrs(),
            Self::StaticExec(image) => image.phdrs(),
        }
    }

    /// Returns the PT_INTERP string when present.
    #[inline]
    pub fn interp(&self) -> Option<&str> {
        match self {
            Self::Dynamic(image) => image.interp(),
            Self::StaticExec(image) => image.interp(),
        }
    }

    /// Returns the dynamic scan data when this is a dynamic image.
    #[inline]
    pub fn as_dynamic(&self) -> Option<&ScannedDynamic<L>> {
        match self {
            Self::Dynamic(image) => Some(image),
            Self::StaticExec(_) => None,
        }
    }

    /// Returns the static executable scan data when this is a static executable.
    #[inline]
    pub fn as_static_exec(&self) -> Option<&ScannedExec<L>> {
        match self {
            Self::Dynamic(_) => None,
            Self::StaticExec(image) => Some(image),
        }
    }

    /// Consumes this value and returns dynamic scan data when present.
    #[inline]
    pub fn into_dynamic(self) -> Option<ScannedDynamic<L>> {
        match self {
            Self::Dynamic(image) => Some(image),
            Self::StaticExec(_) => None,
        }
    }

    /// Consumes this value and returns static executable scan data when present.
    #[inline]
    pub fn into_static_exec(self) -> Option<ScannedExec<L>> {
        match self {
            Self::Dynamic(_) => None,
            Self::StaticExec(image) => Some(image),
        }
    }

    /// Returns whether the image exposes a usable section-table view.
    #[inline]
    pub fn has_sections(&self) -> bool {
        match self {
            Self::Dynamic(image) => image.has_sections(),
            Self::StaticExec(image) => image.has_sections(),
        }
    }

    /// Returns the raw ELF section headers, when the section table is usable.
    #[inline]
    pub fn section_headers(&self) -> Option<&[ElfShdr<L>]> {
        match self {
            Self::Dynamic(image) => image.section_headers(),
            Self::StaticExec(image) => image.section_headers(),
        }
    }

    /// Returns one scanned section by id.
    #[inline]
    pub fn section(&self, id: impl Into<ScannedSectionId>) -> Option<ScannedSection<'_, L>> {
        match self {
            Self::Dynamic(image) => image.section(id),
            Self::StaticExec(image) => image.section(id),
        }
    }

    /// Iterates over all scanned sections together with stable ids.
    #[inline]
    pub fn sections(&self) -> ScannedSections<'_, L> {
        match self {
            Self::Dynamic(image) => image.sections(),
            Self::StaticExec(image) => image.sections(),
        }
    }

    /// Iterates over sections that contribute to the loaded memory image.
    #[inline]
    pub fn alloc_sections(&self) -> impl Iterator<Item = ScannedSection<'_, L>> {
        self.sections().filter(|section| section.is_allocated())
    }

    /// Captures one section's backing bytes.
    pub fn section_data(
        &mut self,
        id: impl Into<ScannedSectionId>,
    ) -> Result<Option<AlignedBytes>> {
        match self {
            Self::Dynamic(image) => image.section_data(id),
            Self::StaticExec(image) => image.section_data(id),
        }
    }
}

impl<L: ElfLayout> ScannedDynamic<L> {
    pub(crate) fn from_builder(builder: ScanBuilder<L>) -> Result<Self> {
        let ScanBuilder {
            name,
            ehdr,
            phdrs,
            mut reader,
        } = builder;
        let interp = read_interp(reader.as_mut(), &phdrs)?;
        let DynamicScanParts {
            dynamic,
            strtab,
            needed_libs,
            rpath,
            runpath,
        } = DynamicScanParts::new(reader.as_mut(), &phdrs)?;
        let section_table = SectionTable::new(reader.as_mut(), &ehdr)?;
        let strtab_view = ElfStringTable::new(strtab.as_ptr());
        let capability = section_table
            .as_ref()
            .map_or(ModuleCapability::Opaque, |table| {
                classify_module_capability(&table.sections)
            });

        Ok(Self {
            name,
            ehdr,
            phdrs,
            interp,
            _strtab_bytes: strtab,
            strtab: strtab_view,
            section_table,
            rpath,
            runpath,
            needed_libs,
            capability,
            reader,
            dynamic,
        })
    }

    /// Returns the file name or path selected for this image.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the short image name.
    #[inline]
    pub fn short_name(&self) -> &str {
        let name = self.name();
        name.rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or(name)
    }

    /// Returns the parsed ELF header.
    #[inline]
    pub fn ehdr(&self) -> &ElfHeader<L> {
        &self.ehdr
    }

    /// Returns the parsed program headers.
    #[inline]
    pub fn phdrs(&self) -> &[ElfPhdr<L>] {
        &self.phdrs
    }

    /// Returns the PT_INTERP string when present.
    #[inline]
    pub fn interp(&self) -> Option<&str> {
        self.interp.as_deref().and_then(|bytes| {
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len());
            core::str::from_utf8(&bytes[..end]).ok()
        })
    }

    /// Returns the DT_RPATH string when present.
    #[inline]
    pub fn rpath(&self) -> Option<&str> {
        self.rpath.map(|offset| self.strtab.get_str(offset))
    }

    /// Returns the DT_RUNPATH string when present.
    #[inline]
    pub fn runpath(&self) -> Option<&str> {
        self.runpath.map(|offset| self.strtab.get_str(offset))
    }

    /// Returns one `DT_NEEDED` entry by index.
    #[inline]
    pub fn needed_lib(&self, index: usize) -> Option<&str> {
        self.needed_libs
            .get(index)
            .map(|offset| self.strtab.get_str(*offset))
    }

    /// Iterates over the `DT_NEEDED` entries.
    #[inline]
    pub fn needed_libs(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.needed_libs
            .iter()
            .map(|offset| self.strtab.get_str(*offset))
    }

    /// Returns the planning capability of this module.
    #[inline]
    pub const fn capability(&self) -> ModuleCapability {
        self.capability
    }

    #[inline]
    fn shstrtab(&self) -> Option<ElfStringTable> {
        self.section_table
            .as_ref()
            .map(|table| ElfStringTable::new(table.shstrtab.as_ptr()))
    }

    /// Returns whether the module exposes a usable section-table view.
    #[inline]
    pub fn has_sections(&self) -> bool {
        self.section_table.is_some()
    }

    /// Returns the raw ELF section headers, when the section table is usable.
    #[inline]
    pub fn section_headers(&self) -> Option<&[ElfShdr<L>]> {
        self.section_table
            .as_ref()
            .map(|table| table.sections.as_ref())
    }

    /// Returns one scanned section by id.
    #[inline]
    pub fn section(&self, id: impl Into<ScannedSectionId>) -> Option<ScannedSection<'_, L>> {
        let id = id.into();
        let section_table = self.section_table.as_ref()?;
        let shstrtab = self.shstrtab()?;
        let header = section_table.sections.get(id.index())?;
        Some(ScannedSection::new(
            id,
            shstrtab.get_str(header.sh_name() as usize),
            header,
        ))
    }

    /// Iterates over all scanned sections together with stable ids.
    #[inline]
    pub fn sections(&self) -> ScannedSections<'_, L> {
        ScannedSections::new(
            self.section_table
                .as_ref()
                .map_or(&[], |table| table.sections.as_ref()),
            self.section_table
                .as_ref()
                .map_or(ptr::null(), |table| table.shstrtab.as_ptr()),
        )
    }

    /// Iterates over sections that contribute to the loaded memory image.
    #[inline]
    pub fn alloc_sections(&self) -> impl Iterator<Item = ScannedSection<'_, L>> {
        self.sections().filter(|section| section.is_allocated())
    }

    /// Iterates over retained relocation sections emitted into the section table.
    #[inline]
    pub fn relocation_sections(&self) -> impl Iterator<Item = ScannedSection<'_, L>> {
        self.sections()
            .filter(|section| section.is_relocation_section())
    }

    /// Captures one section's backing bytes.
    pub fn section_data(
        &mut self,
        id: impl Into<ScannedSectionId>,
    ) -> Result<Option<AlignedBytes>> {
        let Some(section) = self.section(id) else {
            return Ok(None);
        };

        if section.is_nobits() {
            return Ok(Some(
                AlignedBytes::with_len(section.size()).expect("failed to allocate section bytes"),
            ));
        }

        Ok(Some(
            self.read_bytes(section.file_offset(), section.size())?,
        ))
    }

    #[inline]
    fn read_bytes(&mut self, offset: usize, len: usize) -> Result<AlignedBytes> {
        let mut bytes = AlignedBytes::with_len(len).ok_or(ParseDynamicError::AddressOverflow)?;
        self.reader.read_slice(bytes.as_mut(), offset)?;
        Ok(bytes)
    }

    /// Returns the dynamic binding and TLS policy flags discovered during scan.
    #[inline]
    pub fn dynamic(&self) -> &ScannedDynamicInfo {
        &self.dynamic
    }

    pub(crate) fn into_load_parts(self) -> ScannedDynamicLoadParts<L> {
        let Self {
            ehdr,
            phdrs,
            reader,
            ..
        } = self;

        ScannedDynamicLoadParts {
            ehdr,
            phdrs,
            reader,
        }
    }
}

impl<L: ElfLayout> ScannedExec<L> {
    pub(crate) fn from_builder(builder: ScanBuilder<L>) -> Result<Self> {
        let ScanBuilder {
            name,
            ehdr,
            phdrs,
            mut reader,
        } = builder;
        let interp = read_interp(reader.as_mut(), &phdrs)?;
        let section_table = SectionTable::new(reader.as_mut(), &ehdr)?;

        Ok(Self {
            name,
            ehdr,
            phdrs,
            interp,
            section_table,
            reader,
        })
    }

    /// Returns the file name or path selected for this executable.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the short executable name.
    #[inline]
    pub fn short_name(&self) -> &str {
        let name = self.name();
        name.rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or(name)
    }

    /// Returns the parsed ELF header.
    #[inline]
    pub fn ehdr(&self) -> &ElfHeader<L> {
        &self.ehdr
    }

    /// Returns the parsed program headers.
    #[inline]
    pub fn phdrs(&self) -> &[ElfPhdr<L>] {
        &self.phdrs
    }

    /// Returns the PT_INTERP string when present.
    #[inline]
    pub fn interp(&self) -> Option<&str> {
        self.interp.as_deref().and_then(|bytes| {
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len());
            core::str::from_utf8(&bytes[..end]).ok()
        })
    }

    #[inline]
    fn shstrtab(&self) -> Option<ElfStringTable> {
        self.section_table
            .as_ref()
            .map(|table| ElfStringTable::new(table.shstrtab.as_ptr()))
    }

    /// Returns whether the executable exposes a usable section-table view.
    #[inline]
    pub fn has_sections(&self) -> bool {
        self.section_table.is_some()
    }

    /// Returns the raw ELF section headers, when the section table is usable.
    #[inline]
    pub fn section_headers(&self) -> Option<&[ElfShdr<L>]> {
        self.section_table
            .as_ref()
            .map(|table| table.sections.as_ref())
    }

    /// Returns one scanned section by id.
    #[inline]
    pub fn section(&self, id: impl Into<ScannedSectionId>) -> Option<ScannedSection<'_, L>> {
        let id = id.into();
        let section_table = self.section_table.as_ref()?;
        let shstrtab = self.shstrtab()?;
        let header = section_table.sections.get(id.index())?;
        Some(ScannedSection::new(
            id,
            shstrtab.get_str(header.sh_name() as usize),
            header,
        ))
    }

    /// Iterates over all scanned sections together with stable ids.
    #[inline]
    pub fn sections(&self) -> ScannedSections<'_, L> {
        ScannedSections::new(
            self.section_table
                .as_ref()
                .map_or(&[], |table| table.sections.as_ref()),
            self.section_table
                .as_ref()
                .map_or(ptr::null(), |table| table.shstrtab.as_ptr()),
        )
    }

    /// Iterates over sections that contribute to the loaded memory image.
    #[inline]
    pub fn alloc_sections(&self) -> impl Iterator<Item = ScannedSection<'_, L>> {
        self.sections().filter(|section| section.is_allocated())
    }

    /// Captures one section's backing bytes.
    pub fn section_data(
        &mut self,
        id: impl Into<ScannedSectionId>,
    ) -> Result<Option<AlignedBytes>> {
        let Some(section) = self.section(id) else {
            return Ok(None);
        };

        if section.is_nobits() {
            return Ok(Some(
                AlignedBytes::with_len(section.size()).expect("failed to allocate section bytes"),
            ));
        }

        Ok(Some(
            self.read_bytes(section.file_offset(), section.size())?,
        ))
    }

    #[inline]
    fn read_bytes(&mut self, offset: usize, len: usize) -> Result<AlignedBytes> {
        let mut bytes = AlignedBytes::with_len(len).ok_or(ParseDynamicError::AddressOverflow)?;
        self.reader.read_slice(bytes.as_mut(), offset)?;
        Ok(bytes)
    }
}

fn classify_module_capability<L: ElfLayout>(sections: &[ElfShdr<L>]) -> ModuleCapability {
    for section in sections {
        if !matches!(
            section.section_type(),
            ElfSectionType::REL | ElfSectionType::RELA
        ) {
            continue;
        }

        if !section.flags().contains(ElfSectionFlags::ALLOC)
            && section.sh_info() != 0
            && section.sh_link() != 0
        {
            return ModuleCapability::SectionReorderable;
        }
    }

    ModuleCapability::SectionData
}

fn read_interp<L: ElfLayout>(
    object: &mut dyn ElfReader,
    phdrs: &[ElfPhdr<L>],
) -> Result<Option<Box<[u8]>>> {
    let Some(interp) = phdrs
        .iter()
        .find(|phdr| phdr.program_type() == ElfProgramType::INTERP)
    else {
        return Ok(None);
    };

    let bytes = object.read_to_vec(interp.p_offset(), interp.p_filesz())?;
    Ok(Some(bytes.into_boxed_slice()))
}

fn vaddr_to_file_offset<L: ElfLayout>(vaddr: usize, phdrs: &[ElfPhdr<L>]) -> Result<usize> {
    for phdr in phdrs
        .iter()
        .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
    {
        let seg_start = phdr.p_vaddr();
        let seg_end = seg_start
            .checked_add(phdr.p_filesz())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        if seg_start <= vaddr && vaddr < seg_end {
            return phdr
                .p_offset()
                .checked_add(vaddr - seg_start)
                .ok_or(ParseDynamicError::AddressOverflow.into());
        }
    }

    Err(ParsePhdrError::MalformedProgramHeaders.into())
}
