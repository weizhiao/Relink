#[cfg(feature = "version")]
use crate::elf::{ElfLayout, SymbolTableView};
use crate::{
    ByteRepr, ParseDynamicError, Result,
    elf::{ElfDynamicTag, ElfStringTable, hash::sysv_hash},
    memory::{ImageMemoryExt, MappedView, RegionAccess, VmAddr, VmOffset},
    segment::ElfSegments,
};
use alloc::vec::Vec;
use core::{fmt, mem::size_of, num::NonZeroUsize};
use elf::abi;

const VERSION_CURRENT: u16 = 1;
const VER_FLG_BASE: u16 = 0x1;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VerDef {
    pub(crate) vd_version: u16,
    pub(crate) vd_flags: u16,
    pub(crate) vd_ndx: u16,
    pub(crate) vd_cnt: u16,
    pub(crate) vd_hash: u32,
    pub(crate) vd_aux: u32,
    pub(crate) vd_next: u32,
}

impl VerDef {
    #[inline]
    pub(crate) fn index(self) -> usize {
        (self.vd_ndx & abi::VER_NDX_VERSION) as usize
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VerDefAux {
    pub(crate) vda_name: u32,
    pub(crate) vda_next: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VerNeed {
    vn_version: u16,
    vn_cnt: u16,
    vn_file: u32,
    vn_aux: u32,
    vn_next: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VerNeedAux {
    vna_hash: u32,
    vna_flags: u16,
    vna_other: u16,
    vna_name: u32,
    vna_next: u32,
}

impl VerNeedAux {
    #[inline]
    fn index(self) -> usize {
        (self.vna_other & abi::VER_NDX_VERSION) as usize
    }
}

// Safety: these native-endian ELF records contain only integer fields, have no
// padding, and accept every possible bit pattern.
unsafe impl ByteRepr for VerDef {}
unsafe impl ByteRepr for VerDefAux {}
unsafe impl ByteRepr for VerNeed {}
unsafe impl ByteRepr for VerNeedAux {}

#[derive(Clone, Copy, Debug)]
struct VersionIndex(u16);

impl VersionIndex {
    #[inline]
    fn index(self) -> usize {
        (self.0 & abi::VER_NDX_VERSION) as usize
    }

    #[inline]
    fn is_hidden(self) -> bool {
        (self.0 & abi::VER_NDX_HIDDEN) != 0
    }
}

#[derive(Clone)]
struct VersionIndexTable(MappedView<u16>);

impl fmt::Debug for VersionIndexTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.as_slice().iter().copied().map(VersionIndex))
            .finish()
    }
}

impl VersionIndexTable {
    fn parse<R: RegionAccess>(addr: VmAddr, segments: &ElfSegments<R>) -> Result<Self> {
        let offset = addr
            .checked_offset_from(segments.base())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let entries = segments.read_tail_view(offset)?;
        Ok(Self(entries))
    }

    #[inline]
    fn get(&self, symbol_index: usize) -> Option<VersionIndex> {
        self.0
            .as_slice()
            .get(symbol_index)
            .copied()
            .map(VersionIndex)
    }
}

#[derive(Clone)]
struct Version {
    name: &'static [u8],
    hash: u32,
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Version")
            .field("name", &self.name.escape_ascii())
            .field("hash", &format_args!("0x{:x}", self.hash))
            .finish()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ELFVersion {
    version_ids: VersionIndexTable,
    versions: Vec<Option<Version>>,
}

impl ELFVersion {
    pub(crate) fn new<R: RegionAccess>(
        version_ids_addr: Option<NonZeroUsize>,
        verneeds: Option<NonZeroUsize>,
        verdefs: Option<NonZeroUsize>,
        strtab: &ElfStringTable,
        segments: &ElfSegments<R>,
    ) -> Result<Option<Self>> {
        let Some(version_ids_addr) = version_ids_addr else {
            return Ok(None);
        };

        let version_ids = VersionIndexTable::parse(VmAddr::new(version_ids_addr.get()), segments)?;
        let mut versions = Vec::new();
        versions.resize_with(2, || None);

        if let Some(addr) = verneeds {
            parse_verneeds(VmAddr::new(addr.get()), strtab, segments, &mut versions)?;
        }
        if let Some(addr) = verdefs {
            parse_verdefs(VmAddr::new(addr.get()), strtab, segments, &mut versions)?;
        }

        Ok(Some(Self {
            version_ids,
            versions,
        }))
    }

    #[inline]
    fn version(&self, index: usize) -> Option<&Version> {
        self.versions.get(index)?.as_ref()
    }
}

fn read_record<T: ByteRepr, R: RegionAccess>(
    segments: &ElfSegments<R>,
    addr: VmAddr,
    tag: ElfDynamicTag,
    detail: &'static str,
) -> Result<T> {
    if !segments.contains_range(addr, size_of::<T>()) {
        return Err(ParseDynamicError::malformed_table(tag, detail).into());
    }
    unsafe { segments.read_value(addr) }
}

fn insert_version(versions: &mut Vec<Option<Version>>, index: usize, version: Version) {
    if versions.len() <= index {
        versions.resize_with(index + 1, || None);
    }
    versions[index] = Some(version);
}

fn parse_verdefs<R: RegionAccess>(
    mut addr: VmAddr,
    strtab: &ElfStringTable,
    segments: &ElfSegments<R>,
    versions: &mut Vec<Option<Version>>,
) -> Result<()> {
    loop {
        let verdef: VerDef = read_record(
            segments,
            addr,
            ElfDynamicTag::VERDEF,
            "entry is outside mapped ELF segments",
        )?;

        if verdef.vd_flags & VER_FLG_BASE == 0 {
            let aux: VerDefAux = read_record(
                segments,
                addr + VmOffset::new(verdef.vd_aux as usize),
                ElfDynamicTag::VERDEF,
                "auxiliary entry is outside mapped ELF segments",
            )?;
            insert_version(
                versions,
                verdef.index(),
                Version {
                    name: strtab.get_cstr(aux.vda_name as usize).to_bytes(),
                    hash: verdef.vd_hash,
                },
            );
        }

        if verdef.vd_next == 0 {
            break;
        }
        addr = addr + VmOffset::new(verdef.vd_next as usize);
    }
    Ok(())
}

fn parse_verneeds<R: RegionAccess>(
    mut addr: VmAddr,
    strtab: &ElfStringTable,
    segments: &ElfSegments<R>,
    versions: &mut Vec<Option<Version>>,
) -> Result<()> {
    let mut verneed: VerNeed = read_record(
        segments,
        addr,
        ElfDynamicTag::VERNEED,
        "entry is outside mapped ELF segments",
    )?;
    if verneed.vn_version != VERSION_CURRENT {
        return Err(ParseDynamicError::malformed_table(
            ElfDynamicTag::VERNEED,
            "entry has an unsupported revision",
        )
        .into());
    }

    loop {
        let mut aux_addr = addr + VmOffset::new(verneed.vn_aux as usize);
        loop {
            let aux: VerNeedAux = read_record(
                segments,
                aux_addr,
                ElfDynamicTag::VERNEED,
                "auxiliary entry is outside mapped ELF segments",
            )?;
            insert_version(
                versions,
                aux.index(),
                Version {
                    name: strtab.get_cstr(aux.vna_name as usize).to_bytes(),
                    hash: aux.vna_hash,
                },
            );

            if aux.vna_next == 0 {
                break;
            }
            aux_addr = aux_addr + VmOffset::new(aux.vna_next as usize);
        }

        if verneed.vn_next == 0 {
            break;
        }
        addr = addr + VmOffset::new(verneed.vn_next as usize);
        verneed = read_record(
            segments,
            addr,
            ElfDynamicTag::VERNEED,
            "entry is outside mapped ELF segments",
        )?;
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct SymbolVersion<'a> {
    name: &'a [u8],
    hash: u32,
    hidden: bool,
}

impl fmt::Debug for SymbolVersion<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolVersion")
            .field("name", &self.name.escape_ascii())
            .field("hash", &format_args!("0x{:x}", self.hash))
            .field("hidden", &self.hidden)
            .finish()
    }
}

impl<'a> SymbolVersion<'a> {
    pub(crate) fn new(name: &'a [u8]) -> Self {
        Self {
            name,
            hash: sysv_hash(name),
            hidden: true,
        }
    }

    #[inline]
    pub(crate) const fn name(&self) -> &'a [u8] {
        self.name
    }
}

#[cfg(feature = "version")]
impl<'symtab, L: ElfLayout> SymbolTableView<'symtab, L> {
    pub(crate) fn get_requirement(&self, sym_idx: usize) -> Option<SymbolVersion<'symtab>> {
        let gnu_version = self.version?;
        let version_index = gnu_version.version_ids.get(sym_idx)?;
        if version_index.index() <= 1 {
            return None;
        }
        let version = gnu_version.version(version_index.index())?;
        Some(SymbolVersion {
            name: version.name,
            hash: version.hash,
            hidden: version_index.is_hidden(),
        })
    }

    pub(crate) fn check_match(&self, sym_idx: usize, requirement: Option<&SymbolVersion>) -> bool {
        let Some(gnu_version) = self.version else {
            return requirement.is_none_or(|version| !version.hidden);
        };
        let Some(version_index) = gnu_version.version_ids.get(sym_idx) else {
            return false;
        };

        let index = version_index.index();
        let Some(requirement) = requirement else {
            return index <= 1 || !version_index.is_hidden();
        };
        if index <= 1 {
            return !requirement.hidden;
        }

        gnu_version.version(index).is_some_and(|definition| {
            definition.hash == requirement.hash && definition.name == requirement.name
        })
    }
}
