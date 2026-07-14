use crate::{
    ByteRepr, ParseDynamicError, Result,
    elf::{ElfStringTable, SymbolTableView, hash::sysv_hash},
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
struct VerDef {
    vd_version: u16,
    vd_flags: u16,
    vd_ndx: u16,
    vd_cnt: u16,
    vd_hash: u32,
    vd_aux: u32,
    vd_next: u32,
}

impl VerDef {
    #[inline]
    fn index(self) -> usize {
        (self.vd_ndx & abi::VER_NDX_VERSION) as usize
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VerDefAux {
    vda_name: u32,
    vda_next: u32,
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
    fn parse<R: RegionAccess>(
        addr: VmAddr,
        symbol_count: usize,
        segments: &ElfSegments<R>,
    ) -> Result<Self> {
        let byte_len = symbol_count
            .checked_mul(size_of::<u16>())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let offset = addr
            .checked_offset_from(segments.base())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        let entries = segments.read_view(offset, byte_len).ok_or(
            ParseDynamicError::MalformedVersionTable {
                detail: "DT_VERSYM table is outside mapped ELF segments or has invalid alignment",
            },
        )?;
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
    name: &'static str,
    hash: u32,
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Version")
            .field("name", &self.name)
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
        symbol_count: usize,
        strtab: &ElfStringTable,
        segments: &ElfSegments<R>,
    ) -> Result<Option<Self>> {
        let Some(version_ids_addr) = version_ids_addr else {
            return Ok(None);
        };

        let version_ids =
            VersionIndexTable::parse(VmAddr::new(version_ids_addr.get()), symbol_count, segments)?;
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
    detail: &'static str,
) -> Result<T> {
    if !segments.contains_range(addr, size_of::<T>()) {
        return Err(ParseDynamicError::MalformedVersionTable { detail }.into());
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
            "DT_VERDEF entry is outside mapped ELF segments",
        )?;

        if verdef.vd_flags & VER_FLG_BASE == 0 {
            let aux: VerDefAux = read_record(
                segments,
                addr + VmOffset::new(verdef.vd_aux as usize),
                "DT_VERDEF auxiliary entry is outside mapped ELF segments",
            )?;
            insert_version(
                versions,
                verdef.index(),
                Version {
                    name: strtab.get_str(aux.vda_name as usize),
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
        "DT_VERNEED entry is outside mapped ELF segments",
    )?;
    if verneed.vn_version != VERSION_CURRENT {
        return Err(ParseDynamicError::MalformedVersionTable {
            detail: "DT_VERNEED entry has an unsupported revision",
        }
        .into());
    }

    loop {
        let mut aux_addr = addr + VmOffset::new(verneed.vn_aux as usize);
        loop {
            let aux: VerNeedAux = read_record(
                segments,
                aux_addr,
                "DT_VERNEED auxiliary entry is outside mapped ELF segments",
            )?;
            insert_version(
                versions,
                aux.index(),
                Version {
                    name: strtab.get_str(aux.vna_name as usize),
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
            "DT_VERNEED entry is outside mapped ELF segments",
        )?;
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct SymbolVersion<'a> {
    name: &'a str,
    hash: u32,
    hidden: bool,
}

impl fmt::Debug for SymbolVersion<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolVersion")
            .field("name", &self.name)
            .field("hash", &format_args!("0x{:x}", self.hash))
            .field("hidden", &self.hidden)
            .finish()
    }
}

impl<'a> SymbolVersion<'a> {
    pub(crate) fn new(name: &'a str) -> Self {
        Self {
            name,
            hash: sysv_hash(name.as_bytes()),
            hidden: true,
        }
    }

    #[inline]
    pub(crate) const fn name(&self) -> &'a str {
        self.name
    }
}

impl<'symtab, L: crate::elf::ElfLayout, H> SymbolTableView<'symtab, L, H> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        elf::NativeElfLayout,
        memory::{HostRegion, MappedRegion},
    };
    use alloc::boxed::Box;

    const VERSYM_OFFSET: usize = 0;
    const VERDEF_OFFSET: usize = 16;
    const VERDEF_AUX_OFFSET: usize = 48;
    const VERDEF_PARENT_OFFSET: usize = 64;
    const VERNEED_OFFSET: usize = 80;
    const VERNEED_AUX_OFFSET: usize = 104;
    const VERNEED_SECOND_AUX_OFFSET: usize = 128;
    const STRTAB_OFFSET: usize = 160;

    const VER_DEF_NAME: u32 = 1;
    const PARENT_NAME: u32 = 9;
    const FILE_NAME: u32 = 16;
    const VER_NEED_NAME: u32 = 26;
    const VER_OTHER_NAME: u32 = 35;

    #[repr(align(8))]
    struct AlignedBytes([u8; 256]);

    struct VersionFixture {
        segments: ElfSegments<HostRegion>,
        strtab: ElfStringTable,
        versym: NonZeroUsize,
        verdef: NonZeroUsize,
        verneed: NonZeroUsize,
    }

    fn write_record<T: ByteRepr>(bytes: &mut [u8], offset: usize, value: T) {
        let raw = unsafe {
            core::slice::from_raw_parts((&value as *const T).cast::<u8>(), size_of::<T>())
        };
        bytes[offset..offset + raw.len()].copy_from_slice(raw);
    }

    fn version_fixture(version_ids: [u16; 4], broken_aux_chain: bool) -> VersionFixture {
        let storage = Box::leak(Box::new(AlignedBytes([0; 256])));
        let bytes = &mut storage.0;

        for (index, version) in version_ids.into_iter().enumerate() {
            write_record(bytes, VERSYM_OFFSET + index * size_of::<u16>(), version);
        }

        write_record(
            bytes,
            VERDEF_OFFSET,
            VerDef {
                vd_version: 7,
                vd_flags: 0x4000,
                vd_ndx: 2,
                vd_cnt: 0,
                vd_hash: sysv_hash(b"VER_DEF"),
                vd_aux: (VERDEF_AUX_OFFSET - VERDEF_OFFSET) as u32,
                vd_next: 0,
            },
        );
        write_record(
            bytes,
            VERDEF_AUX_OFFSET,
            VerDefAux {
                vda_name: VER_DEF_NAME,
                vda_next: (VERDEF_PARENT_OFFSET - VERDEF_AUX_OFFSET) as u32,
            },
        );
        write_record(
            bytes,
            VERDEF_PARENT_OFFSET,
            VerDefAux {
                vda_name: PARENT_NAME,
                vda_next: 0,
            },
        );

        write_record(
            bytes,
            VERNEED_OFFSET,
            VerNeed {
                vn_version: VERSION_CURRENT,
                vn_cnt: 0,
                vn_file: FILE_NAME,
                vn_aux: (VERNEED_AUX_OFFSET - VERNEED_OFFSET) as u32,
                vn_next: 0,
            },
        );
        write_record(
            bytes,
            VERNEED_AUX_OFFSET,
            VerNeedAux {
                vna_hash: sysv_hash(b"VER_NEED"),
                vna_flags: 0,
                vna_other: 3,
                vna_name: VER_NEED_NAME,
                vna_next: if broken_aux_chain {
                    0
                } else {
                    (VERNEED_SECOND_AUX_OFFSET - VERNEED_AUX_OFFSET) as u32
                },
            },
        );
        write_record(
            bytes,
            VERNEED_SECOND_AUX_OFFSET,
            VerNeedAux {
                vna_hash: 0xdead_beef,
                vna_flags: u16::MAX,
                vna_other: 4,
                vna_name: VER_OTHER_NAME,
                vna_next: 0,
            },
        );

        bytes[STRTAB_OFFSET..STRTAB_OFFSET + 45]
            .copy_from_slice(b"\0VER_DEF\0PARENT\0libdep.so\0VER_NEED\0VER_OTHER\0");

        let bytes: &'static [u8] = &storage.0;
        let base = VmAddr::from_ptr(bytes.as_ptr());
        let region =
            MappedRegion::local_alias_no_unmap(bytes.as_ptr().cast_mut().cast(), bytes.len());
        let segments = ElfSegments::new(region, base, VmOffset::new(0));
        let strtab = ElfStringTable::new(MappedView::from_slice(&bytes[STRTAB_OFFSET..]));
        let addr = |offset| NonZeroUsize::new((base + VmOffset::new(offset)).get()).unwrap();

        VersionFixture {
            segments,
            strtab,
            versym: addr(VERSYM_OFFSET),
            verdef: addr(VERDEF_OFFSET),
            verneed: addr(VERNEED_OFFSET),
        }
    }

    fn parse_fixture(fixture: &VersionFixture) -> Result<ELFVersion> {
        ELFVersion::new(
            Some(fixture.versym),
            Some(fixture.verneed),
            Some(fixture.verdef),
            4,
            &fixture.strtab,
            &fixture.segments,
        )
        .map(|version| version.expect("fixture has DT_VERSYM"))
    }

    #[test]
    fn parses_non_contiguous_version_auxiliary_chains() {
        let fixture = version_fixture([0, 1, 2, abi::VER_NDX_HIDDEN | 3], false);
        let version = parse_fixture(&fixture).unwrap();

        assert_eq!(version.version(2).unwrap().name, "VER_DEF");
        assert_eq!(version.version(3).unwrap().name, "VER_NEED");
        assert_eq!(version.version(4).unwrap().name, "VER_OTHER");
        assert_eq!(version.version(4).unwrap().hash, 0xdead_beef);
    }

    #[test]
    fn follows_auxiliary_links_instead_of_counts() {
        let fixture = version_fixture([0, 1, 2, abi::VER_NDX_HIDDEN | 3], true);
        let version = parse_fixture(&fixture).unwrap();

        assert_eq!(version.version(3).unwrap().name, "VER_NEED");
        assert!(version.version(4).is_none());
    }

    #[test]
    fn allows_unknown_version_indices() {
        let fixture = version_fixture([0, 1, 2, 5], false);
        let version = parse_fixture(&fixture).unwrap();

        assert!(version.version(5).is_none());
    }

    #[test]
    fn matches_default_hidden_and_explicit_versions() {
        let fixture = version_fixture([0, 1, 2, abi::VER_NDX_HIDDEN | 3], false);
        let version = parse_fixture(&fixture).unwrap();
        let table = SymbolTableView::<NativeElfLayout, ()> {
            hashtab: &(),
            symbols: &[],
            strtab: &fixture.strtab,
            version: Some(&version),
        };

        assert!(table.check_match(0, None));
        assert!(table.check_match(2, None));
        assert!(!table.check_match(3, None));

        let exact = SymbolVersion::new("VER_DEF");
        let mismatch = SymbolVersion::new("VER_OTHER");
        assert!(table.check_match(2, Some(&exact)));
        assert!(!table.check_match(2, Some(&mismatch)));

        let compatible = table.get_requirement(2).unwrap();
        assert!(!compatible.hidden);
        assert!(table.check_match(1, Some(&compatible)));
        assert!(!table.check_match(1, Some(&exact)));

        let hidden = table.get_requirement(3).unwrap();
        assert!(hidden.hidden);
        assert!(table.check_match(3, Some(&hidden)));
    }

    #[test]
    fn unversioned_tables_only_satisfy_non_exact_requirements() {
        let fixture = version_fixture([0, 1, 2, 3], false);
        let table = SymbolTableView::<NativeElfLayout, ()> {
            hashtab: &(),
            symbols: &[],
            strtab: &fixture.strtab,
            version: None,
        };
        let exact = SymbolVersion::new("VER_DEF");
        let compatible = SymbolVersion {
            name: "VER_DEF",
            hash: sysv_hash(b"VER_DEF"),
            hidden: false,
        };

        assert!(!table.check_match(0, Some(&exact)));
        assert!(table.check_match(0, Some(&compatible)));
    }
}
