//! Parsing `.dynamic` section
use super::raw::ElfDynRaw;
use crate::{
    ParseDynamicError, RelocTableError, Result,
    arch::NativeArch,
    elf::{ElfLayout, ElfRel, ElfRelType, ElfRela, ElfRelr, ElfWord, Lifecycle, NativeElfLayout},
    memory::{MappedView, RegionAccess, VmAddr, VmOffset},
    relocation::RelocationArch,
    segment::ElfSegments,
};
use alloc::vec::Vec;
use core::fmt::{self, Debug, Display};
use core::num::NonZeroUsize;
use elf::abi::*;

/// This element holds the total size, in bytes, of the DT_RELR relocation table.
const DT_RELRSZ: i64 = 35;
/// This element is similar to DT_RELA, except its table has implicit addends and info.
const DT_RELR: i64 = 36;
/// This element holds the size, in bytes, of the DT_RELR relocation entry.
const DT_RELRENT: i64 = 37;

/// Semantic wrapper for the ELF `d_tag` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfDynamicTag(i64);

impl ElfDynamicTag {
    /// `DT_NULL`: terminates the dynamic array.
    pub const NULL: Self = Self(DT_NULL);
    /// `DT_NEEDED`: string-table offset naming a needed shared object.
    pub const NEEDED: Self = Self(DT_NEEDED);
    /// `DT_PLTRELSZ`: size of the PLT relocation table.
    pub const PLTRELSZ: Self = Self(DT_PLTRELSZ);
    /// `DT_PLTGOT`: address of the PLT/GOT area.
    pub const PLTGOT: Self = Self(DT_PLTGOT);
    /// `DT_HASH`: address of the System V hash table.
    pub const HASH: Self = Self(DT_HASH);
    /// `DT_STRTAB`: address of the dynamic string table.
    pub const STRTAB: Self = Self(DT_STRTAB);
    /// `DT_SYMTAB`: address of the dynamic symbol table.
    pub const SYMTAB: Self = Self(DT_SYMTAB);
    /// `DT_RELA`: address of explicit-addend relocations.
    pub const RELA: Self = Self(DT_RELA);
    /// `DT_RELASZ`: size of the `DT_RELA` table.
    pub const RELASZ: Self = Self(DT_RELASZ);
    /// `DT_RELAENT`: size of one `DT_RELA` entry.
    pub const RELAENT: Self = Self(DT_RELAENT);
    /// `DT_SYMENT`: size of one dynamic symbol entry.
    pub const SYMENT: Self = Self(DT_SYMENT);
    /// `DT_REL`: address of implicit-addend relocations.
    pub const REL: Self = Self(DT_REL);
    /// `DT_RELSZ`: size of the `DT_REL` table.
    pub const RELSZ: Self = Self(DT_RELSZ);
    /// `DT_RELENT`: size of one `DT_REL` entry.
    pub const RELENT: Self = Self(DT_RELENT);
    /// `DT_PLTREL`: relocation entry format used by the PLT table.
    pub const PLTREL: Self = Self(DT_PLTREL);
    /// `DT_DEBUG`: runtime linker debug hook.
    pub const DEBUG: Self = Self(DT_DEBUG);
    /// `DT_SONAME`: string-table offset naming this shared object.
    pub const SONAME: Self = Self(DT_SONAME);
    /// `DT_SYMBOLIC`: legacy symbolic binding marker.
    pub const SYMBOLIC: Self = Self(DT_SYMBOLIC);
    /// `DT_TEXTREL`: text relocations are present.
    pub const TEXTREL: Self = Self(DT_TEXTREL);
    /// `DT_BIND_NOW`: eager binding is requested.
    pub const BIND_NOW: Self = Self(DT_BIND_NOW);
    /// `DT_JMPREL`: address of PLT relocations.
    pub const JMPREL: Self = Self(DT_JMPREL);
    /// `DT_INIT`: initialization function address.
    pub const INIT: Self = Self(DT_INIT);
    /// `DT_FINI`: finalization function address.
    pub const FINI: Self = Self(DT_FINI);
    /// `DT_INIT_ARRAY`: initialization function array address.
    pub const INIT_ARRAY: Self = Self(DT_INIT_ARRAY);
    /// `DT_INIT_ARRAYSZ`: size of the initialization function array.
    pub const INIT_ARRAYSZ: Self = Self(DT_INIT_ARRAYSZ);
    /// `DT_FINI_ARRAY`: finalization function array address.
    pub const FINI_ARRAY: Self = Self(DT_FINI_ARRAY);
    /// `DT_FINI_ARRAYSZ`: size of the finalization function array.
    pub const FINI_ARRAYSZ: Self = Self(DT_FINI_ARRAYSZ);
    /// `DT_RPATH`: legacy runtime search path.
    pub const RPATH: Self = Self(DT_RPATH);
    /// `DT_RUNPATH`: runtime search path.
    pub const RUNPATH: Self = Self(DT_RUNPATH);
    /// `DT_FLAGS`: dynamic flags.
    pub const FLAGS: Self = Self(DT_FLAGS);
    /// `DT_FLAGS_1`: extended dynamic flags.
    pub const FLAGS_1: Self = Self(DT_FLAGS_1);
    /// `DT_STRSZ`: dynamic string-table size.
    pub const STRSZ: Self = Self(DT_STRSZ);
    /// `DT_PREINIT_ARRAY`: pre-initialization function array address.
    pub const PREINIT_ARRAY: Self = Self(DT_PREINIT_ARRAY);
    /// `DT_PREINIT_ARRAYSZ`: size of the pre-initialization function array.
    pub const PREINIT_ARRAYSZ: Self = Self(DT_PREINIT_ARRAYSZ);
    /// `DT_SYMTAB_SHNDX`: extended symbol section-index table.
    pub const SYMTAB_SHNDX: Self = Self(DT_SYMTAB_SHNDX);
    /// `DT_GNU_HASH`: GNU hash table address.
    pub const GNU_HASH: Self = Self(DT_GNU_HASH);
    /// `DT_GNU_LIBLIST`: GNU prelink library list.
    pub const GNU_LIBLIST: Self = Self(DT_GNU_LIBLIST);
    /// `DT_VERSYM`: symbol version index table.
    pub const VERSYM: Self = Self(DT_VERSYM);
    /// `DT_VERDEF`: version definition table.
    pub const VERDEF: Self = Self(DT_VERDEF);
    /// `DT_VERDEFNUM`: number of version definitions.
    pub const VERDEFNUM: Self = Self(DT_VERDEFNUM);
    /// `DT_VERNEED`: version dependency table.
    pub const VERNEED: Self = Self(DT_VERNEED);
    /// `DT_VERNEEDNUM`: number of version dependency entries.
    pub const VERNEEDNUM: Self = Self(DT_VERNEEDNUM);
    /// `DT_RELACOUNT`: number of leading relative `RELA` relocations.
    pub const RELACOUNT: Self = Self(DT_RELACOUNT);
    /// `DT_RELCOUNT`: number of leading relative `REL` relocations.
    pub const RELCOUNT: Self = Self(DT_RELCOUNT);
    /// `DT_RELR`: address of compact RELR relocations.
    pub const RELR: Self = Self(DT_RELR);
    /// `DT_RELRSZ`: size of the RELR table.
    pub const RELRSZ: Self = Self(DT_RELRSZ);
    /// `DT_RELRENT`: size of one RELR entry.
    pub const RELRENT: Self = Self(DT_RELRENT);

    /// Creates a dynamic tag wrapper from a raw `d_tag` value.
    #[inline]
    pub const fn new(raw: i64) -> Self {
        Self(raw)
    }

    /// Returns the raw `d_tag` value.
    #[inline]
    pub const fn raw(self) -> i64 {
        self.0
    }
}

impl From<i64> for ElfDynamicTag {
    #[inline]
    fn from(value: i64) -> Self {
        Self::new(value)
    }
}

impl From<ElfDynamicTag> for i64 {
    #[inline]
    fn from(value: ElfDynamicTag) -> Self {
        value.raw()
    }
}

impl Display for ElfDynamicTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            DT_NULL => f.write_str("DT_NULL"),
            DT_NEEDED => f.write_str("DT_NEEDED"),
            DT_PLTRELSZ => f.write_str("DT_PLTRELSZ"),
            DT_PLTGOT => f.write_str("DT_PLTGOT"),
            DT_HASH => f.write_str("DT_HASH"),
            DT_STRTAB => f.write_str("DT_STRTAB"),
            DT_SYMTAB => f.write_str("DT_SYMTAB"),
            DT_RELA => f.write_str("DT_RELA"),
            DT_RELASZ => f.write_str("DT_RELASZ"),
            DT_RELAENT => f.write_str("DT_RELAENT"),
            DT_STRSZ => f.write_str("DT_STRSZ"),
            DT_SYMENT => f.write_str("DT_SYMENT"),
            DT_SONAME => f.write_str("DT_SONAME"),
            DT_REL => f.write_str("DT_REL"),
            DT_RELSZ => f.write_str("DT_RELSZ"),
            DT_RELENT => f.write_str("DT_RELENT"),
            DT_PLTREL => f.write_str("DT_PLTREL"),
            DT_DEBUG => f.write_str("DT_DEBUG"),
            DT_SYMBOLIC => f.write_str("DT_SYMBOLIC"),
            DT_TEXTREL => f.write_str("DT_TEXTREL"),
            DT_BIND_NOW => f.write_str("DT_BIND_NOW"),
            DT_JMPREL => f.write_str("DT_JMPREL"),
            DT_INIT => f.write_str("DT_INIT"),
            DT_FINI => f.write_str("DT_FINI"),
            DT_INIT_ARRAY => f.write_str("DT_INIT_ARRAY"),
            DT_INIT_ARRAYSZ => f.write_str("DT_INIT_ARRAYSZ"),
            DT_FINI_ARRAY => f.write_str("DT_FINI_ARRAY"),
            DT_FINI_ARRAYSZ => f.write_str("DT_FINI_ARRAYSZ"),
            DT_RPATH => f.write_str("DT_RPATH"),
            DT_RUNPATH => f.write_str("DT_RUNPATH"),
            DT_FLAGS => f.write_str("DT_FLAGS"),
            DT_FLAGS_1 => f.write_str("DT_FLAGS_1"),
            DT_PREINIT_ARRAY => f.write_str("DT_PREINIT_ARRAY"),
            DT_PREINIT_ARRAYSZ => f.write_str("DT_PREINIT_ARRAYSZ"),
            DT_SYMTAB_SHNDX => f.write_str("DT_SYMTAB_SHNDX"),
            DT_GNU_HASH => f.write_str("DT_GNU_HASH"),
            DT_GNU_LIBLIST => f.write_str("DT_GNU_LIBLIST"),
            DT_VERSYM => f.write_str("DT_VERSYM"),
            DT_VERDEF => f.write_str("DT_VERDEF"),
            DT_VERDEFNUM => f.write_str("DT_VERDEFNUM"),
            DT_VERNEED => f.write_str("DT_VERNEED"),
            DT_VERNEEDNUM => f.write_str("DT_VERNEEDNUM"),
            DT_RELACOUNT => f.write_str("DT_RELACOUNT"),
            DT_RELCOUNT => f.write_str("DT_RELCOUNT"),
            DT_RELR => f.write_str("DT_RELR"),
            DT_RELRSZ => f.write_str("DT_RELRSZ"),
            DT_RELRENT => f.write_str("DT_RELRENT"),
            raw => write!(f, "unknown ELF dynamic tag {raw}"),
        }
    }
}

/// ELF dynamic section entry.
#[derive(Debug)]
#[repr(transparent)]
pub struct ElfDyn<L: ElfLayout = NativeElfLayout> {
    dyn_: L::Dyn,
}

impl<L: ElfLayout> ElfDyn<L> {
    /// Creates an owned ELF dynamic entry from a tag and payload value.
    #[inline]
    pub fn new(tag: ElfDynamicTag, value: usize) -> Self {
        let mut dyn_: L::Dyn = unsafe { core::mem::zeroed() };
        dyn_.set_d_tag(tag.raw());
        dyn_.set_d_un(value);
        Self { dyn_ }
    }

    /// Returns the parsed ELF dynamic tag of this entry.
    #[inline]
    pub fn tag(&self) -> ElfDynamicTag {
        ElfDynamicTag::new(self.dyn_.d_tag())
    }

    /// Returns the dynamic value or pointer payload.
    #[inline]
    pub fn value(&self) -> usize {
        self.dyn_.d_un()
    }

    /// Sets the dynamic tag (`d_tag`).
    #[inline]
    pub fn set_tag(&mut self, tag: ElfDynamicTag) {
        self.dyn_.set_d_tag(tag.raw());
    }

    /// Sets the dynamic payload value (`d_un`).
    #[inline]
    pub fn set_value(&mut self, value: usize) {
        self.dyn_.set_d_un(value);
    }
}

/// Raw dynamic-section fields decoded from the DT entries.
#[derive(Debug, Default)]
pub(crate) struct ParsedDynamic {
    pub(crate) symtab_off: usize,
    pub(crate) strtab_off: usize,
    pub(crate) strtab_size: Option<NonZeroUsize>,
    pub(crate) elf_hash_off: Option<usize>,
    pub(crate) gnu_hash_off: Option<usize>,
    pub(crate) got_off: Option<NonZeroUsize>,
    pub(crate) pltrel_size: Option<NonZeroUsize>,
    pub(crate) pltrel_off: Option<NonZeroUsize>,
    pub(crate) rel_off: Option<NonZeroUsize>,
    pub(crate) rel_size: Option<NonZeroUsize>,
    pub(crate) rel_entry_size: Option<usize>,
    pub(crate) rela_entry_size: Option<usize>,
    pub(crate) rel_count: Option<NonZeroUsize>,
    pub(crate) relr_off: Option<NonZeroUsize>,
    pub(crate) relr_size: Option<NonZeroUsize>,
    pub(crate) relr_entry_size: Option<usize>,
    pub(crate) init_off: Option<NonZeroUsize>,
    pub(crate) fini_off: Option<NonZeroUsize>,
    pub(crate) init_array_off: Option<NonZeroUsize>,
    pub(crate) init_array_size: Option<NonZeroUsize>,
    pub(crate) fini_array_off: Option<NonZeroUsize>,
    pub(crate) fini_array_size: Option<NonZeroUsize>,
    pub(crate) version_ids_off: Option<NonZeroUsize>,
    pub(crate) verneed_off: Option<NonZeroUsize>,
    pub(crate) verdef_off: Option<NonZeroUsize>,
    pub(crate) soname_off: Option<NonZeroUsize>,
    pub(crate) rpath_off: Option<usize>,
    pub(crate) runpath_off: Option<usize>,
    pub(crate) dt_debug_idx: Option<usize>,
    pub(crate) bind_now: bool,
    pub(crate) symbolic: bool,
    pub(crate) flags: usize,
    pub(crate) flags_1: usize,
    pub(crate) is_rela: Option<bool>,
    pub(crate) needed_libs: Vec<NonZeroUsize>,
}

#[inline]
fn dynamic_table_end(offset: Option<NonZeroUsize>, size: Option<NonZeroUsize>) -> Option<usize> {
    offset?.get().checked_add(size.map_or(0, NonZeroUsize::get))
}

impl ParsedDynamic {
    #[inline]
    fn apply(&mut self, idx: usize, tag: ElfDynamicTag, value: usize) -> bool {
        match tag {
            ElfDynamicTag::FLAGS => self.flags = value,
            ElfDynamicTag::FLAGS_1 => self.flags_1 = value,
            ElfDynamicTag::PLTGOT => self.got_off = NonZeroUsize::new(value),
            ElfDynamicTag::NEEDED => {
                if let Some(val) = NonZeroUsize::new(value) {
                    self.needed_libs.push(val);
                }
            }
            ElfDynamicTag::HASH => self.elf_hash_off = Some(value),
            ElfDynamicTag::GNU_HASH => self.gnu_hash_off = Some(value),
            ElfDynamicTag::BIND_NOW => self.bind_now = true,
            ElfDynamicTag::SYMBOLIC => self.symbolic = true,
            ElfDynamicTag::SONAME => self.soname_off = NonZeroUsize::new(value),
            ElfDynamicTag::SYMTAB => self.symtab_off = value,
            ElfDynamicTag::STRTAB => self.strtab_off = value,
            ElfDynamicTag::PLTRELSZ => self.pltrel_size = NonZeroUsize::new(value),
            ElfDynamicTag::PLTREL => {
                self.is_rela = Some(ElfDynamicTag::new(value as i64) == ElfDynamicTag::RELA);
            }
            ElfDynamicTag::JMPREL => self.pltrel_off = NonZeroUsize::new(value),
            ElfDynamicTag::RELR => self.relr_off = NonZeroUsize::new(value),
            ElfDynamicTag::RELA | ElfDynamicTag::REL => {
                self.is_rela = Some(tag == ElfDynamicTag::RELA);
                self.rel_off = NonZeroUsize::new(value)
            }
            ElfDynamicTag::RELASZ | ElfDynamicTag::RELSZ => {
                self.rel_size = NonZeroUsize::new(value)
            }
            ElfDynamicTag::RELAENT => self.rela_entry_size = Some(value),
            ElfDynamicTag::RELENT => self.rel_entry_size = Some(value),
            ElfDynamicTag::RELRSZ => self.relr_size = NonZeroUsize::new(value),
            ElfDynamicTag::RELRENT => self.relr_entry_size = Some(value),
            ElfDynamicTag::RELACOUNT | ElfDynamicTag::RELCOUNT => {
                self.rel_count = NonZeroUsize::new(value)
            }
            ElfDynamicTag::INIT => self.init_off = NonZeroUsize::new(value),
            ElfDynamicTag::FINI => self.fini_off = NonZeroUsize::new(value),
            ElfDynamicTag::INIT_ARRAY => self.init_array_off = NonZeroUsize::new(value),
            ElfDynamicTag::INIT_ARRAYSZ => self.init_array_size = NonZeroUsize::new(value),
            ElfDynamicTag::FINI_ARRAY => self.fini_array_off = NonZeroUsize::new(value),
            ElfDynamicTag::FINI_ARRAYSZ => self.fini_array_size = NonZeroUsize::new(value),
            ElfDynamicTag::VERSYM => self.version_ids_off = NonZeroUsize::new(value),
            ElfDynamicTag::VERNEED => self.verneed_off = NonZeroUsize::new(value),
            ElfDynamicTag::VERDEF => self.verdef_off = NonZeroUsize::new(value),
            ElfDynamicTag::RPATH => self.rpath_off = Some(value),
            ElfDynamicTag::RUNPATH => self.runpath_off = Some(value),
            ElfDynamicTag::STRSZ => self.strtab_size = NonZeroUsize::new(value),
            ElfDynamicTag::DEBUG => self.dt_debug_idx = Some(idx),
            ElfDynamicTag::NULL => return true,
            _ => {}
        }

        false
    }
}

/// Parses a stream of dynamic-section entries into raw offsets and flags.
#[inline]
pub(crate) fn parse_dynamic_entries<I>(entries: I) -> ParsedDynamic
where
    I: IntoIterator<Item = (ElfDynamicTag, usize)>,
{
    let mut parsed = ParsedDynamic::default();
    for (idx, (tag, value)) in entries.into_iter().enumerate() {
        if parsed.apply(idx, tag, value) {
            break;
        }
    }
    parsed
}

impl<Arch> ElfDynamic<Arch>
where
    Arch: RelocationArch,
{
    /// Parse the dynamic section of an ELF file
    pub(crate) fn new<R: RegionAccess>(
        dynamic_entries: MappedView<ElfDyn<Arch::Layout>>,
        dynamic_addr: VmAddr,
        segments: &ElfSegments<R>,
    ) -> Result<Self> {
        dynamic_entries
            .as_slice()
            .first()
            .ok_or(ParseDynamicError::MissingRequiredTag {
                tag: ElfDynamicTag::NULL,
            })?;
        let parsed = parse_dynamic_entries(
            dynamic_entries
                .as_slice()
                .iter()
                .map(|entry| (entry.tag(), entry.value())),
        );
        let dt_debug_addr = parsed
            .dt_debug_idx
            .map(|idx| -> Result<_> {
                let offset = idx
                    .checked_mul(size_of::<ElfDyn<Arch::Layout>>())
                    .ok_or(ParseDynamicError::AddressOverflow)?;
                dynamic_addr
                    .checked_add(VmOffset::new(offset))
                    .ok_or_else(|| ParseDynamicError::AddressOverflow.into())
            })
            .transpose()?;
        let base = segments.base();

        // Verify relocation type consistency
        if let Some(is_rela) = parsed.is_rela {
            assert!(
                is_rela && size_of::<Arch::Relocation>() == size_of::<ElfRela<Arch::Layout>>()
                    || !is_rela
                        && size_of::<Arch::Relocation>() == size_of::<ElfRel<Arch::Layout>>()
            );
        }

        let add_base = |offset: usize| -> Result<VmAddr> {
            base.checked_add(VmOffset::new(offset))
                .ok_or(ParseDynamicError::AddressOverflow.into())
        };
        let add_base_nonzero = |offset: NonZeroUsize| -> Result<NonZeroUsize> {
            NonZeroUsize::new(add_base(offset.get())?.get())
                .ok_or_else(|| ParseDynamicError::AddressOverflow.into())
        };

        // Determine which hash table to use (prefer GNU hash)
        let hash_off = if let Some(off) = parsed.gnu_hash_off {
            ElfDynamicHashTab::Gnu(add_base(off)?)
        } else if let Some(off) = parsed.elf_hash_off {
            ElfDynamicHashTab::Elf(add_base(off)?)
        } else {
            return Err(ParseDynamicError::MissingRequiredTag {
                tag: ElfDynamicTag::GNU_HASH,
            }
            .into());
        };

        // Extract relocation tables
        let pltrel = parsed
            .pltrel_off
            .map(|pltrel_off| -> Result<_> {
                let view = segments
                    .read_view::<ElfRelType<Arch>>(
                        VmOffset::new(pltrel_off.get()),
                        parsed.pltrel_size.map(|len| len.get()).unwrap_or(0),
                    )
                    .ok_or(ParseDynamicError::InvalidRelocTable {
                        reason: RelocTableError::JmpRelSize,
                    })?;
                Ok(view)
            })
            .transpose()?;
        let dynrel = parsed
            .rel_off
            .map(|rel_off| -> Result<_> {
                if parsed.is_rela.unwrap_or(false) {
                    let entry_size =
                        parsed
                            .rela_entry_size
                            .ok_or(ParseDynamicError::MissingRequiredTag {
                                tag: ElfDynamicTag::RELAENT,
                            })?;
                    let expected = size_of::<ElfRela<Arch::Layout>>();
                    if entry_size != expected {
                        return Err(ParseDynamicError::InvalidRelocTable {
                            reason: RelocTableError::RelaEntrySize {
                                expected,
                                actual: entry_size,
                            },
                        }
                        .into());
                    }
                } else {
                    let entry_size =
                        parsed
                            .rel_entry_size
                            .ok_or(ParseDynamicError::MissingRequiredTag {
                                tag: ElfDynamicTag::RELENT,
                            })?;
                    let expected = size_of::<ElfRel<Arch::Layout>>();
                    if entry_size != expected {
                        return Err(ParseDynamicError::InvalidRelocTable {
                            reason: RelocTableError::RelEntrySize {
                                expected,
                                actual: entry_size,
                            },
                        }
                        .into());
                    }
                }
                let view = segments
                    .read_view::<ElfRelType<Arch>>(
                        VmOffset::new(rel_off.get()),
                        parsed.rel_size.map(|len| len.get()).unwrap_or(0),
                    )
                    .ok_or(ParseDynamicError::InvalidRelocTable {
                        reason: RelocTableError::DynRelSize,
                    })?;
                Ok(view)
            })
            .transpose()?;
        let relr = parsed
            .relr_off
            .map(|relr_off| -> Result<_> {
                let entry_size =
                    parsed
                        .relr_entry_size
                        .ok_or(ParseDynamicError::MissingRequiredTag {
                            tag: ElfDynamicTag::RELRENT,
                        })?;
                let expected = size_of::<ElfRelr<Arch::Layout>>();
                if entry_size != expected {
                    return Err(ParseDynamicError::InvalidRelocTable {
                        reason: RelocTableError::RelrEntrySize {
                            expected,
                            actual: entry_size,
                        },
                    }
                    .into());
                }
                let view = segments
                    .read_view::<ElfRelr<Arch::Layout>>(
                        VmOffset::new(relr_off.get()),
                        parsed.relr_size.map(|len| len.get()).unwrap_or(0),
                    )
                    .ok_or(ParseDynamicError::InvalidRelocTable {
                        reason: RelocTableError::RelrSize,
                    })?;
                Ok(view)
            })
            .transpose()?;
        let pltrel_is_dynrel_tail = matches!(
            (
                dynamic_table_end(parsed.rel_off, parsed.rel_size),
                dynamic_table_end(parsed.pltrel_off, parsed.pltrel_size),
            ),
            (Some(dynrel_end), Some(pltrel_end)) if dynrel_end == pltrel_end
        );

        // Extract initialization and finalization functions
        let init_fn = parsed
            .init_off
            .map(|init_off| add_base(init_off.get()))
            .transpose()?;
        let init_array_size = parsed.init_array_size.map(|len| len.get()).unwrap_or(0);
        let fini_fn = parsed
            .fini_off
            .map(|fini_off| add_base(fini_off.get()))
            .transpose()?;
        let fini_array_size = parsed.fini_array_size.map(|len| len.get()).unwrap_or(0);

        // Extract versioning information
        let verneed = parsed.verneed_off.map(add_base_nonzero).transpose()?;
        let verdef = parsed.verdef_off.map(add_base_nonzero).transpose()?;
        let version_idx = parsed.version_ids_off.map(add_base_nonzero).transpose()?;

        Ok(ElfDynamic {
            dt_debug_addr,
            hashtab: hash_off,
            symtab: add_base(parsed.symtab_off)?,
            strtab: add_base(parsed.strtab_off)?,
            strtab_size: parsed.strtab_size,
            // Check if binding should be done immediately
            bind_now: parsed.bind_now
                || parsed.flags & DF_BIND_NOW as usize != 0
                || parsed.flags_1 & DF_1_NOW as usize != 0,
            symbolic: parsed.symbolic || parsed.flags & DF_SYMBOLIC as usize != 0,
            static_tls: parsed.flags & DF_STATIC_TLS as usize != 0,
            got_plt: parsed.got_off.map(|off| add_base(off.get())).transpose()?,
            needed_libs: parsed.needed_libs,
            pltrel,
            dynrel,
            relr,
            pltrel_is_dynrel_tail,
            init: LifecycleSpec::new(init_fn, parsed.init_array_off, init_array_size),
            fini: LifecycleSpec::new(fini_fn, parsed.fini_array_off, fini_array_size),
            rel_count: parsed.rel_count,
            soname_off: parsed.soname_off,
            rpath_off: parsed.rpath_off,
            runpath_off: parsed.runpath_off,
            version_idx,
            verneed,
            verdef,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LifecycleSpec {
    func: Option<VmAddr>,
    array_offset: Option<NonZeroUsize>,
    array_byte_len: usize,
}

impl LifecycleSpec {
    #[inline]
    const fn new(
        func: Option<VmAddr>,
        array_offset: Option<NonZeroUsize>,
        array_byte_len: usize,
    ) -> Self {
        Self {
            func,
            array_offset,
            array_byte_len,
        }
    }

    pub(crate) fn resolve<L: ElfLayout, R: RegionAccess>(
        self,
        segments: &ElfSegments<R>,
        malformed: &'static str,
    ) -> Result<Lifecycle> {
        let array = self
            .array_offset
            .map(|offset| -> Result<_> {
                let words = segments
                    .read_view::<L::Word>(VmOffset::new(offset.get()), self.array_byte_len)
                    .ok_or(ParseDynamicError::MalformedLifecycleTable { detail: malformed })?;

                Ok(words
                    .as_slice()
                    .iter()
                    .copied()
                    .map(|addr| VmAddr::new(addr.to_usize()))
                    .collect())
            })
            .transpose()?;
        Ok(Lifecycle::new(self.func, array))
    }
}

/// Hash table type used for symbol lookup
pub(crate) enum ElfDynamicHashTab {
    /// GNU-style hash table (DT_GNU_HASH)
    Gnu(VmAddr),
    /// Traditional ELF hash table (DT_HASH)
    Elf(VmAddr),
}

#[allow(unused)]
/// Information from the ELF dynamic section.
pub(crate) struct ElfDynamic<Arch: RelocationArch = NativeArch> {
    /// Runtime address of the DT_DEBUG entry, when present.
    pub(crate) dt_debug_addr: Option<VmAddr>,
    /// Hash table information.
    pub(crate) hashtab: ElfDynamicHashTab,
    /// Symbol table address.
    pub(crate) symtab: VmAddr,
    /// String table address.
    pub(crate) strtab: VmAddr,
    /// String table size.
    pub(crate) strtab_size: Option<NonZeroUsize>,
    /// Whether to bind symbols immediately.
    pub(crate) bind_now: bool,
    /// Whether relocations in this object prefer definitions from itself.
    pub(crate) symbolic: bool,
    /// Whether the object uses static thread-local storage.
    pub(crate) static_tls: bool,
    /// Global Offset Table address.
    pub(crate) got_plt: Option<VmAddr>,
    /// Initialization lifecycle functions.
    pub(crate) init: LifecycleSpec,
    /// Finalization lifecycle functions.
    pub(crate) fini: LifecycleSpec,
    /// PLT relocation entries.
    pub(crate) pltrel: Option<MappedView<ElfRelType<Arch>>>,
    /// Dynamic relocation entries.
    pub(crate) dynrel: Option<MappedView<ElfRelType<Arch>>>,
    /// RELR relocation entries.
    pub(crate) relr: Option<MappedView<ElfRelr<Arch::Layout>>>,
    /// Whether PLT relocation entries are the tail of the dynamic relocation table.
    pub(crate) pltrel_is_dynrel_tail: bool,
    /// Count of relative relocations.
    pub(crate) rel_count: Option<NonZeroUsize>,
    /// Required libraries.
    pub(crate) needed_libs: Vec<NonZeroUsize>,
    /// Symbol version index.
    pub(crate) version_idx: Option<NonZeroUsize>,
    /// Version needed information.
    pub(crate) verneed: Option<NonZeroUsize>,
    /// Version definition information.
    pub(crate) verdef: Option<NonZeroUsize>,
    /// Shared-object name.
    pub(crate) soname_off: Option<NonZeroUsize>,
    /// Runtime library search path.
    pub(crate) rpath_off: Option<usize>,
    /// Runtime library search path (overrides RPATH).
    pub(crate) runpath_off: Option<usize>,
}

impl<Arch: RelocationArch> Debug for ElfDynamic<Arch> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfDynamic")
            .field("dt_debug_addr", &self.dt_debug_addr)
            .field("symtab", &format_args!("0x{:x}", self.symtab.get()))
            .field("strtab", &format_args!("0x{:x}", self.strtab.get()))
            .field("bind_now", &self.bind_now)
            .field("symbolic", &self.symbolic)
            .field("static_tls", &self.static_tls)
            .field("got_plt", &self.got_plt)
            .field("needed_libs_count", &self.needed_libs.len())
            .field(
                "pltrel_count",
                &self.pltrel.as_ref().map(|r| r.len()).unwrap_or(0),
            )
            .field(
                "dynrel_count",
                &self.dynrel.as_ref().map(|r| r.len()).unwrap_or(0),
            )
            .field(
                "relr_count",
                &self.relr.as_ref().map(|r| r.len()).unwrap_or(0),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{ElfDyn, ElfDynamicTag, parse_dynamic_entries};
    use core::num::NonZeroUsize;
    use elf::abi::DF_SYMBOLIC;

    #[test]
    fn owned_dyn_round_trips_and_mutates() {
        let mut dyn_: ElfDyn = ElfDyn::new(ElfDynamicTag::STRTAB, 0x1234);
        assert_eq!(dyn_.tag(), ElfDynamicTag::STRTAB);
        assert_eq!(dyn_.value(), 0x1234);

        dyn_.set_tag(ElfDynamicTag::NULL);
        dyn_.set_value(0x5678);
        assert_eq!(dyn_.tag(), ElfDynamicTag::NULL);
        assert_eq!(dyn_.value(), 0x5678);
    }

    #[test]
    fn parses_metadata_only_dynamic_tags() {
        let parsed = parse_dynamic_entries([
            (ElfDynamicTag::SONAME, 0x24),
            (ElfDynamicTag::BIND_NOW, 0),
            (ElfDynamicTag::NULL, 0),
        ]);

        assert_eq!(parsed.soname_off, NonZeroUsize::new(0x24));
        assert!(parsed.bind_now);
    }

    #[test]
    fn parses_symbolic_dynamic_flags() {
        let parsed = parse_dynamic_entries([
            (ElfDynamicTag::SYMBOLIC, 0),
            (ElfDynamicTag::FLAGS, DF_SYMBOLIC as usize),
            (ElfDynamicTag::NULL, 0),
        ]);

        assert!(parsed.symbolic);
        assert_eq!(parsed.flags & DF_SYMBOLIC as usize, DF_SYMBOLIC as usize);
    }

    #[test]
    fn parses_relocation_entry_size_tags() {
        let parsed = parse_dynamic_entries([
            (ElfDynamicTag::RELAENT, 24),
            (ElfDynamicTag::RELENT, 16),
            (ElfDynamicTag::RELRENT, 8),
            (ElfDynamicTag::NULL, 0),
        ]);

        assert_eq!(parsed.rela_entry_size, Some(24));
        assert_eq!(parsed.rel_entry_size, Some(16));
        assert_eq!(parsed.relr_entry_size, Some(8));
    }

    #[test]
    fn preserves_empty_runpath_tag() {
        let parsed = parse_dynamic_entries([(ElfDynamicTag::RUNPATH, 0), (ElfDynamicTag::NULL, 0)]);

        assert_eq!(parsed.runpath_off, Some(0));
    }
}
