//! Parsing `.dynamic` section
use crate::{
    ParseDynamicError, Result,
    elf::{ElfLayout, ElfRel, ElfRelType, ElfRela, ElfRelr, NativeElfLayout},
    segment::ElfSegments,
};
use alloc::vec::Vec;
use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;
use core::{num::NonZeroUsize, ptr::NonNull};
use elf::abi::*;

/// This element holds the total size, in bytes, of the DT_RELR relocation table.
pub const DT_RELRSZ: i64 = 35;
/// This element is similar to DT_RELA, except its table has implicit
/// addends and info, such as Elf32_Relr for the 32-bit file class or
/// Elf64_Relr for the 64-bit file class. If this element is present,
/// the dynamic structure must also have DT_RELRSZ and DT_RELRENT elements.
pub const DT_RELR: i64 = 36;
/// This element holds the size, in bytes, of the DT_RELR relocation entry.
pub const DT_RELRENT: i64 = 37;

/// Semantic wrapper for the ELF `d_tag` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfDynamicTag(i64);

impl ElfDynamicTag {
    pub const NULL: Self = Self(DT_NULL);
    pub const NEEDED: Self = Self(DT_NEEDED);
    pub const PLTRELSZ: Self = Self(DT_PLTRELSZ);
    pub const PLTGOT: Self = Self(DT_PLTGOT);
    pub const HASH: Self = Self(DT_HASH);
    pub const STRTAB: Self = Self(DT_STRTAB);
    pub const SYMTAB: Self = Self(DT_SYMTAB);
    pub const RELA: Self = Self(DT_RELA);
    pub const RELASZ: Self = Self(DT_RELASZ);
    pub const RELAENT: Self = Self(DT_RELAENT);
    pub const REL: Self = Self(DT_REL);
    pub const RELSZ: Self = Self(DT_RELSZ);
    pub const RELENT: Self = Self(DT_RELENT);
    pub const PLTREL: Self = Self(DT_PLTREL);
    pub const DEBUG: Self = Self(elf::abi::DT_DEBUG);
    pub const JMPREL: Self = Self(DT_JMPREL);
    pub const INIT: Self = Self(DT_INIT);
    pub const FINI: Self = Self(DT_FINI);
    pub const INIT_ARRAY: Self = Self(DT_INIT_ARRAY);
    pub const INIT_ARRAYSZ: Self = Self(DT_INIT_ARRAYSZ);
    pub const FINI_ARRAY: Self = Self(DT_FINI_ARRAY);
    pub const FINI_ARRAYSZ: Self = Self(DT_FINI_ARRAYSZ);
    pub const RPATH: Self = Self(DT_RPATH);
    pub const RUNPATH: Self = Self(DT_RUNPATH);
    pub const FLAGS: Self = Self(DT_FLAGS);
    pub const FLAGS_1: Self = Self(DT_FLAGS_1);
    pub const STRSZ: Self = Self(DT_STRSZ);
    pub const GNU_HASH: Self = Self(DT_GNU_HASH);
    pub const GNU_LIBLIST: Self = Self(DT_GNU_LIBLIST);
    pub const VERSYM: Self = Self(DT_VERSYM);
    pub const VERDEF: Self = Self(DT_VERDEF);
    pub const VERDEFNUM: Self = Self(DT_VERDEFNUM);
    pub const VERNEED: Self = Self(DT_VERNEED);
    pub const VERNEEDNUM: Self = Self(DT_VERNEEDNUM);
    pub const RELACOUNT: Self = Self(DT_RELACOUNT);
    pub const RELCOUNT: Self = Self(DT_RELCOUNT);
    pub const RELR: Self = Self(DT_RELR);
    pub const RELRSZ: Self = Self(DT_RELRSZ);
    pub const RELRENT: Self = Self(DT_RELRENT);

    #[inline]
    pub const fn new(raw: i64) -> Self {
        Self(raw)
    }

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
            DT_REL => f.write_str("DT_REL"),
            DT_RELSZ => f.write_str("DT_RELSZ"),
            DT_PLTREL => f.write_str("DT_PLTREL"),
            elf::abi::DT_DEBUG => f.write_str("DT_DEBUG"),
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
            raw => write!(f, "unknown ELF dynamic tag {raw}"),
        }
    }
}

/// ELF dynamic section entry.
#[derive(Debug)]
#[repr(transparent)]
pub struct ElfDyn {
    dyn_: <NativeElfLayout as ElfLayout>::Dyn,
}

impl ElfDyn {
    /// Creates an owned ELF dynamic entry from a tag and payload value.
    #[inline]
    pub fn new(tag: ElfDynamicTag, value: usize) -> Self {
        let mut dyn_: <NativeElfLayout as ElfLayout>::Dyn = unsafe { core::mem::zeroed() };
        dyn_.d_tag = tag.raw() as _;
        dyn_.d_un = value as _;
        Self { dyn_ }
    }

    /// Returns the parsed ELF dynamic tag of this entry.
    #[inline]
    pub fn tag(&self) -> ElfDynamicTag {
        ElfDynamicTag::new(self.dyn_.d_tag as i64)
    }

    /// Returns the dynamic value or pointer payload.
    #[inline]
    pub fn value(&self) -> usize {
        self.dyn_.d_un as usize
    }

    /// Sets the dynamic tag (`d_tag`).
    #[inline]
    pub fn set_tag(&mut self, tag: ElfDynamicTag) {
        self.dyn_.d_tag = tag.raw() as _;
    }

    /// Sets the dynamic payload value (`d_un`).
    #[inline]
    pub fn set_value(&mut self, value: usize) {
        self.dyn_.d_un = value as _;
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
    pub(crate) rel_count: Option<NonZeroUsize>,
    pub(crate) relr_off: Option<NonZeroUsize>,
    pub(crate) relr_size: Option<NonZeroUsize>,
    pub(crate) init_off: Option<NonZeroUsize>,
    pub(crate) fini_off: Option<NonZeroUsize>,
    pub(crate) init_array_off: Option<NonZeroUsize>,
    pub(crate) init_array_size: Option<NonZeroUsize>,
    pub(crate) fini_array_off: Option<NonZeroUsize>,
    pub(crate) fini_array_size: Option<NonZeroUsize>,
    pub(crate) version_ids_off: Option<NonZeroUsize>,
    pub(crate) verneed_off: Option<NonZeroUsize>,
    pub(crate) verneed_num: Option<NonZeroUsize>,
    pub(crate) verdef_off: Option<NonZeroUsize>,
    pub(crate) verdef_num: Option<NonZeroUsize>,
    pub(crate) rpath_off: Option<NonZeroUsize>,
    pub(crate) runpath_off: Option<NonZeroUsize>,
    pub(crate) flags: usize,
    pub(crate) flags_1: usize,
    pub(crate) is_rela: Option<bool>,
    pub(crate) needed_libs: Vec<NonZeroUsize>,
}

impl ParsedDynamic {
    #[inline]
    fn apply(&mut self, tag: ElfDynamicTag, value: usize) -> bool {
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
            ElfDynamicTag::RELRSZ => self.relr_size = NonZeroUsize::new(value),
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
            ElfDynamicTag::VERNEEDNUM => self.verneed_num = NonZeroUsize::new(value),
            ElfDynamicTag::VERDEF => self.verdef_off = NonZeroUsize::new(value),
            ElfDynamicTag::VERDEFNUM => self.verdef_num = NonZeroUsize::new(value),
            ElfDynamicTag::RPATH => self.rpath_off = NonZeroUsize::new(value),
            ElfDynamicTag::RUNPATH => self.runpath_off = NonZeroUsize::new(value),
            ElfDynamicTag::STRSZ => self.strtab_size = NonZeroUsize::new(value),
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
    for (tag, value) in entries {
        if parsed.apply(tag, value) {
            break;
        }
    }
    parsed
}

struct DynamicPtrIter {
    cur: *const ElfDyn,
    done: bool,
    _marker: PhantomData<ElfDyn>,
}

impl DynamicPtrIter {
    #[inline]
    fn new(cur: *const ElfDyn) -> Self {
        Self {
            cur,
            done: false,
            _marker: PhantomData,
        }
    }
}

impl Iterator for DynamicPtrIter {
    type Item = (ElfDynamicTag, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        unsafe {
            let dynamic = &*self.cur;
            let tag = dynamic.tag();
            let value = dynamic.value();
            self.cur = self.cur.add(1);
            if tag == ElfDynamicTag::NULL {
                self.done = true;
            }
            Some((tag, value))
        }
    }
}

impl ElfDynamic {
    /// Parse the dynamic section of an ELF file
    pub fn new(dynamic_ptr: *const ElfDyn, segments: &ElfSegments) -> Result<Self> {
        let parsed = parse_dynamic_entries(DynamicPtrIter::new(dynamic_ptr));
        let base = segments.base();

        // Verify relocation type consistency
        if let Some(is_rela) = parsed.is_rela {
            assert!(
                is_rela && size_of::<ElfRelType>() == size_of::<ElfRela>()
                    || !is_rela && size_of::<ElfRelType>() == size_of::<ElfRel>()
            );
        }

        let add_base = |offset: usize| -> Result<usize> {
            base.checked_add(offset)
                .ok_or(ParseDynamicError::AddressOverflow.into())
        };
        let add_base_nonzero = |offset: NonZeroUsize| -> Result<NonZeroUsize> {
            NonZeroUsize::new(add_base(offset.get())?)
                .ok_or_else(|| ParseDynamicError::AddressOverflow.into())
        };

        // Determine which hash table to use (prefer GNU hash)
        let hash_off = if let Some(off) = parsed.gnu_hash_off {
            ElfDynamicHashTab::Gnu(add_base(off)?)
        } else if let Some(off) = parsed.elf_hash_off {
            ElfDynamicHashTab::Elf(add_base(off)?)
        } else {
            return Err(ParseDynamicError::MissingHashTable.into());
        };

        // Extract relocation tables
        let pltrel = parsed.pltrel_off.map(|pltrel_off| {
            segments.get_slice(
                pltrel_off.get(),
                parsed.pltrel_size.map(|s| s.get()).unwrap_or(0),
            )
        });
        let dynrel = parsed.rel_off.map(|rel_off| {
            segments.get_slice(rel_off.get(), parsed.rel_size.map(|s| s.get()).unwrap_or(0))
        });
        let relr = parsed.relr_off.map(|relr_off| {
            segments.get_slice(
                relr_off.get(),
                parsed.relr_size.map(|s| s.get()).unwrap_or(0),
            )
        });

        // Extract initialization and finalization functions
        let init_fn = parsed
            .init_off
            .map(|val| unsafe { core::mem::transmute(segments.get_ptr::<fn()>(val.get())) });
        let init_array_fn = parsed.init_array_off.map(|init_array_off| {
            segments.get_slice(
                init_array_off.get(),
                parsed.init_array_size.map(|s| s.get()).unwrap_or(0),
            )
        });
        let fini_fn = parsed.fini_off.map(|fini_off| unsafe {
            core::mem::transmute(segments.get_ptr::<fn()>(fini_off.get()))
        });
        let fini_array_fn = parsed.fini_array_off.map(|fini_array_off| {
            segments.get_slice(
                fini_array_off.get(),
                parsed.fini_array_size.map(|s| s.get()).unwrap_or(0),
            )
        });

        // Extract versioning information
        let verneed = parsed
            .verneed_off
            .map(|verneed_off| -> Result<_> {
                Ok((
                    add_base_nonzero(verneed_off)?,
                    parsed
                        .verneed_num
                        .ok_or(ParseDynamicError::MissingVersionCount { tag: "DT_VERNEED" })?,
                ))
            })
            .transpose()?;
        let verdef = parsed
            .verdef_off
            .map(|verdef_off| -> Result<_> {
                Ok((
                    add_base_nonzero(verdef_off)?,
                    parsed
                        .verdef_num
                        .ok_or(ParseDynamicError::MissingVersionCount { tag: "DT_VERDEF" })?,
                ))
            })
            .transpose()?;
        let version_idx = parsed.version_ids_off.map(add_base_nonzero).transpose()?;

        Ok(ElfDynamic {
            dyn_ptr: dynamic_ptr,
            hashtab: hash_off,
            symtab: add_base(parsed.symtab_off)?,
            strtab: add_base(parsed.strtab_off)?,
            // Check if binding should be done immediately
            bind_now: parsed.flags & DF_BIND_NOW as usize != 0
                || parsed.flags_1 & DF_1_NOW as usize != 0,
            static_tls: parsed.flags & DF_STATIC_TLS as usize != 0,
            got_plt: parsed
                .got_off
                .map(|off| add_base(off.get()))
                .transpose()?
                .map(|addr| unsafe { NonNull::new_unchecked(addr as *mut usize) }),
            needed_libs: parsed.needed_libs,
            pltrel,
            dynrel,
            relr,
            init_fn,
            init_array_fn,
            fini_fn,
            fini_array_fn,
            rel_count: parsed.rel_count,
            rpath_off: parsed.rpath_off,
            runpath_off: parsed.runpath_off,
            version_idx,
            verneed,
            verdef,
        })
    }
}

/// Hash table type used for symbol lookup
pub enum ElfDynamicHashTab {
    /// GNU-style hash table (DT_GNU_HASH)
    Gnu(usize),
    /// Traditional ELF hash table (DT_HASH)
    Elf(usize),
}

#[allow(unused)]
/// Information from the ELF dynamic section.
pub(crate) struct ElfDynamic {
    /// Pointer to the dynamic section.
    pub dyn_ptr: *const ElfDyn,
    /// Hash table information.
    pub hashtab: ElfDynamicHashTab,
    /// Symbol table address.
    pub symtab: usize,
    /// String table address.
    pub strtab: usize,
    /// Whether to bind symbols immediately.
    pub bind_now: bool,
    /// Whether the object uses static thread-local storage.
    pub static_tls: bool,
    /// Global Offset Table address.
    pub got_plt: Option<NonNull<usize>>,
    /// Initialization function.
    pub init_fn: Option<fn()>,
    /// Initialization function array.
    pub init_array_fn: Option<&'static [fn()]>,
    /// Finalization function.
    pub fini_fn: Option<fn()>,
    /// Finalization function array.
    pub fini_array_fn: Option<&'static [fn()]>,
    /// PLT relocation entries.
    pub pltrel: Option<&'static [ElfRelType]>,
    /// Dynamic relocation entries.
    pub dynrel: Option<&'static [ElfRelType]>,
    /// RELR relocation entries.
    pub relr: Option<&'static [ElfRelr]>,
    /// Count of relative relocations.
    pub rel_count: Option<NonZeroUsize>,
    /// Required libraries.
    pub needed_libs: Vec<NonZeroUsize>,
    /// Symbol version index.
    pub version_idx: Option<NonZeroUsize>,
    /// Version needed information.
    pub verneed: Option<(NonZeroUsize, NonZeroUsize)>,
    /// Version definition information.
    pub verdef: Option<(NonZeroUsize, NonZeroUsize)>,
    /// Runtime library search path.
    pub rpath_off: Option<NonZeroUsize>,
    /// Runtime library search path (overrides RPATH).
    pub runpath_off: Option<NonZeroUsize>,
}

impl Debug for ElfDynamic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfDynamic")
            .field("dyn_ptr", &self.dyn_ptr)
            .field("symtab", &format_args!("0x{:x}", self.symtab))
            .field("strtab", &format_args!("0x{:x}", self.strtab))
            .field("bind_now", &self.bind_now)
            .field("static_tls", &self.static_tls)
            .field("got_plt", &self.got_plt)
            .field("needed_libs_count", &self.needed_libs.len())
            .field("pltrel_count", &self.pltrel.map(|r| r.len()).unwrap_or(0))
            .field("dynrel_count", &self.dynrel.map(|r| r.len()).unwrap_or(0))
            .field("relr_count", &self.relr.map(|r| r.len()).unwrap_or(0))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{ElfDyn, ElfDynamicTag};

    #[test]
    fn owned_dyn_round_trips_and_mutates() {
        let mut dyn_ = ElfDyn::new(ElfDynamicTag::STRTAB, 0x1234);
        assert_eq!(dyn_.tag(), ElfDynamicTag::STRTAB);
        assert_eq!(dyn_.value(), 0x1234);

        dyn_.set_tag(ElfDynamicTag::NULL);
        dyn_.set_value(0x5678);
        assert_eq!(dyn_.tag(), ElfDynamicTag::NULL);
        assert_eq!(dyn_.value(), 0x5678);
    }
}
