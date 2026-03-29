//! Parsing `.dynamic` section
use crate::{
    ParseDynamicError, Result,
    elf::{ElfLayout, ElfRel, ElfRelType, ElfRela, ElfRelr, NativeElfLayout},
    segment::ElfSegments,
};
use alloc::vec::Vec;
use core::fmt::{self, Debug, Display};
use core::{num::NonZeroUsize, ptr::NonNull};
use elf::abi::*;

/// This element holds the total size, in bytes, of the DT_RELR relocation table.
pub const DT_RELRSZ: i64 = 35;
/// This element is similar to DT_RELA, except its table has implicit
/// addends and info, such as Elf32_Relr for the 32-bit file class or
/// Elf64_Relr for the 64-bit file class. If this element is present,
/// the dynamic structure must also have DT_RELRSZ and DT_RELRENT elements.
pub const DT_RELR: i64 = 36;

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
    pub const REL: Self = Self(DT_REL);
    pub const RELSZ: Self = Self(DT_RELSZ);
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
    pub const GNU_HASH: Self = Self(DT_GNU_HASH);
    pub const VERSYM: Self = Self(DT_VERSYM);
    pub const VERDEF: Self = Self(DT_VERDEF);
    pub const VERDEFNUM: Self = Self(DT_VERDEFNUM);
    pub const VERNEED: Self = Self(DT_VERNEED);
    pub const VERNEEDNUM: Self = Self(DT_VERNEEDNUM);
    pub const RELACOUNT: Self = Self(DT_RELACOUNT);
    pub const RELCOUNT: Self = Self(DT_RELCOUNT);
    pub const RELR: Self = Self(DT_RELR);
    pub const RELRSZ: Self = Self(DT_RELRSZ);

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

impl ElfDynamic {
    /// Parse the dynamic section of an ELF file
    pub fn new(dynamic_ptr: *const ElfDyn, segments: &ElfSegments) -> Result<Self> {
        // These are required fields in a valid ELF dynamic library
        let mut symtab_off = 0; // Symbol table offset
        let mut strtab_off = 0; // String table offset
        let mut elf_hash_off = None; // ELF hash table offset
        let mut gnu_hash_off = None; // GNU hash table offset
        let mut got_off = None; // Global Offset Table offset
        let mut pltrel_size = None; // PLT relocation table size
        let mut pltrel_off = None; // PLT relocation table offset
        let mut rel_off = None; // Relocation table offset
        let mut rel_size = None; // Relocation table size
        let mut rel_count = None; // Relocation count
        let mut relr_off = None; // RELR relocation table offset
        let mut relr_size = None; // RELR relocation table size
        let mut init_off = None; // Initialization function offset
        let mut fini_off = None; // Finalization function offset
        let mut init_array_off = None; // Initialization function array offset
        let mut init_array_size = None; // Initialization function array size
        let mut fini_array_off = None; // Finalization function array offset
        let mut fini_array_size = None; // Finalization function array size
        let mut version_ids_off = None; // Symbol versioning information offset
        let mut verneed_off = None; // Version needed section offset
        let mut verneed_num = None; // Number of version needed entries
        let mut verdef_off = None; // Version definition section offset
        let mut verdef_num = None; // Number of version definition entries
        let mut rpath_off = None; // Runtime library search path offset
        let mut runpath_off = None; // Runtime library search path offset (overrides RPATH)
        let mut flags = 0; // Dynamic section flags
        let mut flags_1 = 0; // Additional dynamic section flags
        let mut is_rela = None; // Indicates if RELA or REL relocations are used
        let mut needed_libs = Vec::new(); // Required libraries (dependencies)

        let mut cur_dyn_ptr = dynamic_ptr;
        let base = segments.base();

        // Parse all dynamic entries
        unsafe {
            loop {
                let dynamic = &*cur_dyn_ptr;
                let tag = dynamic.tag();
                let value = dynamic.value();

                match tag {
                    ElfDynamicTag::FLAGS => flags = value,
                    ElfDynamicTag::FLAGS_1 => flags_1 = value,
                    ElfDynamicTag::PLTGOT => got_off = NonZeroUsize::new(value),
                    ElfDynamicTag::NEEDED => {
                        if let Some(val) = NonZeroUsize::new(value) {
                            needed_libs.push(val);
                        }
                    }
                    ElfDynamicTag::HASH => elf_hash_off = Some(value),
                    ElfDynamicTag::GNU_HASH => gnu_hash_off = Some(value),
                    ElfDynamicTag::SYMTAB => symtab_off = value,
                    ElfDynamicTag::STRTAB => strtab_off = value,
                    ElfDynamicTag::PLTRELSZ => pltrel_size = NonZeroUsize::new(value),
                    ElfDynamicTag::PLTREL => {
                        is_rela = Some(ElfDynamicTag::new(value as i64) == ElfDynamicTag::RELA);
                    }
                    ElfDynamicTag::JMPREL => pltrel_off = NonZeroUsize::new(value),
                    ElfDynamicTag::RELR => relr_off = NonZeroUsize::new(value),
                    ElfDynamicTag::RELA | ElfDynamicTag::REL => {
                        is_rela = Some(tag == ElfDynamicTag::RELA);
                        rel_off = NonZeroUsize::new(value)
                    }
                    ElfDynamicTag::RELASZ | ElfDynamicTag::RELSZ => {
                        rel_size = NonZeroUsize::new(value)
                    }
                    ElfDynamicTag::RELRSZ => relr_size = NonZeroUsize::new(value),
                    ElfDynamicTag::RELACOUNT | ElfDynamicTag::RELCOUNT => {
                        rel_count = NonZeroUsize::new(value)
                    }
                    ElfDynamicTag::INIT => init_off = NonZeroUsize::new(value),
                    ElfDynamicTag::FINI => fini_off = NonZeroUsize::new(value),
                    ElfDynamicTag::INIT_ARRAY => init_array_off = NonZeroUsize::new(value),
                    ElfDynamicTag::INIT_ARRAYSZ => init_array_size = NonZeroUsize::new(value),
                    ElfDynamicTag::FINI_ARRAY => fini_array_off = NonZeroUsize::new(value),
                    ElfDynamicTag::FINI_ARRAYSZ => fini_array_size = NonZeroUsize::new(value),
                    ElfDynamicTag::VERSYM => version_ids_off = NonZeroUsize::new(value),
                    ElfDynamicTag::VERNEED => verneed_off = NonZeroUsize::new(value),
                    ElfDynamicTag::VERNEEDNUM => verneed_num = NonZeroUsize::new(value),
                    ElfDynamicTag::VERDEF => verdef_off = NonZeroUsize::new(value),
                    ElfDynamicTag::VERDEFNUM => verdef_num = NonZeroUsize::new(value),
                    ElfDynamicTag::RPATH => rpath_off = NonZeroUsize::new(value),
                    ElfDynamicTag::RUNPATH => runpath_off = NonZeroUsize::new(value),
                    ElfDynamicTag::NULL => break,
                    _ => {}
                }
                cur_dyn_ptr = cur_dyn_ptr.add(1);
            }
        }

        // Verify relocation type consistency
        if let Some(is_rela) = is_rela {
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
        let hash_off = if let Some(off) = gnu_hash_off {
            ElfDynamicHashTab::Gnu(add_base(off)?)
        } else if let Some(off) = elf_hash_off {
            ElfDynamicHashTab::Elf(add_base(off)?)
        } else {
            return Err(ParseDynamicError::MissingHashTable.into());
        };

        // Extract relocation tables
        let pltrel = pltrel_off.map(|pltrel_off| {
            segments.get_slice(pltrel_off.get(), pltrel_size.map(|s| s.get()).unwrap_or(0))
        });
        let dynrel = rel_off.map(|rel_off| {
            segments.get_slice(rel_off.get(), rel_size.map(|s| s.get()).unwrap_or(0))
        });
        let relr = relr_off.map(|relr_off| {
            segments.get_slice(relr_off.get(), relr_size.map(|s| s.get()).unwrap_or(0))
        });

        // Extract initialization and finalization functions
        let init_fn = init_off
            .map(|val| unsafe { core::mem::transmute(segments.get_ptr::<fn()>(val.get())) });
        let init_array_fn = init_array_off.map(|init_array_off| {
            segments.get_slice(
                init_array_off.get(),
                init_array_size.map(|s| s.get()).unwrap_or(0),
            )
        });
        let fini_fn = fini_off.map(|fini_off| unsafe {
            core::mem::transmute(segments.get_ptr::<fn()>(fini_off.get()))
        });
        let fini_array_fn = fini_array_off.map(|fini_array_off| {
            segments.get_slice(
                fini_array_off.get(),
                fini_array_size.map(|s| s.get()).unwrap_or(0),
            )
        });

        // Extract versioning information
        let verneed = verneed_off
            .map(|verneed_off| -> Result<_> {
                Ok((
                    add_base_nonzero(verneed_off)?,
                    verneed_num
                        .ok_or(ParseDynamicError::MissingVersionCount { tag: "DT_VERNEED" })?,
                ))
            })
            .transpose()?;
        let verdef = verdef_off
            .map(|verdef_off| -> Result<_> {
                Ok((
                    add_base_nonzero(verdef_off)?,
                    verdef_num
                        .ok_or(ParseDynamicError::MissingVersionCount { tag: "DT_VERDEF" })?,
                ))
            })
            .transpose()?;
        let version_idx = version_ids_off.map(add_base_nonzero).transpose()?;

        Ok(ElfDynamic {
            dyn_ptr: dynamic_ptr,
            hashtab: hash_off,
            symtab: add_base(symtab_off)?,
            strtab: add_base(strtab_off)?,
            // Check if binding should be done immediately
            bind_now: flags & DF_BIND_NOW as usize != 0 || flags_1 & DF_1_NOW as usize != 0,
            static_tls: flags & DF_STATIC_TLS as usize != 0,
            got_plt: got_off
                .map(|off| add_base(off.get()))
                .transpose()?
                .map(|addr| unsafe { NonNull::new_unchecked(addr as *mut usize) }),
            needed_libs,
            pltrel,
            dynrel,
            relr,
            init_fn,
            init_array_fn,
            fini_fn,
            fini_array_fn,
            rel_count,
            rpath_off,
            runpath_off,
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
