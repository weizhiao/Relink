//! Parsing `.dynamic` section
use crate::{
    ParseDynamicError, Result,
    arch::NativeArch,
    elf::{
        ElfDynRaw, ElfDynamicTag, ElfLayout, ElfRel, ElfRelType, ElfRela, ElfRelr, ElfWord,
        Lifecycle, NativeElfLayout,
    },
    os::{MappedView, RegionAccess, VmAddr, VmOffset},
    relocation::RelocationArch,
    segment::ElfSegments,
};
use alloc::vec::Vec;
use core::fmt::Debug;
use core::{num::NonZeroUsize, ptr::NonNull};
use elf::abi::*;

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
    pub(crate) soname_off: Option<NonZeroUsize>,
    pub(crate) rpath_off: Option<NonZeroUsize>,
    pub(crate) runpath_off: Option<NonZeroUsize>,
    pub(crate) dt_debug_idx: Option<usize>,
    pub(crate) bind_now: bool,
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
    pub fn new<R: RegionAccess>(
        dynamic_entries: MappedView<ElfDyn<Arch::Layout>>,
        dynamic_addr: VmAddr,
        segments: &ElfSegments<R>,
    ) -> Result<Self> {
        dynamic_entries
            .as_slice()
            .first()
            .ok_or(ParseDynamicError::MissingRequiredTag { tag: "DT_NULL" })?;
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
                tag: "DT_GNU_HASH or DT_HASH",
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
                    .ok_or(ParseDynamicError::MalformedRelocationTable {
                        detail: "DT_JMPREL relocation table size is malformed",
                    })?;
                Ok(view)
            })
            .transpose()?;
        let dynrel = parsed
            .rel_off
            .map(|rel_off| -> Result<_> {
                let view = segments
                    .read_view::<ElfRelType<Arch>>(
                        VmOffset::new(rel_off.get()),
                        parsed.rel_size.map(|len| len.get()).unwrap_or(0),
                    )
                    .ok_or(ParseDynamicError::MalformedRelocationTable {
                        detail: "DT_REL/DT_RELA relocation table size is malformed",
                    })?;
                Ok(view)
            })
            .transpose()?;
        let relr = parsed
            .relr_off
            .map(|relr_off| -> Result<_> {
                let view = segments
                    .read_view::<ElfRelr<Arch::Layout>>(
                        VmOffset::new(relr_off.get()),
                        parsed.relr_size.map(|len| len.get()).unwrap_or(0),
                    )
                    .ok_or(ParseDynamicError::MalformedRelocationTable {
                        detail: "DT_RELR relocation table size is malformed",
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
        let verneed = parsed
            .verneed_off
            .map(|verneed_off| -> Result<_> {
                Ok((
                    add_base_nonzero(verneed_off)?,
                    parsed
                        .verneed_num
                        .ok_or(ParseDynamicError::MissingRequiredTag {
                            tag: "DT_VERNEEDNUM",
                        })?,
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
                        .ok_or(ParseDynamicError::MissingRequiredTag {
                            tag: "DT_VERDEFNUM",
                        })?,
                ))
            })
            .transpose()?;
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
            static_tls: parsed.flags & DF_STATIC_TLS as usize != 0,
            got_plt: parsed
                .got_off
                .map(|off| add_base(off.get()))
                .transpose()?
                .map(|addr| unsafe { NonNull::new_unchecked(addr.as_mut_ptr::<usize>()) }),
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
                    .ok_or_else(|| ParseDynamicError::MalformedLifecycleTable {
                        detail: malformed,
                    })?;

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
pub enum ElfDynamicHashTab {
    /// GNU-style hash table (DT_GNU_HASH)
    Gnu(VmAddr),
    /// Traditional ELF hash table (DT_HASH)
    Elf(VmAddr),
}

#[allow(unused)]
/// Information from the ELF dynamic section.
pub(crate) struct ElfDynamic<Arch: RelocationArch = NativeArch> {
    /// Runtime address of the DT_DEBUG entry, when present.
    pub dt_debug_addr: Option<VmAddr>,
    /// Hash table information.
    pub hashtab: ElfDynamicHashTab,
    /// Symbol table address.
    pub symtab: VmAddr,
    /// String table address.
    pub strtab: VmAddr,
    /// String table size.
    pub strtab_size: Option<NonZeroUsize>,
    /// Whether to bind symbols immediately.
    pub bind_now: bool,
    /// Whether the object uses static thread-local storage.
    pub static_tls: bool,
    /// Global Offset Table address.
    pub got_plt: Option<NonNull<usize>>,
    /// Initialization lifecycle functions.
    pub init: LifecycleSpec,
    /// Finalization lifecycle functions.
    pub fini: LifecycleSpec,
    /// PLT relocation entries.
    pub pltrel: Option<MappedView<ElfRelType<Arch>>>,
    /// Dynamic relocation entries.
    pub dynrel: Option<MappedView<ElfRelType<Arch>>>,
    /// RELR relocation entries.
    pub relr: Option<MappedView<ElfRelr<Arch::Layout>>>,
    /// Whether PLT relocation entries are the tail of the dynamic relocation table.
    pub pltrel_is_dynrel_tail: bool,
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
    /// Shared-object name.
    pub soname_off: Option<NonZeroUsize>,
    /// Runtime library search path.
    pub rpath_off: Option<NonZeroUsize>,
    /// Runtime library search path (overrides RPATH).
    pub runpath_off: Option<NonZeroUsize>,
}

impl<Arch: RelocationArch> Debug for ElfDynamic<Arch> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfDynamic")
            .field("dt_debug_addr", &self.dt_debug_addr)
            .field("symtab", &format_args!("0x{:x}", self.symtab.get()))
            .field("strtab", &format_args!("0x{:x}", self.strtab.get()))
            .field("bind_now", &self.bind_now)
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
}
