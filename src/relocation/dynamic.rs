//! Relocation of elf objects
use crate::{
    ByteRepr, LazyBindingError, RelocReason, RelocationError, Result,
    arch::NativeArch,
    elf::{ElfDynamicTag, ElfLayout, ElfRelEntry, ElfRelType, ElfRelr, ElfSectionType, ElfWord},
    error::RelocTableError,
    hint::{likely, unlikely},
    image::{GlobalScope, LoadedCore, RawDynamic},
    lazy::{LazyBinder, LazyRuntime, install_plt, relocate_jump_slot},
    logging,
    memory::{ImageMemory, ImageMemoryExt, MappedView, RegionAccess, VmOffset},
    observer::{DynamicRelocatedEvent, LifecycleRunner, RelocationObserver},
    relocation::{
        BindingDeps, BindingMode, RelocHelper, RelocateArgs, RelocationArch, SymbolResolver,
    },
    runtime::CodeContext,
    tls::{TlsRelocOutcome, TlsResolver},
};
use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroUsize;

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    RawDynamic<D, Arch, R, Tls>
{
    fn apply_relro(&self, lazy: bool) -> Result<()> {
        if lazy {
            return Ok(());
        }

        if let Some(relro) = self.relro() {
            relro.apply(self.segments())?;
        }
        Ok(())
    }

    pub(crate) fn relocate_impl<Obs, Binder>(
        self,
        args: RelocateArgs<'_, Arch, Obs, Binder>,
    ) -> Result<LoadedCore<D, Arch, R, Tls>>
    where
        D: Send + Sync + 'static,
        Obs: RelocationObserver<Arch> + ?Sized,
        Binder: LazyBinder<Arch> + ?Sized,
        <Arch::Layout as ElfLayout>::Word: ByteRepr,
    {
        logging::info!("Relocating dynamic library: {}", self.name().escape_ascii());

        let RelocateArgs {
            scope,
            global,
            symbols,
            binding,
            lookup_order,
            run_init,
            lazy_binder,
            observer,
            ..
        } = args;
        let relocation = self.relocation();

        let wants_lazy = match binding {
            BindingMode::Eager => false,
            BindingMode::Default => self.is_lazy(),
            BindingMode::Lazy => true,
        };
        let setup = if wants_lazy {
            lazy_binder.prepare(LazyRuntime::new(&self.inner.runtime))?
        } else {
            None
        };
        if matches!(binding, BindingMode::Lazy) && setup.is_none() {
            return Err(RelocationError::LazyBinding(LazyBindingError::Unsupported).into());
        }
        let lazy = setup.is_some();
        if let Some(setup) = setup {
            logging::debug!("Using lazy binding for {}", self.name().escape_ascii());
            install_plt(setup, &self)?;
        }
        // Stabilize global lookup order and retain providers until dependency
        // bindings have been installed on the relocated module.
        let global_snapshot = global.as_ref().map(GlobalScope::modules);
        let source = self.module_handle();
        let resolver = SymbolResolver::new(
            &source,
            &scope,
            global_snapshot.as_ref(),
            symbols.as_deref(),
            self.symbolic(),
            lookup_order,
        );
        let mut helper = RelocHelper::new(
            &self,
            &resolver,
            BindingDeps::new(),
            self.inner.exports.elf_symbols().view(),
            self.segments(),
            observer,
        );

        if !relocation.is_empty() {
            self.relocate_relative(helper.memory())?
                .relocate_dynrel(&mut helper)?
                .relocate_pltrel(lazy, &mut helper)?;
        }

        let bindings = helper.into_bindings();
        drop(resolver);

        let (init, fini) = self.resolve_lifecycle()?;
        let initializer = LifecycleRunner::new(init);
        let finalizer = LifecycleRunner::new(fini);

        if !scope.is_empty() {
            logging::debug!(
                "[{}] Lookup scope: {:?}",
                self.name().escape_ascii(),
                &scope
            );
        }

        let mut dynamic_event =
            DynamicRelocatedEvent::new(&self, self.dynamic_addr(), initializer, finalizer);
        observer.on_dynamic_relocated(&mut dynamic_event)?;
        self.set_lifecycle(dynamic_event.into_lifecycle());
        self.publish_tls()?;

        logging::debug!(
            "Preparing initialization functions for {}",
            self.name().escape_ascii()
        );
        if run_init {
            self.initialize()?;
        }

        // Protect RELRO only after every write path (relocations, ifunc GOT
        // fill, initializer runs) has completed, matching bionic's ordering.
        self.apply_relro(lazy)?;

        logging::info!("Relocation completed for {}", self.name().escape_ascii());

        let core = self.into_core();
        bindings.install(core.state());
        let loaded = unsafe {
            LoadedCore::from_relocated(core, scope, global.as_ref(), symbols, lookup_order)
        };
        Ok(loaded)
    }
}

/// Types of relative relocations
enum RelativeRel<Arch: RelocationArch> {
    /// Standard REL/RELA relocations
    Rel(MappedView<ElfRelType<Arch>>),
    /// Compact RELR relocations
    Relr(MappedView<ElfRelr<Arch::Layout>>),
}

impl<Arch: RelocationArch> RelativeRel<Arch> {
    #[inline]
    fn is_empty(&self) -> bool {
        match self {
            RelativeRel::Rel(rel) => rel.is_empty(),
            RelativeRel::Relr(relr) => relr.is_empty(),
        }
    }
}

/// Applies `R_*_RELATIVE` entries from a regular `REL`/`RELA` relocation table.
///
/// The input slice is expected to contain only relative relocations, such as the
/// prefix described by `DT_RELCOUNT`/`DT_RELACOUNT`.
pub fn relocate_relative<Arch, Memory>(rel: &[ElfRelType<Arch>], memory: &Memory) -> Result<()>
where
    Arch: RelocationArch,
    Memory: ImageMemory,
    <Arch::Layout as ElfLayout>::Word: ByteRepr,
{
    debug_assert!(rel.iter().all(|rel| rel.r_type() == Arch::RELATIVE));
    for entry in rel {
        Arch::apply_relative(entry, memory)?;
    }
    Ok(())
}

/// Applies `RELR` compact relative relocation entries.
pub fn relocate_relr<L, Memory>(relr: &[ElfRelr<L>], memory: &Memory) -> Result<()>
where
    L: ElfLayout,
    Memory: ImageMemory,
    L::Word: ByteRepr,
{
    let base = memory.base();
    let update_relative_word = |addr| unsafe {
        memory.update_value::<_>(addr, |word: L::Word| {
            L::Word::from_usize((base + VmOffset::new(word.to_usize())).get())
        })
    };

    let word_size = core::mem::size_of::<L::Relr>();
    let mut next_offset = 0usize;
    for entry in relr {
        let value = entry.value();

        if (value & 1) == 0 {
            next_offset = value.wrapping_add(word_size);
            update_relative_word(base + VmOffset::new(value))?;
            continue;
        }

        let mut bitmap = value >> 1;
        while bitmap != 0 {
            let offset = next_offset
                .wrapping_add((bitmap.trailing_zeros() as usize).wrapping_mul(word_size));
            update_relative_word(base + VmOffset::new(offset))?;
            bitmap &= bitmap - 1;
        }
        next_offset = next_offset.wrapping_add((<L::Relr as ElfWord>::BITS - 1) * word_size);
    }
    Ok(())
}

/// Holds parsed relocation information
pub(crate) struct DynamicRelocation<Arch: RelocationArch = NativeArch> {
    /// Relative relocations (REL_RELATIVE)
    relative: RelativeRel<Arch>,
    /// PLT relocations
    pub(in crate::relocation) pltrel: MappedView<ElfRelType<Arch>>,
    /// Other dynamic relocations
    dynrel: MappedView<ElfRelType<Arch>>,
    /// Relocations expanded from an Android packed RELA stream
    packed_rela: Vec<ElfRelType<Arch>>,
}

impl<D: Send + Sync + 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
    RawDynamic<D, Arch, R, Tls>
{
    /// Relocate PLT (Procedure Linkage Table) entries
    fn relocate_pltrel<Obs>(
        &self,
        lazy: bool,
        helper: &mut RelocHelper<'_, D, Arch, R, Tls, Obs>,
    ) -> Result<&Self>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
        <Arch::Layout as ElfLayout>::Word: ByteRepr,
    {
        let base = self.segments().base();
        let reloc = self.relocation();

        // Process PLT relocations
        let pltrel = reloc.pltrel.as_slice();
        for rel in pltrel {
            if !helper.handle_pre(rel)?.is_unhandled() {
                continue;
            }
            let r_type = rel.r_type();
            let place = base + rel.r_offset();
            let mut failure_reason = RelocReason::Unsupported;

            // Handle jump slot relocations
            if likely(r_type == Arch::JUMP_SLOT) {
                if relocate_jump_slot::<Arch, _>(lazy, helper.memory(), base, rel)? {
                    continue;
                }

                if let Some(addr) = helper.bind_symbol_addr(rel)? {
                    let word = <Arch::Layout as ElfLayout>::Word::from_usize(addr.get());
                    unsafe { helper.memory().write_value(place, word)? };
                    continue;
                }
                failure_reason = RelocReason::UnknownSymbol;
            } else if unlikely(Arch::IRELATIVE == Some(r_type)) {
                let r_addend = rel.read_addend(helper.memory(), place)?;
                let addr = base.wrapping_add_signed(r_addend);
                let resolved = helper
                    .core
                    .executor()
                    .resolve_ifunc(CodeContext::<Arch>::new(self.name(), helper.memory()), addr)?;
                let word = <Arch::Layout as ElfLayout>::Word::from_usize(resolved.get());
                unsafe { helper.memory().write_value(place, word)? };
                continue;
            } else if unlikely(Arch::TLSDESC == Some(r_type)) {
                // If the resolver cannot provide a TLSDESC binding, keep the
                // specific TLS failure for the final error while still giving
                // the post handler a chance.
                match helper.handle_tls_reloc(rel)? {
                    TlsRelocOutcome::Applied => continue,
                    TlsRelocOutcome::Failed(reason) => failure_reason = reason,
                }
            }

            helper.handle_fallback(rel, failure_reason)?;
        }
        Ok(self)
    }

    /// Perform relative relocations (REL_RELATIVE)
    fn relocate_relative<Memory>(&self, memory: &Memory) -> Result<&Self>
    where
        Memory: ImageMemory,
        <Arch::Layout as ElfLayout>::Word: ByteRepr,
    {
        let reloc = self.relocation();

        match &reloc.relative {
            RelativeRel::Rel(rel) => {
                let rel = rel.as_slice();
                assert!(rel.is_empty() || rel[0].r_type() == Arch::RELATIVE);
                relocate_relative::<Arch, _>(rel, memory)?;
            }
            RelativeRel::Relr(relr) => {
                relocate_relr::<Arch::Layout, _>(relr.as_slice(), memory)?;
            }
        }
        Ok(self)
    }

    /// Perform dynamic relocations (non-PLT, non-relative)
    fn relocate_dynrel<Obs>(
        &self,
        helper: &mut RelocHelper<'_, D, Arch, R, Tls, Obs>,
    ) -> Result<&Self>
    where
        Obs: RelocationObserver<Arch> + ?Sized,
        <Arch::Layout as ElfLayout>::Word: ByteRepr,
    {
        /*
            Relocation formula components:
            A = Addend used to compute the value of the relocatable field
            B = Base address at which a shared object is loaded
            S = Value of the symbol whose index resides in the relocation entry
        */

        let reloc = self.relocation();
        let base = self.segments().base();

        // Process each dynamic relocation entry
        let dynrel = reloc.dynrel.as_slice();
        for rel in dynrel.iter().chain(reloc.packed_rela.iter()) {
            if !helper.handle_pre(rel)?.is_unhandled() {
                continue;
            }
            let r_type = rel.r_type();
            let place = base + rel.r_offset();
            let mut failure_reason = RelocReason::Unsupported;

            // Handle `REL_NONE` first because some architectures use `0` as a
            // sentinel for unsupported relocation classes such as TLSDESC.
            if r_type == Arch::NONE {
                continue;
            }

            // Apply relative relocations outside the preprocessed prefix,
            // including those decoded from packed streams.
            if r_type == Arch::RELATIVE {
                Arch::apply_relative(rel, helper.memory())?;
                continue;
            }

            if r_type == Arch::GOT || r_type == Arch::SYMBOLIC {
                // Handle GOT and symbolic relocations
                if let Some(addr) = helper.bind_symbol_addr(rel)? {
                    let r_addend = rel.read_addend(helper.memory(), place)?;
                    let value = addr.wrapping_add_signed(r_addend);
                    let word = <Arch::Layout as ElfLayout>::Word::from_usize(value.get());
                    unsafe { helper.memory().write_value(place, word)? };
                    continue;
                }
                failure_reason = RelocReason::UnknownSymbol;
            } else if Arch::COPY == Some(r_type) {
                // Handle copy relocations (typically for global data)
                let symbol = helper.symbol_entry(rel);
                let len = symbol.symbol().st_size();
                if let Some((symdef, effect)) = helper.find_copy_symdef(&symbol)
                    && let Some((symbol, source)) = symdef.definition()
                {
                    let mut src = vec![0; len];
                    source
                        .memory()
                        .read_bytes(source.resolve_symbol(symbol)?, &mut src)?;
                    helper.memory().write_bytes(base + rel.r_offset(), &src)?;
                    helper.record_binding(effect);
                    continue;
                }
                failure_reason = RelocReason::UnknownSymbol;
            } else if Arch::IRELATIVE == Some(r_type) {
                let r_addend = rel.read_addend(helper.memory(), place)?;
                let addr = base.wrapping_add_signed(r_addend);
                let resolved = helper
                    .core
                    .executor()
                    .resolve_ifunc(CodeContext::<Arch>::new(self.name(), helper.memory()), addr)?;
                let word = <Arch::Layout as ElfLayout>::Word::from_usize(resolved.get());
                unsafe { helper.memory().write_value(place, word)? };
                continue;
            } else if Arch::is_tls(r_type) {
                // Resolver-provided TLS metadata is enough for DTPMOD/DTPOFF/TPOFF.
                // TLSDESC uses resolver hooks so custom runtimes can supply
                // target-visible descriptors without the built-in TLS manager.
                match helper.handle_tls_reloc(rel)? {
                    TlsRelocOutcome::Applied => continue,
                    TlsRelocOutcome::Failed(reason) => failure_reason = reason,
                }
            }

            helper.handle_fallback(rel, failure_reason)?;
        }
        Ok(self)
    }
}

impl<Arch: RelocationArch> DynamicRelocation<Arch> {
    /// Create a new DynamicRelocation instance from parsed relocation data
    #[inline]
    pub(crate) fn new(
        pltrel: Option<MappedView<ElfRelType<Arch>>>,
        dynrel: Option<MappedView<ElfRelType<Arch>>>,
        relr: Option<MappedView<ElfRelr<Arch::Layout>>>,
        packed_rela: Vec<ElfRelType<Arch>>,
        rela_count: Option<NonZeroUsize>,
        pltrel_is_dynrel_tail: bool,
    ) -> Result<Self> {
        let pltrel = pltrel.unwrap_or_else(MappedView::empty);
        let dynrel = dynrel.unwrap_or_else(MappedView::empty);

        let (relative, dynrel) = if let Some(relr) = relr {
            // Regular REL/RELA entries still pass through relocate_dynrel,
            // which also handles relative entries when RELR is present.
            (RelativeRel::Relr(relr), dynrel)
        } else {
            let mut nrelative = rela_count.map(|v| v.get()).unwrap_or(0);

            // DT_ANDROID_RELA carries the whole table, including the relative
            // prefix counted by DT_RELACOUNT, while the plain table is absent.
            // bionic ignores relcount in that case; the packed entries reach
            // the generic pass below, which applies relative types too.
            if dynrel.is_empty() && !packed_rela.is_empty() {
                nrelative = 0;
            }

            let Some((relative, dynrel)) = dynrel.split_at(nrelative) else {
                return Err(RelocTableError::CountOutOfRange {
                    tag: if Arch::Relocation::SECTION_TYPE == ElfSectionType::RELA {
                        ElfDynamicTag::RELACOUNT
                    } else {
                        ElfDynamicTag::RELCOUNT
                    },
                    count: nrelative,
                    available: dynrel.len(),
                }
                .into());
            };
            (RelativeRel::Rel(relative), dynrel)
        };

        // JMPREL can alias the end of the regular table, independently of
        // whether relative relocations use REL/RELA or RELR.
        let dynrel =
            if pltrel_is_dynrel_tail {
                let dynrel_len = dynrel.len().checked_sub(pltrel.len()).ok_or(
                    RelocTableError::CountOutOfRange {
                        tag: ElfDynamicTag::JMPREL,
                        count: pltrel.len(),
                        available: dynrel.len(),
                    },
                )?;
                let Some((dynrel, _)) = dynrel.split_at(dynrel_len) else {
                    unreachable!("validated dynamic relocation split");
                };
                dynrel
            } else {
                dynrel
            };

        Ok(Self {
            relative,
            pltrel,
            dynrel,
            packed_rela,
        })
    }

    #[inline]
    pub(crate) fn pltrel(&self) -> &[ElfRelType<Arch>] {
        self.pltrel.as_slice()
    }

    /// Check if there are no relocations to process
    #[inline]
    fn is_empty(&self) -> bool {
        self.relative.is_empty()
            && self.dynrel.is_empty()
            && self.pltrel.is_empty()
            && self.packed_rela.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DynamicRelocation, ElfDynamicTag, ElfRelEntry, ElfSectionType, RelocTableError,
        RelocationArch,
    };
    use crate::{
        Error, ParseDynamicError, Result,
        arch::NativeArch,
        elf::ElfRelType,
        memory::{MappedRegion, MappedView},
    };
    use alloc::{boxed::Box, vec::Vec};
    use core::num::NonZeroUsize;

    fn relocation_table<const N: usize>() -> MappedView<ElfRelType> {
        // Relocation entries contain only integers; these tests inspect table lengths.
        let entries = Box::leak(Box::new(unsafe { core::mem::zeroed::<[ElfRelType; N]>() }));
        let byte_len = core::mem::size_of_val(entries);
        let region =
            unsafe { MappedRegion::local_alias_no_unmap(entries.as_mut_ptr().cast(), byte_len) };
        region.read_view(0, byte_len).unwrap()
    }

    fn assert_count_out_of_range(
        result: Result<DynamicRelocation<NativeArch>>,
        expected_tag: ElfDynamicTag,
    ) {
        let err = result.err().expect("out-of-range count should be rejected");
        let Error::ParseDynamic(ParseDynamicError::InvalidRelocTable { reason }) = err else {
            panic!("expected an invalid relocation table, got {err}");
        };
        assert!(matches!(
            *reason,
            RelocTableError::CountOutOfRange { tag, .. } if tag == expected_tag
        ));
    }

    #[test]
    fn rejects_relative_count_past_dynrel_len() {
        let result = DynamicRelocation::<NativeArch>::new(
            None,
            Some(relocation_table::<1>()),
            None,
            Vec::new(),
            NonZeroUsize::new(2),
            false,
        );
        let tag =
            if <NativeArch as RelocationArch>::Relocation::SECTION_TYPE == ElfSectionType::RELA {
                ElfDynamicTag::RELACOUNT
            } else {
                ElfDynamicTag::RELCOUNT
            };
        assert_count_out_of_range(result, tag);
    }

    #[test]
    fn rejects_pltrel_suffix_longer_than_remaining_dynrel() {
        let dynrel = relocation_table::<3>();
        let result = DynamicRelocation::<NativeArch>::new(
            Some(dynrel.clone()),
            Some(dynrel),
            None,
            Vec::new(),
            NonZeroUsize::new(1),
            true,
        );
        assert_count_out_of_range(result, ElfDynamicTag::JMPREL);
    }
}
