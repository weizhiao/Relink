//! Relocation of elf objects
use crate::{
    ByteRepr, ParseDynamicError, RelocReason, Result,
    arch::NativeArch,
    elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfRelr, ElfWord},
    hint::{likely, unlikely},
    image::{GlobalScope, LoadedCore, RawDynamic},
    lazy::{LazyBinder, prepare_plt, relocate_jump_slot},
    logging,
    memory::{ImageMemory, ImageMemoryExt, MappedView, RegionAccess, VmOffset},
    observer::{DynamicRelocatedEvent, LifecycleRunner, RelocationObserver},
    relocation::{BindingDeps, RelocHelper, RelocateArgs, RelocationArch, SymbolResolver},
    runtime::CodeContext,
    tls::{TlsRelocOutcome, TlsResolver},
};
use alloc::vec;
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
        args: RelocateArgs<'_, Arch, Tls, Obs, Binder>,
    ) -> Result<LoadedCore<D, Arch, R, Tls>>
    where
        D: Send + Sync + 'static,
        Obs: RelocationObserver<Arch> + ?Sized,
        Binder: LazyBinder<Arch> + ?Sized,
        <Arch::Layout as ElfLayout>::Word: ByteRepr,
    {
        logging::info!("Relocating dynamic library: {}", self.name());

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
        let domain = self.domain_id();
        scope.check_domain(domain)?;
        if let Some(global) = &global {
            domain.ensure(global.domain_id())?;
        }
        let relocation = self.relocation();
        if relocation.is_empty() {
            logging::debug!("No relocations needed for {}", self.name());
        }

        let lazy = lazy_binder.resolve_binding(binding, self.is_lazy());
        if lazy {
            logging::debug!("Using lazy binding for {}", self.name());
        }
        prepare_plt(lazy_binder, lazy, &self)?;
        // Stabilize global lookup order and retain providers until dependency
        // bindings have been installed on the relocated module.
        let global_snapshot = global.as_ref().map(GlobalScope::modules);
        let source = self.module_handle();
        let resolver = SymbolResolver::new(
            &source,
            scope,
            global_snapshot.as_ref(),
            symbols.as_deref(),
            self.symbolic(),
            lookup_order,
        );
        let mut helper = RelocHelper::new(
            &self,
            resolver,
            BindingDeps::new(),
            self.symtab().view(),
            self.segments(),
            observer,
        );

        if !relocation.is_empty() {
            self.relocate_relative(helper.memory())?
                .relocate_dynrel(&mut helper)?
                .relocate_pltrel(lazy, &mut helper)?;
        }

        let (scope, bindings) = helper.into_parts();

        let (init, fini) = self.resolve_lifecycle()?;
        let initializer = LifecycleRunner::new(init);
        let finalizer = LifecycleRunner::new(fini);

        if !scope.is_empty() {
            logging::debug!("[{}] Lookup scope: {:?}", self.name(), &scope);
        }

        self.apply_relro(lazy)?;
        let mut dynamic_event =
            DynamicRelocatedEvent::new(&self, self.dynamic_addr(), initializer, finalizer);
        observer.on_dynamic_relocated(&mut dynamic_event)?;
        self.set_lifecycle(dynamic_event.into_lifecycle());
        self.publish_tls()?;

        logging::debug!("Preparing initialization functions for {}", self.name());
        if run_init {
            self.initialize()?;
        }

        logging::info!("Relocation completed for {}", self.name());

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
        let mut offset = next_offset;
        while bitmap != 0 {
            if (bitmap & 1) != 0 {
                update_relative_word(base + VmOffset::new(offset))?;
            }
            bitmap >>= 1;
            offset = offset.wrapping_add(word_size);
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

                let symbol = helper.symbol_entry(rel);
                if let Some(addr) = helper.bind_symbol_addr(rel, symbol)? {
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
        for rel in dynrel {
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

            if r_type == Arch::GOT || r_type == Arch::SYMBOLIC {
                // Handle GOT and symbolic relocations
                let symbol = helper.symbol_entry(rel);
                if let Some(addr) = helper.bind_symbol_addr(rel, symbol)? {
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
                if let Some(symdef) = helper.find_copy_symdef(&symbol)
                    && let Some((symbol, source)) = symdef.definition()
                {
                    let provider = symdef.provider_id();
                    let mut src = vec![0; len];
                    source
                        .memory()
                        .read_bytes(source.resolve_symbol(symbol)?, &mut src)?;
                    helper.memory().write_bytes(base + rel.r_offset(), &src)?;
                    helper.record_binding(provider);
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
        rela_count: Option<NonZeroUsize>,
        pltrel_is_dynrel_tail: bool,
    ) -> Result<Self> {
        let pltrel = pltrel.unwrap_or_else(MappedView::empty);
        let dynrel = dynrel.unwrap_or_else(MappedView::empty);

        if let Some(relr) = relr {
            // Use RELR relocations if available (more compact format)
            Ok(Self {
                relative: RelativeRel::Relr(relr),
                pltrel,
                dynrel,
            })
        } else {
            // Use traditional REL/RELA relocations
            // nrelative indicates the count of REL_RELATIVE relocation types
            let nrelative = rela_count.map(|v| v.get()).unwrap_or(0);

            let Some((relative, dynrel)) = dynrel.split_at(nrelative) else {
                return Err(ParseDynamicError::RelativeRelocationCountOutOfRange {
                    count: nrelative,
                    table_len: dynrel.len(),
                }
                .into());
            };

            // Split relocations into relative and non-relative parts
            let dynrel = if pltrel_is_dynrel_tail {
                // If contiguous, exclude pltrel entries from dynrel
                let dynrel_len = dynrel.len().checked_sub(pltrel.len()).ok_or(
                    ParseDynamicError::PltRelocationTailOutOfRange {
                        plt_len: pltrel.len(),
                        dynrel_tail_len: dynrel.len(),
                    },
                )?;
                let Some((dynrel, _)) = dynrel.split_at(dynrel_len) else {
                    unreachable!("validated dynamic relocation split");
                };
                dynrel
            } else {
                // Otherwise, use all remaining entries
                dynrel
            };

            Ok(Self {
                relative: RelativeRel::Rel(relative),
                pltrel,
                dynrel,
            })
        }
    }

    #[inline]
    pub(crate) fn pltrel(&self) -> &[ElfRelType<Arch>] {
        self.pltrel.as_slice()
    }

    /// Check if there are no relocations to process
    #[inline]
    fn is_empty(&self) -> bool {
        self.relative.is_empty() && self.dynrel.is_empty() && self.pltrel.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::DynamicRelocation;
    use crate::{
        ByteRepr, Error, ParseDynamicError,
        arch::NativeArch,
        elf::ElfRelType,
        memory::{MappedRegion, MappedView},
    };
    use alloc::boxed::Box;
    use core::num::NonZeroUsize;

    fn zeroed_rel() -> ElfRelType {
        unsafe { core::mem::zeroed() }
    }

    fn mapped_view<T: ByteRepr + 'static>(slice: &'static [T]) -> MappedView<T> {
        let byte_len = core::mem::size_of_val(slice);
        let region = unsafe {
            MappedRegion::local_alias_no_unmap(slice.as_ptr().cast_mut().cast(), byte_len)
        };
        region.read_view::<T>(0, byte_len).unwrap()
    }

    #[test]
    fn rejects_relative_count_past_dynrel_len() {
        let dynrel = Box::leak(Box::new([zeroed_rel()]));
        let err = match DynamicRelocation::<NativeArch>::new(
            None,
            Some(mapped_view(&dynrel[..])),
            None,
            NonZeroUsize::new(2),
            false,
        ) {
            Ok(_) => panic!("relative count should be validated"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            Error::ParseDynamic(ParseDynamicError::RelativeRelocationCountOutOfRange { .. })
        ));
    }

    #[test]
    fn rejects_pltrel_suffix_longer_than_remaining_dynrel() {
        let dynrel = Box::leak(Box::new([zeroed_rel(), zeroed_rel(), zeroed_rel()]));
        let err = match DynamicRelocation::<NativeArch>::new(
            Some(mapped_view(&dynrel[..])),
            Some(mapped_view(&dynrel[..])),
            None,
            NonZeroUsize::new(1),
            true,
        ) {
            Ok(_) => panic!("contiguous PLT suffix should fit in the non-relative tail"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            Error::ParseDynamic(ParseDynamicError::PltRelocationTailOutOfRange { .. })
        ));
    }
}
