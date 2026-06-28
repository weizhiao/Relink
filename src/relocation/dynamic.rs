//! Relocation of elf objects
use crate::{
    ParseDynamicError, RelocReason, Result,
    elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfRelr, ElfWord},
    hint::{likely, unlikely},
    image::{LoadedCore, RawDynamic},
    lazy::traits::LazyBinder,
    logging,
    memory::{ImageMemory, ImageMemoryExt, MappedView, RegionAccess, VmOffset},
    observer::{DynamicRelocatedEvent, Finalizer, RelocationObserver},
    relocation::{RelocHelper, RelocateArgs, RelocationArch, RelocationHandler, SymDef},
    runtime::CodeContext,
    sync::Arc,
    tls::{TlsRelocOutcome, TlsResolver},
};
use alloc::vec;
use core::num::NonZeroUsize;

impl<D, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> RawDynamic<D, Arch, R, Tls> {
    fn apply_relro(&self, lazy_binding: bool) -> Result<()> {
        if lazy_binding {
            return Ok(());
        }

        if let Some(relro) = self.relro() {
            relro.apply(self.core_ref().segments())?;
        }
        Ok(())
    }

    pub(crate) fn relocate_impl<PreH, PostH, Obs>(
        self,
        args: RelocateArgs<'_, Arch, Tls, PreH, PostH, Obs>,
    ) -> Result<LoadedCore<D, Arch, R, Tls>>
    where
        D: 'static,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
        <Arch::Layout as ElfLayout>::Word: crate::ByteRepr,
    {
        logging::info!("Relocating dynamic library: {}", self.name());

        let RelocateArgs {
            scope,
            binding,
            lazy_binder,
            pre_handler,
            post_handler,
            observer,
            ..
        } = args;
        let relocation = self.relocation();
        if relocation.is_empty() {
            logging::debug!("No relocations needed for {}", self.name());
        }

        let lazy_binding = lazy_binder.resolve_binding(binding, self.is_lazy());
        if lazy_binding {
            logging::debug!("Using lazy binding for {}", self.name());
        }
        let mut helper = RelocHelper::new(
            self.core_ref(),
            self.symtab().view(),
            self.core_ref().segments(),
            scope,
            pre_handler,
            post_handler,
            observer,
        );

        if !relocation.is_empty() {
            self.relocate_relative(helper.memory())?
                .relocate_dynrel(&mut helper)?
                .relocate_pltrel(lazy_binding, &mut helper, lazy_binder.clone())?;
        }

        let RelocHelper { scope, .. } = helper;

        let (init, fini) = self.resolve_lifecycle()?;
        let finalizer = Finalizer::new(fini);

        let dep_names = scope
            .iter()
            .map(|source| source.name())
            .collect::<alloc::vec::Vec<_>>();
        if !dep_names.is_empty() {
            logging::debug!("[{}] Bound dependencies: {:?}", self.name(), dep_names);
        }

        self.apply_relro(lazy_binding)?;
        let mut dynamic_event =
            DynamicRelocatedEvent::new(self.core_ref(), self.dynamic_addr(), finalizer);
        observer.on_dynamic_relocated(&mut dynamic_event)?;
        self.core_ref()
            .set_finalizer(dynamic_event.into_finalizer());
        self.core_ref().init_tls()?;

        logging::debug!("Preparing initialization functions for {}", self.name());
        self.call_init(observer, &init)?;

        logging::info!("Relocation completed for {}", self.name());

        Ok(unsafe { LoadedCore::from_core_scope(self.into_core(), scope) })
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
    <Arch::Layout as ElfLayout>::Word: crate::ByteRepr,
{
    let base = memory.base();
    debug_assert!(rel.iter().all(|rel| rel.r_type() == Arch::RELATIVE));
    for entry in rel {
        debug_assert!(entry.r_type() == Arch::RELATIVE);
        let place = base + entry.r_offset();
        let addend = entry.read_addend(memory, place)?;
        let value = base.wrapping_add_signed(addend);
        let word = <Arch::Layout as ElfLayout>::Word::from_usize(value.get());
        unsafe { memory.write_value(place, word)? };
    }
    Ok(())
}

/// Applies `RELR` compact relative relocation entries.
pub fn relocate_relr<L, Memory>(relr: &[ElfRelr<L>], memory: &Memory) -> Result<()>
where
    L: ElfLayout,
    Memory: ImageMemory,
    L::Word: crate::ByteRepr,
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
pub(crate) struct DynamicRelocation<Arch: RelocationArch = crate::arch::NativeArch> {
    /// Relative relocations (REL_RELATIVE)
    relative: RelativeRel<Arch>,
    /// PLT relocations
    pub(in crate::relocation) pltrel: MappedView<ElfRelType<Arch>>,
    /// Other dynamic relocations
    dynrel: MappedView<ElfRelType<Arch>>,
}

impl<D, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> RawDynamic<D, Arch, R, Tls> {
    /// Relocate PLT (Procedure Linkage Table) entries
    fn relocate_pltrel<PreH, PostH, Obs>(
        &self,
        lazy_binding: bool,
        helper: &mut RelocHelper<'_, D, Arch, R, Tls, PreH, PostH, Obs>,
        lazy_binder: Arc<dyn LazyBinder<Arch>>,
    ) -> Result<&Self>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
        <Arch::Layout as ElfLayout>::Word: crate::ByteRepr,
    {
        let core = self.core_ref();
        let base = core.base();
        let reloc = self.relocation();
        lazy_binder.prepare_plt(lazy_binding, self)?;

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
                if lazy_binder.relocate_jump_slot(lazy_binding, helper.memory(), base, rel)? {
                    continue;
                }

                let symbol = helper.symbol_entry(rel);
                let symdef = helper.find_symdef(&symbol);
                let addr = helper.resolve_symbol_addr(&symbol, symdef.as_ref())?;
                if let Some(addr) = helper.bind_symbol_addr(rel, &symbol, addr)? {
                    let word = <Arch::Layout as ElfLayout>::Word::from_usize(addr.get());
                    unsafe { helper.memory().write_value(place, word)? };
                    continue;
                }
                failure_reason = RelocReason::UnknownSymbol;
            } else if unlikely(r_type == Arch::IRELATIVE) {
                let r_addend = rel.read_addend(helper.memory(), place)?;
                let addr = base.wrapping_add_signed(r_addend);
                let resolved = helper
                    .core
                    .executor()
                    .resolve_ifunc(CodeContext::<Arch>::new(core.name(), helper.memory()), addr)?;
                let word = <Arch::Layout as ElfLayout>::Word::from_usize(resolved.get());
                unsafe { helper.memory().write_value(place, word)? };
                continue;
            } else if unlikely(Arch::is_tlsdesc(r_type)) {
                // If the resolver cannot provide a TLSDESC binding, keep the
                // specific TLS failure for the final error while still giving
                // the post handler a chance.
                match helper.handle_tls_reloc(rel)? {
                    TlsRelocOutcome::Applied => continue,
                    TlsRelocOutcome::Failed(reason) => failure_reason = reason,
                }
            }
            // Handle unknown relocations with the provided handler
            if helper.handle_post(rel)?.is_unhandled() {
                return Err(helper.reloc_error(rel, failure_reason));
            }
        }
        Ok(self)
    }

    /// Perform relative relocations (REL_RELATIVE)
    fn relocate_relative<Memory>(&self, memory: &Memory) -> Result<&Self>
    where
        Memory: ImageMemory,
        <Arch::Layout as ElfLayout>::Word: crate::ByteRepr,
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
    fn relocate_dynrel<PreH, PostH, Obs>(
        &self,
        helper: &mut RelocHelper<'_, D, Arch, R, Tls, PreH, PostH, Obs>,
    ) -> Result<&Self>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
        <Arch::Layout as ElfLayout>::Word: crate::ByteRepr,
    {
        /*
            Relocation formula components:
            A = Addend used to compute the value of the relocatable field
            B = Base address at which a shared object is loaded
            S = Value of the symbol whose index resides in the relocation entry
        */

        let core = self.core_ref();
        let reloc = self.relocation();
        let base = core.base();

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
                let symdef = helper.find_symdef(&symbol);
                let addr = helper.resolve_symbol_addr(&symbol, symdef.as_ref())?;
                if let Some(addr) = helper.bind_symbol_addr(rel, &symbol, addr)? {
                    let r_addend = rel.read_addend(helper.memory(), place)?;
                    let value = addr.wrapping_add_signed(r_addend);
                    let word = <Arch::Layout as ElfLayout>::Word::from_usize(value.get());
                    unsafe { helper.memory().write_value(place, word)? };
                    continue;
                }
                failure_reason = RelocReason::UnknownSymbol;
            } else if r_type == Arch::COPY {
                // Handle copy relocations (typically for global data)
                let symbol = helper.symbol_entry(rel);
                let len = symbol.symbol().st_size();
                if let Some(SymDef::Defined {
                    symbol: sym,
                    source,
                }) = helper.find_symdef(&symbol)
                {
                    let mut src = vec![0; len];
                    let memory = source.memory();
                    memory.read_bytes(memory.base() + VmOffset::new(sym.st_value()), &mut src)?;
                    helper.memory().write_bytes(base + rel.r_offset(), &src)?;
                    continue;
                }
                failure_reason = RelocReason::UnknownSymbol;
            } else if r_type == Arch::IRELATIVE {
                let r_addend = rel.read_addend(helper.memory(), place)?;
                let addr = base.wrapping_add_signed(r_addend);
                let resolved = helper
                    .core
                    .executor()
                    .resolve_ifunc(CodeContext::<Arch>::new(core.name(), helper.memory()), addr)?;
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

            // Handle unknown relocations with the provided handler
            if helper.handle_post(rel)?.is_unhandled() {
                return Err(helper.reloc_error(rel, failure_reason));
            }
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
        let region = MappedRegion::local_alias_no_unmap(slice.as_ptr().cast_mut().cast(), byte_len);
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
