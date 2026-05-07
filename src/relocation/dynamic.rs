//! Relocation of elf objects
use crate::{
    ParseDynamicError, RelocationError, RelocationFailureReason, Result,
    elf::{ElfRelType, ElfRelr},
    image::{LoadedCore, RawDynamic},
    logging,
    relocation::{
        BindingMode, RelocHelper, RelocateArgs, RelocationArch, RelocationHandler, ResolvedBinding,
        SymbolLookup, likely, reloc_error, resolve_ifunc, unlikely,
    },
    tls::{handle_tls_reloc, lookup_tls_get_addr},
};
use core::num::NonZeroUsize;

impl<D, Arch: RelocationArch> RawDynamic<D, Arch> {
    fn apply_relro(&self, binding: &ResolvedBinding) -> Result<()> {
        if binding.is_lazy() {
            return Ok(());
        }

        if let Some(relro) = self.relro() {
            relro.relro()?;
        }
        Ok(())
    }

    pub(crate) fn relocate_impl<PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, PreS, PostS, LazyPreS, LazyPostS, PreH, PostH>,
    ) -> Result<LoadedCore<D>>
    where
        D: 'static,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyPreS: SymbolLookup + Send + Sync + 'static,
        LazyPostS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        logging::info!("Relocating dynamic library: {}", self.name());

        let RelocateArgs {
            scope,
            binding,
            lookup,
            lazy_lookup,
            handlers,
        } = args;

        let relocation = self.relocation();
        if relocation.is_empty() {
            logging::debug!("No relocations needed for {}", self.name());
        }

        let binding = if Arch::SUPPORTS_NATIVE_RUNTIME {
            self.resolve_binding(binding)
        } else if binding == BindingMode::Lazy {
            return Err(RelocationError::UnsupportedRelocationType.into());
        } else {
            self.resolve_binding(BindingMode::Eager)
        };
        let tls_get_addr = self.tls_get_addr();

        if binding.is_lazy() {
            logging::debug!("Using lazy binding for {}", self.name());
        }

        let hooked_pre_find = |name: &str| -> Option<*const ()> {
            if Arch::SUPPORTS_NATIVE_RUNTIME {
                if let Some(symbol) = lookup_tls_get_addr(name, tls_get_addr) {
                    return Some(symbol);
                }
            }
            lookup.pre_find.lookup(name)
        };

        let mut helper = RelocHelper::new(
            self.core_ref(),
            scope,
            &hooked_pre_find,
            lookup.post_find,
            handlers.pre,
            handlers.post,
            tls_get_addr,
        );

        if !relocation.is_empty() {
            self.relocate_relative()
                .relocate_dynrel(&mut helper)?
                .relocate_pltrel(&binding, &mut helper)?;
        }

        let RelocHelper {
            scope: deps,
            tls_desc_args,
            ..
        } = helper;

        // Persist TLSDESC backing storage collected during relocation.
        unsafe {
            self.core_ref().set_tls_desc_args(tls_desc_args);
        }

        if !deps.is_empty() {
            logging::debug!(
                "[{}] Bound dependencies: {:?}",
                self.name(),
                deps.iter()
                    .map(|d| d.name())
                    .collect::<alloc::vec::Vec<_>>()
            );
        }

        self.apply_relro(&binding)?;
        self.install_lazy_lookup(binding, lazy_lookup, deps.clone())?;

        if Arch::SUPPORTS_NATIVE_RUNTIME {
            logging::debug!("Executing initialization functions for {}", self.name());
            self.call_init();
        } else {
            logging::debug!(
                "Skipping initialization functions for non-native relocation of {}",
                self.name()
            );
        }

        logging::info!("Relocation completed for {}", self.name());

        Ok(unsafe { LoadedCore::from_core_deps(self.into_core(), deps) })
    }
}

/// Types of relative relocations
enum RelativeRel {
    /// Standard REL/RELA relocations
    Rel(&'static [ElfRelType]),
    /// Compact RELR relocations
    Relr(&'static [ElfRelr]),
}

impl RelativeRel {
    #[inline]
    fn is_empty(&self) -> bool {
        match self {
            RelativeRel::Rel(rel) => rel.is_empty(),
            RelativeRel::Relr(relr) => relr.is_empty(),
        }
    }
}

/// Holds parsed relocation information
pub(crate) struct DynamicRelocation {
    /// Relative relocations (REL_RELATIVE)
    relative: RelativeRel,
    /// PLT relocations
    pub(in crate::relocation) pltrel: &'static [ElfRelType],
    /// Other dynamic relocations
    dynrel: &'static [ElfRelType],
}

impl<D, Arch: RelocationArch> RawDynamic<D, Arch> {
    /// Relocate PLT (Procedure Linkage Table) entries
    fn relocate_pltrel<PreS, PostS, PreH, PostH>(
        &self,
        binding: &ResolvedBinding,
        helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
    ) -> Result<&Self>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        let core = self.core_ref();
        let base = core.base_addr();
        let segments = core.segments();
        let reloc = self.relocation();
        if binding.is_lazy() && !Arch::SUPPORTS_NATIVE_RUNTIME {
            return Err(RelocationError::UnsupportedRelocationType.into());
        }
        binding.prepare_plt(self)?;

        // Process PLT relocations
        for rel in reloc.pltrel {
            if !helper.handle_pre(rel)?.is_unhandled() {
                continue;
            }
            let r_type = rel.r_type();
            let r_sym = rel.r_symbol();

            // Handle jump slot relocations
            if likely(r_type == Arch::JUMP_SLOT) {
                if binding.relocate_jump_slot(base, rel) {
                    continue;
                }

                if let Some(symbol) = helper.find_symbol(r_sym) {
                    segments.write(rel.r_offset(), symbol);
                    continue;
                }
            } else if unlikely(r_type == Arch::IRELATIVE) {
                // IFUNC resolvers run on the host CPU, so they only make
                // sense when the relocated module shares the host's ABI.
                // Cross-architecture loaders fall through to the post
                // `RelocationHandler` below.
                if Arch::SUPPORTS_NATIVE_RUNTIME {
                    let r_addend = rel.r_addend(base.into_inner());
                    let addr = base.addend(r_addend);
                    segments.write(rel.r_offset(), unsafe { resolve_ifunc(addr) });
                    continue;
                }
            } else if unlikely(Arch::is_tlsdesc(r_type)) {
                // `handle_tls_reloc` performs its own SUPPORTS_NATIVE_RUNTIME
                // gate for TLSDESC; if it returns `false` we fall through to
                // the post handler.
                if handle_tls_reloc::<_, Arch, _, _, _, _>(helper, rel) {
                    continue;
                }
            }
            // Handle unknown relocations with the provided handler
            if helper.handle_post(rel)?.is_unhandled() {
                return Err(reloc_error::<Arch, _>(
                    rel,
                    RelocationFailureReason::Unhandled,
                    core,
                ));
            }
        }
        Ok(self)
    }

    /// Perform relative relocations (REL_RELATIVE)
    fn relocate_relative(&self) -> &Self {
        let core = self.core_ref();
        let reloc = self.relocation();
        let segments = core.segments();
        let base = core.base_addr();

        match reloc.relative {
            RelativeRel::Rel(rel) => {
                assert!(rel.is_empty() || rel[0].r_type() == Arch::RELATIVE);
                // Apply all relative relocations: new_value = base_address + addend
                for rel in rel {
                    debug_assert!(rel.r_type() == Arch::RELATIVE);
                    let r_addend = rel.r_addend(base.into_inner());
                    segments.write(rel.r_offset(), base.addend(r_addend));
                }
            }
            RelativeRel::Relr(relr) => {
                // Apply compact relative relocations (RELR format)
                let mut reloc_addr = core::ptr::null_mut::<usize>();

                for relr in relr {
                    let value = relr.value();

                    unsafe {
                        if (value & 1) == 0 {
                            reloc_addr = segments.get_mut_ptr(value);
                            reloc_addr.write(base.offset(reloc_addr.read()).into_inner());
                            reloc_addr = reloc_addr.add(1);
                            continue;
                        }

                        let mut bitmap = value >> 1;
                        let mut ptr = reloc_addr;
                        while bitmap != 0 {
                            if (bitmap & 1) != 0 {
                                ptr.write(base.offset(ptr.read()).into_inner());
                            }
                            bitmap >>= 1;
                            ptr = ptr.add(1);
                        }
                        reloc_addr = reloc_addr.add(usize::BITS as usize - 1);
                    }
                }
            }
        }
        self
    }

    /// Perform dynamic relocations (non-PLT, non-relative)
    fn relocate_dynrel<PreS, PostS, PreH, PostH>(
        &self,
        helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
    ) -> Result<&Self>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        /*
            Relocation formula components:
            A = Addend used to compute the value of the relocatable field
            B = Base address at which a shared object is loaded
            S = Value of the symbol whose index resides in the relocation entry
        */

        let core = self.core_ref();
        let reloc = self.relocation();
        let segments = core.segments();
        let base = core.base_addr();

        // Process each dynamic relocation entry
        for rel in reloc.dynrel {
            if !helper.handle_pre(rel)?.is_unhandled() {
                continue;
            }
            let r_type = rel.r_type();
            let r_sym = rel.r_symbol();

            // Handle `REL_NONE` first because some architectures use `0` as a
            // sentinel for unsupported relocation classes such as TLSDESC.
            if r_type == Arch::NONE {
                continue;
            }

            if r_type == Arch::GOT || r_type == Arch::SYMBOLIC {
                // Handle GOT and symbolic relocations
                if let Some(symbol) = helper.find_symbol(r_sym) {
                    let r_addend = rel.r_addend(base.into_inner());
                    segments.write(rel.r_offset(), symbol.addend(r_addend));
                    continue;
                }
            } else if r_type == Arch::COPY {
                // Handle copy relocations (typically for global data)
                if let Some(symdef) = helper.find_symdef(r_sym) {
                    let len = core.symtab().symbol_idx(r_sym).0.st_size();
                    let dest = core.segments().get_slice_mut::<u8>(rel.r_offset(), len);
                    let src = symdef
                        .lib
                        .segments()
                        .get_slice(symdef.sym.unwrap().st_value(), len);
                    dest.copy_from_slice(src);
                    continue;
                }
            } else if r_type == Arch::IRELATIVE {
                // IFUNC resolvers run on the host CPU, so they only make
                // sense when the relocated module shares the host's ABI.
                // Cross-architecture loaders fall through to the post
                // `RelocationHandler` below.
                if Arch::SUPPORTS_NATIVE_RUNTIME {
                    let r_addend = rel.r_addend(base.into_inner());
                    let addr = base.addend(r_addend);
                    segments.write(rel.r_offset(), unsafe { resolve_ifunc(addr) });
                    continue;
                }
            } else if Arch::is_tls(r_type) {
                // `handle_tls_reloc` is a pure data computation for
                // DTPMOD/DTPOFF/TPOFF (safe under cross-arch loads) and
                // gates TLSDESC on SUPPORTS_NATIVE_RUNTIME internally.
                // Anything it cannot handle falls through to the post
                // handler.
                if handle_tls_reloc::<_, Arch, _, _, _, _>(helper, rel) {
                    continue;
                }
            }

            // Handle unknown relocations with the provided handler
            if helper.handle_post(rel)?.is_unhandled() {
                return Err(reloc_error::<Arch, _>(
                    rel,
                    RelocationFailureReason::Unhandled,
                    core,
                ));
            }
        }
        Ok(self)
    }
}

impl DynamicRelocation {
    /// Create a new DynamicRelocation instance from parsed relocation data
    #[inline]
    pub(crate) fn new(
        pltrel: Option<&'static [ElfRelType]>,
        dynrel: Option<&'static [ElfRelType]>,
        relr: Option<&'static [ElfRelr]>,
        rela_count: Option<NonZeroUsize>,
    ) -> Result<Self> {
        if let Some(relr) = relr {
            // Use RELR relocations if available (more compact format)
            Ok(Self {
                relative: RelativeRel::Relr(relr),
                pltrel: pltrel.unwrap_or(&[]),
                dynrel: dynrel.unwrap_or(&[]),
            })
        } else {
            // Use traditional REL/RELA relocations
            // nrelative indicates the count of REL_RELATIVE relocation types
            let nrelative = rela_count.map(|v| v.get()).unwrap_or(0);
            let old_dynrel = dynrel.unwrap_or(&[]);

            if nrelative > old_dynrel.len() {
                return Err(ParseDynamicError::MalformedRelocationTable {
                    detail:
                        "DT_RELCOUNT/DT_RELACOUNT relocation table is malformed: relative relocation count exceeds the relocation table length",
                }
                .into());
            }

            // Split relocations into relative and non-relative parts
            let relative = RelativeRel::Rel(&old_dynrel[..nrelative]);
            let temp_dynrel = &old_dynrel[nrelative..];

            let pltrel = pltrel.unwrap_or(&[]);
            let dynrel = if unsafe {
                // Check if dynrel and pltrel are contiguous in memory
                core::ptr::eq(
                    old_dynrel.as_ptr().add(old_dynrel.len()),
                    pltrel.as_ptr().add(pltrel.len()),
                )
            } {
                // If contiguous, exclude pltrel entries from dynrel
                let dynrel_len = temp_dynrel.len().checked_sub(pltrel.len()).ok_or(
                    ParseDynamicError::MalformedRelocationTable {
                        detail:
                            "DT_JMPREL relocation table is malformed: PLT relocations exceed the tail of DT_REL/DT_RELA",
                    },
                )?;
                &temp_dynrel[..dynrel_len]
            } else {
                // Otherwise, use all remaining entries
                temp_dynrel
            };

            Ok(Self {
                relative,
                pltrel,
                dynrel,
            })
        }
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
    use crate::{Error, ParseDynamicError, elf::ElfRelType};
    use alloc::boxed::Box;
    use core::num::NonZeroUsize;

    fn zeroed_rel() -> ElfRelType {
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn rejects_relative_count_past_dynrel_len() {
        let dynrel = Box::leak(Box::new([zeroed_rel()]));
        let err = match DynamicRelocation::new(None, Some(&dynrel[..]), None, NonZeroUsize::new(2))
        {
            Ok(_) => panic!("relative count should be validated"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            Error::ParseDynamic(ParseDynamicError::MalformedRelocationTable { .. })
        ));
    }

    #[test]
    fn rejects_pltrel_suffix_longer_than_remaining_dynrel() {
        let dynrel = Box::leak(Box::new([zeroed_rel(), zeroed_rel(), zeroed_rel()]));
        let err = match DynamicRelocation::new(
            Some(&dynrel[..]),
            Some(&dynrel[..]),
            None,
            NonZeroUsize::new(1),
        ) {
            Ok(_) => panic!("contiguous PLT suffix should fit in the non-relative tail"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            Error::ParseDynamic(ParseDynamicError::MalformedRelocationTable { .. })
        ));
    }
}
