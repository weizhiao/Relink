//! Relocation of elf objects
use crate::sync::Arc;
use crate::{
    Result,
    arch::*,
    elf::{ElfRelType, ElfRelr},
    image::{DynamicImage, LoadedCore},
    logging,
    relocation::{
        BindingOptions, RelocAddr, RelocArtifacts, RelocHelper, RelocValue, RelocationHandler,
        ResolvedBinding, SymbolLookup, likely, reloc_error, unlikely,
    },
    tls::{handle_tls_reloc, is_tls_relocation, is_tlsdesc_relocation, lookup_tls_get_addr},
};
use alloc::vec::Vec;
use core::{num::NonZeroUsize, ptr::null_mut};

/// Resolve indirect function address
///
/// # Safety
/// The address must point to a valid IFUNC function.
#[inline(always)]
unsafe fn resolve_ifunc(addr: RelocAddr) -> RelocAddr {
    let ifunc: fn() -> usize = unsafe { core::mem::transmute(addr.into_inner()) };
    RelocValue::new(ifunc())
}

impl<D> DynamicImage<D> {
    fn apply_relro(&self, binding: &ResolvedBinding) -> Result<()> {
        if let Some(relro) = self.relro() {
            if !binding.is_lazy() {
                relro.relro()?;
            }
        }
        Ok(())
    }

    pub(crate) fn relocate_impl<PreS, PostS, LazyS, PreH, PostH>(
        self,
        scope: Vec<LoadedCore<D>>,
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
        binding: BindingOptions<LazyS>,
    ) -> Result<LoadedCore<D>>
    where
        D: 'static,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        logging::info!("Relocating dynamic library: {}", self.name());

        // Optimization: check if relocation is empty
        if self.relocation().is_empty() {
            logging::debug!("No relocations needed for {}", self.name());
            let core = self.into_core();
            let relocated = unsafe { LoadedCore::from_core(core) };
            return Ok(relocated);
        }

        let binding = self.resolve_binding(binding);
        let tls_get_addr = self.tls_get_addr();

        if binding.is_lazy() {
            logging::debug!("Using lazy binding for {}", self.name());
        }

        let hooked_pre_find = |name: &str| -> Option<*const ()> {
            if let Some(symbol) = lookup_tls_get_addr(name, tls_get_addr) {
                return Some(symbol);
            }
            pre_find.lookup(name)
        };

        let mut helper = RelocHelper::new(
            self.core_ref(),
            scope,
            &hooked_pre_find,
            post_find,
            pre_handler,
            post_handler,
            tls_get_addr,
        );

        self.relocate_relative()
            .relocate_dynrel(&mut helper)?
            .relocate_pltrel(&binding, &mut helper)?;

        let RelocArtifacts {
            deps,
            tls_desc_args,
        } = helper.finish(self.needed_libs());

        // Persist TLSDESC backing storage collected during relocation.
        unsafe {
            self.core_ref().set_tls_desc_args(tls_desc_args);
        }

        let deps: Arc<[LoadedCore<D>]> = Arc::from(deps);

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
        self.install_lazy_scope(binding, deps.clone())?;

        logging::debug!("Executing initialization functions for {}", self.name());
        self.call_init();

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

impl<D> DynamicImage<D> {
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
        binding.prepare_plt(self)?;

        // Process PLT relocations
        for rel in reloc.pltrel {
            if !helper.handle_pre(rel)? {
                continue;
            }
            let r_type = rel.r_type() as u32;
            let r_sym = rel.r_symbol();
            let r_addend = rel.r_addend(base.into_inner());

            // Handle jump slot relocations
            if likely(r_type == REL_JUMP_SLOT) {
                if binding.relocate_jump_slot(base, rel) {
                    continue;
                }

                if let Some(symbol) = helper.find_symbol(r_sym) {
                    segments.write(rel.r_offset(), symbol);
                    continue;
                }
            } else if unlikely(r_type == REL_IRELATIVE) {
                // Handle indirect function relocations
                let addr = base.addend(r_addend);
                segments.write(rel.r_offset(), unsafe { resolve_ifunc(addr) });
                continue;
            } else if unlikely(is_tlsdesc_relocation(r_type)) {
                // Handle TLSDESC relocations
                if handle_tls_reloc(helper, rel) {
                    continue;
                }
            }
            // Handle unknown relocations with the provided handler
            if helper.handle_post(rel)? {
                return Err(reloc_error(
                    rel,
                    crate::RelocationFailureReason::Unhandled,
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
                assert!(rel.is_empty() || rel[0].r_type() == REL_RELATIVE as usize);
                // Apply all relative relocations: new_value = base_address + addend
                rel.iter().for_each(|rel| {
                    debug_assert!(rel.r_type() == REL_RELATIVE as usize);
                    let r_addend = rel.r_addend(base.into_inner());
                    let val = base.addend(r_addend);
                    segments.write(rel.r_offset(), val);
                })
            }
            RelativeRel::Relr(relr) => {
                // Apply compact relative relocations (RELR format)
                let mut reloc_addr: *mut usize = null_mut();
                relr.iter().for_each(|relr| {
                    let value = relr.value();
                    unsafe {
                        if (value & 1) == 0 {
                            // Single relocation entry
                            reloc_addr = core.segments().get_mut_ptr(value);
                            reloc_addr.write(base.offset(reloc_addr.read()).into_inner());
                            reloc_addr = reloc_addr.add(1);
                        } else {
                            // Bitmap of relocations
                            let mut bitmap = value;
                            let mut idx = 0;
                            while bitmap != 0 {
                                bitmap >>= 1;
                                if (bitmap & 1) != 0 {
                                    let ptr = reloc_addr.add(idx);
                                    ptr.write(base.offset(ptr.read()).into_inner());
                                }
                                idx += 1;
                            }
                            reloc_addr = reloc_addr.add(usize::BITS as usize - 1);
                        }
                    }
                });
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
            if !helper.handle_pre(rel)? {
                continue;
            }
            let r_type = rel.r_type() as u32;
            let r_sym = rel.r_symbol();
            let r_addend = rel.r_addend(base.into_inner());

            // Handle `REL_NONE` first because some architectures use `0` as a
            // sentinel for unsupported relocation classes such as TLSDESC.
            if r_type == REL_NONE {
                continue;
            }

            if r_type == REL_GOT || r_type == REL_SYMBOLIC {
                // Handle GOT and symbolic relocations
                if let Some(symbol) = helper.find_symbol(r_sym) {
                    segments.write(rel.r_offset(), symbol.addend(r_addend));
                    continue;
                }
            } else if r_type == REL_COPY {
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
            } else if r_type == REL_IRELATIVE {
                // Handle indirect function relocations
                let addr = base.addend(r_addend);
                segments.write(rel.r_offset(), unsafe { resolve_ifunc(addr) });
                continue;
            } else if is_tls_relocation(r_type) {
                // Handle TLS (Thread Local Storage) relocations
                if handle_tls_reloc(helper, rel) {
                    continue;
                }
            }

            // Handle unknown relocations with the provided handler
            if helper.handle_post(rel)? {
                return Err(reloc_error(
                    rel,
                    crate::RelocationFailureReason::Unhandled,
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
    ) -> Self {
        if let Some(relr) = relr {
            // Use RELR relocations if available (more compact format)
            Self {
                relative: RelativeRel::Relr(relr),
                pltrel: pltrel.unwrap_or(&[]),
                dynrel: dynrel.unwrap_or(&[]),
            }
        } else {
            // Use traditional REL/RELA relocations
            // nrelative indicates the count of REL_RELATIVE relocation types
            let nrelative = rela_count.map(|v| v.get()).unwrap_or(0);
            let old_dynrel = dynrel.unwrap_or(&[]);

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
                &temp_dynrel[..temp_dynrel.len() - pltrel.len()]
            } else {
                // Otherwise, use all remaining entries
                temp_dynrel
            };

            Self {
                relative,
                pltrel,
                dynrel,
            }
        }
    }

    /// Check if there are no relocations to process
    #[inline]
    fn is_empty(&self) -> bool {
        self.relative.is_empty() && self.dynrel.is_empty() && self.pltrel.is_empty()
    }
}
