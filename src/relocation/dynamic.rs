//! Relocation of elf objects
use crate::{
    Result,
    arch::*,
    elf::{ElfRelType, ElfRelr},
    image::{CoreInner, DynamicImage, ElfCoreRef, LoadedCore},
    relocation::{
        RelocHelper, RelocValue, RelocationContext, RelocationHandler, SymbolLookup,
        find_symbol_addr, likely, reloc_error, unlikely,
    },
};
use alloc::vec::Vec;
use core::{num::NonZeroUsize, ptr::null_mut};

#[cfg(not(feature = "portable-atomic"))]
use alloc::sync::Arc;
#[cfg(feature = "portable-atomic")]
use portable_atomic_util::Arc;

/// LazyScope holds both the local scope lookup and an optional parent scope
/// This avoids requiring D to be 'static by storing weak references to libraries
struct LazyScope<D = (), S: SymbolLookup = ()>
where
    S: SymbolLookup,
{
    /// Weak references to the local libraries for symbol lookup
    libs: Vec<ElfCoreRef<D>>,
    custom_scope: Option<S>,
    tls_get_addr: usize,
}

impl<D, S: SymbolLookup> SymbolLookup for LazyScope<D, S> {
    fn lookup(&self, name: &str) -> Option<*const ()> {
        if name == "__tls_get_addr" {
            return Some(self.tls_get_addr as *const ());
        }
        // First try the parent scope if available
        if let Some(parent) = &self.custom_scope {
            if let Some(sym) = parent.lookup(name) {
                return Some(sym);
            }
        }
        // Then try the local libraries
        self.libs.iter().find_map(|lib| unsafe {
            let core = lib.upgrade()?;
            LoadedCore::from_core(core)
                .get::<()>(name)
                .map(|sym| sym.into_raw())
        })
    }
}

/// Resolve indirect function address
///
/// # Safety
/// The address must point to a valid IFUNC function.
#[inline(always)]
unsafe fn resolve_ifunc(addr: RelocValue<usize>) -> RelocValue<usize> {
    let ifunc: fn() -> usize = unsafe { core::mem::transmute(addr.0) };
    RelocValue::new(ifunc())
}

impl<D> DynamicImage<D> {
    pub(crate) fn relocate_impl<PreS, PostS, LazyS, PreH, PostH>(
        self,
        scope: Vec<LoadedCore<D>>,
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
        lazy: Option<bool>,
        lazy_scope: Option<LazyS>,
    ) -> Result<LoadedCore<D>>
    where
        D: 'static,
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        // Optimization: check if relocation is empty
        if self.relocation().is_empty() {
            let core = self.into_core();
            let relocated = unsafe { LoadedCore::from_core(core) };
            return Ok(relocated);
        }

        let is_lazy = lazy.unwrap_or(self.is_lazy());
        let tls_get_addr = self.tls_get_addr();

        let hooked_pre_find = |name: &str| -> Option<*const ()> {
            if name == "__tls_get_addr" {
                return Some(tls_get_addr as *const ());
            }
            pre_find.lookup(name)
        };

        let mut helper = RelocHelper {
            dependency_flags: alloc::vec![false; scope.len()],
            scope,
            pre_find: &hooked_pre_find,
            post_find,
            pre_handler,
            post_handler,
        };

        self.relocate_relative().relocate_dynrel(&mut helper)?;

        let deps = {
            let needed_libs = self.needed_libs();

            let lazy_scope = if is_lazy {
                let libs = helper.scope
                    .iter()
                    .filter(|lib| needed_libs.contains(&lib.name()))
                    .map(|lib| lib.core.downgrade())
                    .collect();
                Some(LazyScope {
                    libs,
                    custom_scope: lazy_scope,
                    tls_get_addr: tls_get_addr as *const () as usize,
                })
            } else {
                None
            };

            self.relocate_pltrel(is_lazy, lazy_scope, &mut helper)?
                .finish();

            let RelocHelper {
                scope,
                dependency_flags,
                ..
            } = helper;

            scope
                .into_iter()
                .zip(dependency_flags)
                .filter_map(|(module, flag)| {
                    (flag || needed_libs.contains(&module.name())).then(|| module)
                })
                .collect::<Vec<_>>()
        };

        Ok(unsafe { LoadedCore::from_core_deps(self.into_core(), deps) })
    }
}

/// Lazy binding fixup function called by PLT (Procedure Linkage Table)
pub(crate) unsafe extern "C" fn dl_fixup(dylib: &CoreInner, rela_idx: usize) -> usize {
    // Get the relocation entry for this function call
    let rela = unsafe {
        &*dylib
            .dynamic_info
            .as_ref()
            .unwrap()
            .pltrel
            .unwrap()
            .add(rela_idx)
            .as_ptr()
    };
    let r_type = rela.r_type();
    let r_sym = rela.r_symbol();
    let segments = &dylib.segments;

    // Ensure this is a jump slot relocation for a valid symbol
    assert!(r_type == REL_JUMP_SLOT as usize && r_sym != 0);

    // Get symbol information
    let (_, syminfo) = dylib.symtab.symbol_idx(r_sym);

    // Look up symbol in local scope
    let symbol = dylib
        .dynamic_info
        .as_ref()
        .unwrap()
        .lazy_scope
        .as_ref()
        .unwrap()
        .lookup(syminfo.name())
        .expect("lazy bind fail") as usize;

    // Write the resolved symbol address to the GOT entry
    segments.write(rela.r_offset(), RelocValue::new(symbol));
    symbol
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
    pltrel: &'static [ElfRelType],
    /// Other dynamic relocations
    dynrel: &'static [ElfRelType],
}

impl<D> DynamicImage<D> {
    /// Relocate PLT (Procedure Linkage Table) entries
    fn relocate_pltrel<PreS, PostS, LazyS, PreH, PostH>(
        &self,
        is_lazy: bool,
        lazy_scope: Option<LazyS>,
        helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
    ) -> Result<&Self>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        LazyS: SymbolLookup + Send + Sync + 'static,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        let core = self.core_ref();
        let base = core.base();
        let segments = core.segments();
        let reloc = self.relocation();
        let symtab = self.symtab();

        // Process PLT relocations
        for rel in reloc.pltrel {
            if !helper.handle_pre(rel, core)? {
                continue;
            }
            let r_type = rel.r_type() as u32;
            let r_sym = rel.r_symbol();
            let r_addend = rel.r_addend(base);

            // Handle jump slot relocations
            if likely(r_type == REL_JUMP_SLOT) {
                if is_lazy {
                    let addr = RelocValue::new(base) + rel.r_offset();
                    let ptr = addr.as_mut_ptr::<usize>();
                    // Even with lazy binding, basic relocation is needed for PLT to work
                    unsafe {
                        let origin_val = ptr.read();
                        let new_val = origin_val + base;
                        ptr.write(new_val);
                    }
                } else {
                    if let Some((symbol, idx)) = find_symbol_addr(
                        helper.pre_find,
                        helper.post_find,
                        core,
                        symtab,
                        &helper.scope,
                        r_sym,
                    ) {
                        if let Some(idx) = idx {
                            helper.dependency_flags[idx] = true;
                        }
                        segments.write(rel.r_offset(), symbol);
                    }
                }
                continue;
            } else if unlikely(r_type == REL_IRELATIVE) {
                // Handle indirect function relocations
                let addr = RelocValue::new(base) + r_addend;
                segments.write(rel.r_offset(), unsafe { resolve_ifunc(addr) });
                continue;
            }
            // Handle unknown relocations with the provided handler
            if helper.handle_post(rel, core)? {
                return Err(reloc_error(rel, "Unhandled relocation", core));
            }
        }

        if is_lazy {
            // Prepare for lazy binding if we have PLT relocations
            if !reloc.pltrel.is_empty() {
                prepare_lazy_bind(
                    self.got().unwrap().as_ptr(),
                    Arc::as_ptr(&core.inner) as usize,
                );
            }

            // Ensure lazy scope is available
            assert!(
                reloc.pltrel.is_empty() || lazy_scope.is_some(),
                "{}: lazy scope is not set",
                core.name()
            );

            // Set the lazy scope if provided
            if let Some(lazy_scope) = lazy_scope {
                self.set_lazy_scope(lazy_scope);
            }
        } else {
            // Apply RELRO (RELocation Read-Only) protection if available
            if let Some(relro) = self.relro() {
                relro.relro()?;
            }
        }
        Ok(self)
    }

    /// Perform relative relocations (REL_RELATIVE)
    fn relocate_relative(&self) -> &Self {
        let core = self.core_ref();
        let reloc = self.relocation();
        let segments = core.segments();
        let base = core.base();

        match reloc.relative {
            RelativeRel::Rel(rel) => {
                assert!(rel.is_empty() || rel[0].r_type() == REL_RELATIVE as usize);
                // Apply all relative relocations: new_value = base_address + addend
                rel.iter().for_each(|rel| {
                    debug_assert!(rel.r_type() == REL_RELATIVE as usize);
                    let r_addend = rel.r_addend(base);
                    let val = RelocValue::new(base) + r_addend;
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
                            reloc_addr.write(base + reloc_addr.read());
                            reloc_addr = reloc_addr.add(1);
                        } else {
                            // Bitmap of relocations
                            let mut bitmap = value;
                            let mut idx = 0;
                            while bitmap != 0 {
                                bitmap >>= 1;
                                if (bitmap & 1) != 0 {
                                    let ptr = reloc_addr.add(idx);
                                    ptr.write(base + ptr.read());
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
        let symtab = self.symtab();
        let segments = core.segments();
        let base = core.base();

        // Process each dynamic relocation entry
        for rel in reloc.dynrel {
            if !helper.handle_pre(rel, core)? {
                continue;
            }
            let r_type = rel.r_type() as u32;
            let r_sym = rel.r_symbol();
            let r_addend = rel.r_addend(base);

            match r_type {
                // Handle GOT and symbolic relocations
                REL_GOT | REL_SYMBOLIC => {
                    if let Some((symbol, idx)) = find_symbol_addr(
                        helper.pre_find,
                        helper.post_find,
                        core,
                        symtab,
                        &helper.scope,
                        r_sym,
                    ) {
                        if let Some(idx) = idx {
                            helper.dependency_flags[idx] = true;
                        }
                        segments.write(rel.r_offset(), symbol + r_addend);
                        continue;
                    }
                }
                // Handle copy relocations (typically for global data)
                REL_COPY => {
                    let hctx = RelocationContext::new(rel, core, &helper.scope);
                    if let Some((symdef, idx)) = hctx.find_symdef(r_sym) {
                        let len = hctx.lib().symtab().symbol_idx(r_sym).0.st_size();
                        if let Some(idx) = idx {
                            helper.dependency_flags[idx] = true;
                        }
                        let dest = core.segments().get_slice_mut::<u8>(rel.r_offset(), len);
                        let src = symdef
                            .lib
                            .segments()
                            .get_slice(symdef.sym.unwrap().st_value(), len);
                        dest.copy_from_slice(src);
                        continue;
                    }
                }
                REL_IRELATIVE => {
                    // Handle indirect function relocations
                    let addr = RelocValue::new(base) + r_addend;
                    segments.write(rel.r_offset(), unsafe { resolve_ifunc(addr) });
                    continue;
                }
                // Handle TLS (Thread Local Storage) relocations
                REL_DTPOFF | REL_DTPMOD | REL_TPOFF => {
                    let hctx = RelocationContext::new(rel, core, &helper.scope);
                    if super::tls::handle_tls_reloc(&hctx, rel, &mut helper.dependency_flags) {
                        continue;
                    }
                }
                // No relocation needed
                REL_NONE => continue,
                // Unknown relocation type
                _ => {}
            }

            // Handle unknown relocations with the provided handler
            if helper.handle_post(rel, core)? {
                return Err(reloc_error(rel, "Unhandled relocation", core));
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
