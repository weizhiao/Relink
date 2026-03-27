#[cfg(feature = "lazy-binding")]
mod enabled {
    use crate::image::{CoreInner, DynamicImage, DynamicInfo, LoadedCore};
    use crate::{
        RelocationError, Result,
        arch::REL_JUMP_SLOT,
        arch::prepare_lazy_bind,
        elf::ElfRelType,
        relocation::{BindingMode, LazyLookupHooks, RelocAddr, SymbolLookup, unlikely},
        sync::Arc,
        tls::lookup_tls_get_addr,
    };
    use alloc::boxed::Box;
    use core::ptr::NonNull;

    struct LazyLookup<D = ()> {
        libs: Arc<[LoadedCore<D>]>,
        pre_find: Box<dyn SymbolLookup + Send + Sync>,
        post_find: Box<dyn SymbolLookup + Send + Sync>,
        tls_get_addr: RelocAddr,
    }

    impl<D> SymbolLookup for LazyLookup<D> {
        fn lookup(&self, name: &str) -> Option<*const ()> {
            if let Some(symbol) = lookup_tls_get_addr(name, self.tls_get_addr) {
                return Some(symbol);
            }

            if let Some(symbol) = self.pre_find.lookup(name) {
                return Some(symbol);
            }

            self.libs
                .iter()
                .find_map(|lib| unsafe { lib.get::<()>(name).map(|sym| sym.into_raw()) })
                .or_else(|| self.post_find.lookup(name))
        }
    }

    pub(crate) enum ResolvedBinding {
        Eager,
        Lazy,
    }

    impl ResolvedBinding {
        #[inline]
        pub(crate) fn is_lazy(&self) -> bool {
            matches!(self, Self::Lazy)
        }

        pub(crate) fn prepare_plt<D>(&self, image: &DynamicImage<D>) -> Result<()>
        where
            D: 'static,
        {
            if self.is_lazy() {
                let pltrel = image.relocation().pltrel;
                if pltrel.is_empty() {
                    return Ok(());
                }

                let got = lazy_binding_got(image)?;
                let core = image.core_ref();
                prepare_lazy_bind(got.as_ptr(), RelocAddr::from_ptr(Arc::as_ptr(&core.inner)));
            }
            Ok(())
        }

        pub(crate) fn relocate_jump_slot(&self, base: RelocAddr, rel: &ElfRelType) -> bool {
            if !self.is_lazy() {
                return false;
            }

            let addr = base.offset(rel.r_offset());
            let ptr = addr.as_mut_ptr::<usize>();
            unsafe {
                let origin_val = ptr.read();
                let new_val = base.offset(origin_val).into_inner();
                ptr.write(new_val);
            }
            true
        }
    }

    impl<D> DynamicImage<D> {
        pub(crate) fn resolve_binding(&self, binding: BindingMode) -> ResolvedBinding {
            match binding {
                BindingMode::Default => {
                    if self.is_lazy() {
                        ResolvedBinding::Lazy
                    } else {
                        ResolvedBinding::Eager
                    }
                }
                BindingMode::Eager => ResolvedBinding::Eager,
                BindingMode::Lazy => ResolvedBinding::Lazy,
            }
        }

        pub(crate) fn install_lazy_lookup<LazyPreS, LazyPostS>(
            &self,
            binding: ResolvedBinding,
            lazy_lookup: LazyLookupHooks<LazyPreS, LazyPostS>,
            deps: Arc<[LoadedCore<D>]>,
        ) -> Result<()>
        where
            LazyPreS: SymbolLookup + Send + Sync + 'static,
            LazyPostS: SymbolLookup + Send + Sync + 'static,
            D: 'static,
        {
            if let ResolvedBinding::Lazy = binding {
                if self.relocation().pltrel.is_empty() {
                    return Ok(());
                }

                let dynamic_info = self.core_ref().inner.dynamic_info.as_ref().ok_or(
                    RelocationError::LazyBindingSetup {
                        detail: "lazy binding requires dynamic metadata",
                    },
                )?;
                let info = unsafe { &mut *(Arc::as_ptr(dynamic_info) as *mut DynamicInfo) };
                let LazyLookupHooks {
                    pre_find,
                    post_find,
                } = lazy_lookup;
                info.lazy.lookup = Some(Box::new(LazyLookup {
                    libs: deps,
                    pre_find: Box::new(pre_find),
                    post_find: Box::new(post_find),
                    tls_get_addr: self.core_ref().tls_get_addr(),
                }));
            }
            Ok(())
        }
    }

    fn lazy_binding_got<D>(image: &DynamicImage<D>) -> Result<NonNull<usize>>
    where
        D: 'static,
    {
        image.got().ok_or(
            RelocationError::LazyBindingSetup {
                detail: "lazy binding requires a GOT/PLTGOT entry",
            }
            .into(),
        )
    }

    #[cold]
    #[inline(never)]
    fn unresolved_symbol(name: &str, symbol: &str) -> ! {
        panic!("lazy binding failed for {name}: unresolved symbol {symbol}");
    }

    #[cold]
    #[inline(never)]
    fn invalid_state(name: &str, reason: &str) -> ! {
        panic!("lazy binding failed for {name}: {reason}");
    }

    #[cold]
    #[inline(never)]
    fn invalid_relocation(name: &str, rela_idx: usize, rel: &ElfRelType) -> ! {
        panic!(
            "lazy binding failed for {name}: invalid PLT relocation {rela_idx} (type {}, sym {})",
            rel.r_type(),
            rel.r_symbol()
        );
    }

    #[cold]
    #[inline(never)]
    fn invalid_relocation_index(name: &str, rela_idx: usize, len: usize) -> ! {
        panic!(
            "lazy binding failed for {name}: relocation index {rela_idx} out of range (len {len})"
        );
    }

    #[cold]
    #[inline(never)]
    fn invalid_symbol_index(name: &str, r_sym: usize, sym_count: usize) -> ! {
        panic!(
            "lazy binding failed for {name}: symbol index {r_sym} out of range (len {})",
            sym_count
        );
    }

    pub(crate) unsafe extern "C" fn dl_fixup(dylib: &CoreInner, rela_idx: usize) -> usize {
        let Some(dynamic_info) = dylib.dynamic_info.as_ref() else {
            invalid_state(dylib.name.as_str(), "missing dynamic metadata")
        };
        let pltrel = dynamic_info.lazy.pltrel;

        let Some(rela) = pltrel.get(rela_idx) else {
            invalid_relocation_index(dylib.name.as_str(), rela_idx, pltrel.len())
        };
        let r_type = rela.r_type();
        let r_sym = rela.r_symbol();
        let segments = &dylib.segments;

        if unlikely(r_type != REL_JUMP_SLOT as usize || r_sym == 0) {
            invalid_relocation(dylib.name.as_str(), rela_idx, rela);
        }

        let sym_count = dylib.symtab.count_syms();
        if unlikely(r_sym >= sym_count) {
            invalid_symbol_index(dylib.name.as_str(), r_sym, sym_count);
        }

        let (_, syminfo) = dylib.symtab.symbol_idx(r_sym);

        let Some(lookup) = dynamic_info.lazy.lookup.as_ref() else {
            invalid_state(dylib.name.as_str(), "missing lazy lookup")
        };
        let symbol = match lookup.lookup(syminfo.name()) {
            Some(symbol) => RelocAddr::from_ptr(symbol),
            None => unresolved_symbol(dylib.name.as_str(), syminfo.name()),
        };

        segments.write(rela.r_offset(), symbol);
        symbol.into_inner()
    }
}

#[cfg(not(feature = "lazy-binding"))]
mod disabled {
    use crate::{
        elf::ElfRelType,
        image::{DynamicImage, LoadedCore},
        relocation::{BindingMode, LazyLookupHooks, SymbolLookup},
        sync::Arc,
    };

    pub(crate) enum ResolvedBinding {
        Eager,
    }

    impl ResolvedBinding {
        #[inline]
        pub(crate) const fn is_lazy(&self) -> bool {
            false
        }

        pub(crate) fn prepare_plt<D>(&self, _image: &DynamicImage<D>) -> crate::Result<()>
        where
            D: 'static,
        {
            Ok(())
        }

        pub(crate) const fn relocate_jump_slot(
            &self,
            _base: crate::relocation::RelocAddr,
            _rel: &ElfRelType,
        ) -> bool {
            false
        }
    }

    impl<D> DynamicImage<D> {
        pub(crate) fn resolve_binding(&self, _binding: BindingMode) -> ResolvedBinding {
            ResolvedBinding::Eager
        }

        pub(crate) fn install_lazy_lookup<LazyPreS, LazyPostS>(
            &self,
            _binding: ResolvedBinding,
            lazy_lookup: LazyLookupHooks<LazyPreS, LazyPostS>,
            _deps: Arc<[LoadedCore<D>]>,
        ) -> crate::Result<()>
        where
            LazyPreS: SymbolLookup + Send + Sync + 'static,
            LazyPostS: SymbolLookup + Send + Sync + 'static,
            D: 'static,
        {
            lazy_lookup.pre_find;
            lazy_lookup.post_find;
            Ok(())
        }
    }
}

#[cfg(not(feature = "lazy-binding"))]
pub(crate) use disabled::ResolvedBinding;
#[cfg(feature = "lazy-binding")]
pub(crate) use enabled::{ResolvedBinding, dl_fixup};
