#[cfg(feature = "lazy-binding")]
mod enabled {
    use crate::image::{CoreInner, DynamicImage, DynamicInfo, LoadedCore};
    use crate::{
        Result,
        arch::REL_JUMP_SLOT,
        arch::prepare_lazy_bind,
        elf::ElfRelType,
        relocate_lazy_binding_missing_got_error,
        relocation::{BindingOptions, RelocAddr, SymbolLookup},
        sync::Arc,
        tls::lookup_tls_get_addr,
    };
    use alloc::boxed::Box;
    use core::ptr::NonNull;

    struct LazyScope<D = ()> {
        libs: Arc<[LoadedCore<D>]>,
        custom_scope: Option<Box<dyn SymbolLookup + Send + Sync>>,
        tls_get_addr: RelocAddr,
    }

    impl<D> SymbolLookup for LazyScope<D> {
        fn lookup(&self, name: &str) -> Option<*const ()> {
            if let Some(symbol) = lookup_tls_get_addr(name, self.tls_get_addr) {
                return Some(symbol);
            }

            if let Some(parent) = &self.custom_scope {
                if let Some(sym) = parent.lookup(name) {
                    return Some(sym);
                }
            }

            self.libs
                .iter()
                .find_map(|lib| unsafe { lib.get::<()>(name).map(|sym| sym.into_raw()) })
        }
    }

    pub(crate) enum ResolvedBinding {
        Eager,
        Lazy {
            scope: Option<Box<dyn SymbolLookup + Send + Sync>>,
        },
    }

    impl ResolvedBinding {
        #[inline]
        pub(crate) fn is_lazy(&self) -> bool {
            matches!(self, Self::Lazy { .. })
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
        pub(crate) fn resolve_binding<LazyS>(
            &self,
            binding: BindingOptions<LazyS>,
        ) -> ResolvedBinding
        where
            LazyS: SymbolLookup + Send + Sync + 'static,
        {
            match binding {
                BindingOptions::Default => {
                    if self.is_lazy() {
                        ResolvedBinding::Lazy { scope: None }
                    } else {
                        ResolvedBinding::Eager
                    }
                }
                BindingOptions::Eager => ResolvedBinding::Eager,
                BindingOptions::Lazy { scope } => ResolvedBinding::Lazy {
                    scope: scope
                        .map(|scope| Box::new(scope) as Box<dyn SymbolLookup + Send + Sync>),
                },
            }
        }

        pub(crate) fn install_lazy_scope(
            &self,
            binding: ResolvedBinding,
            deps: Arc<[LoadedCore<D>]>,
        ) -> Result<()>
        where
            D: 'static,
        {
            if let ResolvedBinding::Lazy { scope } = binding {
                if self.relocation().pltrel.is_empty() {
                    return Ok(());
                }

                let dynamic_info = self
                    .core_ref()
                    .inner
                    .dynamic_info
                    .as_ref()
                    .expect("DynamicImage must carry dynamic_info during lazy binding setup");
                let info = unsafe { &mut *(Arc::as_ptr(dynamic_info) as *mut DynamicInfo) };
                info.lazy.scope = Some(Box::new(LazyScope {
                    libs: deps,
                    custom_scope: scope,
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
        image
            .got()
            .ok_or_else(relocate_lazy_binding_missing_got_error)
    }

    #[cold]
    #[inline(never)]
    fn lazy_bind_unresolved_symbol(name: &str, symbol: &str) -> ! {
        panic!("lazy binding failed for {name}: unresolved symbol {symbol}");
    }

    #[allow(improper_ctypes_definitions)]
    pub(crate) unsafe extern "C" fn dl_fixup(dylib: &CoreInner, rela_idx: usize) -> usize {
        let dynamic_info = unsafe { dylib.dynamic_info.as_ref().unwrap_unchecked() };
        let pltrel = dynamic_info.lazy.pltrel;

        debug_assert!(rela_idx < pltrel.len());

        // All structural lazy-binding checks were front-loaded during installation.
        let rela = unsafe { pltrel.get_unchecked(rela_idx) };
        let r_type = rela.r_type();
        let r_sym = rela.r_symbol();
        let segments = &dylib.segments;

        debug_assert!(r_type == REL_JUMP_SLOT as usize && r_sym != 0);

        let (_, syminfo) = dylib.symtab.symbol_idx(r_sym);

        let scope = unsafe { dynamic_info.lazy.scope.as_ref().unwrap_unchecked() };
        let symbol = match scope.lookup(syminfo.name()) {
            Some(symbol) => RelocAddr::from_ptr(symbol),
            None => lazy_bind_unresolved_symbol(dylib.name.as_str(), syminfo.name()),
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
        relocation::{BindingOptions, SymbolLookup},
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
        pub(crate) fn resolve_binding<LazyS>(
            &self,
            binding: BindingOptions<LazyS>,
        ) -> ResolvedBinding
        where
            LazyS: SymbolLookup + Send + Sync + 'static,
        {
            match binding {
                BindingOptions::Default | BindingOptions::Eager | BindingOptions::__Marker(_) => {
                    ResolvedBinding::Eager
                }
            }
        }

        pub(crate) fn install_lazy_scope(
            &self,
            _binding: ResolvedBinding,
            _deps: Arc<[LoadedCore<D>]>,
        ) -> crate::Result<()>
        where
            D: 'static,
        {
            Ok(())
        }
    }
}

#[cfg(not(feature = "lazy-binding"))]
pub(crate) use disabled::ResolvedBinding;
#[cfg(feature = "lazy-binding")]
pub(crate) use enabled::{ResolvedBinding, dl_fixup};
