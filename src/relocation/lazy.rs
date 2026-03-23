#[cfg(feature = "lazy-binding")]
mod enabled {
    use crate::image::{CoreInner, DynamicImage, DynamicInfo, LoadedCore};
    use crate::{
        arch::REL_JUMP_SLOT,
        arch::prepare_lazy_bind,
        elf::ElfRelType,
        relocation::{BindingOptions, RelocValue, SymbolLookup},
        sync::Arc,
    };
    use alloc::boxed::Box;

    struct LazyScope<D = ()> {
        libs: Arc<[LoadedCore<D>]>,
        custom_scope: Option<Box<dyn SymbolLookup + Send + Sync>>,
        tls_get_addr: usize,
    }

    impl<D> SymbolLookup for LazyScope<D> {
        fn lookup(&self, name: &str) -> Option<*const ()> {
            if name == "__tls_get_addr" {
                return Some(self.tls_get_addr as *const ());
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

        pub(crate) fn prepare_plt<D>(&self, image: &DynamicImage<D>)
        where
            D: 'static,
        {
            if self.is_lazy() && image.relocation().has_pltrel() {
                let core = image.core_ref();
                prepare_lazy_bind(
                    image
                        .got()
                        .expect("GOT not found for lazy binding")
                        .as_ptr(),
                    Arc::as_ptr(&core.inner) as usize,
                );
            }
        }

        pub(crate) fn relocate_jump_slot(&self, base: usize, rel: &ElfRelType) -> bool {
            if !self.is_lazy() {
                return false;
            }

            let addr = RelocValue::new(base) + rel.r_offset();
            let ptr = addr.as_mut_ptr::<usize>();
            unsafe {
                let origin_val = ptr.read();
                let new_val = origin_val + base;
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
            tls_get_addr: usize,
        ) where
            D: 'static,
        {
            if let ResolvedBinding::Lazy { scope } = binding {
                let dynamic_info = self.core_ref().inner.dynamic_info.as_ref().unwrap();
                let info = unsafe { &mut *(Arc::as_ptr(dynamic_info) as *mut DynamicInfo) };
                info.lazy.scope = Some(Box::new(LazyScope {
                    libs: deps,
                    custom_scope: scope,
                    tls_get_addr,
                }));
            }
        }
    }

    #[allow(improper_ctypes_definitions)]
    pub(crate) unsafe extern "C" fn dl_fixup(dylib: &CoreInner, rela_idx: usize) -> usize {
        let dynamic_info = dylib.dynamic_info.as_ref().expect("dynamic_info missing");
        let pltrel = dynamic_info.lazy.pltrel.expect("pltrel missing");

        let rela = unsafe { &*pltrel.as_ptr().add(rela_idx) };
        let r_type = rela.r_type();
        let r_sym = rela.r_symbol();
        let segments = &dylib.segments;

        assert!(r_type == REL_JUMP_SLOT as usize && r_sym != 0);

        let (_, syminfo) = dylib.symtab.symbol_idx(r_sym);

        let symbol = dynamic_info
            .lazy
            .scope
            .as_ref()
            .expect("lazy scope missing")
            .lookup(syminfo.name())
            .expect("lazy bind fail") as usize;

        segments.write(rela.r_offset(), RelocValue::new(symbol));
        symbol
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

        pub(crate) fn prepare_plt<D>(&self, _image: &DynamicImage<D>)
        where
            D: 'static,
        {
        }

        pub(crate) const fn relocate_jump_slot(&self, _base: usize, _rel: &ElfRelType) -> bool {
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
            _tls_get_addr: usize,
        ) where
            D: 'static,
        {
        }
    }
}

#[cfg(not(feature = "lazy-binding"))]
pub(crate) use disabled::ResolvedBinding;
#[cfg(feature = "lazy-binding")]
pub(crate) use enabled::{ResolvedBinding, dl_fixup};
