#[cfg(feature = "lazy-binding")]
mod enabled {
    use crate::image::{
        CoreInner, DynamicInfo, Module, ModuleScope, RawDylib, RawDynamic, RawElf, RawExec,
    };
    use crate::{
        RelocationError, Result,
        arch::{NativeArch, prepare_lazy_bind},
        elf::{ElfRelEntry, ElfRelType, SymbolInfo},
        relocation::{BindingMode, RelocAddr, RelocationArch, SupportLazy, SymDef, unlikely},
        sync::Arc,
        tls::lookup_tls_get_addr,
    };
    use core::ptr::NonNull;

    impl<D: 'static, Arch: RelocationArch> SupportLazy for RawDynamic<D, Arch> {}

    impl<D: 'static, Arch: RelocationArch> SupportLazy for RawDylib<D, Arch> {}

    impl<D: 'static, Arch: RelocationArch> SupportLazy for RawExec<D, Arch> {}

    impl<D: 'static, Arch: RelocationArch> SupportLazy for RawElf<D, Arch> {}

    fn lookup_addr<Arch: RelocationArch>(
        source: &dyn Module<Arch>,
        name: &str,
    ) -> Option<RelocAddr> {
        let syminfo = SymbolInfo::from_str(name, None);
        let mut precompute = syminfo.precompute();
        let sym = source.lookup_symbol(&syminfo, &mut precompute)?;
        Some(SymDef::<(), Arch>::new(Some(sym), source).convert())
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

        pub(crate) fn prepare_plt<D, Arch: RelocationArch>(
            &self,
            image: &RawDynamic<D, Arch>,
        ) -> Result<()>
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

        pub(crate) fn relocate_jump_slot<Arch: RelocationArch>(
            &self,
            base: RelocAddr,
            rel: &ElfRelType<Arch>,
        ) -> bool {
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

    impl<D, Arch: RelocationArch> RawDynamic<D, Arch> {
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

        pub(crate) fn install_lazy_lookup(
            &self,
            binding: ResolvedBinding,
            scope: ModuleScope<Arch>,
        ) -> Result<()>
        where
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
                let info = unsafe { &mut *(Arc::as_ptr(dynamic_info) as *mut DynamicInfo<Arch>) };
                info.lazy.scope = Some(scope);
            }
            Ok(())
        }
    }

    fn lazy_binding_got<D, Arch: RelocationArch>(
        image: &RawDynamic<D, Arch>,
    ) -> Result<NonNull<usize>>
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

        if unlikely(r_type != <NativeArch as RelocationArch>::JUMP_SLOT || r_sym == 0) {
            invalid_relocation(dylib.name.as_str(), rela_idx, rela);
        }

        let sym_count = dylib.symtab.count_syms();
        if unlikely(r_sym >= sym_count) {
            invalid_symbol_index(dylib.name.as_str(), r_sym, sym_count);
        }

        let (_, syminfo) = dylib.symtab.symbol_idx(r_sym);

        let Some(scope) = dynamic_info.lazy.scope.as_ref() else {
            invalid_state(dylib.name.as_str(), "missing lazy lookup")
        };
        let symbol = lookup_tls_get_addr(syminfo.name(), dylib.tls.tls_get_addr())
            .map(RelocAddr::from_ptr)
            .or_else(|| {
                scope
                    .iter()
                    .find_map(|source| lookup_addr::<NativeArch>(&**source, syminfo.name()))
            })
            .unwrap_or_else(|| unresolved_symbol(dylib.name.as_str(), syminfo.name()));

        segments.write(rela.r_offset(), symbol);
        symbol.into_inner()
    }
}

#[cfg(not(feature = "lazy-binding"))]
mod disabled {
    use crate::{
        elf::ElfRelType,
        image::{ModuleScope, RawDynamic},
        relocation::{BindingMode, RelocationArch},
    };

    pub(crate) enum ResolvedBinding {
        Eager,
    }

    impl ResolvedBinding {
        #[inline]
        pub(crate) const fn is_lazy(&self) -> bool {
            false
        }

        pub(crate) fn prepare_plt<D, Arch: RelocationArch>(
            &self,
            _image: &RawDynamic<D, Arch>,
        ) -> crate::Result<()>
        where
            D: 'static,
        {
            Ok(())
        }

        pub(crate) fn relocate_jump_slot<Arch: RelocationArch>(
            &self,
            _base: crate::relocation::RelocAddr,
            _rel: &ElfRelType<Arch>,
        ) -> bool {
            false
        }
    }

    impl<D, Arch: RelocationArch> RawDynamic<D, Arch> {
        pub(crate) fn resolve_binding(&self, _binding: BindingMode) -> ResolvedBinding {
            ResolvedBinding::Eager
        }

        pub(crate) fn install_lazy_lookup(
            &self,
            _binding: ResolvedBinding,
            _scope: ModuleScope<Arch>,
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
