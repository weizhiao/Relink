#[cfg(feature = "lazy-binding")]
mod enabled {
    use crate::image::{CoreInner, Module, ModuleScope, RawDylib, RawDynamic, RawElf, RawExec};
    use crate::{
        RelocationError, Result,
        arch::{NativeArch, prepare_lazy_bind},
        elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord, SymbolInfo},
        memory::{ImageMemory, RegionAccess, VmAddr, VmOffset},
        relocation::{
            BindingMode, ObjectRelocationArch, RelocationArch, SupportLazy, SymDef, unlikely,
        },
        sync::Arc,
        tls::lookup_tls_get_addr,
    };
    use core::ptr::NonNull;

    impl<D: 'static, Arch: RelocationArch, R: RegionAccess> SupportLazy for RawDynamic<D, Arch, R> {}

    impl<D: 'static, Arch: RelocationArch, R: RegionAccess> SupportLazy for RawDylib<D, Arch, R> {}

    impl<D: 'static, Arch: RelocationArch> SupportLazy for RawExec<D, Arch> {}

    impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess> SupportLazy for RawElf<D, Arch, R> {}

    fn lookup_addr<Arch: RelocationArch>(source: &dyn Module<Arch>, name: &str) -> Option<VmAddr> {
        let syminfo = SymbolInfo::from_str(name, None);
        let mut precompute = syminfo.precompute();
        let sym = source.exports().lookup(&syminfo, &mut precompute)?;
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

        pub(crate) fn prepare_plt<D, Arch: RelocationArch, R: RegionAccess>(
            &self,
            image: &RawDynamic<D, Arch, R>,
        ) -> Result<()>
        where
            D: 'static,
        {
            if self.is_lazy() {
                let pltrel = image.relocation().pltrel.as_slice();
                if pltrel.is_empty() {
                    return Ok(());
                }

                let got = lazy_binding_got(image)?;
                let core = image.core_ref();
                prepare_lazy_bind(got.as_ptr(), VmAddr::from_ptr(Arc::as_ptr(&core.inner)));
            }
            Ok(())
        }

        pub(crate) fn relocate_jump_slot<Arch, Memory>(
            &self,
            memory: &Memory,
            base: VmAddr,
            rel: &ElfRelType<Arch>,
        ) -> Result<bool>
        where
            Arch: RelocationArch,
            Memory: ImageMemory,
            <Arch::Layout as ElfLayout>::Word: crate::ByteRepr,
        {
            if !self.is_lazy() {
                return Ok(false);
            }

            unsafe {
                ImageMemory::update_value(
                    memory,
                    base + rel.r_offset(),
                    |word: <Arch::Layout as ElfLayout>::Word| {
                        <Arch::Layout as ElfLayout>::Word::from_usize(
                            (base + VmOffset::new(word.to_usize())).get(),
                        )
                    },
                )?
            };
            Ok(true)
        }
    }

    impl<D, Arch: RelocationArch, R: RegionAccess> RawDynamic<D, Arch, R> {
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
                assert!(
                    dynamic_info.lazy.scope.set(scope).is_ok(),
                    "lazy binding scope must be installed only once",
                );
            }
            Ok(())
        }
    }

    fn lazy_binding_got<D, Arch: RelocationArch, R: RegionAccess>(
        image: &RawDynamic<D, Arch, R>,
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
            invalid_state(dylib.path.as_str(), "missing dynamic metadata")
        };
        let pltrel = dynamic_info.lazy.pltrel.as_slice();

        let Some(rela) = pltrel.get(rela_idx) else {
            invalid_relocation_index(dylib.path.as_str(), rela_idx, pltrel.len())
        };
        let r_type = rela.r_type();
        let r_sym = rela.r_symbol();
        let segments = &dylib.segments;

        if unlikely(r_type != <NativeArch as RelocationArch>::JUMP_SLOT || r_sym == 0) {
            invalid_relocation(dylib.path.as_str(), rela_idx, rela);
        }

        let symtab = dynamic_info.lazy.symtab.view();
        let sym_count = symtab.count_syms();
        if unlikely(r_sym >= sym_count) {
            invalid_symbol_index(dylib.path.as_str(), r_sym, sym_count);
        }

        let (_, syminfo) = symtab.symbol_idx(r_sym);

        let Some(scope) = dynamic_info.lazy.scope.get() else {
            invalid_state(dylib.path.as_str(), "missing lazy lookup")
        };
        let symbol = lookup_tls_get_addr(syminfo.name(), dylib.tls.tls_get_addr())
            .map(VmAddr::from_ptr)
            .or_else(|| {
                scope
                    .iter()
                    .find_map(|source| lookup_addr::<NativeArch>(&**source, syminfo.name()))
            })
            .unwrap_or_else(|| unresolved_symbol(dylib.path.as_str(), syminfo.name()));

        unsafe {
            if ImageMemory::write_value(
                segments,
                dylib.segments.base() + rela.r_offset(),
                symbol.get(),
            )
            .is_err()
            {
                invalid_state(dylib.path.as_str(), "lazy binding write failed");
            }
        };
        symbol.get()
    }
}

#[cfg(not(feature = "lazy-binding"))]
mod disabled {
    use crate::{
        elf::ElfRelType,
        image::{ModuleScope, RawDynamic},
        memory::{ImageMemory, RegionAccess, VmAddr},
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

        pub(crate) fn prepare_plt<D, Arch: RelocationArch, R: RegionAccess>(
            &self,
            _image: &RawDynamic<D, Arch, R>,
        ) -> crate::Result<()>
        where
            D: 'static,
        {
            Ok(())
        }

        pub(crate) fn relocate_jump_slot<Arch, Memory>(
            &self,
            _memory: &Memory,
            _base: VmAddr,
            _rel: &ElfRelType<Arch>,
        ) -> crate::Result<bool>
        where
            Arch: RelocationArch,
            Memory: ImageMemory,
        {
            Ok(false)
        }
    }

    impl<D, Arch: RelocationArch, R: RegionAccess> RawDynamic<D, Arch, R> {
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
