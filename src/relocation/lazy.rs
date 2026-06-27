#[cfg(feature = "lazy-binding")]
mod enabled {
    use super::super::helper::find_symdef_impl;
    use crate::image::{
        CoreInner, LazyBindingRuntime, ModuleScope, RawDylib, RawDynamic, RawElf, RawExec,
    };
    use crate::{
        RelocationError, Result,
        arch::prepare_lazy_bind,
        elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord},
        hint::unlikely,
        memory::{ImageMemory, RegionAccess, VmAddr, VmOffset},
        relocation::{BindingMode, ObjectRelocationArch, RelocationArch, SupportLazy},
        runtime::NativeCodeExecutor,
        sync::Arc,
        tls::{TLS_GET_ADDR_SYMBOL, TlsResolver},
    };
    use core::ptr::NonNull;

    impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> SupportLazy
        for RawDynamic<D, Arch, R, Tls>
    {
    }

    impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> SupportLazy
        for RawDylib<D, Arch, R, Tls>
    {
    }

    impl<D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> SupportLazy
        for RawExec<D, Arch, R, Tls>
    {
    }

    impl<D: 'static, Arch: ObjectRelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>
        SupportLazy for RawElf<D, Arch, R, Tls>
    {
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

        pub(crate) fn prepare_plt<
            D,
            Arch: RelocationArch,
            R: RegionAccess,
            Tls: TlsResolver<Arch>,
        >(
            &self,
            image: &RawDynamic<D, Arch, R, Tls>,
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
                let dynamic_info =
                    core.inner
                        .dynamic_info
                        .as_ref()
                        .ok_or(RelocationError::LazyBindingSetup {
                            detail: "lazy binding requires dynamic metadata",
                        })?;
                if dynamic_info.lazy.runtime.get().is_none() {
                    assert!(
                        dynamic_info
                            .lazy
                            .runtime
                            .set(LazyBindingRuntime::new(
                                Arc::as_ptr(&core.inner).cast(),
                                dl_fixup_typed::<D, Arch, R, Tls>,
                            ))
                            .is_ok(),
                        "lazy binding runtime must be installed only once",
                    );
                }
                let runtime =
                    dynamic_info
                        .lazy
                        .runtime
                        .get()
                        .ok_or(RelocationError::LazyBindingSetup {
                            detail: "lazy binding runtime was not installed",
                        })?;
                prepare_lazy_bind(got.as_ptr(), VmAddr::from_ptr(runtime));
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

    impl<D, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>> RawDynamic<D, Arch, R, Tls> {
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
            scope: ModuleScope<Arch, Tls>,
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

    fn lazy_binding_got<D, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver<Arch>>(
        image: &RawDynamic<D, Arch, R, Tls>,
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
    fn invalid_relocation<Arch: RelocationArch>(
        name: &str,
        rela_idx: usize,
        rel: &ElfRelType<Arch>,
    ) -> ! {
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

    unsafe fn dl_fixup_typed<D, Arch, R, Tls>(dylib: *const (), rela_idx: usize) -> usize
    where
        D: 'static,
        Arch: RelocationArch,
        R: RegionAccess,
        Tls: TlsResolver<Arch>,
    {
        let dylib = unsafe { &*dylib.cast::<CoreInner<D, Arch, R, Tls>>() };
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

        if unlikely(r_type != Arch::JUMP_SLOT || r_sym == 0) {
            invalid_relocation::<Arch>(dylib.path.as_str(), rela_idx, rela);
        }

        let symtab = dynamic_info.lazy.symtab.view();
        let sym_count = symtab.count_syms();
        if unlikely(r_sym >= sym_count) {
            invalid_symbol_index(dylib.path.as_str(), r_sym, sym_count);
        }

        let (sym, syminfo) = symtab.symbol_idx(r_sym);

        let Some(scope) = dynamic_info.lazy.scope.get() else {
            invalid_state(dylib.path.as_str(), "missing lazy lookup")
        };
        let symbol = if Tls::OVERRIDE_TLS_GET_ADDR && syminfo.name() == TLS_GET_ADDR_SYMBOL {
            Tls::bind_tls_get_addr()
                .unwrap_or_else(|_| invalid_state(dylib.path.as_str(), "lazy TLS binding failed"))
        } else {
            find_symdef_impl(dylib, scope, sym, &syminfo, dynamic_info.symbolic)
                .map(|symdef| symdef.resolve_addr(&NativeCodeExecutor))
                .transpose()
                .unwrap_or_else(|_| {
                    invalid_state(dylib.path.as_str(), "lazy IFUNC resolution failed")
                })
                .unwrap_or_else(|| unresolved_symbol(dylib.path.as_str(), syminfo.name()))
        };

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

    pub(crate) unsafe extern "C" fn dl_fixup(
        runtime: &LazyBindingRuntime,
        rela_idx: usize,
    ) -> usize {
        unsafe { runtime.fixup(rela_idx) }
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

        pub(crate) fn prepare_plt<D, Arch: RelocationArch, R: RegionAccess, Tls>(
            &self,
            _image: &RawDynamic<D, Arch, R, Tls>,
        ) -> crate::Result<()>
        where
            D: 'static,
            Tls: crate::tls::TlsResolver<Arch>,
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

    impl<D, Arch: RelocationArch, R: RegionAccess, Tls: crate::tls::TlsResolver<Arch>>
        RawDynamic<D, Arch, R, Tls>
    {
        pub(crate) fn resolve_binding(&self, _binding: BindingMode) -> ResolvedBinding {
            ResolvedBinding::Eager
        }

        pub(crate) fn install_lazy_lookup(
            &self,
            _binding: ResolvedBinding,
            _scope: ModuleScope<Arch, Tls>,
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
