use super::request::DependencyOwner;
use crate::{
    Result,
    arch::{
        ArchKind, aarch64::relocation::AArch64Arch, arm::relocation::ArmArch,
        loongarch64::relocation::LoongArch64Arch, riscv32::relocation::RiscV32Arch,
        riscv64::relocation::RiscV64Arch, x86::relocation::X86Arch, x86_64::relocation::X86_64Arch,
    },
    image::{AnyScannedDynamic, LoadedCore, LoadedModule, RawDynamic, ScannedDynamic},
    relocation::{BindingMode, RelocationArch, RelocationHandler, Relocator, SymbolLookup},
    sync::Arc,
};

pub(crate) trait BuiltinArch: RelocationArch + Sized {
    fn wrap_raw<D: 'static>(raw: RawDynamic<D, Self>) -> AnyRawDynamic<D>;
    fn wrap_scanned(scanned: ScannedDynamic<Self::Layout>) -> AnyScannedDynamic;
    fn unwrap_scanned(scanned: AnyScannedDynamic) -> Option<ScannedDynamic<Self::Layout>>;
}

macro_rules! builtin_arches {
    ($(($variant:ident, $arch:ty)),+ $(,)?) => {
        pub(crate) enum AnyRawDynamic<D: 'static> {
            $($variant(RawDynamic<D, $arch>),)+
        }

        $(
            impl BuiltinArch for $arch {
                #[inline]
                fn wrap_raw<D: 'static>(raw: RawDynamic<D, Self>) -> AnyRawDynamic<D> {
                    AnyRawDynamic::$variant(raw)
                }

                #[inline]
                fn wrap_scanned(scanned: ScannedDynamic<Self::Layout>) -> AnyScannedDynamic {
                    AnyScannedDynamic::$variant(scanned)
                }

                #[inline]
                fn unwrap_scanned(scanned: AnyScannedDynamic) -> Option<ScannedDynamic<Self::Layout>> {
                    match scanned {
                        AnyScannedDynamic::$variant(scanned) => Some(scanned),
                        _ => None,
                    }
                }
            }
        )+

        pub(crate) trait BuiltinRelocationHandler:
            $(RelocationHandler<$arch> +)+
        {
        }

        impl<T> BuiltinRelocationHandler for T
        where
            T: $(RelocationHandler<$arch> +)+
        {
        }

        impl<D: 'static> AnyRawDynamic<D> {
            #[inline]
            pub(crate) fn arch_kind(&self) -> ArchKind {
                match self {
                    $(Self::$variant(_) => <$arch as RelocationArch>::KIND,)+
                }
            }

            #[inline]
            pub(crate) fn mapped_len(&self) -> usize {
                match self {
                    $(Self::$variant(raw) => raw.mapped_len(),)+
                }
            }

            #[inline]
            pub(crate) fn placeholder_module(&self) -> LoadedModule<D> {
                match self {
                    $(Self::$variant(raw) => {
                        LoadedModule::from(unsafe { LoadedCore::from_core(raw.core()) })
                    },)+
                }
            }

            pub(crate) fn relocate<PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD>(
                self,
                relocator: &Relocator<(), PreS, PostS, LazyPreS, LazyPostS, PreH, PostH, ScopeD>,
                scope: Arc<[LoadedModule<D>]>,
                binding: BindingMode,
            ) -> Result<LoadedModule<D>>
            where
                PreS: SymbolLookup + Clone,
                PostS: SymbolLookup + Clone,
                LazyPreS: SymbolLookup + Send + Sync + 'static + Clone,
                LazyPostS: SymbolLookup + Send + Sync + 'static + Clone,
                PreH: BuiltinRelocationHandler + Clone,
                PostH: BuiltinRelocationHandler + Clone,
                ScopeD: 'static,
            {
                match self {
                    $(Self::$variant(raw) => {
                        let loaded = relocator
                            .clone()
                            .with_object(raw)
                            .binding(binding)
                            .shared_scope(scope)
                            .relocate()?;
                        Ok(LoadedModule::from(loaded))
                    },)+
                }
            }
        }

        impl<D: 'static> DependencyOwner for AnyRawDynamic<D> {
            #[inline]
            fn name(&self) -> &str {
                match self {
                    $(Self::$variant(raw) => raw.name(),)+
                }
            }

            #[inline]
            fn arch_kind(&self) -> ArchKind {
                self.arch_kind()
            }

            #[inline]
            fn rpath(&self) -> Option<&str> {
                match self {
                    $(Self::$variant(raw) => raw.rpath(),)+
                }
            }

            #[inline]
            fn runpath(&self) -> Option<&str> {
                match self {
                    $(Self::$variant(raw) => raw.runpath(),)+
                }
            }

            #[inline]
            fn interp(&self) -> Option<&str> {
                match self {
                    $(Self::$variant(raw) => raw.interp(),)+
                }
            }

            #[inline]
            fn needed_len(&self) -> usize {
                match self {
                    $(Self::$variant(raw) => raw.needed_libs().len(),)+
                }
            }

            #[inline]
            fn needed_lib(&self, index: usize) -> Option<&str> {
                match self {
                    $(Self::$variant(raw) => raw.needed_libs().get(index).copied(),)+
                }
            }
        }
    };
}

builtin_arches!(
    (X86_64, X86_64Arch),
    (AArch64, AArch64Arch),
    (RiscV64, RiscV64Arch),
    (RiscV32, RiscV32Arch),
    (LoongArch64, LoongArch64Arch),
    (X86, X86Arch),
    (Arm, ArmArch),
);
