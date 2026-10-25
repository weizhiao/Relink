use super::{
    ExportTable, Symbol,
    module::{ModuleState, lookup_symbol},
};
use crate::{
    Result,
    arch::NativeArch,
    elf::{ElfSymbol, SymbolLookup},
    memory::{ImageMemory, VmAddr},
    relocation::RelocationArch,
    sync::Arc,
    tls::TlsModule,
};
use core::any::Any;

use super::search::ModuleSearch;

/// A loaded or synthetic module that supplies symbols for relocation.
///
/// Implementations retain their TLS runtime and expose their domain through
/// [`Self::state`], which scopes use to check compatibility.
pub trait Module<Arch: RelocationArch = NativeArch>: Any + Send + Sync {
    /// Returns the module name used for diagnostics.
    fn name(&self) -> &[u8];

    /// Returns metadata used when this module initiates another load.
    fn search(&self) -> Option<&ModuleSearch> {
        None
    }

    /// Returns this module's runtime exports. The table must remain stable
    /// while borrowed, since relocation may retain it for the entire pass.
    fn exports(&self) -> &ExportTable<Arch::Layout>;

    /// Returns this module's runtime memory view.
    fn memory(&self) -> &dyn ImageMemory;

    /// Resolves one of this module's exported symbols to its runtime address.
    ///
    /// `symbol` must describe a definition exposed by this module's
    /// [`ExportTable`]. Implementations define how ordinary, absolute, TLS,
    /// IFUNC, and module-specific symbols become target-visible addresses.
    fn resolve_symbol(&self, symbol: &ElfSymbol<Arch::Layout>) -> Result<VmAddr>;

    /// Returns the registration used for TLS relocation and current-thread lookup.
    /// The registration must belong to the domain in `state()`. Implementations
    /// must keep it and its runtime valid for all module uses;
    /// the returned metadata does not own or retain the registration.
    fn tls(&self) -> Option<&TlsModule> {
        None
    }

    /// Returns this module's identity, domain, and lifecycle state.
    /// All wrappers of the same module must return the same stable state address.
    fn state(&self) -> &ModuleState;

    /// Performs this module's initialization hook.
    ///
    /// Relink invokes this through [`ModuleHandle`](super::ModuleHandle), which
    /// guarantees that the hook runs at most once.
    fn initialize(&self) -> Result<()> {
        Ok(())
    }

    /// Performs this module's finalization hook.
    ///
    /// The module's owning allocation should invoke this through
    /// [`ModuleState::finalize`] from its `Drop` implementation. Core-backed ELF
    /// modules already do this in `ElfModule`.
    fn finalize(&self) -> Result<()> {
        Ok(())
    }
}

impl<Arch> dyn Module<Arch>
where
    Arch: RelocationArch,
{
    /// Downcasts this borrowed module to a concrete implementation.
    #[inline]
    pub fn downcast_ref<M>(&self) -> Option<&M>
    where
        M: Module<Arch> + 'static,
    {
        (self as &dyn Any).downcast_ref()
    }

    /// Returns whether two borrowed views refer to the same logical module.
    #[inline]
    pub fn ptr_eq(&self, other: &dyn Module<Arch>) -> bool {
        core::ptr::eq(self.state(), other.state())
    }

    /// Tries to resolve a typed symbol while this module remains borrowed.
    ///
    /// Names are raw bytes or strings and must not contain NUL bytes;
    /// this is not checked.
    ///
    /// # Safety
    ///
    /// `T` must match the symbol's type and calling convention. A TLS address may
    /// only be used in the resolving thread while its module and thread are alive.
    #[inline]
    pub unsafe fn get<T>(&self, name: impl AsRef<[u8]>) -> Result<Option<Symbol<'_, T>>> {
        let addr = lookup_symbol(self, &mut SymbolLookup::new(name.as_ref()))?;
        Ok(addr.map(|addr| unsafe { Symbol::from_raw(addr.as_mut_ptr()) }))
    }

    /// Tries to resolve a versioned typed symbol while this module remains borrowed.
    ///
    /// Names must not contain NUL bytes; this is not checked.
    /// Versions are raw bytes without a trailing NUL.
    ///
    /// # Safety
    ///
    /// `T` must match the symbol's type and calling convention. A TLS address may
    /// only be used in the resolving thread while its module and thread are alive.
    #[cfg(feature = "version")]
    #[inline]
    pub unsafe fn get_version<T>(
        &self,
        name: impl AsRef<[u8]>,
        version: impl AsRef<[u8]>,
    ) -> Result<Option<Symbol<'_, T>>> {
        let addr = lookup_symbol(
            self,
            &mut SymbolLookup::with_version(name.as_ref(), version.as_ref()),
        )?;
        Ok(addr.map(|addr| unsafe { Symbol::from_raw(addr.as_mut_ptr()) }))
    }
}

impl<M, Arch> Module<Arch> for Arc<M>
where
    M: Module<Arch> + ?Sized + 'static,
    Arch: RelocationArch,
{
    #[inline]
    fn name(&self) -> &[u8] {
        (**self).name()
    }

    #[inline]
    fn search(&self) -> Option<&ModuleSearch> {
        (**self).search()
    }

    #[inline]
    fn exports(&self) -> &ExportTable<Arch::Layout> {
        (**self).exports()
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        (**self).memory()
    }

    #[inline]
    fn resolve_symbol(&self, symbol: &ElfSymbol<Arch::Layout>) -> Result<VmAddr> {
        (**self).resolve_symbol(symbol)
    }

    #[inline]
    fn tls(&self) -> Option<&TlsModule> {
        (**self).tls()
    }

    #[inline]
    fn state(&self) -> &ModuleState {
        (**self).state()
    }

    #[inline]
    fn initialize(&self) -> Result<()> {
        (**self).initialize()
    }

    #[inline]
    fn finalize(&self) -> Result<()> {
        (**self).finalize()
    }
}
