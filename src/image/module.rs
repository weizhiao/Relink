use super::{Module, Symbol};
use crate::{
    Result,
    arch::NativeArch,
    custom_error,
    elf::SymbolLookup,
    memory::VmAddr,
    relocation::RelocationArch,
    runtime::DomainId,
    sync::{Arc, AtomicUsize, Ordering, Weak, arc_unsize},
    tls::TlsResolver,
};
use alloc::vec::Vec;
use core::{any::Any, fmt, ops::Deref, slice};

const UNINITIALIZED: usize = 0;
const INITIALIZING: usize = 1;
const INITIALIZED: usize = 2;
const FAILED: usize = 3;
const FINALIZED: usize = 4;

struct InitializationGuard<'a>(&'a AtomicUsize);

impl Drop for InitializationGuard<'_> {
    fn drop(&mut self) {
        self.0.store(FAILED, Ordering::Release);
    }
}

#[inline]
pub(super) fn lookup_symbol<Arch, Tls>(
    module: &dyn Module<Arch, Tls>,
    lookup: &mut SymbolLookup<'_>,
) -> Result<Option<VmAddr>>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    let Some(symbol) = module.exports().lookup(lookup) else {
        return Ok(None);
    };
    if !symbol.is_exported() {
        return Ok(None);
    }
    module.resolve_symbol(symbol).map(Some)
}

/// Lifecycle state shared by every view of one logical module.
///
/// Module implementations store this value and return it from
/// [`Module::state`]. It coordinates initialization and finalization without
/// duplicating the ownership count already maintained by [`Arc`].
pub struct ModuleState {
    value: AtomicUsize,
}

impl ModuleState {
    /// Creates state for a module whose initializer has not run.
    #[inline]
    pub const fn new() -> Self {
        Self {
            value: AtomicUsize::new(UNINITIALIZED),
        }
    }

    /// Creates state for a module that is already initialized.
    #[inline]
    pub const fn initialized() -> Self {
        Self {
            value: AtomicUsize::new(INITIALIZED),
        }
    }

    /// Returns whether the module is currently initialized.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.value.load(Ordering::Acquire) == INITIALIZED
    }

    /// Runs the module initializer at most once.
    ///
    /// Recursive callers observe an initialization in progress as already
    /// claimed and do not run the initializer again.
    pub fn initialize(&self, initialize: impl FnOnce() -> Result<()>) -> Result<()> {
        let mut value = self.value.load(Ordering::Acquire);
        loop {
            match value {
                INITIALIZING | INITIALIZED => return Ok(()),
                FAILED => return Err(custom_error("cannot initialize a failed module")),
                FINALIZED => return Err(custom_error("cannot initialize a finalized module")),
                _ => {}
            }
            match self.value.compare_exchange_weak(
                value,
                INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let guard = InitializationGuard(&self.value);
                    let result = initialize();
                    self.value.store(
                        if result.is_ok() { INITIALIZED } else { FAILED },
                        Ordering::Release,
                    );
                    core::mem::forget(guard);
                    return result;
                }
                Err(current) => value = current,
            }
        }
    }

    /// Runs the module finalizer at most once after initialization was attempted.
    ///
    /// A module with finalization work should call this from its owning
    /// allocation's [`Drop`] implementation. For core-backed ELF modules,
    /// `CoreInner` already provides that integration.
    pub fn finalize(&self, finalize: impl FnOnce() -> Result<()>) -> Result<()> {
        let mut value = self.value.load(Ordering::Acquire);
        loop {
            match value {
                INITIALIZED | FAILED => {}
                _ => return Ok(()),
            }
            match self.value.compare_exchange_weak(
                value,
                FINALIZED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return finalize(),
                Err(current) => value = current,
            }
        }
    }
}

impl Default for ModuleState {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// One shared ownership reference to a module.
///
/// Finalization follows the lifetime of the underlying module allocation, not
/// an individual handle. Cloning or dropping a handle only changes the [`Arc`]
/// ownership count.
pub struct ModuleHandle<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    module: Arc<dyn Module<Arch, Tls>>,
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> Clone for ModuleHandle<Arch, Tls> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            module: Arc::clone(&self.module),
        }
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> ModuleHandle<Arch, Tls> {
    /// Creates the canonical shared handle for a module.
    ///
    /// Clone this handle when the same logical module is used in another scope
    /// or link context.
    #[inline]
    pub fn new<M>(module: M) -> Self
    where
        M: Module<Arch, Tls> + 'static,
    {
        Self::from_shared(arc_unsize!(Arc::new(module) => dyn Module<Arch, Tls>))
    }

    /// Wraps a shared module while preserving the state owned by that module.
    #[inline]
    pub fn from_shared(module: Arc<dyn Module<Arch, Tls>>) -> Self {
        Self { module }
    }

    /// Returns the underlying dynamic module reference.
    #[inline]
    pub fn as_dyn(&self) -> &(dyn Module<Arch, Tls> + 'static) {
        &*self.module
    }

    /// Returns whether both handles share the same logical module state.
    #[inline]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.as_dyn().state(), other.as_dyn().state())
    }

    /// Runs this module's initialization hook at most once.
    #[inline]
    pub fn initialize(&self) -> Result<()> {
        let module = self.as_dyn();
        module.state().initialize(|| module.initialize())
    }

    /// Tries to get a typed function or object exported by this module.
    ///
    /// The module performs any runtime-specific TLS or IFUNC resolution before
    /// the typed symbol is returned.
    ///
    /// # Safety
    ///
    /// `T` must match the type and ABI of the resolved symbol.
    #[inline]
    pub unsafe fn try_get<'module, T>(
        &'module self,
        name: &str,
    ) -> Result<Option<Symbol<'module, T>>> {
        let addr = lookup_symbol(self.as_dyn(), &mut SymbolLookup::new(name))?;
        Ok(addr.map(|addr| unsafe { Symbol::from_raw(addr.as_mut_ptr()) }))
    }

    /// Gets a typed function or object exported by this module.
    ///
    /// Resolution failures and missing symbols both produce `None`. Use
    /// [`ModuleHandle::try_get`] when the error must be preserved.
    ///
    /// # Safety
    ///
    /// `T` must match the type and ABI of the resolved symbol.
    #[inline]
    pub unsafe fn get<'module, T>(&'module self, name: &str) -> Option<Symbol<'module, T>> {
        unsafe { self.try_get(name).ok().flatten() }
    }

    /// Tries to get a versioned typed symbol exported by this module.
    ///
    /// # Safety
    ///
    /// `T` must match the type and ABI of the resolved symbol.
    #[cfg(feature = "version")]
    #[inline]
    pub unsafe fn try_get_version<'module, T>(
        &'module self,
        name: &str,
        version: &str,
    ) -> Result<Option<Symbol<'module, T>>> {
        let addr = lookup_symbol(
            self.as_dyn(),
            &mut SymbolLookup::with_version(name, version),
        )?;
        Ok(addr.map(|addr| unsafe { Symbol::from_raw(addr.as_mut_ptr()) }))
    }

    /// Gets a versioned typed symbol exported by this module.
    ///
    /// Resolution failures and missing symbols both produce `None`. Use
    /// [`ModuleHandle::try_get_version`] when the error must be preserved.
    ///
    /// # Safety
    ///
    /// `T` must match the type and ABI of the resolved symbol.
    #[cfg(feature = "version")]
    #[inline]
    pub unsafe fn get_version<'module, T>(
        &'module self,
        name: &str,
        version: &str,
    ) -> Option<Symbol<'module, T>> {
        unsafe { self.try_get_version(name, version).ok().flatten() }
    }

    /// Downcasts the retained module to a concrete type.
    #[inline]
    pub fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: Module<Arch, Tls> + 'static,
    {
        let module = self.as_dyn() as &dyn Any;
        module
            .downcast_ref::<T>()
            .or_else(|| module.downcast_ref::<Arc<T>>().map(|module| &**module))
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> Deref for ModuleHandle<Arch, Tls> {
    type Target = dyn Module<Arch, Tls>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_dyn()
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> AsRef<dyn Module<Arch, Tls>>
    for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn as_ref(&self) -> &(dyn Module<Arch, Tls> + 'static) {
        self.as_dyn()
    }
}

/// Copy-on-write ordered modules used for relocation symbol lookup.
///
/// Modules are searched in order and held alive by relocated outputs that keep
/// this scope. Clones remain stable when another clone is modified.
pub struct ModuleScope<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    modules: Arc<Vec<ModuleHandle<Arch, Tls>>>,
    domain: DomainId,
}

/// Ordered groups used for symbol lookup.
///
/// Groups preserve lookup-policy boundaries such as the global scope and one
/// object's dependency scope without copying their module lists.
pub struct LookupScope<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    groups: Arc<[ModuleScope<Arch, Tls>]>,
    domain: DomainId,
}

/// Weak reference to a retained lookup scope.
pub(crate) struct WeakLookupScope<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    groups: Weak<[ModuleScope<Arch, Tls>]>,
    domain: DomainId,
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> Clone for ModuleScope<Arch, Tls> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            modules: Arc::clone(&self.modules),
            domain: self.domain,
        }
    }
}

impl<Arch, Tls> fmt::Debug for ModuleScope<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.modules.iter().map(|module| module.name()))
            .finish()
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> ModuleScope<Arch, Tls> {
    /// Creates an empty module scope for `domain`.
    #[inline]
    pub fn new(domain: DomainId) -> Self {
        Self {
            modules: Arc::new(Vec::new()),
            domain,
        }
    }

    /// Returns the runtime domain shared by this module group.
    #[inline]
    pub const fn domain_id(&self) -> DomainId {
        self.domain
    }

    /// Checks that this scope and all its modules belong to `expected`.
    pub fn check_domain(&self, expected: DomainId) -> Result<()> {
        expected.ensure(self.domain)?;
        for module in self.modules.iter() {
            expected.ensure(module.domain_id())?;
        }
        Ok(())
    }

    /// Returns the modules in lookup order.
    #[inline]
    pub fn as_slice(&self) -> &[ModuleHandle<Arch, Tls>] {
        &self.modules
    }

    /// Iterates over modules in lookup order.
    #[inline]
    pub fn iter(&self) -> slice::Iter<'_, ModuleHandle<Arch, Tls>> {
        self.modules.iter()
    }

    /// Returns the number of modules in this scope.
    #[inline]
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Returns whether the scope contains no modules.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Appends a module without modifying existing snapshots.
    pub fn push(&mut self, module: ModuleHandle<Arch, Tls>) {
        Arc::make_mut(&mut self.modules).push(module);
    }

    /// Replaces this scope's modules without modifying existing snapshots.
    pub fn replace<I, R>(&mut self, modules: I)
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        if let Some(current) = Arc::get_mut(&mut self.modules) {
            current.clear();
            current.extend(modules.into_iter().map(Into::into));
        } else {
            self.modules = Arc::new(modules.into_iter().map(Into::into).collect());
        }
    }

    /// Appends modules without modifying existing snapshots.
    pub fn extend<I, R>(&mut self, modules: I)
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        Arc::make_mut(&mut self.modules).extend(modules.into_iter().map(Into::into));
    }

    /// Retains only modules accepted by `keep` without modifying existing snapshots.
    pub fn retain(&mut self, keep: impl FnMut(&ModuleHandle<Arch, Tls>) -> bool) {
        Arc::make_mut(&mut self.modules).retain(keep);
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> Clone for LookupScope<Arch, Tls> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            groups: Arc::clone(&self.groups),
            domain: self.domain,
        }
    }
}

impl<Arch, Tls> fmt::Debug for LookupScope<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.groups.iter()).finish()
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> LookupScope<Arch, Tls> {
    /// Creates an empty lookup scope for `domain`.
    #[inline]
    pub fn empty(domain: DomainId) -> Self {
        Self {
            groups: Arc::from([]),
            domain,
        }
    }

    /// Creates a lookup scope containing one module group.
    #[inline]
    pub fn from_group(group: ModuleScope<Arch, Tls>) -> Self {
        Self {
            domain: group.domain,
            groups: Arc::from([group]),
        }
    }

    /// Combines retained module groups in lookup order.
    pub fn from_groups<I>(domain: DomainId, groups: I) -> Self
    where
        I: IntoIterator<Item = ModuleScope<Arch, Tls>>,
    {
        Self {
            groups: Arc::from(groups.into_iter().collect::<Vec<_>>()),
            domain,
        }
    }

    #[inline]
    /// Checks that every group and module belongs to `expected`.
    pub fn check_domain(&self, expected: DomainId) -> Result<()> {
        expected.ensure(self.domain)?;
        for group in self.groups.iter() {
            group.check_domain(expected)?;
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn downgrade(&self) -> WeakLookupScope<Arch, Tls> {
        WeakLookupScope {
            groups: Arc::downgrade(&self.groups),
            domain: self.domain,
        }
    }

    /// Returns module groups in lookup order.
    #[inline]
    pub fn groups(&self) -> &[ModuleScope<Arch, Tls>] {
        &self.groups
    }

    /// Iterates over modules in lookup order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &ModuleHandle<Arch, Tls>> {
        self.groups.iter().flat_map(ModuleScope::iter)
    }

    /// Returns the total number of module entries in all groups.
    #[inline]
    pub fn len(&self) -> usize {
        self.groups.iter().map(ModuleScope::len).sum()
    }

    /// Returns whether every module group is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.groups.iter().all(ModuleScope::is_empty)
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> WeakLookupScope<Arch, Tls> {
    #[inline]
    pub(crate) fn upgrade(&self) -> Option<LookupScope<Arch, Tls>> {
        self.groups.upgrade().map(|groups| LookupScope {
            groups,
            domain: self.domain,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::image::SyntheticModule;

    #[test]
    fn shared_module_preserves_identity() {
        let module = Arc::new(SyntheticModule::<NativeArch>::empty("shared"));
        let first: ModuleHandle = ModuleHandle::new(module.clone());
        let second: ModuleHandle = ModuleHandle::new(module);

        assert!(first.ptr_eq(&second));
    }

    #[test]
    fn module_scope_mutation_preserves_snapshots() {
        let first: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty("first"));
        let second: ModuleHandle =
            ModuleHandle::new(SyntheticModule::<NativeArch>::empty("second"));
        let mut scope: ModuleScope = ModuleScope::new(DomainId::PROCESS);
        scope.push(first);
        let snapshot = scope.clone();

        scope.push(second);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(scope.len(), 2);

        scope.retain(|module| module.name() == "second");
        assert_eq!(snapshot.iter().next().unwrap().name(), "first");
        assert_eq!(scope.iter().next().unwrap().name(), "second");
    }

    #[test]
    fn initializer_panic_marks_module_failed() {
        let state = ModuleState::new();
        let panic = std::panic::catch_unwind(|| {
            let _ = state.initialize(|| -> crate::Result<()> { panic!("initializer panic") });
        });

        assert!(panic.is_err());
        assert!(!state.is_initialized());
        assert!(state.initialize(|| Ok(())).is_err());
    }
}
