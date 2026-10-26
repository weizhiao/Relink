use super::Module;
use crate::{
    Result,
    arch::NativeArch,
    custom_error,
    elf::SymbolLookup,
    input::ModuleSourceId,
    memory::VmAddr,
    relocation::RelocationArch,
    runtime::{AddressSpaceId, Domain, DomainId},
    sync::{Arc, AtomicU8, AtomicUsize, Ordering, Weak, arc_unsize},
};
use alloc::vec::Vec;
use core::{fmt, num::NonZeroUsize, ops::Deref};
use spin::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

const UNINITIALIZED: u8 = 0;
const INITIALIZING: u8 = 1;
const INITIALIZED: u8 = 2;
const FAILED: u8 = 3;
const FINALIZED: u8 = 4;

static NEXT_INSTANCE: AtomicUsize = AtomicUsize::new(1);

#[inline]
fn next_instance() -> NonZeroUsize {
    #[allow(deprecated)]
    let instance = NEXT_INSTANCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .expect("module instance identity space is exhausted");
    // The counter starts at one and checked increment never wraps through zero.
    NonZeroUsize::new(instance).expect("module instance identity must be nonzero")
}

struct InitializationGuard<'a>(&'a AtomicU8);

impl Drop for InitializationGuard<'_> {
    fn drop(&mut self) {
        // A panic must not leave the module permanently stuck in INITIALIZING.
        self.0.store(FAILED, Ordering::Release);
    }
}

#[inline]
pub(super) fn lookup_symbol<Arch>(
    module: &dyn Module<Arch>,
    lookup: &mut SymbolLookup<'_>,
) -> Result<Option<VmAddr>>
where
    Arch: RelocationArch,
{
    let Some(symbol) = module.exports().lookup(lookup) else {
        return Ok(None);
    };
    if !symbol.is_exported() {
        return Ok(None);
    }
    module.resolve_symbol(symbol).map(Some)
}

/// Tracks a module's identity, domain, lifecycle, and runtime bindings.
/// Module implementations store this state and expose it through [`Module::state`].
pub struct ModuleState {
    id: ModuleInstanceId,
    domain: DomainId,
    phase: AtomicU8,
    // Relocation facts follow this concrete module across context imports.
    // Context-specific pin counts remain owned by LinkContext.
    effects: Mutex<ModuleEffects>,
}

#[derive(Default)]
struct ModuleEffects {
    bindings: Vec<ModuleInstanceId>,
    pins: Vec<ModuleInstanceId>,
}

/// Non-owning identity of one loaded module instance.
///
/// Unlike [`ModuleSourceId`], this value changes when the same source is
/// unloaded and loaded again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleInstanceId {
    source: ModuleSourceId,
    instance: NonZeroUsize,
}

impl ModuleInstanceId {
    #[inline]
    fn new(source: ModuleSourceId) -> Self {
        Self {
            source,
            instance: next_instance(),
        }
    }

    /// Returns the stable identity of the source backing this instance.
    #[inline]
    pub const fn source_id(self) -> ModuleSourceId {
        self.source
    }
}

impl ModuleState {
    /// Creates state for a module whose initializer has not run.
    #[inline]
    pub fn new(source: ModuleSourceId, domain: DomainId) -> Self {
        Self {
            id: ModuleInstanceId::new(source),
            domain,
            phase: AtomicU8::new(UNINITIALIZED),
            effects: Mutex::new(ModuleEffects::default()),
        }
    }

    /// Creates state for a module that is already initialized.
    #[inline]
    pub fn initialized(source: ModuleSourceId, domain: DomainId) -> Self {
        Self {
            id: ModuleInstanceId::new(source),
            domain,
            phase: AtomicU8::new(INITIALIZED),
            effects: Mutex::new(ModuleEffects::default()),
        }
    }

    /// Returns the identity of this particular loaded module instance.
    #[inline]
    pub const fn instance_id(&self) -> ModuleInstanceId {
        self.id
    }

    /// Returns the complete runtime domain identity.
    #[inline]
    pub const fn domain_id(&self) -> DomainId {
        self.domain
    }

    #[inline]
    pub(crate) fn with_effects<T>(
        &self,
        f: impl FnOnce(&[ModuleInstanceId], &[ModuleInstanceId]) -> T,
    ) -> T {
        let effects = self.effects.lock();
        f(&effects.bindings, &effects.pins)
    }

    pub(crate) fn install_effects(
        &self,
        bindings: impl IntoIterator<Item = ModuleInstanceId>,
        pins: impl IntoIterator<Item = ModuleInstanceId>,
    ) {
        let mut effects = self.effects.lock();
        for binding in bindings {
            if binding != self.id && !effects.bindings.contains(&binding) {
                effects.bindings.push(binding);
            }
        }
        for pin in pins {
            if !effects.pins.contains(&pin) {
                effects.pins.push(pin);
            }
        }
    }

    /// Records that this module must remain committed once publication succeeds.
    #[inline]
    pub(crate) fn pin_self(&self) {
        self.install_effects([], [self.id]);
    }

    /// Returns whether the module is currently initialized.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.phase.load(Ordering::Acquire) == INITIALIZED
    }

    /// Runs the module initializer at most once.
    ///
    /// Recursive callers observe an initialization in progress as already
    /// claimed and do not run the initializer again. If the callback returns
    /// an error or unwinds, the state becomes permanently failed.
    pub fn initialize(&self, initialize: impl FnOnce() -> Result<()>) -> Result<()> {
        let mut phase = self.phase.load(Ordering::Acquire);
        loop {
            match phase {
                INITIALIZING | INITIALIZED => return Ok(()),
                FAILED => return Err(custom_error("cannot initialize a failed module")),
                FINALIZED => return Err(custom_error("cannot initialize a finalized module")),
                _ => {}
            }
            match self.phase.compare_exchange_weak(
                phase,
                INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // The guard covers unwinding; the explicit store below
                    // records the callback's normal return value.
                    let guard = InitializationGuard(&self.phase);
                    let result = initialize();
                    self.phase.store(
                        if result.is_ok() { INITIALIZED } else { FAILED },
                        Ordering::Release,
                    );
                    core::mem::forget(guard);
                    return result;
                }
                Err(current) => phase = current,
            }
        }
    }

    /// Runs the finalizer at most once after initialization was attempted.
    ///
    /// Call this from the module owner's [`Drop`] implementation; `ElfModule`
    /// already does so. Calls before initialization or after finalization is
    /// claimed do nothing.
    pub fn finalize(&self, finalize: impl FnOnce() -> Result<()>) -> Result<()> {
        let mut phase = self.phase.load(Ordering::Acquire);
        loop {
            match phase {
                INITIALIZED | FAILED => {}
                _ => return Ok(()),
            }
            match self.phase.compare_exchange_weak(
                phase,
                FINALIZED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return finalize(),
                Err(current) => phase = current,
            }
        }
    }
}

impl Default for ModuleState {
    #[inline]
    fn default() -> Self {
        Self::new(
            ModuleSourceId::fresh(),
            Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id(),
        )
    }
}

/// A shared module handle.
/// Clones keep the same module alive; finalization occurs when its owner is dropped.
pub struct ModuleHandle<Arch: RelocationArch = NativeArch> {
    module: Arc<dyn Module<Arch>>,
}

impl<Arch: RelocationArch> Clone for ModuleHandle<Arch> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            module: Arc::clone(&self.module),
        }
    }
}

impl<Arch: RelocationArch> ModuleHandle<Arch> {
    /// Creates the canonical shared handle for a module.
    ///
    /// Clone this handle when the same logical module is used in another scope
    /// or link context.
    #[inline]
    pub fn new<M>(module: M) -> Self
    where
        M: Module<Arch> + 'static,
    {
        Self::from_shared(arc_unsize!(Arc::new(module) => dyn Module<Arch>))
    }

    /// Wraps a shared module while preserving the state owned by that module.
    #[inline]
    pub fn from_shared(module: Arc<dyn Module<Arch>>) -> Self {
        Self { module }
    }

    #[inline]
    pub(crate) fn downgrade(&self) -> Weak<dyn Module<Arch>> {
        Arc::downgrade(&self.module)
    }

    /// Returns the stable identity of the source backing this module.
    #[inline]
    pub fn source_id(&self) -> ModuleSourceId {
        self.module.state().instance_id().source_id()
    }

    /// Returns the runtime domain in which this module's addresses are meaningful.
    #[inline]
    pub fn domain_id(&self) -> DomainId {
        self.module.state().domain_id()
    }

    /// Runs this module's initialization hook at most once.
    #[inline]
    pub fn initialize(&self) -> Result<()> {
        let module = &*self.module;
        module.state().initialize(|| module.initialize())
    }
}

impl<Arch: RelocationArch> Deref for ModuleHandle<Arch> {
    type Target = dyn Module<Arch>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &*self.module
    }
}

impl<Arch: RelocationArch> AsRef<dyn Module<Arch>> for ModuleHandle<Arch> {
    #[inline]
    fn as_ref(&self) -> &(dyn Module<Arch> + 'static) {
        &*self.module
    }
}

/// An ordered list of modules for symbol lookup that keeps its modules alive.
///
/// Changes to a clone do not affect other copies. Added modules must match the
/// scope's [`DomainId`]. Dereferences to a read-only module slice.
pub struct ModuleScope<Arch: RelocationArch = NativeArch> {
    modules: Arc<Vec<ModuleHandle<Arch>>>,
    domain: DomainId,
}

/// Local symbol scopes for immediate relocation and lazy binding.
/// Linker-managed images normally use their dependency closure for lazy binding.
pub struct LocalScope<Arch: RelocationArch = NativeArch> {
    groups: Arc<[ModuleScope<Arch>]>,
    lazy: ModuleScope<Arch>,
}

/// Weak references to the local and global scopes used by lazy binding.
/// The linker's local scope is the requesting module's dependency closure.
pub(crate) struct WeakLocalScope<Arch: RelocationArch = NativeArch> {
    local: Weak<Vec<ModuleHandle<Arch>>>,
    global: Option<Weak<GlobalScopeInner<Arch>>>,
    domain: DomainId,
}

/// Shared live global lookup order owned by a [`LinkContext`](crate::LinkContext).
///
/// Clones refer to the same global scope. Use
/// [`LinkContext::promote_global`](crate::LinkContext::promote_global) or
/// [`LinkContext::extend_global`](crate::LinkContext::extend_global) to change
/// its contents without bypassing the context's lifetime bookkeeping.
pub struct GlobalScope<Arch: RelocationArch = NativeArch> {
    inner: Arc<GlobalScopeInner<Arch>>,
}

struct GlobalScopeInner<Arch: RelocationArch> {
    modules: RwLock<ModuleScope<Arch>>,
    domain: DomainId,
}

impl<Arch: RelocationArch> Clone for ModuleScope<Arch> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            modules: Arc::clone(&self.modules),
            domain: self.domain,
        }
    }
}

impl<Arch> fmt::Debug for ModuleScope<Arch>
where
    Arch: RelocationArch,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.modules.iter().map(|module| module.name()))
            .finish()
    }
}

impl<Arch: RelocationArch> Deref for ModuleScope<Arch> {
    type Target = [ModuleHandle<Arch>];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.modules
    }
}

impl<Arch: RelocationArch> ModuleScope<Arch> {
    /// Creates an empty scope bound to a fixed runtime domain.
    pub fn new(domain: DomainId) -> Self {
        Self {
            modules: Arc::new(Vec::new()),
            domain,
        }
    }

    /// Returns the complete runtime domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain
    }

    /// Checks compatibility without revisiting modules already admitted here.
    pub(crate) fn check_scope(&self, other: &Self) -> Result<()> {
        self.domain.ensure(other.domain)
    }

    fn check_module(&self, module: &ModuleHandle<Arch>) -> Result<()> {
        self.domain.ensure(module.domain_id())
    }

    // Only context/session records that have already passed admission use this.
    pub(crate) fn push_admitted(&mut self, module: ModuleHandle<Arch>) {
        Arc::make_mut(&mut self.modules).push(module);
    }

    /// Admits a module without modifying existing snapshots.
    pub fn push(&mut self, module: ModuleHandle<Arch>) -> Result<()> {
        self.check_module(&module)?;
        self.push_admitted(module);
        Ok(())
    }

    /// Replaces the scope atomically after admitting every supplied module.
    pub fn replace<I, R>(&mut self, modules: I) -> Result<()>
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch>>,
    {
        let modules = modules.into_iter().map(Into::into).collect::<Vec<_>>();
        for module in &modules {
            self.check_module(module)?;
        }
        self.modules = Arc::new(modules);
        Ok(())
    }

    /// Appends modules atomically after admitting every supplied module.
    pub fn extend<I, R>(&mut self, modules: I) -> Result<()>
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch>>,
    {
        let modules = modules.into_iter().map(Into::into).collect::<Vec<_>>();
        for module in &modules {
            self.check_module(module)?;
        }
        Arc::make_mut(&mut self.modules).extend(modules);
        Ok(())
    }

    /// Retains only modules accepted by `keep` without modifying existing snapshots.
    pub fn retain(&mut self, keep: impl FnMut(&ModuleHandle<Arch>) -> bool) {
        Arc::make_mut(&mut self.modules).retain(keep);
    }
}

impl<Arch: RelocationArch> Clone for LocalScope<Arch> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            groups: Arc::clone(&self.groups),
            lazy: self.lazy.clone(),
        }
    }
}

impl<Arch: RelocationArch> Clone for GlobalScope<Arch> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<Arch> fmt::Debug for LocalScope<Arch>
where
    Arch: RelocationArch,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalScope")
            .field("groups", &self.groups)
            .field("lazy", &self.lazy)
            .finish()
    }
}

impl<Arch: RelocationArch> LocalScope<Arch> {
    /// Creates an empty local scope bound to a fixed runtime.
    pub fn empty(domain: DomainId) -> Self {
        Self {
            groups: Arc::from([]),
            lazy: ModuleScope::new(domain),
        }
    }

    /// Uses one admitted group for both eager and deferred lookup.
    pub fn from_group(group: ModuleScope<Arch>) -> Self {
        Self {
            groups: Arc::from([group.clone()]),
            lazy: group,
        }
    }

    /// Combines compatible eager groups and a deferred scope.
    pub fn new<I>(groups: I, lazy: ModuleScope<Arch>) -> Result<Self>
    where
        I: IntoIterator<Item = ModuleScope<Arch>>,
    {
        let groups = groups.into_iter().collect::<Arc<[_]>>();
        for group in groups.iter() {
            lazy.check_scope(group)?;
        }
        Ok(Self { groups, lazy })
    }

    /// Returns the complete runtime domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.lazy.domain_id()
    }

    pub(crate) fn check_scope(&self, other: &Self) -> Result<()> {
        self.lazy.check_scope(&other.lazy)
    }

    #[inline]
    pub(crate) fn downgrade(&self, global: Option<&GlobalScope<Arch>>) -> WeakLocalScope<Arch> {
        let domain = self.domain_id();
        debug_assert!(global.is_none_or(|global| global.domain_id() == domain));
        WeakLocalScope {
            local: Arc::downgrade(&self.lazy.modules),
            global: global.map(GlobalScope::downgrade),
            domain: self.lazy.domain,
        }
    }

    /// Returns the eager module groups in lookup order.
    #[inline]
    pub fn groups(&self) -> &[ModuleScope<Arch>] {
        &self.groups
    }

    /// Returns the local scope retained for deferred PLT lookup.
    #[inline]
    pub const fn lazy_scope(&self) -> &ModuleScope<Arch> {
        &self.lazy
    }

    /// Appends a compatible eager group without changing deferred lookup.
    pub fn push_eager(&mut self, group: ModuleScope<Arch>) -> Result<()> {
        self.extend_eager([group])
    }

    /// Appends compatible eager groups atomically.
    pub fn extend_eager<I>(&mut self, groups: I) -> Result<()>
    where
        I: IntoIterator<Item = ModuleScope<Arch>>,
    {
        let groups = groups.into_iter().collect::<Vec<_>>();
        for group in &groups {
            self.lazy.check_scope(group)?;
        }
        let mut current = self.groups.to_vec();
        current.extend(groups);
        self.groups = Arc::from(current);
        Ok(())
    }

    /// Iterates over eager lookup modules in order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &ModuleHandle<Arch>> {
        self.groups.iter().flat_map(|group| group.iter())
    }

    /// Returns the number of eager lookup entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.groups.iter().map(|group| group.len()).sum()
    }

    /// Returns whether the eager lookup scope is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.groups.iter().all(|group| group.is_empty())
    }

    /// Replaces the local scope retained for deferred PLT lookup.
    #[inline]
    pub fn set_lazy_scope(&mut self, scope: ModuleScope<Arch>) -> Result<()> {
        self.lazy.check_scope(&scope)?;
        self.lazy = scope;
        Ok(())
    }
}

impl<Arch: RelocationArch> WeakLocalScope<Arch> {
    #[inline]
    pub(crate) fn upgrade_local(&self) -> Option<LocalScope<Arch>> {
        let scope = ModuleScope {
            modules: self.local.upgrade()?,
            domain: self.domain,
        };
        Some(LocalScope::from_group(scope))
    }

    #[inline]
    pub(crate) fn upgrade_global(&self) -> Option<GlobalScope<Arch>> {
        self.global
            .as_ref()
            .and_then(Weak::upgrade)
            .map(|inner| GlobalScope { inner })
    }
}

impl<Arch: RelocationArch> GlobalScope<Arch> {
    #[inline]
    pub(crate) fn new(domain: DomainId) -> Self {
        Self {
            inner: Arc::new(GlobalScopeInner {
                modules: RwLock::new(ModuleScope::new(domain)),
                domain,
            }),
        }
    }

    #[inline]
    /// Returns the runtime domain shared by modules in this scope.
    pub fn domain_id(&self) -> DomainId {
        self.inner.domain
    }

    pub(crate) fn check_scope(&self, scope: &LocalScope<Arch>) -> Result<()> {
        self.inner.domain.ensure(scope.domain_id())
    }

    #[inline]
    fn downgrade(&self) -> Weak<GlobalScopeInner<Arch>> {
        Arc::downgrade(&self.inner)
    }

    #[inline]
    /// Captures the current global lookup order.
    ///
    /// The returned copy-on-write scope remains stable if the context later
    /// promotes or unloads modules.
    pub fn modules(&self) -> ModuleScope<Arch> {
        self.read().clone()
    }

    #[inline]
    pub(crate) fn read(&self) -> RwLockReadGuard<'_, ModuleScope<Arch>> {
        self.inner.modules.read()
    }

    #[inline]
    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, ModuleScope<Arch>> {
        self.inner.modules.write()
    }
}

#[cfg(test)]
mod tests {
    use crate::tls::TlsResolver;
    extern crate std;

    use super::*;
    use crate::image::SyntheticModule;

    #[test]
    fn shared_module_preserves_identity() {
        let module = Arc::new(SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "shared",
        ));
        let first: ModuleHandle = ModuleHandle::new(module.clone());
        let second: ModuleHandle = ModuleHandle::new(module);

        assert!(first.as_ref().ptr_eq(second.as_ref()));
    }

    #[test]
    fn scope_admission_preserves_runtime_and_snapshots() {
        use crate::tls::{
            TlsBinding, TlsInfo, TlsModule, TlsModuleId, TlsRegistration, TlsRequest, TlsTemplate,
        };

        #[derive(Clone)]
        struct Resolver(usize);
        impl TlsResolver<NativeArch> for Resolver {
            fn register(&self, _: TlsInfo, _: TlsRequest) -> Result<TlsRegistration> {
                // This metadata-only registration never resolves storage.
                let entry = self.bind_tls_get_addr()?;
                Ok(unsafe {
                    TlsRegistration::new(
                        TlsModule::new(TlsBinding::new(TlsModuleId::new(1), None), entry),
                        || {},
                    )
                })
            }
            fn publish(&self, _: TlsTemplate, _: TlsModuleId) -> Result<()> {
                Ok(())
            }
            fn unregister(&self, _: TlsModuleId) {}
            fn bind_tls_get_addr(&self) -> Result<VmAddr> {
                Ok(VmAddr::new(self.0))
            }
        }
        let first = Resolver(0x1000);
        let second = Resolver(0x2000);
        let foreign: ModuleHandle<NativeArch> = ModuleHandle::new(
            SyntheticModule::<NativeArch>::empty(
                &Domain::native(AddressSpaceId::PROCESS)
                    .with_tls(second.clone())
                    .unwrap(),
                "foreign",
            )
            .with_tls(
                second
                    .register(TlsInfo::default(), TlsRequest::Dynamic)
                    .unwrap(),
            )
            .unwrap(),
        );
        let domain = Domain::native(AddressSpaceId::PROCESS)
            .with_tls(first)
            .unwrap();
        let mut group = ModuleScope::new(domain.id());
        group
            .push(ModuleHandle::new(SyntheticModule::<NativeArch>::empty(
                &domain, "retained",
            )))
            .unwrap();
        let snapshot = group.clone();

        let error = group
            .extend([
                ModuleHandle::new(SyntheticModule::<NativeArch>::empty(&domain, "extra")),
                foreign.clone(),
            ])
            .unwrap_err();
        assert!(matches!(error, crate::Error::DomainMismatch(_)));
        assert_eq!(group.len(), 1);
        assert!(group.replace([foreign.clone()]).is_err());
        assert!(group.push(foreign).is_err());
        assert_eq!(group[0].name(), b"retained");
        assert_eq!(snapshot[0].name(), b"retained");

        // An empty group still carries a runtime identity: later additions must not
        // change which namespace a composed or live global scope accepts.
        let foreign = ModuleScope::new(
            Domain::native(AddressSpaceId::PROCESS)
                .with_tls(second.clone())
                .unwrap()
                .id(),
        );
        assert!(LocalScope::new([foreign.clone()], group.clone()).is_err());
        let mut local = LocalScope::from_group(group.clone());
        assert!(local.extend_eager([group, foreign.clone()]).is_err());
        assert_eq!(local.groups().len(), 1);
        assert!(local.set_lazy_scope(foreign.clone()).is_err());
        assert!(local.push_eager(foreign).is_err());
        assert_eq!(local.lazy_scope()[0].name(), b"retained");
        let global = GlobalScope::new(
            Domain::native(AddressSpaceId::PROCESS)
                .with_tls(second)
                .unwrap()
                .id(),
        );
        assert!(global.check_scope(&local).is_err());
    }

    #[test]
    fn module_scope_mutation_preserves_snapshots() {
        let first: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "first",
        ));
        let second: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "second",
        ));
        let mut scope: ModuleScope =
            ModuleScope::new(Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id());
        scope.push(first).unwrap();
        let snapshot = scope.clone();

        scope.push(second).unwrap();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(scope.len(), 2);

        scope.retain(|module| module.name() == b"second");
        assert_eq!(snapshot.iter().next().unwrap().name(), b"first");
        assert_eq!(scope.iter().next().unwrap().name(), b"second");
    }

    #[test]
    fn local_scope_retains_modules_and_tracks_live_global() {
        let first: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "first",
        ));
        let second: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "second",
        ));
        let local: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "local",
        ));
        let global = GlobalScope::new(Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id());
        global.write().push(first).unwrap();
        let prepared = global.modules();

        let mut local_scope =
            ModuleScope::new(Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id());
        local_scope.push(local).unwrap();
        let scope = LocalScope::from_group(local_scope);
        let weak = scope.downgrade(Some(&global));

        global.write().replace([second]).unwrap();
        assert_eq!(
            prepared
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["first".as_bytes()]
        );
        assert_eq!(
            weak.upgrade_local()
                .unwrap()
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["local".as_bytes()]
        );

        let deferred = weak.upgrade_local().unwrap();
        let live = weak.upgrade_global().unwrap();
        assert_eq!(
            live.modules()
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["second".as_bytes()]
        );
        assert_eq!(
            deferred
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["local".as_bytes()]
        );

        drop(live);
        drop(global);
        let deferred = weak.upgrade_local().unwrap();
        assert!(weak.upgrade_global().is_none());
        assert_eq!(
            deferred
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["local".as_bytes()]
        );
        assert_eq!(
            scope.iter().map(|module| module.name()).collect::<Vec<_>>(),
            ["local".as_bytes()]
        );
    }

    #[test]
    fn deferred_scope_uses_retained_dependencies() {
        let root: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "root",
        ));
        let dependency: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "dependency",
        ));
        let unrelated: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "unrelated",
        ));
        let mut group =
            ModuleScope::new(Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id());
        group.extend([root, dependency.clone()]).unwrap();
        let mut retained =
            ModuleScope::new(Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id());
        retained.push(dependency).unwrap();
        let owner = retained.clone();
        let mut scope = LocalScope::new([group], retained).unwrap();
        let mut extra =
            ModuleScope::new(Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id());
        extra.push(unrelated).unwrap();
        scope.push_eager(extra).unwrap();
        let weak = scope.downgrade(None);

        assert_eq!(
            scope.iter().map(|module| module.name()).collect::<Vec<_>>(),
            [
                "root".as_bytes(),
                "dependency".as_bytes(),
                "unrelated".as_bytes()
            ]
        );
        assert_eq!(
            scope
                .lazy_scope()
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["dependency".as_bytes()]
        );
        assert_eq!(
            weak.upgrade_local()
                .unwrap()
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["dependency".as_bytes()]
        );

        drop(scope);
        drop(owner);
        assert!(weak.upgrade_local().is_none());
    }

    #[test]
    fn initializer_panic_marks_module_failed() {
        let state = ModuleState::new(
            ModuleSourceId::fresh(),
            Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id(),
        );
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = state.initialize(|| -> crate::Result<()> { panic!("initializer panic") });
        }));

        assert!(panic.is_err());
        assert!(!state.is_initialized());
        assert!(state.initialize(|| Ok(())).is_err());
    }

    #[test]
    fn module_state_ignores_self_binding() {
        let module = SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "module",
        );
        let state = <SyntheticModule<NativeArch> as Module<NativeArch>>::state(&module);
        let binding = state.instance_id();

        state.install_effects([binding], []);

        assert!(state.with_effects(|bindings, _| bindings.is_empty()));
    }

    #[test]
    fn binding_distinguishes_reloaded_source() {
        let source = ModuleSourceId::fresh();
        let old = ModuleState::new(
            source,
            Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id(),
        );
        let binding = old.instance_id();
        let replacement = ModuleState::new(
            source,
            Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id(),
        );

        assert_eq!(binding, old.instance_id());
        assert_ne!(binding, replacement.instance_id());
    }
}
