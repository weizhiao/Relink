use super::Module;
use crate::{
    Result,
    arch::NativeArch,
    custom_error,
    elf::SymbolLookup,
    input::ModuleSourceId,
    memory::VmAddr,
    relocation::RelocationArch,
    runtime::DomainId,
    sync::{Arc, AtomicBool, AtomicU8, AtomicUsize, Ordering, Weak, arc_unsize},
    tls::TlsResolver,
};
use alloc::vec::Vec;
use core::{fmt, ops::Deref};
use spin::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

const UNINITIALIZED: u8 = 0;
const INITIALIZING: u8 = 1;
const INITIALIZED: u8 = 2;
const FAILED: u8 = 3;
const FINALIZED: u8 = 4;

static NEXT_INSTANCE: AtomicUsize = AtomicUsize::new(1);

#[inline]
fn next_instance() -> usize {
    NEXT_INSTANCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .expect("module instance identity space is exhausted")
}

struct InitializationGuard<'a>(&'a AtomicU8);

impl Drop for InitializationGuard<'_> {
    fn drop(&mut self) {
        // A panic must not leave the module permanently stuck in INITIALIZING.
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

/// Identity and runtime state shared by every view of one logical module.
///
/// Module implementations store this value and return it from
/// [`Module::state`]. It owns the canonical instance identity and runtime domain,
/// and coordinates initialization, finalization, and runtime bindings without
/// duplicating the ownership count already maintained by [`Arc`].
pub struct ModuleState {
    id: ModuleInstanceId,
    domain: DomainId,
    phase: AtomicU8,
    bindings: Mutex<Vec<ModuleInstanceId>>,
    nodelete: AtomicBool,
}

/// Non-owning identity of one loaded module instance.
///
/// Unlike [`ModuleSourceId`], this value changes when the same source is
/// unloaded and loaded again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleInstanceId {
    source: ModuleSourceId,
    instance: usize,
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
            bindings: Mutex::new(Vec::new()),
            nodelete: AtomicBool::new(false),
        }
    }

    /// Creates state for a module that is already initialized.
    #[inline]
    pub fn initialized(source: ModuleSourceId, domain: DomainId) -> Self {
        Self {
            id: ModuleInstanceId::new(source),
            domain,
            phase: AtomicU8::new(INITIALIZED),
            bindings: Mutex::new(Vec::new()),
            nodelete: AtomicBool::new(false),
        }
    }

    /// Returns the identity of this particular loaded module instance.
    #[inline]
    pub const fn instance_id(&self) -> ModuleInstanceId {
        self.id
    }

    /// Returns the runtime domain in which this module's addresses are meaningful.
    #[inline]
    pub const fn domain_id(&self) -> DomainId {
        self.domain
    }

    #[inline]
    pub(super) fn set_domain(&mut self, domain: DomainId) {
        self.domain = domain;
    }

    #[inline]
    pub(crate) fn with_bindings<T>(&self, f: impl FnOnce(&mut Vec<ModuleInstanceId>) -> T) -> T {
        let mut bindings = self.bindings.lock();
        f(&mut bindings)
    }

    #[inline]
    pub(crate) fn mark_nodelete(&self) {
        self.nodelete.store(true, Ordering::Release);
    }

    #[inline]
    pub(crate) fn is_nodelete(&self) -> bool {
        self.nodelete.load(Ordering::Acquire)
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

    /// Runs the module finalizer at most once after initialization was attempted.
    ///
    /// A module with finalization work should call this from its owning
    /// allocation's [`Drop`] implementation. For core-backed ELF modules,
    /// `ElfModule` already provides that integration. Calls made before
    /// initialization or after another finalizer claimed the module are no-ops.
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
        Self::new(ModuleSourceId::fresh(), DomainId::PROCESS)
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

    #[inline]
    pub(crate) fn downgrade(&self) -> Weak<dyn Module<Arch, Tls>> {
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

impl<Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> Deref for ModuleHandle<Arch, Tls> {
    type Target = dyn Module<Arch, Tls>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &*self.module
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch> + 'static> AsRef<dyn Module<Arch, Tls>>
    for ModuleHandle<Arch, Tls>
{
    #[inline]
    fn as_ref(&self) -> &(dyn Module<Arch, Tls> + 'static) {
        &*self.module
    }
}

/// Copy-on-write ordered modules used for symbol lookup and dependency retention.
///
/// Modules are searched in order and held alive by relocated outputs that keep
/// this scope. Clones remain stable when another clone is modified. The scope
/// dereferences to its ordered module slice for read-only access.
pub struct ModuleScope<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    modules: Arc<Vec<ModuleHandle<Arch, Tls>>>,
    domain: DomainId,
}

/// Eager and deferred local scopes used while relocating one module.
///
/// The eager scope is used for ordinary relocation. The lazy scope is always
/// present and is retained by standalone loaded images. Linker-managed images
/// normally use their dependency closure as the lazy scope.
pub struct LookupScope<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    groups: Arc<[ModuleScope<Arch, Tls>]>,
    lazy: ModuleScope<Arch, Tls>,
}

/// Weak references used by deferred lookup to recover local and global scopes.
///
/// Linker-managed images use their retained dependency closure instead of the
/// wider eager-relocation load group. This deliberately gives lazy binding the
/// conservative `retained + global` lookup semantics documented by the linker.
pub(crate) struct WeakLookupScope<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    scope: Weak<Vec<ModuleHandle<Arch, Tls>>>,
    global: Option<Weak<GlobalScopeInner<Arch, Tls>>>,
    domain: DomainId,
}

/// Shared live global lookup order owned by a [`LinkContext`](crate::LinkContext).
///
/// Clones refer to the same global scope. Use
/// [`LinkContext::promote_global`](crate::LinkContext::promote_global) or
/// [`LinkContext::extend_global`](crate::LinkContext::extend_global) to change
/// its contents without bypassing the context's lifetime bookkeeping.
pub struct GlobalScope<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    inner: Arc<GlobalScopeInner<Arch, Tls>>,
}

struct GlobalScopeInner<Arch: RelocationArch, Tls: TlsResolver<Arch>> {
    modules: RwLock<ModuleScope<Arch, Tls>>,
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

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> Deref for ModuleScope<Arch, Tls> {
    type Target = [ModuleHandle<Arch, Tls>];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.modules
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
            lazy: self.lazy.clone(),
        }
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> Clone for GlobalScope<Arch, Tls> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<Arch, Tls> fmt::Debug for LookupScope<Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LookupScope")
            .field("groups", &self.groups)
            .field("lazy", &self.lazy)
            .finish()
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> LookupScope<Arch, Tls> {
    /// Creates an empty lookup scope for `domain`.
    #[inline]
    pub fn empty(domain: DomainId) -> Self {
        Self::new([], ModuleScope::new(domain))
    }

    /// Creates a lookup scope with explicit eager groups and deferred scope.
    pub fn new<I>(groups: I, lazy: ModuleScope<Arch, Tls>) -> Self
    where
        I: IntoIterator<Item = ModuleScope<Arch, Tls>>,
    {
        let groups = groups.into_iter().collect::<Vec<_>>();
        debug_assert!(
            groups
                .iter()
                .all(|group| group.domain_id() == lazy.domain_id())
        );
        Self {
            groups: Arc::from(groups),
            lazy,
        }
    }

    /// Returns the runtime domain shared by this lookup scope.
    #[inline]
    pub const fn domain_id(&self) -> DomainId {
        self.lazy.domain_id()
    }

    /// Checks that both lookup scopes and their modules belong to `expected`.
    #[inline]
    pub fn check_domain(&self, expected: DomainId) -> Result<()> {
        for group in self.groups.iter() {
            group.check_domain(expected)?;
        }
        self.lazy.check_domain(expected)
    }

    #[inline]
    pub(crate) fn downgrade(
        &self,
        global: Option<&GlobalScope<Arch, Tls>>,
    ) -> WeakLookupScope<Arch, Tls> {
        let domain = self.domain_id();
        debug_assert!(global.is_none_or(|global| global.domain_id() == domain));
        WeakLookupScope {
            scope: Arc::downgrade(&self.lazy.modules),
            global: global.map(GlobalScope::downgrade),
            domain,
        }
    }

    /// Returns the eager module groups in lookup order.
    #[inline]
    pub fn groups(&self) -> &[ModuleScope<Arch, Tls>] {
        &self.groups
    }

    /// Returns the local scope retained for deferred PLT lookup.
    #[inline]
    pub const fn lazy_scope(&self) -> &ModuleScope<Arch, Tls> {
        &self.lazy
    }

    /// Appends an eager lookup group without changing deferred lookup.
    pub fn push(&mut self, group: ModuleScope<Arch, Tls>) {
        debug_assert_eq!(group.domain_id(), self.domain_id());
        let mut groups = Vec::with_capacity(self.groups.len() + 1);
        groups.extend(self.groups.iter().cloned());
        groups.push(group);
        self.groups = Arc::from(groups);
    }

    /// Appends eager lookup groups without changing deferred lookup.
    pub fn extend<I>(&mut self, groups: I)
    where
        I: IntoIterator<Item = ModuleScope<Arch, Tls>>,
    {
        let mut groups = groups.into_iter().peekable();
        if groups.peek().is_none() {
            return;
        }
        let (lower, _) = groups.size_hint();
        let mut current = Vec::with_capacity(self.groups.len() + lower);
        current.extend(self.groups.iter().cloned());
        for group in groups {
            debug_assert_eq!(group.domain_id(), self.domain_id());
            current.push(group);
        }
        self.groups = Arc::from(current);
    }

    pub(crate) fn extend_modules<I, R>(&mut self, modules: I)
    where
        I: IntoIterator<Item = R>,
        R: Into<ModuleHandle<Arch, Tls>>,
    {
        let follows_eager =
            self.groups.len() == 1 && Arc::ptr_eq(&self.groups[0].modules, &self.lazy.modules);
        if self.groups.is_empty() {
            let mut group = ModuleScope::new(self.domain_id());
            group.extend(modules);
            self.lazy = group.clone();
            self.groups = Arc::from([group]);
        } else {
            let group = Arc::make_mut(&mut self.groups)
                .last_mut()
                .expect("non-empty lookup scope must have a final group");
            group.extend(modules);
            if follows_eager {
                self.lazy = group.clone();
            }
        }
    }

    /// Iterates over eager lookup modules in order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &ModuleHandle<Arch, Tls>> {
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
    pub fn set_lazy_scope(&mut self, scope: ModuleScope<Arch, Tls>) {
        debug_assert_eq!(scope.domain_id(), self.domain_id());
        self.lazy = scope;
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> WeakLookupScope<Arch, Tls> {
    #[inline]
    pub(crate) fn upgrade_scope(&self) -> Option<LookupScope<Arch, Tls>> {
        let scope = ModuleScope {
            modules: self.scope.upgrade()?,
            domain: self.domain,
        };
        Some(LookupScope::new([scope.clone()], scope))
    }

    #[inline]
    pub(crate) fn upgrade_global(&self) -> Option<GlobalScope<Arch, Tls>> {
        self.global
            .as_ref()
            .and_then(Weak::upgrade)
            .map(|inner| GlobalScope { inner })
    }
}

impl<Arch: RelocationArch, Tls: TlsResolver<Arch>> GlobalScope<Arch, Tls> {
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

    #[inline]
    fn downgrade(&self) -> Weak<GlobalScopeInner<Arch, Tls>> {
        Arc::downgrade(&self.inner)
    }

    #[inline]
    /// Captures the current global lookup order.
    ///
    /// The returned copy-on-write scope remains stable if the context later
    /// promotes or unloads modules.
    pub fn modules(&self) -> ModuleScope<Arch, Tls> {
        self.read().clone()
    }

    #[inline]
    pub(crate) fn read(&self) -> RwLockReadGuard<'_, ModuleScope<Arch, Tls>> {
        self.inner.modules.read()
    }

    #[inline]
    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, ModuleScope<Arch, Tls>> {
        self.inner.modules.write()
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

        assert!(first.as_ref().ptr_eq(second.as_ref()));
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
    fn lookup_scope_retains_local_and_tracks_live_global() {
        let first: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty("first"));
        let second: ModuleHandle =
            ModuleHandle::new(SyntheticModule::<NativeArch>::empty("second"));
        let local: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty("local"));
        let global = GlobalScope::new(DomainId::PROCESS);
        global.write().push(first);
        let prepared = global.modules();

        let mut local_scope = ModuleScope::new(DomainId::PROCESS);
        local_scope.push(local);
        let scope = LookupScope::new([local_scope.clone()], local_scope);
        let weak = scope.downgrade(Some(&global));

        global.write().replace([second]);
        assert_eq!(
            prepared
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["first"]
        );
        assert_eq!(
            weak.upgrade_scope()
                .unwrap()
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["local"]
        );

        let deferred = weak.upgrade_scope().unwrap();
        let live = weak.upgrade_global().unwrap();
        assert_eq!(
            live.modules()
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["second"]
        );
        assert_eq!(
            deferred
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["local"]
        );

        drop(live);
        drop(global);
        let deferred = weak.upgrade_scope().unwrap();
        assert!(weak.upgrade_global().is_none());
        assert_eq!(
            deferred
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["local"]
        );
        assert_eq!(
            scope.iter().map(|module| module.name()).collect::<Vec<_>>(),
            ["local"]
        );
    }

    #[test]
    fn deferred_scope_uses_retained_dependencies() {
        let root: ModuleHandle = ModuleHandle::new(SyntheticModule::<NativeArch>::empty("root"));
        let dependency: ModuleHandle =
            ModuleHandle::new(SyntheticModule::<NativeArch>::empty("dependency"));
        let unrelated: ModuleHandle =
            ModuleHandle::new(SyntheticModule::<NativeArch>::empty("unrelated"));
        let mut group = ModuleScope::new(DomainId::PROCESS);
        group.extend([root, dependency.clone()]);
        let mut retained = ModuleScope::new(DomainId::PROCESS);
        retained.push(dependency);
        let owner = retained.clone();
        let mut scope = LookupScope::new([group], retained);
        let mut extra = ModuleScope::new(DomainId::PROCESS);
        extra.push(unrelated);
        scope.push(extra);
        let weak = scope.downgrade(None);

        assert_eq!(
            scope.iter().map(|module| module.name()).collect::<Vec<_>>(),
            ["root", "dependency", "unrelated"]
        );
        assert_eq!(
            scope
                .lazy_scope()
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["dependency"]
        );
        assert_eq!(
            weak.upgrade_scope()
                .unwrap()
                .iter()
                .map(|module| module.name())
                .collect::<Vec<_>>(),
            ["dependency"]
        );

        drop(scope);
        drop(owner);
        assert!(weak.upgrade_scope().is_none());
    }

    #[test]
    fn initializer_panic_marks_module_failed() {
        let state = ModuleState::new(ModuleSourceId::fresh(), DomainId::PROCESS);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = state.initialize(|| -> crate::Result<()> { panic!("initializer panic") });
        }));

        assert!(panic.is_err());
        assert!(!state.is_initialized());
        assert!(state.initialize(|| Ok(())).is_err());
    }

    #[test]
    fn module_state_ignores_self_binding() {
        let module = SyntheticModule::<NativeArch>::empty("module");
        let state = <SyntheticModule<NativeArch> as Module<NativeArch>>::state(&module);
        let binding = state.instance_id();

        state.with_bindings(|bindings| {
            if binding != state.instance_id() && !bindings.contains(&binding) {
                bindings.push(binding);
            }
        });

        assert!(state.with_bindings(|bindings| bindings.is_empty()));
    }

    #[test]
    fn binding_distinguishes_reloaded_source() {
        let source = ModuleSourceId::fresh();
        let old = ModuleState::new(source, DomainId::PROCESS);
        let binding = old.instance_id();
        let replacement = ModuleState::new(source, DomainId::PROCESS);

        assert_eq!(binding, old.instance_id());
        assert_ne!(binding, replacement.instance_id());
    }
}
