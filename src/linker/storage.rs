use super::unload::{UnloadGroup, UnloadedModule};
use crate::{
    LinkContextError, LinkerError, Result,
    arch::NativeArch,
    entity::{PrimaryMap, entity_ref},
    image::{ModuleHandle, ModuleInstanceId, ModuleScope},
    input::{ModuleSourceId, Path, PathBuf},
    linker::AddressIndex,
    relocation::RelocationArch,
    runtime::DomainId,
    sync::{Arc, AtomicUsize, Ordering},
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::Entry},
    string::String,
    vec::Vec,
};
use core::{
    borrow::Borrow,
    fmt::{self, Display},
    ops::Deref,
};
use spin::Mutex;

/// Logical name used to address a module inside a [`LinkContext`](super::LinkContext).
///
/// A key is an ordered lookup name such as a resolved path, `DT_SONAME`, or
/// `DT_NEEDED` name. Physical module identity is tracked separately by
/// [`ModuleSourceId`], so several modules may be registered under one key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleKey(Arc<[u8]>);

impl ModuleKey {
    /// Creates a key from a loader-visible name or path.
    #[inline]
    pub fn new(value: impl AsRef<[u8]>) -> Self {
        Self(Arc::from(value.as_ref()))
    }

    /// Returns the key as a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for ModuleKey {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for ModuleKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<[u8]> for ModuleKey {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Display for ModuleKey {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.escape_ascii().fmt(f)
    }
}

impl From<&str> for ModuleKey {
    #[inline]
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ModuleKey {
    #[inline]
    fn from(value: String) -> Self {
        Self::from(value.into_bytes())
    }
}

impl From<&[u8]> for ModuleKey {
    #[inline]
    fn from(value: &[u8]) -> Self {
        Self::new(value)
    }
}

impl From<Vec<u8>> for ModuleKey {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self(Arc::from(value))
    }
}

impl From<&Path> for ModuleKey {
    #[inline]
    fn from(path: &Path) -> Self {
        Self::new(path.as_bytes())
    }
}

impl From<PathBuf> for ModuleKey {
    #[inline]
    fn from(value: PathBuf) -> Self {
        Self(Arc::from(value.into_bytes()))
    }
}

/// Symbol-namespace identity of a [`LinkContext`](super::LinkContext).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextId(usize);

impl ContextId {
    #[inline]
    pub(crate) fn fresh() -> Self {
        static NEXT_CONTEXT_ID: AtomicUsize = AtomicUsize::new(1);

        let id = NEXT_CONTEXT_ID.fetch_add(1, Ordering::Relaxed);
        assert!(id != 0, "link context id counter overflowed");
        Self(id)
    }
}

impl Display for ContextId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::linker) struct ModuleSlot(usize);
entity_ref!(ModuleSlot);

/// Identity of one committed module incarnation in a
/// [`LinkContext`](super::LinkContext).
///
/// An id becomes stale after its module is unloaded, even if the same key is
/// loaded again later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleId {
    context: ContextId,
    slot: ModuleSlot,
    generation: u32,
}

impl ModuleId {
    #[inline]
    pub(in crate::linker) const fn from_slot(
        context: ContextId,
        slot: ModuleSlot,
        generation: u32,
    ) -> Self {
        Self {
            context,
            slot,
            generation,
        }
    }

    #[inline]
    pub(in crate::linker) const fn context(self) -> ContextId {
        self.context
    }
}

impl Display for ModuleId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} in link context {}",
            self.slot.0, self.generation, self.context
        )
    }
}

/// A module acquisition returned by loading, insertion, or explicit acquisition.
///
/// Pass it to [`LinkContext::release`](super::LinkContext::release) when finished.
/// Dropping a lease does not release it: the module remains a root until the
/// context is dropped. Leases cannot be cloned or copied.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a module lease must eventually be released"]
pub struct ModuleLease {
    id: ModuleId,
}

impl ModuleLease {
    #[inline]
    pub(in crate::linker) const fn new(id: ModuleId) -> Self {
        Self { id }
    }

    /// Returns the identity of the acquired module.
    #[inline]
    pub const fn id(&self) -> ModuleId {
        self.id
    }
}

pub(in crate::linker) struct CommittedModuleMut<'a, Meta, Arch>
where
    Arch: RelocationArch,
{
    entry: &'a mut StoredEntry<Meta, Arch>,
}

impl<'a, Meta, Arch> CommittedModuleMut<'a, Meta, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(super) fn cache_load_group(&mut self, scope: ModuleScope<Arch>) {
        debug_assert!(self.entry.load_group.is_none());
        self.entry.load_group = Some(scope);
    }

    #[inline]
    pub(crate) fn acquire_root(&mut self) {
        self.entry.roots = self
            .entry
            .roots
            .checked_add(1)
            .expect("module acquisition count overflow");
    }

    #[inline]
    pub(crate) fn release_root(&mut self) -> usize {
        self.entry.roots = self
            .entry
            .roots
            .checked_sub(1)
            .expect("module lease must represent a direct acquisition");
        self.entry.roots
    }

    #[inline]
    pub(crate) fn pin(&mut self) {
        self.entry.pins = self
            .entry
            .pins
            .checked_add(1)
            .expect("module pin count overflow");
    }

    #[inline]
    pub(crate) fn unpin(&mut self) {
        self.entry.pins = self
            .entry
            .pins
            .checked_sub(1)
            .expect("module must have a matching pin");
    }

    #[inline]
    pub(crate) fn meta_mut(self) -> &'a mut Meta {
        &mut self.entry.meta
    }
}

pub(in crate::linker) type ReservationReturns = Arc<Mutex<Vec<(ModuleSlot, u32)>>>;

pub(crate) struct CommittedStorage<Meta = (), Arch: RelocationArch = NativeArch> {
    context: ContextId,
    domain: DomainId,
    bindings: BTreeMap<ModuleKey, Vec<ModuleSlot>>,
    sources: BTreeMap<ModuleSourceId, ModuleSlot>,
    entries: PrimaryMap<ModuleSlot, ModuleCell<Meta, Arch>>,
    lifecycle: Vec<ModuleSlot>,
    free_slots: Vec<ModuleSlot>,
    reservation_returns: Option<ReservationReturns>,
    pub(super) addresses: Arc<AddressIndex>,
}

impl<Meta, Arch> CommittedStorage<Meta, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new(context: ContextId, domain: DomainId) -> Self {
        Self {
            context,
            domain,
            bindings: BTreeMap::new(),
            sources: BTreeMap::new(),
            entries: PrimaryMap::default(),
            lifecycle: Vec::new(),
            free_slots: Vec::new(),
            reservation_returns: None,
            addresses: Arc::new(AddressIndex::default()),
        }
    }

    #[inline]
    pub(crate) const fn context(&self) -> ContextId {
        self.context
    }

    #[inline]
    pub(crate) const fn domain(&self) -> DomainId {
        self.domain
    }

    pub(crate) fn ensure_domain(&self, domain: DomainId) -> Result<()> {
        self.domain.ensure(domain)
    }

    #[inline]
    pub(in crate::linker) fn make_module_id(&self, slot: ModuleSlot) -> ModuleId {
        ModuleId::from_slot(self.context, slot, self.entries[slot].generation)
    }

    #[inline]
    pub(in crate::linker) fn module_slot(&self, id: ModuleId) -> Result<ModuleSlot> {
        self.checked_module(id).map(|_| id.slot)
    }

    #[inline]
    pub(in crate::linker) fn contains_id(&self, id: ModuleId) -> Result<bool> {
        Ok(self.find_by_id(id)?.is_some())
    }

    #[inline]
    pub(in crate::linker) fn checked_module(
        &self,
        id: ModuleId,
    ) -> Result<&StoredEntry<Meta, Arch>> {
        self.find_by_id(id)?
            .ok_or_else(|| LinkerError::context(LinkContextError::StaleModuleId { id }).into())
    }

    #[inline]
    fn find_by_id(&self, id: ModuleId) -> Result<Option<&StoredEntry<Meta, Arch>>> {
        if id.context != self.context {
            return Err(
                LinkerError::context(LinkContextError::ModuleContextMismatch {
                    id,
                    expected: self.context,
                })
                .into(),
            );
        }
        Ok(self
            .entries
            .get(id.slot)
            .filter(|cell| cell.generation == id.generation)
            .and_then(|cell| cell.entry.as_ref()))
    }

    #[inline]
    pub(in crate::linker) fn module(&self, slot: ModuleSlot) -> Option<&StoredEntry<Meta, Arch>> {
        self.entries.get(slot)?.entry.as_ref()
    }

    #[inline]
    pub(crate) fn module_mut(
        &mut self,
        slot: ModuleSlot,
    ) -> Option<CommittedModuleMut<'_, Meta, Arch>> {
        match self.entries.get_mut(slot) {
            Some(ModuleCell {
                entry: Some(entry), ..
            }) => Some(CommittedModuleMut { entry }),
            _ => None,
        }
    }

    #[inline]
    pub(in crate::linker) fn module_for_key(&self, key: impl AsRef<[u8]>) -> Option<ModuleSlot> {
        let module = self.bindings.get(key.as_ref())?.first().copied()?;
        debug_assert!(
            self.contains_module(module),
            "key bindings must only contain committed modules"
        );
        Some(module)
    }

    #[inline]
    pub(in crate::linker) fn contains_module(&self, slot: ModuleSlot) -> bool {
        self.entries
            .get(slot)
            .is_some_and(|cell| cell.entry.is_some())
    }

    #[inline]
    pub(in crate::linker) fn generation(&self, slot: ModuleSlot) -> u32 {
        self.entries[slot].generation
    }

    #[inline]
    pub(in crate::linker) fn module_for_source(
        &self,
        source: ModuleSourceId,
    ) -> Option<ModuleSlot> {
        self.sources.get(&source).copied()
    }

    #[inline]
    pub(in crate::linker) fn module_for_binding(
        &self,
        binding: ModuleInstanceId,
    ) -> Option<ModuleSlot> {
        let slot = self.module_for_source(binding.source_id())?;
        (binding == self.module(slot)?.handle().state().instance_id()).then_some(slot)
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.lifecycle.is_empty()
    }

    #[inline]
    pub(crate) fn lifecycle(&self) -> impl DoubleEndedIterator<Item = ModuleSlot> + '_ {
        self.lifecycle.iter().copied()
    }

    pub(crate) fn bind_key(&mut self, key: ModuleKey, module: ModuleSlot) {
        let entry = self
            .entries
            .get_mut(module)
            .and_then(|cell| cell.entry.as_mut())
            .expect("key bindings must refer to committed modules");
        let binding = self.bindings.entry(key);
        if let Entry::Occupied(binding) = &binding
            && binding.get().contains(&module)
        {
            return;
        }
        let alias = (binding.key() != &entry.entry_key).then(|| binding.key().clone());
        binding
            .or_insert_with(|| Vec::with_capacity(1))
            .push(module);
        if let Some(alias) = alias {
            debug_assert!(!entry.aliases.contains(&alias));
            entry.aliases.push(alias);
        }
    }

    // Callers validate the whole batch before entering publication. Insertions
    // record lifecycle order directly; address indexing runs once per batch.
    pub(crate) fn publish<R>(
        &mut self,
        additional: usize,
        publish: impl FnOnce(&mut Publication<'_, Meta, Arch>) -> R,
    ) -> R {
        let start = self.lifecycle.len();
        self.lifecycle.reserve(additional);
        let result = publish(&mut Publication { storage: self });
        let added = &self.lifecycle[start..];
        if added.is_empty() {
            return result;
        }
        let entries = &self.entries;
        let context = self.context;
        Arc::make_mut(&mut self.addresses).extend(added.iter().map(|&slot| {
            let cell = &entries[slot];
            let entry = cell.entry.as_ref().expect("published module must exist");
            (
                ModuleId::from_slot(context, slot, cell.generation),
                entry.module.memory(),
            )
        }));
        result
    }

    // Called once when a transaction first reserves a module, so subsequent
    // allocations in the same group do not acquire the return queue lock.
    pub(crate) fn reserve_returns(&mut self) -> ReservationReturns {
        self.reclaim_returned_slots();
        Arc::clone(
            self.reservation_returns
                .get_or_insert_with(|| Arc::new(Mutex::new(Vec::new()))),
        )
    }

    pub(crate) fn reclaim_returned_slots(&mut self) {
        let Some(returns) = &self.reservation_returns else {
            return;
        };
        let mut returned = returns.lock();
        for (slot, generation) in returned.drain(..) {
            let Some(cell) = self.entries.get_mut(slot) else {
                continue;
            };
            if cell.generation == generation && cell.entry.is_none() {
                // A returned reservation must not invalidate a later occupant
                // or put the same vacant slot on the free list twice.
                cell.advance_generation();
                self.free_slots.push(slot);
            }
        }
    }

    pub(crate) fn alloc_module(&mut self) -> ModuleSlot {
        if let Some(slot) = self.free_slots.pop() {
            return slot;
        }
        self.entries.push(ModuleCell {
            generation: 0,
            entry: None,
        })
    }

    pub(crate) fn remove_batch(&mut self, order: Vec<ModuleSlot>) -> UnloadGroup<Meta, Arch> {
        let mut modules = Vec::with_capacity(order.len());
        for &slot in &order {
            let id = self.make_module_id(slot);
            let (module, retained, meta) = self.remove(slot);
            modules.push(UnloadedModule::new(id, module, retained, meta));
        }
        if !modules.is_empty() {
            // Reuse the unload order if the empty free list would otherwise grow.
            // Its traversal capacity stays available for later slot reuse.
            if self.free_slots.is_empty() && self.free_slots.capacity() < order.len() {
                self.free_slots = order;
            } else {
                self.free_slots.extend(order);
            }
            self.prune_removed();
        }
        UnloadGroup::new(modules)
    }

    #[inline]
    fn remove(&mut self, slot: ModuleSlot) -> (ModuleHandle<Arch>, ModuleScope<Arch>, Meta) {
        let entry = {
            let cell = &mut self.entries[slot];
            let entry = cell
                .entry
                .take()
                .expect("unload order must refer to a committed module");
            cell.advance_generation();
            entry
        };
        for key in core::iter::once(entry.entry_key).chain(entry.aliases) {
            let Entry::Occupied(mut binding) = self.bindings.entry(key) else {
                panic!("module key must have a binding list");
            };
            binding.get_mut().retain(|candidate| *candidate != slot);
            if binding.get().is_empty() {
                binding.remove();
            }
        }
        let indexed = self
            .sources
            .remove(&entry.module.source_id())
            .expect("committed module must have a source entry");
        assert_eq!(indexed, slot, "module source must refer to its slot");
        (entry.module, entry.retained, entry.meta)
    }

    fn prune_removed(&mut self) {
        let entries = &self.entries;
        self.lifecycle
            .retain(|slot| entries.get(*slot).is_some_and(|cell| cell.entry.is_some()));
        // One pass for the whole unload group, preserving exported snapshots.
        Arc::make_mut(&mut self.addresses).retain(|id| {
            entries
                .get(id.slot)
                .is_some_and(|cell| cell.entry.is_some() && cell.generation == id.generation)
        });
    }
}

pub(in crate::linker) struct Publication<'a, Meta, Arch: RelocationArch> {
    storage: &'a mut CommittedStorage<Meta, Arch>,
}

impl<Meta, Arch: RelocationArch> Publication<'_, Meta, Arch> {
    pub(crate) fn insert(&mut self, slot: ModuleSlot, entry: StoredEntry<Meta, Arch>) -> ModuleId {
        let source = entry.module.source_id();
        assert!(
            !self.storage.sources.contains_key(&source),
            "module source is already committed"
        );
        let cell = &mut self.storage.entries[slot];
        assert!(cell.entry.is_none(), "module slot is already committed");
        cell.advance_generation();
        cell.entry = Some(entry);
        self.storage.sources.insert(source, slot);
        self.storage.lifecycle.push(slot);
        self.storage.make_module_id(slot)
    }

    #[inline]
    pub(crate) fn bind_key(&mut self, key: ModuleKey, slot: ModuleSlot) {
        self.storage.bind_key(key, slot);
    }

    #[inline]
    pub(crate) fn acquire_root(&mut self, slot: ModuleSlot) -> ModuleId {
        self.storage
            .module_mut(slot)
            .expect("reused module must remain committed")
            .acquire_root();
        self.storage.make_module_id(slot)
    }

    #[inline]
    pub(crate) fn pin(&mut self, slot: ModuleSlot) {
        self.storage
            .module_mut(slot)
            .expect("published pin must refer to a committed module")
            .pin();
    }
}

struct ModuleCell<Meta = (), Arch: RelocationArch = NativeArch> {
    // Incremented on publication, removal, and reservation reclamation to guard
    // transactional references and make unloaded module ids stale.
    generation: u32,
    entry: Option<StoredEntry<Meta, Arch>>,
}

impl<Meta, Arch: RelocationArch> ModuleCell<Meta, Arch> {
    #[inline]
    fn advance_generation(&mut self) {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("module generation overflowed");
    }
}

pub(in crate::linker) struct StoredEntry<Meta = (), Arch: RelocationArch = NativeArch> {
    entry_key: ModuleKey,
    aliases: Vec<ModuleKey>,
    module: ModuleHandle<Arch>,
    direct_deps: Box<[ModuleSlot]>,
    // Keeps only this module's dependency closure alive for deferred lookup and
    // finalization; the wider relocation group is owned by its root entry.
    retained: ModuleScope<Arch>,
    // Direct dependency edges are immutable for one committed incarnation.
    load_group: Option<ModuleScope<Arch>>,
    roots: usize,
    pins: usize,
    meta: Meta,
}

impl<Meta, Arch> StoredEntry<Meta, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(in crate::linker) const fn entry_key(&self) -> &ModuleKey {
        &self.entry_key
    }

    #[inline]
    pub(in crate::linker) fn handle(&self) -> &ModuleHandle<Arch> {
        &self.module
    }

    #[inline]
    pub(in crate::linker) fn direct_deps(&self) -> &[ModuleSlot] {
        &self.direct_deps
    }

    #[inline]
    pub(in crate::linker) const fn retained(&self) -> &ModuleScope<Arch> {
        &self.retained
    }

    #[inline]
    pub(in crate::linker) const fn load_group(&self) -> Option<&ModuleScope<Arch>> {
        self.load_group.as_ref()
    }

    #[inline]
    pub(in crate::linker) const fn is_root(&self) -> bool {
        self.pins != 0 || self.roots != 0
    }

    #[inline]
    pub(in crate::linker) const fn meta(&self) -> &Meta {
        &self.meta
    }

    #[inline]
    pub(in crate::linker) fn new(
        entry_key: ModuleKey,
        module: ModuleHandle<Arch>,
        direct_deps: Box<[ModuleSlot]>,
        retained: ModuleScope<Arch>,
        roots: usize,
        meta: Meta,
    ) -> Self {
        Self {
            entry_key,
            aliases: Vec::new(),
            module,
            direct_deps,
            retained,
            load_group: None,
            roots,
            pins: 0,
            meta,
        }
    }
}

impl<Meta, Arch> Drop for CommittedStorage<Meta, Arch>
where
    Arch: RelocationArch,
{
    fn drop(&mut self) {
        // ModuleHandle performs the release. Taking entries here only preserves
        // dependent-before-dependency finalization for modules without scopes.
        for slot in self.lifecycle.iter().rev().copied() {
            if let Some(cell) = self.entries.get_mut(slot) {
                let _ = cell.entry.take();
            }
        }
    }
}
