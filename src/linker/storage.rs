use crate::{
    LinkContextError, LinkerError, Result,
    arch::NativeArch,
    entity::{PrimaryMap, SecondaryMap, entity_ref},
    image::{LookupScope, ModuleHandle, ModuleIdentity},
    input::FileId,
    relocation::RelocationArch,
    runtime::DomainId,
    sync::{Arc, AtomicUsize, Ordering},
    tls::TlsResolver,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::{
    borrow::Borrow,
    fmt::{self, Display},
};

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
pub(in crate::linker) struct KeySlot(usize);
entity_ref!(KeySlot);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::linker) struct ModuleSlot(usize);
entity_ref!(ModuleSlot);

#[derive(Clone, Copy)]
pub(in crate::linker) struct ModuleGuard {
    pub(in crate::linker) slot: ModuleSlot,
    pub(in crate::linker) generation: u32,
}

/// Stable id for a module key stored in a [`LinkContext`](super::LinkContext).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId {
    context: ContextId,
    slot: KeySlot,
}

impl KeyId {
    #[inline]
    pub(in crate::linker) const fn from_slot(context: ContextId, slot: KeySlot) -> Self {
        Self { context, slot }
    }
}

impl Display for KeyId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in link context {}", self.slot.0, self.context)
    }
}

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

/// One direct acquisition of a committed module.
///
/// A lease is created by [`LinkContext::insert`](super::LinkContext::insert),
/// [`LinkContext::acquire`](super::LinkContext::acquire), or a linker load. It
/// is intentionally neither [`Clone`] nor [`Copy`]; pass it to
/// [`LinkContext::release`](super::LinkContext::release) exactly once when the
/// direct use ends.
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

#[derive(Clone, Copy)]
pub(in crate::linker) struct CommittedModule<'a, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    entry_key: KeySlot,
    entry: &'a StoredEntry<Meta, Arch, Tls>,
}

impl<'a, Meta, Arch, Tls> CommittedModule<'a, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(in crate::linker) fn entry_key(&self) -> KeySlot {
        self.entry_key
    }

    #[inline]
    pub(crate) fn handle(&self) -> &'a ModuleHandle<Arch, Tls> {
        &self.entry.module
    }

    #[inline]
    pub(crate) fn direct_deps(&self) -> &'a [ModuleSlot] {
        &self.entry.direct_deps
    }

    #[inline]
    pub(crate) fn reloc_deps(&self) -> &'a [ModuleSlot] {
        &self.entry.reloc_deps
    }

    #[inline]
    pub(crate) fn dependencies(&self) -> impl Iterator<Item = ModuleSlot> + 'a {
        self.entry
            .direct_deps
            .iter()
            .chain(self.entry.reloc_deps.iter())
            .copied()
    }

    #[inline]
    pub(crate) fn scope(&self) -> Option<&'a LookupScope<Arch, Tls>> {
        self.entry.scope.as_ref()
    }

    #[inline]
    pub(crate) const fn is_root(&self) -> bool {
        self.entry.pinned || self.entry.roots != 0
    }

    #[inline]
    pub(crate) const fn meta(&self) -> &'a Meta {
        &self.entry.meta
    }
}

pub(in crate::linker) struct CommittedModuleMut<'a, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    entry: &'a mut StoredEntry<Meta, Arch, Tls>,
}

impl<'a, Meta, Arch, Tls> CommittedModuleMut<'a, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn acquire_root(&mut self) {
        self.acquire_roots(1);
    }

    #[inline]
    pub(crate) fn acquire_roots(&mut self, count: usize) {
        self.entry.roots = self
            .entry
            .roots
            .checked_add(count)
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
    pub(crate) fn pin_root(&mut self) {
        self.release_root();
        self.entry.pinned = true;
    }

    #[inline]
    pub(crate) fn pin(&mut self) -> bool {
        !core::mem::replace(&mut self.entry.pinned, true)
    }

    #[inline]
    pub(crate) fn unpin(&mut self) {
        self.entry.pinned = false;
    }

    #[inline]
    pub(crate) fn meta_mut(self) -> &'a mut Meta {
        &mut self.entry.meta
    }
}

pub(crate) struct CommittedStorage<
    K,
    Meta = (),
    Arch: RelocationArch = NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    context: ContextId,
    domain: DomainId,
    key_slots: BTreeMap<K, KeySlot>,
    keys: PrimaryMap<KeySlot, K>,
    canonical: SecondaryMap<KeySlot, ModuleSlot>,
    aliases: SecondaryMap<KeySlot, Vec<ModuleSlot>>,
    files: BTreeMap<FileId, ModuleSlot>,
    identities: Arc<BTreeMap<ModuleIdentity, ModuleGuard>>,
    entries: PrimaryMap<ModuleSlot, ModuleCell<Meta, Arch, Tls>>,
    lifecycle: Vec<ModuleSlot>,
}

impl<K, Meta, Arch, Tls> CommittedStorage<K, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn new(context: ContextId, domain: DomainId) -> Self {
        Self {
            context,
            domain,
            key_slots: BTreeMap::new(),
            keys: PrimaryMap::new(),
            canonical: SecondaryMap::new(),
            aliases: SecondaryMap::new(),
            files: BTreeMap::new(),
            identities: Arc::new(BTreeMap::new()),
            entries: PrimaryMap::new(),
            lifecycle: Vec::new(),
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
    pub(in crate::linker) fn make_key_id(&self, slot: KeySlot) -> KeyId {
        KeyId::from_slot(self.context, slot)
    }

    #[inline]
    pub(in crate::linker) fn make_module_id(&self, slot: ModuleSlot) -> ModuleId {
        ModuleId::from_slot(self.context, slot, self.entries[slot].generation)
    }

    #[inline]
    pub(in crate::linker) fn key_slot(&self, id: KeyId) -> Result<KeySlot> {
        (id.context == self.context)
            .then_some(id.slot)
            .ok_or_else(|| {
                LinkerError::context(LinkContextError::KeyContextMismatch {
                    id,
                    expected: self.context,
                })
                .into()
            })
    }

    #[inline]
    pub(in crate::linker) fn module_slot(&self, id: ModuleId) -> Result<ModuleSlot> {
        if id.context != self.context {
            return Err(
                LinkerError::context(LinkContextError::ModuleContextMismatch {
                    id,
                    expected: self.context,
                })
                .into(),
            );
        }
        self.entries
            .get(id.slot)
            .filter(|entry| entry.generation == id.generation)
            .map(|_| id.slot)
            .ok_or_else(|| LinkerError::context(LinkContextError::StaleModuleId { id }).into())
    }

    #[inline]
    pub(in crate::linker) fn contains_id(&self, id: ModuleId) -> Result<bool> {
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
            .is_some_and(|entry| entry.generation == id.generation && entry.entry.is_some()))
    }

    #[inline]
    pub(in crate::linker) fn module(
        &self,
        slot: ModuleSlot,
    ) -> Option<CommittedModule<'_, Meta, Arch, Tls>> {
        match self.entries.get(slot) {
            Some(ModuleCell {
                entry_key,
                entry: Some(entry),
                ..
            }) => Some(CommittedModule {
                entry_key: *entry_key,
                entry,
            }),
            _ => None,
        }
    }

    #[inline]
    pub(crate) fn module_mut(
        &mut self,
        slot: ModuleSlot,
    ) -> Option<CommittedModuleMut<'_, Meta, Arch, Tls>> {
        match self.entries.get_mut(slot) {
            Some(ModuleCell {
                entry: Some(entry), ..
            }) => Some(CommittedModuleMut { entry }),
            _ => None,
        }
    }

    #[inline]
    pub(in crate::linker) fn module_for_key(&self, slot: KeySlot) -> Option<ModuleSlot> {
        self.canonical_module(slot)
            .filter(|module| self.contains_module(*module))
            .or_else(|| self.alias_module(slot))
    }

    #[inline]
    pub(crate) fn canonical_module(&self, slot: KeySlot) -> Option<ModuleSlot> {
        self.canonical.get(slot).copied()
    }

    #[inline]
    pub(crate) fn alias_module(&self, slot: KeySlot) -> Option<ModuleSlot> {
        self.aliases
            .get(slot)?
            .iter()
            .copied()
            .find(|module| self.contains_module(*module))
    }

    pub(crate) fn file_module(&self, id: FileId) -> Option<ModuleSlot> {
        self.files.get(&id).copied()
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
    pub(in crate::linker) fn identity_snapshot(
        &self,
    ) -> Arc<BTreeMap<ModuleIdentity, ModuleGuard>> {
        Arc::clone(&self.identities)
    }

    #[inline]
    pub(in crate::linker) fn identity_module(
        &self,
        identity: ModuleIdentity,
    ) -> Option<ModuleSlot> {
        self.identities.get(&identity).map(|guard| guard.slot)
    }

    #[inline]
    pub(in crate::linker) fn entry_key(&self, slot: ModuleSlot) -> KeySlot {
        self.entries[slot].entry_key
    }
}

impl<K, Meta, Arch, Tls> CommittedStorage<K, Meta, Arch, Tls>
where
    K: Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn key(&self, slot: KeySlot) -> &K {
        debug_assert!(
            self.keys.get(slot).is_some(),
            "key id must resolve to an interned key"
        );
        &self.keys[slot]
    }

    #[inline]
    pub(crate) fn key_slot_for<Q>(&self, key: &Q) -> Option<KeySlot>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.key_slots.get(key).copied()
    }

    #[inline]
    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.key_slot_for(key)
            .and_then(|slot| self.module_for_key(slot))
            .is_some()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.lifecycle.is_empty()
    }

    #[inline]
    pub(crate) fn load_order(&self) -> impl DoubleEndedIterator<Item = ModuleSlot> + '_ {
        self.entries
            .iter()
            .filter_map(|(slot, cell)| cell.entry.as_ref().map(|_| slot))
    }

    #[inline]
    pub(crate) fn lifecycle(&self) -> impl DoubleEndedIterator<Item = ModuleSlot> + '_ {
        self.lifecycle.iter().copied()
    }
}

impl<K, Meta, Arch, Tls> CommittedStorage<K, Meta, Arch, Tls>
where
    K: Clone + Ord,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    pub(in crate::linker) fn intern_key(&mut self, key: K) -> KeySlot {
        if let Some(slot) = self.key_slot_for(&key) {
            return slot;
        }

        let slot = self.keys.push(key.clone());
        let previous = self.key_slots.insert(key, slot);
        debug_assert!(previous.is_none(), "interned key inserted twice");
        slot
    }

    pub(crate) fn add_alias(&mut self, alias: KeySlot, module: ModuleSlot) {
        let modules = self.aliases.get_or_default(alias);
        if !modules.contains(&module) {
            modules.push(module);
        }
    }

    pub(crate) fn prefer_alias(&mut self, alias: KeySlot, module: ModuleSlot) {
        let modules = self.aliases.get_or_default(alias);
        if modules.first() == Some(&module) {
            return;
        }
        if let Some(idx) = modules.iter().position(|candidate| *candidate == module) {
            modules.remove(idx);
        }
        modules.insert(0, module);
    }

    fn add_file(&mut self, id: FileId, module: ModuleSlot) {
        self.files.entry(id).or_insert(module);
    }

    fn remove_file(&mut self, id: FileId, module: ModuleSlot) {
        if self.files.get(&id) != Some(&module) {
            return;
        }
        let replacement = self.entries.iter().find_map(|(slot, cell)| {
            (slot != module
                && cell
                    .entry
                    .as_ref()
                    .and_then(|entry| entry.module.search())
                    .and_then(|search| search.file_id())
                    == Some(id))
            .then_some(slot)
        });
        if let Some(slot) = replacement {
            self.files.insert(id, slot);
        } else {
            self.files.remove(&id);
        }
    }

    pub(crate) fn extend_lifecycle(&mut self, order: &[ModuleSlot]) {
        debug_assert!(
            order
                .iter()
                .enumerate()
                .all(|(idx, slot)| !order[..idx].contains(slot)),
            "lifecycle entries must be unique"
        );
        debug_assert!(
            order.iter().all(|slot| !self.lifecycle.contains(slot)),
            "lifecycle entries must only be recorded once"
        );
        self.lifecycle.extend_from_slice(order);
    }

    pub(crate) fn intern_module(&mut self, slot: KeySlot) -> ModuleSlot {
        if let Some(module_slot) = self.canonical.get(slot).copied() {
            return module_slot;
        }

        let module_slot = self.entries.push(ModuleCell {
            entry_key: slot,
            generation: 0,
            entry: None,
        });
        self.canonical.insert(slot, module_slot);
        module_slot
    }

    pub(crate) fn insert(&mut self, slot: ModuleSlot, entry: StoredEntry<Meta, Arch, Tls>) {
        let identity = entry.module.identity();
        assert!(
            !self.identities.contains_key(&identity),
            "module identity is already committed"
        );
        let file = entry.module.search().and_then(|search| search.file_id());
        let cell = &mut self.entries[slot];
        assert!(cell.entry.is_none(), "module slot is already committed");
        cell.advance_generation();
        let generation = cell.generation;
        cell.entry = Some(entry);
        Arc::make_mut(&mut self.identities).insert(identity, ModuleGuard { slot, generation });
        if let Some(id) = file {
            self.add_file(id, slot);
        }
    }

    #[inline]
    pub(crate) fn take(
        &mut self,
        slot: ModuleSlot,
    ) -> (
        ModuleHandle<Arch, Tls>,
        Option<LookupScope<Arch, Tls>>,
        Meta,
    ) {
        let removed = {
            let cell = &mut self.entries[slot];
            let removed = cell
                .entry
                .take()
                .expect("unload order must refer to a committed module");
            cell.advance_generation();
            removed
        };
        if let Some(id) = removed.module.search().and_then(|search| search.file_id()) {
            self.remove_file(id, slot);
        }
        let identity = removed.module.identity();
        let identities = Arc::make_mut(&mut self.identities);
        let guard = identities
            .remove(&identity)
            .expect("committed module must have an identity entry");
        debug_assert_eq!(guard.slot, slot);
        (removed.module, removed.scope, removed.meta)
    }

    pub(crate) fn prune_removed(&mut self) {
        let entries = &self.entries;
        self.aliases.retain(|_, modules| {
            modules.retain(|slot| entries.get(*slot).is_some_and(|cell| cell.entry.is_some()));
            !modules.is_empty()
        });
        self.lifecycle
            .retain(|slot| entries.get(*slot).is_some_and(|cell| cell.entry.is_some()));
    }
}

struct ModuleCell<Meta = (), Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    entry_key: KeySlot,
    generation: u32,
    entry: Option<StoredEntry<Meta, Arch, Tls>>,
}

impl<Meta, Arch: RelocationArch, Tls: TlsResolver<Arch>> ModuleCell<Meta, Arch, Tls> {
    #[inline]
    fn advance_generation(&mut self) {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("module generation overflowed");
    }
}

pub(in crate::linker) struct StoredEntry<
    Meta = (),
    Arch: RelocationArch = NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[ModuleSlot]>,
    reloc_deps: Box<[ModuleSlot]>,
    scope: Option<LookupScope<Arch, Tls>>,
    roots: usize,
    pinned: bool,
    meta: Meta,
}

impl<Meta, Arch, Tls> StoredEntry<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(in crate::linker) fn new(
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[ModuleSlot]>,
        roots: usize,
        meta: Meta,
    ) -> Self {
        Self::relocated(module, direct_deps, Box::new([]), None, roots, meta)
    }

    #[inline]
    pub(in crate::linker) fn relocated(
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[ModuleSlot]>,
        reloc_deps: Box<[ModuleSlot]>,
        scope: Option<LookupScope<Arch, Tls>>,
        roots: usize,
        meta: Meta,
    ) -> Self {
        Self {
            module,
            direct_deps,
            reloc_deps,
            scope,
            roots,
            pinned: false,
            meta,
        }
    }
}

impl<K, Meta, Arch, Tls> Drop for CommittedStorage<K, Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
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
