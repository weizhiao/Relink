use crate::{
    LinkContextError, LinkerError, Result,
    arch::NativeArch,
    entity::{PrimaryMap, SecondaryMap, entity_ref},
    image::ModuleHandle,
    relocation::RelocationArch,
    runtime::DomainId,
    sync::{AtomicUsize, Ordering},
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

/// Stable id for a committed module stored in a [`LinkContext`](super::LinkContext).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModuleId {
    context: ContextId,
    slot: ModuleSlot,
}

impl ModuleId {
    #[inline]
    pub(in crate::linker) const fn from_slot(context: ContextId, slot: ModuleSlot) -> Self {
        Self { context, slot }
    }

    #[inline]
    pub(in crate::linker) const fn context(self) -> ContextId {
        self.context
    }
}

impl Display for ModuleId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in link context {}", self.slot.0, self.context)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::linker) enum EntryState<T> {
    Absent,
    Removed,
    Present(T),
}

impl<T> EntryState<T> {
    #[inline]
    pub(in crate::linker) fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }

    #[inline]
    pub(in crate::linker) fn present(self) -> Option<T> {
        match self {
            Self::Present(value) => Some(value),
            Self::Absent | Self::Removed => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::linker) struct DepEdge {
    key: KeySlot,
    module: ModuleSlot,
}

impl DepEdge {
    #[inline]
    pub(in crate::linker) fn new(key: KeySlot, module: ModuleSlot) -> Self {
        Self { key, module }
    }

    #[inline]
    pub(in crate::linker) fn key(self) -> KeySlot {
        self.key
    }

    #[inline]
    pub(in crate::linker) fn module(self) -> ModuleSlot {
        self.module
    }
}

#[derive(Clone, Copy)]
pub(in crate::linker) struct CommittedModule<'a, M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    entry: &'a StoredEntry<M, Arch, Tls>,
}

impl<'a, M, Arch, Tls> CommittedModule<'a, M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(in crate::linker) fn entry_key(&self) -> KeySlot {
        self.entry.entry_key
    }

    #[inline]
    pub(crate) fn handle(&self) -> &'a ModuleHandle<Arch, Tls> {
        &self.entry.module
    }

    #[inline]
    pub(crate) fn direct_deps(&self) -> &'a [DepEdge] {
        &self.entry.direct_deps
    }

    #[inline]
    pub(crate) fn meta(&self) -> &'a M {
        &self.entry.meta
    }

    #[inline]
    pub(crate) const fn root_count(&self) -> usize {
        self.entry.roots
    }
}

pub(in crate::linker) struct CommittedModuleMut<'a, M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    entry: &'a mut StoredEntry<M, Arch, Tls>,
}

impl<'a, M, Arch, Tls> CommittedModuleMut<'a, M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    pub(crate) fn acquire_root(&mut self) {
        self.entry.roots = self
            .entry
            .roots
            .checked_add(1)
            .expect("module acquisition count overflow");
    }

    #[inline]
    pub(crate) fn release_root(&mut self) -> Option<usize> {
        let count = self.entry.roots.checked_sub(1)?;
        self.entry.roots = count;
        Some(count)
    }

    #[inline]
    pub(crate) fn meta_mut(self) -> &'a mut M {
        &mut self.entry.meta
    }
}

pub(crate) struct CommittedStorage<
    K,
    D: Send + Sync + 'static,
    M = (),
    Arch: RelocationArch = NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    context: ContextId,
    domain: DomainId,
    key_slots: BTreeMap<K, KeySlot>,
    keys: PrimaryMap<KeySlot, K>,
    key_modules: SecondaryMap<KeySlot, ModuleSlot>,
    entries: PrimaryMap<ModuleSlot, Option<StoredEntry<M, Arch, Tls>>>,
    lifecycle: Vec<ModuleSlot>,
    marker: core::marker::PhantomData<fn() -> D>,
}

impl<K, D: Send + Sync + 'static, M, Arch, Tls> Clone for CommittedStorage<K, D, M, Arch, Tls>
where
    K: Clone,
    M: Clone,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            key_slots: self.key_slots.clone(),
            context: self.context,
            domain: self.domain,
            keys: self.keys.clone(),
            key_modules: self.key_modules.clone(),
            entries: self.entries.clone(),
            lifecycle: self.lifecycle.clone(),
            marker: core::marker::PhantomData,
        }
    }
}

impl<K, D: Send + Sync + 'static, M, Arch, Tls> CommittedStorage<K, D, M, Arch, Tls>
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
            key_modules: SecondaryMap::new(),
            entries: PrimaryMap::new(),
            lifecycle: Vec::new(),
            marker: core::marker::PhantomData,
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
        ModuleId::from_slot(self.context, slot)
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
        (id.context == self.context)
            .then_some(id.slot)
            .ok_or_else(|| {
                LinkerError::context(LinkContextError::ModuleContextMismatch {
                    id,
                    expected: self.context,
                })
                .into()
            })
    }

    #[inline]
    pub(in crate::linker) fn module(
        &self,
        slot: ModuleSlot,
    ) -> EntryState<CommittedModule<'_, M, Arch, Tls>> {
        match self.entries.get(slot) {
            Some(Some(entry)) => EntryState::Present(CommittedModule { entry }),
            Some(None) => EntryState::Removed,
            None => EntryState::Absent,
        }
    }

    #[inline]
    pub(crate) fn module_mut(
        &mut self,
        slot: ModuleSlot,
    ) -> EntryState<CommittedModuleMut<'_, M, Arch, Tls>> {
        match self.entries.get_mut(slot) {
            Some(Some(entry)) => EntryState::Present(CommittedModuleMut { entry }),
            Some(None) => EntryState::Removed,
            None => EntryState::Absent,
        }
    }

    #[inline]
    pub(in crate::linker) fn module_for_key(&self, slot: KeySlot) -> Option<ModuleSlot> {
        self.key_modules.get(slot).copied()
    }

    #[inline]
    pub(in crate::linker) fn contains_module(&self, slot: ModuleSlot) -> bool {
        self.module(slot).is_present()
    }
}

impl<K, D: Send + Sync + 'static, M, Arch, Tls> CommittedStorage<K, D, M, Arch, Tls>
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
            .is_some_and(|slot| self.contains_module(slot))
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.iter().all(|(_, entry)| entry.is_none())
    }

    #[inline]
    pub(crate) fn load_order(&self) -> impl DoubleEndedIterator<Item = ModuleSlot> + '_ {
        self.entries
            .iter()
            .filter_map(|(slot, entry)| entry.as_ref().map(|_| slot))
    }

    #[inline]
    pub(crate) fn lifecycle(&self) -> impl DoubleEndedIterator<Item = ModuleSlot> + '_ {
        self.lifecycle
            .iter()
            .copied()
            .filter(|slot| self.contains_module(*slot))
    }

    #[inline]
    pub(crate) fn aliases(&self) -> impl Iterator<Item = (KeySlot, ModuleSlot)> + '_ {
        self.key_modules
            .iter()
            .filter_map(|(alias_slot, module_slot)| {
                let entry_key = self.entries.get(*module_slot)?.as_ref()?.entry_key;
                (alias_slot != entry_key).then_some((alias_slot, *module_slot))
            })
    }

    #[inline]
    pub(crate) fn get_by_key(&self, slot: KeySlot) -> Option<&ModuleHandle<Arch, Tls>> {
        let module_slot = self.module_for_key(slot)?;
        self.module(module_slot)
            .present()
            .map(|module| module.handle())
    }

    pub(crate) fn resolve_dep_edges(&self, direct_deps: Box<[KeySlot]>) -> Result<Box<[DepEdge]>> {
        direct_deps
            .into_vec()
            .into_iter()
            .map(|key| {
                let Some(module) = self.module_for_key(key) else {
                    return Err(LinkerError::context(LinkContextError::KeyNotCommitted {
                        id: self.make_key_id(key),
                    })
                    .into());
                };
                Ok(DepEdge::new(key, module))
            })
            .collect::<Result<Vec<_>>>()
            .map(Vec::into_boxed_slice)
    }
}

impl<K, D: Send + Sync + 'static, M, Arch, Tls> CommittedStorage<K, D, M, Arch, Tls>
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

    pub(crate) fn add_alias(&mut self, module_slot: ModuleSlot, alias: K) -> Option<ModuleSlot> {
        let slot = self.intern_key(alias);
        let previous = self.key_modules.insert(slot, module_slot);
        previous.filter(|slot| *slot != module_slot)
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

    pub(crate) fn ensure_module_slot(&mut self, slot: KeySlot) -> ModuleSlot {
        if let Some(module_slot) = self.key_modules.get(slot).copied() {
            return module_slot;
        }

        let module_slot = self.entries.push(None);
        self.key_modules.insert(slot, module_slot);
        module_slot
    }

    pub(crate) fn insert(
        &mut self,
        slot: KeySlot,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[DepEdge]>,
        meta: M,
        roots: usize,
    ) -> ModuleSlot {
        let module_slot = self.ensure_module_slot(slot);
        let previous = self.entries[module_slot].as_ref();
        let (entry_key, roots) = previous
            .map(|entry| (entry.entry_key, entry.roots))
            .unwrap_or((slot, roots));
        self.entries[module_slot] = Some(StoredEntry {
            entry_key,
            module,
            direct_deps,
            meta,
            roots,
        });
        module_slot
    }

    #[inline]
    pub(crate) fn take(
        &mut self,
        slot: ModuleSlot,
    ) -> (ModuleHandle<Arch, Tls>, Box<[DepEdge]>, M) {
        let removed = self.entries[slot]
            .take()
            .expect("unload order must refer to a committed module");
        (removed.module, removed.direct_deps, removed.meta)
    }

    pub(crate) fn prune_removed(&mut self) {
        let entries = &self.entries;
        self.key_modules
            .retain(|_, slot| entries.get(*slot).is_some_and(Option::is_some));
        self.lifecycle
            .retain(|slot| entries.get(*slot).is_some_and(Option::is_some));
    }
}

struct StoredEntry<M = (), Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    entry_key: KeySlot,
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[DepEdge]>,
    meta: M,
    roots: usize,
}

impl<M, Arch, Tls> Clone for StoredEntry<M, Arch, Tls>
where
    M: Clone,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            entry_key: self.entry_key,
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
            meta: self.meta.clone(),
            roots: self.roots,
        }
    }
}

impl<K, D: Send + Sync + 'static, M, Arch, Tls> Drop for CommittedStorage<K, D, M, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn drop(&mut self) {
        // ModuleHandle performs the release. Taking entries here only preserves
        // dependent-before-dependency finalization for modules without scopes.
        for slot in self.lifecycle.iter().rev().copied() {
            let _ = self.entries.get_mut(slot).and_then(Option::take);
        }
    }
}
