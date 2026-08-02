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
pub(in crate::linker) struct CommittedModule<'a, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    entry_key: KeySlot,
    entry: &'a StoredEntry<Arch, Tls>,
}

impl<'a, Arch, Tls> CommittedModule<'a, Arch, Tls>
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
    pub(crate) const fn root_count(&self) -> usize {
        self.entry.roots
    }
}

pub(in crate::linker) struct CommittedModuleMut<'a, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    entry: &'a mut StoredEntry<Arch, Tls>,
}

impl<'a, Arch, Tls> CommittedModuleMut<'a, Arch, Tls>
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
    pub(crate) fn release_root(&mut self) -> usize {
        self.entry.roots = self
            .entry
            .roots
            .checked_sub(1)
            .expect("module lease must represent a direct acquisition");
        self.entry.roots
    }
}

pub(crate) struct CommittedStorage<
    K,
    Arch: RelocationArch = NativeArch,
    Tls: TlsResolver<Arch> = (),
> {
    context: ContextId,
    domain: DomainId,
    key_slots: BTreeMap<K, KeySlot>,
    keys: PrimaryMap<KeySlot, K>,
    key_modules: SecondaryMap<KeySlot, ModuleSlot>,
    entries: PrimaryMap<ModuleSlot, ModuleCell<Arch, Tls>>,
    lifecycle: Vec<ModuleSlot>,
}

impl<K, Arch, Tls> CommittedStorage<K, Arch, Tls>
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
    ) -> Option<CommittedModule<'_, Arch, Tls>> {
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
    ) -> Option<CommittedModuleMut<'_, Arch, Tls>> {
        match self.entries.get_mut(slot) {
            Some(ModuleCell {
                entry: Some(entry), ..
            }) => Some(CommittedModuleMut { entry }),
            _ => None,
        }
    }

    #[inline]
    pub(in crate::linker) fn module_for_key(&self, slot: KeySlot) -> Option<ModuleSlot> {
        self.key_modules.get(slot).copied()
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
    pub(in crate::linker) fn entry_key(&self, slot: ModuleSlot) -> KeySlot {
        self.entries[slot].entry_key
    }
}

impl<K, Arch, Tls> CommittedStorage<K, Arch, Tls>
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

impl<K, Arch, Tls> CommittedStorage<K, Arch, Tls>
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

    pub(crate) fn intern_module(&mut self, slot: KeySlot) -> ModuleSlot {
        if let Some(module_slot) = self.key_modules.get(slot).copied() {
            return module_slot;
        }

        let module_slot = self.entries.push(ModuleCell {
            entry_key: slot,
            generation: 0,
            entry: None,
        });
        self.key_modules.insert(slot, module_slot);
        module_slot
    }

    pub(crate) fn insert(
        &mut self,
        slot: ModuleSlot,
        module: ModuleHandle<Arch, Tls>,
        direct_deps: Box<[ModuleSlot]>,
        roots: usize,
    ) {
        let cell = &mut self.entries[slot];
        let roots = cell.entry.as_ref().map_or(roots, |entry| entry.roots);
        cell.entry = Some(StoredEntry {
            module,
            direct_deps,
            roots,
        });
    }

    #[inline]
    pub(crate) fn take(&mut self, slot: ModuleSlot) -> ModuleHandle<Arch, Tls> {
        let cell = &mut self.entries[slot];
        let removed = cell
            .entry
            .take()
            .expect("unload order must refer to a committed module");
        cell.generation = cell
            .generation
            .checked_add(1)
            .expect("module generation overflowed");
        removed.module
    }

    pub(crate) fn prune_removed(&mut self) {
        let entries = &self.entries;
        self.key_modules.retain(|key, slot| {
            entries
                .get(*slot)
                .is_some_and(|cell| cell.entry.is_some() || cell.entry_key == key)
        });
        self.lifecycle
            .retain(|slot| entries.get(*slot).is_some_and(|cell| cell.entry.is_some()));
    }
}

struct ModuleCell<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    entry_key: KeySlot,
    generation: u32,
    entry: Option<StoredEntry<Arch, Tls>>,
}

struct StoredEntry<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    module: ModuleHandle<Arch, Tls>,
    direct_deps: Box<[ModuleSlot]>,
    roots: usize,
}

impl<K, Arch, Tls> Drop for CommittedStorage<K, Arch, Tls>
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
