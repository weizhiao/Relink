use crate::{
    entity::{PrimaryMap, SecondaryMap, entity_ref},
    image::ModuleHandle,
    relocation::RelocationArch,
    sync::Arc,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

/// Stable id for a module key stored in a [`LinkContext`](super::LinkContext).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyId(usize);
entity_ref!(KeyId);

pub(crate) struct CommittedStorage<
    K,
    D: 'static,
    M = (),
    Arch: RelocationArch = crate::arch::NativeArch,
> {
    key_ids: BTreeMap<Arc<K>, KeyId>,
    keys: PrimaryMap<KeyId, Arc<K>>,
    entries: SecondaryMap<KeyId, StoredEntry<D, M, Arch>>,
    load_order: Vec<KeyId>,
}

impl<K, D: 'static, M, Arch> CommittedStorage<K, D, M, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            key_ids: BTreeMap::new(),
            keys: PrimaryMap::new(),
            entries: SecondaryMap::new(),
            load_order: Vec::new(),
        }
    }
}

impl<K, D: 'static, M, Arch> CommittedStorage<K, D, M, Arch>
where
    K: Ord,
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn key(&self, id: KeyId) -> Option<&K> {
        self.keys.get(id).map(Arc::as_ref)
    }

    #[inline]
    pub(crate) fn key_id(&self, key: &K) -> Option<KeyId> {
        self.key_ids.get(key).copied()
    }

    #[inline]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.key_id(key)
            .is_some_and(|id| self.entries.get(id).is_some())
    }

    #[inline]
    pub(crate) fn contains(&self, id: KeyId) -> bool {
        self.entries.get(id).is_some()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.iter().next().is_none()
    }

    #[inline]
    pub(crate) fn get(&self, id: KeyId) -> Option<&ModuleHandle<Arch>> {
        self.entries.get(id).map(|entry| &entry.module)
    }

    #[inline]
    pub(crate) fn meta(&self, id: KeyId) -> Option<&M> {
        self.entries.get(id).map(|entry| &entry.meta)
    }

    #[inline]
    pub(crate) fn meta_mut(&mut self, id: KeyId) -> Option<&mut M> {
        self.entries.get_mut(id).map(|entry| &mut entry.meta)
    }

    #[inline]
    pub(crate) fn load_order(&self) -> impl Iterator<Item = KeyId> + '_ {
        self.load_order.iter().copied()
    }

    #[inline]
    pub(crate) fn direct_deps(&self, id: KeyId) -> Option<&[KeyId]> {
        let entry = self.entries.get(id)?;
        Some(entry.direct_deps.as_ref())
    }
}

impl<K, D: 'static, M, Arch> CommittedStorage<K, D, M, Arch>
where
    K: Clone + Ord,
    Arch: RelocationArch,
{
    pub(crate) fn intern_key(&mut self, key: K) -> KeyId {
        if let Some(id) = self.key_id(&key) {
            return id;
        }

        let key = Arc::new(key);
        let id = self.keys.push(key.clone());
        let previous = self.key_ids.insert(key, id);
        debug_assert!(previous.is_none(), "interned key inserted twice");
        id
    }

    #[inline]
    pub(crate) fn insert_new(
        &mut self,
        id: KeyId,
        module: ModuleHandle<Arch>,
        direct_deps: Box<[KeyId]>,
        meta: M,
    ) -> KeyId {
        assert!(
            self.keys.get(id).is_some(),
            "linked storage inserted an unknown key id"
        );
        assert!(
            self.entries.get(id).is_none(),
            "linked storage inserted a duplicate key"
        );
        self.load_order.push(id);
        let previous = self.entries.insert(
            id,
            StoredEntry {
                module,
                direct_deps,
                meta,
                _marker: core::marker::PhantomData,
            },
        );
        debug_assert!(previous.is_none(), "linked storage precheck must be exact");
        id
    }

    #[inline]
    pub(crate) fn remove(&mut self, id: KeyId) -> Option<(ModuleHandle<Arch>, Box<[KeyId]>, M)> {
        let removed = self.entries.remove(id)?;
        if let Some(idx) = self.load_order.iter().position(|existing| *existing == id) {
            self.load_order.remove(idx);
        }
        Some((removed.module, removed.direct_deps, removed.meta))
    }
}

struct StoredEntry<D: 'static, M = (), Arch: RelocationArch = crate::arch::NativeArch> {
    module: ModuleHandle<Arch>,
    direct_deps: Box<[KeyId]>,
    meta: M,
    _marker: core::marker::PhantomData<fn() -> D>,
}
