use crate::image::LoadedCore;
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

pub(crate) struct CommittedStorage<K, D: 'static> {
    pub(crate) entries: BTreeMap<K, CommittedEntry<K, D>>,
    pub(crate) load_order: Vec<K>,
}

impl<K, D: 'static> CommittedStorage<K, D> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            load_order: Vec::new(),
        }
    }
}

impl<K, D: 'static> CommittedStorage<K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    #[inline]
    pub(crate) fn entry(&self, key: &K) -> Option<&CommittedEntry<K, D>> {
        self.entries.get(key)
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    pub(crate) fn get(&self, key: &K) -> Option<&LoadedCore<D>> {
        self.entry(key).map(|entry| &entry.module)
    }

    #[inline]
    pub(crate) fn view(&self) -> CommittedStorageView<'_, K, D> {
        CommittedStorageView {
            entries: &self.entries,
        }
    }

    #[inline]
    pub(crate) fn load_order(&self) -> &[K] {
        &self.load_order
    }
}

impl<K, D: 'static> CommittedStorage<K, D>
where
    K: Clone + Ord,
{
    #[inline]
    pub(crate) fn insert_new(&mut self, key: K, entry: CommittedEntry<K, D>) {
        self.load_order.push(key.clone());
        let previous = self.entries.insert(key, entry);
        debug_assert!(
            previous.is_none(),
            "linked storage inserted a duplicate key"
        );
    }

    #[inline]
    pub(crate) fn remove(&mut self, key: &K) -> Option<CommittedEntry<K, D>> {
        let removed = self.entries.remove(key)?;
        if let Some(idx) = self.load_order.iter().position(|existing| existing == key) {
            self.load_order.remove(idx);
        }
        Some(removed)
    }
}

pub(crate) struct CommittedStorageView<'a, K, D: 'static> {
    entries: &'a BTreeMap<K, CommittedEntry<K, D>>,
}

impl<'a, K, D: 'static> Copy for CommittedStorageView<'a, K, D> {}

impl<'a, K, D: 'static> Clone for CommittedStorageView<'a, K, D> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static> CommittedStorageView<'a, K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    #[inline]
    pub(crate) fn entry(&self, key: &K) -> Option<&'a CommittedEntry<K, D>> {
        self.entries.get(key)
    }

    #[inline]
    pub(crate) fn direct_deps(&self, key: &K) -> Option<&'a [K]> {
        self.entry(key).map(|entry| entry.direct_deps.as_ref())
    }

    #[inline]
    pub(crate) fn get(&self, key: &K) -> Option<&'a LoadedCore<D>> {
        self.entry(key).map(|entry| &entry.module)
    }
}

pub(crate) struct StagedStorage<K, D: 'static> {
    pub(crate) entries: BTreeMap<K, StagedEntry<K, D>>,
}

impl<K, D: 'static> StagedStorage<K, D> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<K, D: 'static> StagedStorage<K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    #[inline]
    pub(crate) fn view(&self) -> StagedStorageView<'_, K, D> {
        StagedStorageView {
            entries: &self.entries,
        }
    }
}

impl<K, D: 'static> StagedStorage<K, D>
where
    K: Clone + Ord,
{
    #[inline]
    pub(crate) fn insert(&mut self, entry: StagedEntry<K, D>) {
        let previous = self.entries.insert(entry.key.clone(), entry);
        debug_assert!(
            previous.is_none(),
            "linked storage inserted a duplicate key"
        );
    }
}

pub(crate) struct StagedStorageView<'a, K, D: 'static> {
    entries: &'a BTreeMap<K, StagedEntry<K, D>>,
}

impl<'a, K, D: 'static> Copy for StagedStorageView<'a, K, D> {}

impl<'a, K, D: 'static> Clone for StagedStorageView<'a, K, D> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static> StagedStorageView<'a, K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    #[inline]
    pub(crate) fn entry(&self, key: &K) -> Option<&'a StagedEntry<K, D>> {
        self.entries.get(key)
    }

    #[inline]
    pub(crate) fn direct_deps(&self, key: &K) -> Option<&'a [K]> {
        self.entry(key).map(|entry| entry.direct_deps.as_ref())
    }

    #[inline]
    pub(crate) fn get(&self, key: &K) -> Option<&'a LoadedCore<D>> {
        self.entry(key).map(|entry| &entry.module)
    }
}

pub(crate) struct CommittedEntry<K, D: 'static> {
    pub(crate) module: LoadedCore<D>,
    pub(crate) direct_deps: Box<[K]>,
}

impl<K, D: 'static> Clone for CommittedEntry<K, D>
where
    K: Clone,
{
    fn clone(&self) -> Self {
        Self {
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
        }
    }
}

impl<K, D: 'static> CommittedEntry<K, D> {
    #[inline]
    pub(crate) fn new(module: LoadedCore<D>, direct_deps: Box<[K]>) -> Self {
        Self {
            module,
            direct_deps,
        }
    }
}

pub(crate) struct StagedEntry<K, D: 'static> {
    pub(crate) key: K,
    pub(crate) module: LoadedCore<D>,
    pub(crate) direct_deps: Box<[K]>,
}

impl<K, D: 'static> Clone for StagedEntry<K, D>
where
    K: Clone,
{
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
        }
    }
}

impl<K, D: 'static> StagedEntry<K, D> {
    #[inline]
    pub(crate) fn new(key: K, module: LoadedCore<D>, direct_deps: Box<[K]>) -> Self {
        Self {
            key,
            module,
            direct_deps,
        }
    }
}
