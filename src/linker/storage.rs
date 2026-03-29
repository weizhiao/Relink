use crate::image::LoadedCore;
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

pub(crate) struct CommittedStorage<K, D: 'static> {
    pub(crate) index: BTreeMap<K, usize>,
    pub(crate) entries: Vec<CommittedEntry<K, D>>,
}

impl<K, D: 'static> CommittedStorage<K, D> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            index: BTreeMap::new(),
            entries: Vec::new(),
        }
    }
}

impl<K, D: 'static> CommittedStorage<K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }

    #[inline]
    pub(crate) fn entry(&self, key: &K) -> Option<&CommittedEntry<K, D>> {
        self.index
            .get(key)
            .and_then(|&index| self.entries.get(index))
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    #[inline]
    pub(crate) fn get(&self, key: &K) -> Option<&LoadedCore<D>> {
        self.entry(key).map(|entry| &entry.module)
    }

    #[inline]
    pub(crate) fn view(&self) -> CommittedStorageView<'_, K, D> {
        CommittedStorageView {
            index: &self.index,
            entries: &self.entries,
        }
    }
}

impl<K, D: 'static> CommittedStorage<K, D>
where
    K: Clone + Ord,
{
    #[inline]
    pub(crate) fn push_new(&mut self, key: K, entry: CommittedEntry<K, D>) {
        let index = self.entries.len();
        let previous = self.index.insert(key, index);
        debug_assert!(
            previous.is_none(),
            "linked storage inserted a duplicate key"
        );
        self.entries.push(entry);
    }
}

pub(crate) struct CommittedStorageView<'a, K, D: 'static> {
    index: &'a BTreeMap<K, usize>,
    entries: &'a [CommittedEntry<K, D>],
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
        self.index.contains_key(key)
    }

    #[inline]
    pub(crate) fn entry(&self, key: &K) -> Option<&'a CommittedEntry<K, D>> {
        self.index
            .get(key)
            .and_then(|&index| self.entries.get(index))
    }

    #[inline]
    pub(crate) fn direct_deps(&self, key: &K) -> Option<&'a [K]> {
        self.entry(key).map(|entry| entry.direct_deps.as_ref())
    }

    #[inline]
    pub(crate) fn get(&self, key: &K) -> Option<&'a LoadedCore<D>> {
        self.entry(key).map(|entry| &entry.module)
    }

    #[inline]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &'a LoadedCore<D>> {
        self.entries.iter().map(|entry| &entry.module)
    }
}

pub(crate) struct StagedStorage<K, D: 'static> {
    pub(crate) index: BTreeMap<K, usize>,
    pub(crate) entries: Vec<StagedEntry<K, D>>,
}

impl<K, D: 'static> StagedStorage<K, D> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            index: BTreeMap::new(),
            entries: Vec::new(),
        }
    }
}

impl<K, D: 'static> StagedStorage<K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }

    #[inline]
    pub(crate) fn view(&self) -> StagedStorageView<'_, K, D> {
        StagedStorageView {
            index: &self.index,
            entries: &self.entries,
        }
    }
}

impl<K, D: 'static> StagedStorage<K, D>
where
    K: Clone + Ord,
{
    #[inline]
    pub(crate) fn push_new(&mut self, entry: StagedEntry<K, D>) {
        let index = self.entries.len();
        let previous = self.index.insert(entry.key.clone(), index);
        debug_assert!(
            previous.is_none(),
            "linked storage inserted a duplicate key"
        );
        self.entries.push(entry);
    }
}

pub(crate) struct StagedStorageView<'a, K, D: 'static> {
    index: &'a BTreeMap<K, usize>,
    entries: &'a [StagedEntry<K, D>],
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
        self.index.contains_key(key)
    }

    #[inline]
    pub(crate) fn entry(&self, key: &K) -> Option<&'a StagedEntry<K, D>> {
        self.index
            .get(key)
            .and_then(|&index| self.entries.get(index))
    }

    #[inline]
    pub(crate) fn direct_deps(&self, key: &K) -> Option<&'a [K]> {
        self.entry(key).map(|entry| entry.direct_deps.as_ref())
    }

    #[inline]
    pub(crate) fn get(&self, key: &K) -> Option<&'a LoadedCore<D>> {
        self.entry(key).map(|entry| &entry.module)
    }

    #[inline]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &'a LoadedCore<D>> {
        self.entries.iter().map(|entry| &entry.module)
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
    pub(crate) fn new(key: K, module: LoadedCore<D>) -> Self {
        Self {
            key,
            module,
            direct_deps: Vec::new().into_boxed_slice(),
        }
    }

    #[inline]
    pub(crate) fn with_direct_deps(key: K, module: LoadedCore<D>, direct_deps: Box<[K]>) -> Self {
        Self {
            key,
            module,
            direct_deps,
        }
    }
}
