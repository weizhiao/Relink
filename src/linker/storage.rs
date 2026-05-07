use crate::image::LoadedModule;
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::borrow::Borrow;

pub(crate) struct CommittedStorage<K, D: 'static, M = ()> {
    pub(crate) entries: BTreeMap<K, CommittedEntry<K, D, M>>,
    pub(crate) load_order: Vec<K>,
}

impl<K, D: 'static, M> CommittedStorage<K, D, M> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            load_order: Vec::new(),
        }
    }
}

impl<K, D: 'static, M> CommittedStorage<K, D, M>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entries.contains_key(key)
    }

    #[inline]
    pub(crate) fn entry<Q>(&self, key: &Q) -> Option<&CommittedEntry<K, D, M>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entries.get(key)
    }

    #[inline]
    pub(crate) fn entry_mut<Q>(&mut self, key: &Q) -> Option<&mut CommittedEntry<K, D, M>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entries.get_mut(key)
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    pub(crate) fn get<Q>(&self, key: &Q) -> Option<&LoadedModule<D>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entry(key).map(|entry| &entry.module)
    }

    #[inline]
    pub(crate) fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &CommittedEntry<K, D, M>)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entries.get_key_value(key)
    }

    #[inline]
    pub(crate) fn view(&self) -> CommittedStorageView<'_, K, D, M> {
        CommittedStorageView {
            entries: &self.entries,
        }
    }

    #[inline]
    pub(crate) fn load_order(&self) -> &[K] {
        &self.load_order
    }
}

impl<K, D: 'static, M> CommittedStorage<K, D, M>
where
    K: Clone + Ord,
{
    #[inline]
    pub(crate) fn insert_new(&mut self, key: K, entry: CommittedEntry<K, D, M>) {
        self.load_order.push(key.clone());
        let previous = self.entries.insert(key, entry);
        debug_assert!(
            previous.is_none(),
            "linked storage inserted a duplicate key"
        );
    }

    #[inline]
    pub(crate) fn remove<Q>(&mut self, key: &Q) -> Option<CommittedEntry<K, D, M>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let removed = self.entries.remove(key)?;
        if let Some(idx) = self
            .load_order
            .iter()
            .position(|existing| <K as Borrow<Q>>::borrow(existing) == key)
        {
            self.load_order.remove(idx);
        }
        Some(removed)
    }
}

pub(crate) struct CommittedStorageView<'a, K, D: 'static, M = ()> {
    entries: &'a BTreeMap<K, CommittedEntry<K, D, M>>,
}

impl<'a, K, D: 'static, M> Copy for CommittedStorageView<'a, K, D, M> {}

impl<'a, K, D: 'static, M> Clone for CommittedStorageView<'a, K, D, M> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static, M> CommittedStorageView<'a, K, D, M>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entries.contains_key(key)
    }

    #[inline]
    pub(crate) fn entry<Q>(&self, key: &Q) -> Option<&'a CommittedEntry<K, D, M>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entries.get(key)
    }

    #[inline]
    pub(crate) fn direct_deps<Q>(&self, key: &Q) -> Option<&'a [K]>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.entry(key).map(|entry| entry.direct_deps.as_ref())
    }
}

pub(crate) struct CommittedEntry<K, D: 'static, M = ()> {
    pub(crate) module: LoadedModule<D>,
    pub(crate) direct_deps: Box<[K]>,
    pub(crate) meta: M,
}

impl<K, D: 'static, M> Clone for CommittedEntry<K, D, M>
where
    K: Clone,
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
            meta: self.meta.clone(),
        }
    }
}

impl<K, D: 'static, M> CommittedEntry<K, D, M> {
    #[inline]
    pub(crate) fn new(module: LoadedModule<D>, direct_deps: Box<[K]>, meta: M) -> Self {
        Self {
            module,
            direct_deps,
            meta,
        }
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (LoadedModule<D>, Box<[K]>, M) {
        (self.module, self.direct_deps, self.meta)
    }
}
