use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::{Index, IndexMut},
};

/// A typed entity reference backed by a zero-based dense index.
pub(crate) trait EntityRef: Copy + Eq {
    /// Creates a new entity reference from a zero-based index.
    fn new(index: usize) -> Self;

    /// Returns the zero-based index represented by this reference.
    fn index(self) -> usize;
}

/// Compact set for dense typed entity references.
#[derive(Debug, Clone)]
pub(crate) struct EntitySet<K> {
    values: Vec<bool>,
    marker: PhantomData<fn() -> K>,
}

impl<K> Default for EntitySet<K> {
    #[inline]
    fn default() -> Self {
        Self {
            values: Vec::new(),
            marker: PhantomData,
        }
    }
}

impl<K: EntityRef> EntitySet<K> {
    /// Inserts `key`, returning whether it was not already present.
    pub(crate) fn insert(&mut self, key: K) -> bool {
        let index = key.index();
        if self.values.len() <= index {
            self.values.resize(index + 1, false);
        }
        !core::mem::replace(&mut self.values[index], true)
    }

    /// Returns whether `key` is present.
    #[inline]
    pub(crate) fn contains(&self, key: K) -> bool {
        self.values.get(key.index()).copied().unwrap_or(false)
    }
}

impl<K: EntityRef> FromIterator<K> for EntitySet<K> {
    fn from_iter<T: IntoIterator<Item = K>>(iter: T) -> Self {
        let mut set = Self::default();
        for key in iter {
            set.insert(key);
        }
        set
    }
}

/// A dense, append-only primary map keyed by typed entity references.
///
/// This is a small self-contained equivalent of the arena style used in
/// Cranelift: ids are dense indices and storage is backed by a single `Vec<T>`.
#[derive(Debug, Clone)]
pub(crate) struct PrimaryMap<K, V> {
    values: Vec<V>,
    marker: PhantomData<fn() -> K>,
}

impl<K, V> Default for PrimaryMap<K, V> {
    #[inline]
    fn default() -> Self {
        Self {
            values: Vec::new(),
            marker: PhantomData,
        }
    }
}

impl<K, V> PrimaryMap<K, V>
where
    K: EntityRef,
{
    /// Appends one value and returns its typed id.
    #[inline]
    pub(crate) fn push(&mut self, value: V) -> K {
        let key = K::new(self.values.len());
        self.values.push(value);
        key
    }

    /// Returns one stored value by id.
    #[inline]
    pub(crate) fn get(&self, key: K) -> Option<&V> {
        self.values.get(key.index())
    }

    /// Returns one stored value by id mutably.
    #[inline]
    pub(crate) fn get_mut(&mut self, key: K) -> Option<&mut V> {
        self.values.get_mut(key.index())
    }

    /// Iterates over ids and values together.
    #[cfg(feature = "object")]
    #[inline]
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = (K, &V)> + ExactSizeIterator {
        self.values
            .iter()
            .enumerate()
            .map(|(index, value)| (K::new(index), value))
    }
}

impl<K, V> Index<K> for PrimaryMap<K, V>
where
    K: EntityRef,
{
    type Output = V;

    #[inline]
    fn index(&self, index: K) -> &Self::Output {
        self.get(index)
            .expect("primary map indexed with an out-of-bounds entity id")
    }
}

impl<K, V> IndexMut<K> for PrimaryMap<K, V>
where
    K: EntityRef,
{
    #[inline]
    fn index_mut(&mut self, index: K) -> &mut Self::Output {
        self.get_mut(index)
            .expect("primary map indexed with an out-of-bounds entity id")
    }
}

/// A secondary map keyed by typed entity references produced by a primary map.
///
/// This stores side data for an entity id without duplicating the entity's
/// owning storage or external lookup key. Missing ids are represented by empty
/// slots, so sparse side data does not need placeholder values.
#[derive(Debug, Clone)]
pub(crate) struct SecondaryMap<K, V> {
    values: Vec<Option<V>>,
    marker: PhantomData<fn() -> K>,
}

impl<K, V> Default for SecondaryMap<K, V> {
    #[inline]
    fn default() -> Self {
        Self {
            values: Vec::new(),
            marker: PhantomData,
        }
    }
}

impl<K, V> SecondaryMap<K, V>
where
    K: EntityRef,
{
    /// Inserts side data for `key`, returning the previous value if present.
    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        let index = key.index();
        if self.values.len() <= index {
            self.values.resize_with(index + 1, || None);
        }
        self.values[index].replace(value)
    }

    /// Returns side data for `key`.
    #[inline]
    pub(crate) fn get(&self, key: K) -> Option<&V> {
        self.values.get(key.index()).and_then(Option::as_ref)
    }

    /// Returns side data for `key` mutably.
    #[inline]
    pub(crate) fn get_mut(&mut self, key: K) -> Option<&mut V> {
        self.values.get_mut(key.index()).and_then(Option::as_mut)
    }
}

impl<K, V> Index<K> for SecondaryMap<K, V>
where
    K: EntityRef,
{
    type Output = V;

    #[inline]
    fn index(&self, index: K) -> &Self::Output {
        self.get(index)
            .expect("secondary map indexed with a missing entity id")
    }
}

impl<K, V> IndexMut<K> for SecondaryMap<K, V>
where
    K: EntityRef,
{
    #[inline]
    fn index_mut(&mut self, index: K) -> &mut Self::Output {
        self.get_mut(index)
            .expect("secondary map indexed with a missing entity id")
    }
}
