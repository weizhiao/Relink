use alloc::vec::{IntoIter, Vec};
use core::{
    iter::Enumerate,
    marker::PhantomData,
    ops::{Index, IndexMut},
};

/// A typed entity reference backed by a zero-based dense index.
pub trait EntityRef: Copy + Eq {
    /// Creates a new entity reference from a zero-based index.
    fn new(index: usize) -> Self;

    /// Returns the zero-based index represented by this reference.
    fn index(self) -> usize;
}

macro_rules! entity_ref {
    ($name:ident) => {
        impl $name {
            /// Creates a new typed entity reference from a zero-based index.
            #[inline]
            #[allow(dead_code)]
            pub const fn new(index: usize) -> Self {
                Self(index)
            }

            /// Returns the zero-based index represented by this reference.
            #[inline]
            #[allow(dead_code)]
            pub const fn index(self) -> usize {
                self.0
            }
        }

        impl $crate::entity::EntityRef for $name {
            #[inline]
            fn new(index: usize) -> Self {
                Self(index)
            }

            #[inline]
            fn index(self) -> usize {
                self.0
            }
        }
    };
}

pub(crate) use entity_ref;

/// A dense, append-only primary map keyed by typed entity references.
///
/// This is a small self-contained equivalent of the arena style used in
/// Cranelift: ids are dense indices and storage is backed by a single `Vec<T>`.
#[derive(Debug, Clone)]
pub struct PrimaryMap<K, V> {
    values: Vec<V>,
    marker: PhantomData<fn() -> K>,
}

pub struct PrimaryMapIntoIter<K, V> {
    values: Enumerate<IntoIter<V>>,
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
    /// Creates an empty primary map.
    #[inline]
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one value and returns its typed id.
    #[inline]
    pub fn push(&mut self, value: V) -> K {
        let key = K::new(self.values.len());
        self.values.push(value);
        key
    }

    /// Transforms every value while preserving the same dense key space.
    #[inline]
    pub(crate) fn map_values<U>(self, mut f: impl FnMut(K, V) -> U) -> PrimaryMap<K, U> {
        PrimaryMap {
            values: self
                .values
                .into_iter()
                .enumerate()
                .map(|(index, value)| f(K::new(index), value))
                .collect(),
            marker: PhantomData,
        }
    }

    /// Returns one stored value by id.
    #[inline]
    pub fn get(&self, key: K) -> Option<&V> {
        self.values.get(key.index())
    }

    /// Returns one stored value by id mutably.
    #[inline]
    pub fn get_mut(&mut self, key: K) -> Option<&mut V> {
        self.values.get_mut(key.index())
    }

    /// Iterates over ids and values together.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (K, &V)> {
        self.values
            .iter()
            .enumerate()
            .map(|(index, value)| (K::new(index), value))
    }
}

impl<K, V> Iterator for PrimaryMapIntoIter<K, V>
where
    K: EntityRef,
{
    type Item = (K, V);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.values
            .next()
            .map(|(index, value)| (K::new(index), value))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}

impl<K, V> ExactSizeIterator for PrimaryMapIntoIter<K, V> where K: EntityRef {}

impl<K, V> IntoIterator for PrimaryMap<K, V>
where
    K: EntityRef,
{
    type Item = (K, V);
    type IntoIter = PrimaryMapIntoIter<K, V>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        PrimaryMapIntoIter {
            values: self.values.into_iter().enumerate(),
            marker: PhantomData,
        }
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
pub struct SecondaryMap<K, V> {
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
    /// Creates an empty secondary map.
    #[inline]
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts side data for `key`, returning the previous value if present.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let index = key.index();
        if self.values.len() <= index {
            self.values.resize_with(index + 1, || None);
        }
        self.values[index].replace(value)
    }

    /// Removes side data for `key`, returning it if present.
    #[inline]
    pub fn remove(&mut self, key: K) -> Option<V> {
        self.values.get_mut(key.index()).and_then(Option::take)
    }

    /// Returns side data for `key`.
    #[inline]
    pub fn get(&self, key: K) -> Option<&V> {
        self.values.get(key.index()).and_then(Option::as_ref)
    }

    /// Returns side data for `key` mutably.
    #[inline]
    pub fn get_mut(&mut self, key: K) -> Option<&mut V> {
        self.values.get_mut(key.index()).and_then(Option::as_mut)
    }

    /// Iterates over ids and present side-data values together.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (K, &V)> {
        self.values
            .iter()
            .enumerate()
            .filter_map(|(index, value)| value.as_ref().map(|value| (K::new(index), value)))
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

#[cfg(test)]
mod tests {
    use super::{PrimaryMap, SecondaryMap};
    use alloc::vec::Vec;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct TestId(usize);

    super::entity_ref!(TestId);

    #[test]
    fn primary_map_returns_dense_index_ids() {
        let mut arena = PrimaryMap::<TestId, u32>::new();

        let first = arena.push(7);
        let second = arena.push(11);

        assert_eq!(first, TestId(0));
        assert_eq!(second, TestId(1));
        assert_eq!(arena.get(second), Some(&11));
    }

    #[test]
    fn primary_map_supports_index_syntax() {
        let mut arena = PrimaryMap::<TestId, u32>::new();
        let first = arena.push(7);

        assert_eq!(arena[first], 7);
        arena[first] = 13;
        assert_eq!(arena[first], 13);
    }

    #[test]
    fn primary_map_consuming_iterator_yields_keys_and_values() {
        let mut arena = PrimaryMap::<TestId, u32>::new();
        let first = arena.push(7);
        let second = arena.push(11);

        assert_eq!(
            arena.into_iter().collect::<Vec<_>>(),
            [(first, 7), (second, 11)]
        );
    }

    #[test]
    fn secondary_map_tracks_sparse_side_data() {
        let mut map = SecondaryMap::<TestId, &'static str>::new();
        let first = TestId::new(0);
        let third = TestId::new(2);

        assert_eq!(map.insert(third, "three"), None);
        assert_eq!(map.insert(third, "trois"), Some("three"));

        assert_eq!(map.get(first), None);
        assert_eq!(map[third], "trois");
        assert_eq!(map.iter().collect::<Vec<_>>(), [(third, &"trois")]);
    }
}
