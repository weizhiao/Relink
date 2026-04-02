use alloc::vec::Vec;
use core::{
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

/// A dense, append-only arena keyed by typed entity references.
///
/// This is a small self-contained equivalent of the arena style used in
/// Cranelift: ids are dense indices and storage is backed by a single `Vec<T>`.
#[derive(Debug, Clone)]
pub struct EntityArena<K, V> {
    values: Vec<V>,
    marker: PhantomData<fn() -> K>,
}

impl<K, V> Default for EntityArena<K, V> {
    #[inline]
    fn default() -> Self {
        Self {
            values: Vec::new(),
            marker: PhantomData,
        }
    }
}

impl<K, V> EntityArena<K, V>
where
    K: EntityRef,
{
    /// Creates an empty arena.
    #[inline]
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of stored values.
    #[inline]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns whether the arena is empty.
    #[inline]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Appends one value and returns its typed id.
    #[inline]
    pub fn push(&mut self, value: V) -> K {
        let key = K::new(self.values.len());
        self.values.push(value);
        key
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

    /// Iterates over ids and values together mutably.
    #[inline]
    #[allow(dead_code)]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (K, &mut V)> {
        self.values
            .iter_mut()
            .enumerate()
            .map(|(index, value)| (K::new(index), value))
    }

    /// Returns the underlying dense slice of values.
    #[inline]
    pub fn as_slice(&self) -> &[V] {
        &self.values
    }
}

impl<K, V> Index<K> for EntityArena<K, V>
where
    K: EntityRef,
{
    type Output = V;

    #[inline]
    fn index(&self, index: K) -> &Self::Output {
        self.get(index)
            .expect("entity arena indexed with an out-of-bounds entity id")
    }
}

impl<K, V> IndexMut<K> for EntityArena<K, V>
where
    K: EntityRef,
{
    #[inline]
    fn index_mut(&mut self, index: K) -> &mut Self::Output {
        self.get_mut(index)
            .expect("entity arena indexed with an out-of-bounds entity id")
    }
}

#[cfg(test)]
mod tests {
    use super::EntityArena;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct TestId(usize);

    super::entity_ref!(TestId);

    #[test]
    fn entity_arena_returns_dense_index_ids() {
        let mut arena = EntityArena::<TestId, u32>::new();

        let first = arena.push(7);
        let second = arena.push(11);

        assert_eq!(first, TestId(0));
        assert_eq!(second, TestId(1));
        assert_eq!(arena.get(second), Some(&11));
    }

    #[test]
    fn entity_arena_supports_index_syntax() {
        let mut arena = EntityArena::<TestId, u32>::new();
        let first = arena.push(7);

        assert_eq!(arena[first], 7);
        arena[first] = 13;
        assert_eq!(arena[first], 13);
    }
}
