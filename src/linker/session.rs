use crate::{Result, custom_error, image::RawDylib};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use super::storage::{StagedEntry, StagedStorage};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PendingState {
    Unresolved,
    Visiting,
    Resolved,
}

pub(crate) struct PendingEntry<K, D: 'static> {
    pub(crate) raw: RawDylib<D>,
    pub(crate) direct_deps: Box<[K]>,
    pub(crate) state: PendingState,
}

impl<K, D: 'static> PendingEntry<K, D> {
    #[inline]
    fn new(raw: RawDylib<D>) -> Self {
        Self {
            raw,
            direct_deps: Vec::new().into_boxed_slice(),
            state: PendingState::Unresolved,
        }
    }
}

pub(crate) struct LoadSession<K, D: 'static> {
    pub(crate) pending: BTreeMap<K, PendingEntry<K, D>>,
    pub(crate) staged: StagedStorage<K, D>,
}

impl<K, D: 'static> LoadSession<K, D> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            staged: StagedStorage::new(),
        }
    }
}

impl<K, D: 'static> LoadSession<K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn contains_pending(&self, key: &K) -> bool {
        self.pending.contains_key(key)
    }

    #[inline]
    pub(crate) fn contains_staged(&self, key: &K) -> bool {
        self.staged.contains_key(key)
    }

    #[inline]
    pub(crate) fn pending_entry(&self, key: &K) -> Result<&PendingEntry<K, D>> {
        self.pending
            .get(key)
            .ok_or_else(|| custom_error("missing module while resolving dependencies"))
    }

    #[inline]
    pub(crate) fn pending_entry_mut(&mut self, key: &K) -> Result<&mut PendingEntry<K, D>> {
        self.pending
            .get_mut(key)
            .ok_or_else(|| custom_error("missing module while resolving dependencies"))
    }

    #[inline]
    pub(crate) fn pending_state(&self, key: &K) -> Result<PendingState> {
        Ok(self.pending_entry(key)?.state)
    }

    #[inline]
    pub(crate) fn staged_entry(&self, key: &K) -> Option<&StagedEntry<K, D>> {
        self.staged.entry(key)
    }
}

impl<K, D: 'static> LoadSession<K, D>
where
    K: Clone + Ord,
{
    #[inline]
    pub(crate) fn insert_pending(&mut self, key: K, raw: RawDylib<D>) {
        self.pending.insert(key, PendingEntry::new(raw));
    }

    #[inline]
    pub(crate) fn insert_staged(&mut self, entry: StagedEntry<K, D>) {
        self.staged.push_new(entry);
    }
}

pub(crate) fn walk_breadth_first<K, E, F>(root: K, mut visit: F) -> core::result::Result<(), E>
where
    K: Clone,
    F: FnMut(&K, &mut Vec<K>) -> core::result::Result<(), E>,
{
    let mut queue = Vec::new();
    queue.push(root);
    let mut cursor = 0;

    while cursor < queue.len() {
        let key = queue[cursor].clone();
        cursor += 1;
        visit(&key, &mut queue)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::walk_breadth_first;
    use alloc::{collections::BTreeMap, vec, vec::Vec};

    #[test]
    fn breadth_first_walk_visits_siblings_before_descendants() {
        let graph = BTreeMap::from([
            ("A", vec!["B", "C"]),
            ("B", vec!["D"]),
            ("C", Vec::new()),
            ("D", Vec::new()),
        ]);
        let mut visited = Vec::new();

        walk_breadth_first("A", |key, queue| {
            visited.push(*key);
            queue.extend(graph.get(key).into_iter().flatten().copied());
            Ok::<_, ()>(())
        })
        .unwrap();

        assert_eq!(visited, vec!["A", "B", "C", "D"]);
    }
}
