use super::storage::{StagedEntry, StagedStorage};
use crate::image::{LoadedCore, RawDylib};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PendingState {
    Unresolved,
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
    pub(crate) group_order: Vec<K>,
    pub(crate) scope_overrides: BTreeMap<K, Box<[K]>>,
}

impl<K, D: 'static> LoadSession<K, D> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            staged: StagedStorage::new(),
            group_order: Vec::new(),
            scope_overrides: BTreeMap::new(),
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
    pub(crate) fn pending_entry(&self, key: &K) -> &PendingEntry<K, D> {
        self.pending
            .get(key)
            .expect("missing module while resolving dependencies")
    }

    #[inline]
    pub(crate) fn pending_entry_mut(&mut self, key: &K) -> &mut PendingEntry<K, D> {
        self.pending
            .get_mut(key)
            .expect("missing module while resolving dependencies")
    }

    #[inline]
    pub(crate) fn pending_state(&self, key: &K) -> PendingState {
        self.pending_entry(key).state
    }

    #[inline]
    pub(crate) fn scope_keys(&self, key: &K) -> &[K] {
        self.scope_overrides
            .get(key)
            .map(Box::as_ref)
            .unwrap_or(self.group_order.as_slice())
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
    pub(crate) fn insert_pending_resolved(
        &mut self,
        key: K,
        raw: RawDylib<D>,
        direct_deps: Box<[K]>,
    ) {
        self.pending.insert(
            key,
            PendingEntry {
                raw,
                direct_deps,
                state: PendingState::Resolved,
            },
        );
    }

    #[inline]
    pub(crate) fn insert_staged(&mut self, key: K, module: LoadedCore<D>, direct_deps: Box<[K]>) {
        self.staged
            .insert(StagedEntry::new(key, module, direct_deps));
    }

    #[inline]
    pub(crate) fn set_scope_override(&mut self, key: K, scope: Box<[K]>) {
        self.scope_overrides.insert(key, scope);
    }
}

pub(crate) fn walk_breadth_first<K, E, F>(
    queue: &mut Vec<K>,
    mut visit: F,
) -> core::result::Result<(), E>
where
    K: Clone,
    F: FnMut(&K, &mut Vec<K>) -> core::result::Result<(), E>,
{
    let mut cursor = 0;

    while cursor < queue.len() {
        let key = queue[cursor].clone();
        cursor += 1;
        visit(&key, queue)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LoadSession, walk_breadth_first};
    use alloc::{collections::BTreeMap, vec, vec::Vec};

    #[test]
    fn breadth_first_walk_visits_siblings_before_descendants() {
        let graph = BTreeMap::from([
            ("A", vec!["B", "C"]),
            ("B", vec!["D"]),
            ("C", Vec::new()),
            ("D", Vec::new()),
        ]);
        let mut queue = vec!["A"];
        let mut visited = Vec::new();

        walk_breadth_first(&mut queue, |key, queue| {
            visited.push(*key);
            queue.extend(graph.get(key).into_iter().flatten().copied());
            Ok::<_, ()>(())
        })
        .unwrap();

        assert_eq!(visited, vec!["A", "B", "C", "D"]);
    }

    #[test]
    fn scope_override_defaults_to_group_order() {
        let mut session = LoadSession::<&'static str, ()>::new();
        session.group_order = vec!["root", "dep"];

        assert_eq!(session.scope_keys(&"root"), ["root", "dep"]);

        session.set_scope_override("root", vec!["dep"].into_boxed_slice());
        assert_eq!(session.scope_keys(&"root"), ["dep"]);

        assert_eq!(
            session.scope_overrides.remove(&"root"),
            Some(vec!["dep"].into_boxed_slice())
        );
        assert_eq!(session.scope_keys(&"root"), ["root", "dep"]);
    }
}
