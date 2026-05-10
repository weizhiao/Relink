use super::storage::KeyId;
use crate::{image::LoadedCore, relocation::RelocationArch};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

pub(crate) struct GraphEntry<P> {
    pub(crate) payload: P,
    pub(crate) direct_deps: Option<Box<[KeyId]>>,
}

impl<P> GraphEntry<P> {
    #[inline]
    pub(crate) fn new(payload: P) -> Self {
        Self {
            payload,
            direct_deps: None,
        }
    }

    #[inline]
    pub(crate) fn direct_deps(&self) -> Option<&[KeyId]> {
        self.direct_deps.as_deref()
    }

    #[inline]
    pub(crate) fn set_direct_deps(&mut self, direct_deps: Vec<KeyId>) {
        self.direct_deps = Some(direct_deps.into_boxed_slice());
    }
}

pub(crate) struct ReadyCommit<D: 'static, Arch: RelocationArch> {
    pub(crate) module: LoadedCore<D, Arch>,
    pub(crate) direct_deps: Box<[KeyId]>,
}

impl<D: 'static, Arch> Clone for ReadyCommit<D, Arch>
where
    Arch: RelocationArch,
{
    fn clone(&self) -> Self {
        Self {
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
        }
    }
}

impl<D: 'static, Arch> ReadyCommit<D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    fn new(module: LoadedCore<D, Arch>, direct_deps: Box<[KeyId]>) -> Self {
        Self {
            module,
            direct_deps,
        }
    }
}

pub(crate) struct ResolveSession<P> {
    pub(crate) entries: BTreeMap<KeyId, GraphEntry<P>>,
    pub(crate) group_order: Vec<KeyId>,
}

impl<P> ResolveSession<P> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            group_order: Vec::new(),
        }
    }
}

impl<P> ResolveSession<P> {
    #[inline]
    pub(crate) fn contains(&self, id: KeyId) -> bool {
        self.entries.contains_key(&id)
    }

    #[inline]
    pub(crate) fn insert_entry(&mut self, id: KeyId, payload: P) {
        self.entries.insert(id, GraphEntry::new(payload));
    }

    #[inline]
    pub(crate) fn insert_resolved_entry(
        &mut self,
        id: KeyId,
        payload: P,
        direct_deps: Box<[KeyId]>,
    ) {
        self.entries.insert(
            id,
            GraphEntry {
                payload,
                direct_deps: Some(direct_deps),
            },
        );
    }
}

pub(crate) struct LoadSession<D: 'static, Arch: RelocationArch> {
    pub(crate) resolve: ResolveSession<crate::image::RawDynamic<D, Arch>>,
    pub(crate) ready_to_commit: BTreeMap<KeyId, ReadyCommit<D, Arch>>,
}

impl<D: 'static, Arch> LoadSession<D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            resolve: ResolveSession::new(),
            ready_to_commit: BTreeMap::new(),
        }
    }
}

impl<D: 'static, Arch> LoadSession<D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn insert_resolved_pending(
        &mut self,
        id: KeyId,
        raw: crate::image::RawDynamic<D, Arch>,
        direct_deps: Box<[KeyId]>,
    ) {
        self.resolve.insert_resolved_entry(id, raw, direct_deps);
    }

    #[inline]
    pub(crate) fn push_ready(
        &mut self,
        id: KeyId,
        module: LoadedCore<D, Arch>,
        direct_deps: Box<[KeyId]>,
    ) {
        let previous = self
            .ready_to_commit
            .insert(id, ReadyCommit::new(module, direct_deps));
        debug_assert!(previous.is_none(), "ready commit entries must be unique");
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

pub(crate) fn extend_breadth_first<K, E, F>(
    group_order: &mut Vec<K>,
    root: K,
    mut direct_deps: F,
) -> core::result::Result<(), E>
where
    K: Clone + Ord,
    F: FnMut(&K) -> core::result::Result<Vec<K>, E>,
{
    let mut visited = BTreeSet::new();
    visited.insert(root.clone());
    group_order.push(root);

    walk_breadth_first(group_order, |key, queue| {
        for dep_key in direct_deps(key)? {
            if visited.insert(dep_key.clone()) {
                queue.push(dep_key);
            }
        }
        Ok(())
    })
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
}
