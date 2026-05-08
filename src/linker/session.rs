use crate::{image::LoadedCore, relocation::RelocationArch};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

pub(crate) struct GraphEntry<K, P> {
    pub(crate) payload: P,
    pub(crate) direct_deps: Option<Box<[K]>>,
}

impl<K, P> GraphEntry<K, P> {
    #[inline]
    pub(crate) fn new(payload: P) -> Self {
        Self {
            payload,
            direct_deps: None,
        }
    }

    #[inline]
    pub(crate) fn direct_deps(&self) -> Option<&[K]> {
        self.direct_deps.as_deref()
    }

    #[inline]
    pub(crate) fn set_direct_deps(&mut self, direct_deps: Vec<K>) {
        self.direct_deps = Some(direct_deps.into_boxed_slice());
    }
}

pub(crate) struct ReadyCommit<K, D: 'static, Arch: RelocationArch> {
    pub(crate) key: K,
    pub(crate) module: LoadedCore<D, Arch>,
    pub(crate) direct_deps: Box<[K]>,
}

impl<K, D: 'static, Arch> Clone for ReadyCommit<K, D, Arch>
where
    K: Clone,
    Arch: RelocationArch,
{
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
        }
    }
}

impl<K, D: 'static, Arch> ReadyCommit<K, D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    fn new(key: K, module: LoadedCore<D, Arch>, direct_deps: Box<[K]>) -> Self {
        Self {
            key,
            module,
            direct_deps,
        }
    }
}

pub(crate) struct ResolveSession<K, P> {
    pub(crate) entries: BTreeMap<K, GraphEntry<K, P>>,
    pub(crate) group_order: Vec<K>,
}

impl<K, P> ResolveSession<K, P> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            group_order: Vec::new(),
        }
    }
}

impl<K, P> ResolveSession<K, P>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    #[inline]
    pub(crate) fn insert_entry(&mut self, key: K, payload: P) {
        self.entries.insert(key, GraphEntry::new(payload));
    }

    #[inline]
    pub(crate) fn insert_resolved_entry(&mut self, key: K, payload: P, direct_deps: Box<[K]>) {
        self.entries.insert(
            key,
            GraphEntry {
                payload,
                direct_deps: Some(direct_deps),
            },
        );
    }
}

pub(crate) struct LoadSession<K, D: 'static, Arch: RelocationArch> {
    pub(crate) resolve: ResolveSession<K, crate::image::RawDynamic<D, Arch>>,
    pub(crate) ready_to_commit: Vec<ReadyCommit<K, D, Arch>>,
}

impl<K, D: 'static, Arch> LoadSession<K, D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            resolve: ResolveSession::new(),
            ready_to_commit: Vec::new(),
        }
    }
}

impl<K, D: 'static, Arch> LoadSession<K, D, Arch>
where
    K: Ord,
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn insert_resolved_pending(
        &mut self,
        key: K,
        raw: crate::image::RawDynamic<D, Arch>,
        direct_deps: Box<[K]>,
    ) {
        self.resolve.insert_resolved_entry(key, raw, direct_deps);
    }

    #[inline]
    pub(crate) fn push_ready(
        &mut self,
        key: K,
        module: LoadedCore<D, Arch>,
        direct_deps: Box<[K]>,
    ) {
        self.ready_to_commit
            .push(ReadyCommit::new(key, module, direct_deps));
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
