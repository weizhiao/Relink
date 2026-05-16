use super::{request::DependencyOwner, storage::KeyId};
use crate::{image::ModuleHandle, input::Path, relocation::RelocationArch};
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
    pub(crate) module: ModuleHandle<Arch>,
    pub(crate) direct_deps: Box<[KeyId]>,
    _marker: core::marker::PhantomData<fn() -> D>,
}

impl<D: 'static, Arch> Clone for ReadyCommit<D, Arch>
where
    Arch: RelocationArch,
{
    fn clone(&self) -> Self {
        Self {
            module: self.module.clone(),
            direct_deps: self.direct_deps.clone(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<D: 'static, Arch> ReadyCommit<D, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    fn new(module: ModuleHandle<Arch>, direct_deps: Box<[KeyId]>) -> Self {
        Self {
            module,
            direct_deps,
            _marker: core::marker::PhantomData,
        }
    }
}

pub(crate) enum ModulePayload<P, Arch: RelocationArch> {
    Dynamic(P),
    Synthetic(ModuleHandle<Arch>),
}

impl<P, Arch> DependencyOwner for ModulePayload<P, Arch>
where
    P: DependencyOwner,
    Arch: RelocationArch,
{
    #[inline]
    fn path(&self) -> &Path {
        match self {
            Self::Dynamic(module) => module.path(),
            Self::Synthetic(module) => Path::new(module.name()),
        }
    }

    #[inline]
    fn name(&self) -> &str {
        match self {
            Self::Dynamic(module) => module.name(),
            Self::Synthetic(module) => module.name(),
        }
    }

    #[inline]
    fn rpath(&self) -> Option<&str> {
        match self {
            Self::Dynamic(module) => module.rpath(),
            Self::Synthetic(_) => None,
        }
    }

    #[inline]
    fn runpath(&self) -> Option<&str> {
        match self {
            Self::Dynamic(module) => module.runpath(),
            Self::Synthetic(_) => None,
        }
    }

    #[inline]
    fn interp(&self) -> Option<&str> {
        match self {
            Self::Dynamic(module) => module.interp(),
            Self::Synthetic(_) => None,
        }
    }

    #[inline]
    fn needed_len(&self) -> usize {
        match self {
            Self::Dynamic(module) => module.needed_len(),
            Self::Synthetic(_) => 0,
        }
    }

    #[inline]
    fn needed_lib(&self, index: usize) -> Option<&str> {
        match self {
            Self::Dynamic(module) => module.needed_lib(index),
            Self::Synthetic(_) => None,
        }
    }
}

pub(crate) struct ResolveSession<P, Arch: RelocationArch> {
    pub(crate) entries: BTreeMap<KeyId, GraphEntry<ModulePayload<P, Arch>>>,
    pub(crate) group_order: Vec<KeyId>,
}

impl<P, Arch> ResolveSession<P, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            group_order: Vec::new(),
        }
    }
}

impl<P, Arch> ResolveSession<P, Arch>
where
    Arch: RelocationArch,
{
    #[inline]
    pub(crate) fn contains(&self, id: KeyId) -> bool {
        self.entries.contains_key(&id)
    }

    #[inline]
    pub(crate) fn insert_entry(&mut self, id: KeyId, payload: P) {
        self.entries
            .insert(id, GraphEntry::new(ModulePayload::Dynamic(payload)));
    }

    #[inline]
    pub(crate) fn insert_synthetic_entry(
        &mut self,
        id: KeyId,
        module: ModuleHandle<Arch>,
        direct_deps: Box<[KeyId]>,
    ) {
        self.entries.insert(
            id,
            GraphEntry {
                payload: ModulePayload::Synthetic(module),
                direct_deps: Some(direct_deps),
            },
        );
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
                payload: ModulePayload::Dynamic(payload),
                direct_deps: Some(direct_deps),
            },
        );
    }
}

pub(crate) struct LoadSession<D: 'static, Arch: RelocationArch> {
    pub(crate) resolve: ResolveSession<crate::image::RawDynamic<D, Arch>, Arch>,
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
    pub(crate) fn push_ready<R>(&mut self, id: KeyId, module: R, direct_deps: Box<[KeyId]>)
    where
        R: Into<ModuleHandle<Arch>>,
    {
        let previous = self
            .ready_to_commit
            .insert(id, ReadyCommit::new(module.into(), direct_deps));
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
