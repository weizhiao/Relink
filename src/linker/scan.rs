use super::{
    plan::{LinkPlan, PlannedModule},
    session::walk_breadth_first,
};
use crate::{Result, image::ScannedDylib};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

/// A module selected during metadata discovery.
pub enum ResolvedScan<K, D: 'static> {
    /// Reuses a module that is already present in the current discovery session.
    Existing(K),
    /// Introduces a newly scanned but still-unmapped shared object.
    Scanned(K, ScannedDylib<D>),
}

impl<K, D> ResolvedScan<K, D> {
    /// Creates a scanned-module result.
    #[inline]
    pub fn new_scanned(key: K, module: ScannedDylib<D>) -> Self {
        Self::Scanned(key, module)
    }

    /// Reuses a module that is already visible in the current discovery session.
    #[inline]
    pub fn existing(key: K) -> Self {
        Self::Existing(key)
    }

    /// Returns the selected key.
    #[inline]
    pub fn key(&self) -> &K {
        match self {
            Self::Existing(key) | Self::Scanned(key, _) => key,
        }
    }
}

/// A single dependency-resolution request emitted during metadata discovery.
pub struct ScanRequest<'a, K, D: 'static> {
    owner_key: &'a K,
    owner: &'a ScannedDylib<D>,
    needed_index: usize,
    context: ScanContextView<'a, K, D>,
}

impl<'a, K, D: 'static> ScanRequest<'a, K, D> {
    #[inline]
    fn new(
        owner_key: &'a K,
        owner: &'a ScannedDylib<D>,
        needed_index: usize,
        context: ScanContextView<'a, K, D>,
    ) -> Self {
        Self {
            owner_key,
            owner,
            needed_index,
            context,
        }
    }

    /// Returns the owner module key.
    #[inline]
    pub fn owner_key(&self) -> &'a K {
        self.owner_key
    }

    /// Returns the owner module metadata.
    #[inline]
    pub fn owner(&self) -> &'a ScannedDylib<D> {
        self.owner
    }

    /// Returns the current `DT_NEEDED` string.
    #[inline]
    pub fn needed(&self) -> &'a str {
        self.owner
            .needed_libs()
            .get(self.needed_index)
            .expect("DT_NEEDED index out of bounds")
    }

    /// Returns the index of the current `DT_NEEDED` entry.
    #[inline]
    pub fn needed_index(&self) -> usize {
        self.needed_index
    }

    /// Returns the owner's `DT_RPATH`.
    #[inline]
    pub fn rpath(&self) -> Option<&'a str> {
        self.owner.rpath()
    }

    /// Returns the owner's `DT_RUNPATH`.
    #[inline]
    pub fn runpath(&self) -> Option<&'a str> {
        self.owner.runpath()
    }

    /// Returns the owner's `PT_INTERP`.
    #[inline]
    pub fn interp(&self) -> Option<&'a str> {
        self.owner.interp()
    }

    /// Returns a read-only view over the currently discovered modules.
    #[inline]
    pub fn context(&self) -> ScanContextView<'a, K, D> {
        self.context
    }
}

/// Resolver callbacks for root metadata and `DT_NEEDED` edges.
pub trait ModuleScanner<K, D: 'static> {
    /// Scans one root module identified by `key`.
    fn scan(&mut self, key: &K) -> Result<ResolvedScan<K, D>>;

    /// Resolves one dependency request during metadata discovery.
    fn resolve(&mut self, req: &ScanRequest<'_, K, D>) -> Result<Option<ResolvedScan<K, D>>>;
}

struct ScanEntry<K, D: 'static> {
    module: ScannedDylib<D>,
    direct_deps: Box<[K]>,
    resolved: bool,
}

impl<K, D: 'static> ScanEntry<K, D> {
    #[inline]
    fn new(module: ScannedDylib<D>) -> Self {
        Self {
            module,
            direct_deps: Vec::new().into_boxed_slice(),
            resolved: false,
        }
    }
}

/// Read-only view of the modules discovered during scan.
pub struct ScanContextView<'a, K, D: 'static> {
    entries: &'a BTreeMap<K, ScanEntry<K, D>>,
}

impl<'a, K, D: 'static> Copy for ScanContextView<'a, K, D> {}

impl<'a, K, D: 'static> Clone for ScanContextView<'a, K, D> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, K, D: 'static> ScanContextView<'a, K, D>
where
    K: Ord,
{
    #[inline]
    fn new(entries: &'a BTreeMap<K, ScanEntry<K, D>>) -> Self {
        Self { entries }
    }

    /// Returns whether the current discovery session already knows `key`.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// Returns the scanned metadata for `key`.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&'a ScannedDylib<D>> {
        self.entries.get(key).map(|entry| &entry.module)
    }

    /// Returns the direct dependencies recorded for `key`, if already resolved.
    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<&'a [K]> {
        self.entries
            .get(key)
            .and_then(|entry| entry.resolved.then_some(entry.direct_deps.as_ref()))
    }
}

/// A one-shot metadata discovery engine for pre-map global planning.
pub struct ScanContext<K, D: 'static> {
    _marker: core::marker::PhantomData<(K, D)>,
}

impl<K, D: 'static> Default for ScanContext<K, D> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<K, D: 'static> ScanContext<K, D> {
    #[inline]
    pub const fn new() -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }
}

impl<K, D: 'static> ScanContext<K, D>
where
    K: Clone + Ord,
{
    /// Discovers the root module and all of its `DT_NEEDED` dependencies
    /// before any of them are mapped into memory.
    ///
    /// Callers may then run pre-map planning passes over the returned
    /// [`LinkPlan`] before materialization begins.
    pub(crate) fn discover<S>(&mut self, key: K, scanner: &mut S) -> Result<LinkPlan<K, D>>
    where
        S: ModuleScanner<K, D>,
    {
        let mut entries = BTreeMap::new();
        let root = stage_discovered_module(scanner.scan(&key)?, &mut entries);
        let mut group_order = Vec::new();

        let result: Result<()> = (|| {
            let mut visited = BTreeSet::new();
            visited.insert(root.clone());
            group_order.push(root.clone());

            walk_breadth_first(&mut group_order, |key, queue| {
                if entries.get(key).is_some_and(|entry| entry.resolved) {
                    return Ok(());
                }

                let needed_len = entries
                    .get(key)
                    .expect("missing scan entry while resolving dependencies")
                    .module
                    .needed_libs()
                    .len();
                let mut direct_deps = Vec::with_capacity(needed_len);

                for idx in 0..needed_len {
                    let dependency = {
                        let owner = &entries
                            .get(key)
                            .expect("missing scan entry while building request")
                            .module;
                        let req = ScanRequest::new(key, owner, idx, ScanContextView::new(&entries));
                        scanner.resolve(&req)?
                    };
                    let dependency = dependency.ok_or_else(|| {
                        crate::LinkerError::UnresolvedDependency(Box::new(
                            crate::UnresolvedDependencyError::new(
                                entries
                                    .get(key)
                                    .expect("missing scan entry while building error")
                                    .module
                                    .name(),
                                entries
                                    .get(key)
                                    .expect("missing scan entry while building error")
                                    .module
                                    .needed_libs()
                                    .get(idx)
                                    .expect("DT_NEEDED index out of bounds"),
                            ),
                        ))
                    })?;
                    let dep_key = stage_discovered_module(dependency, &mut entries);
                    if !direct_deps.iter().any(|existing| existing == &dep_key) {
                        if visited.insert(dep_key.clone()) {
                            queue.push(dep_key.clone());
                        }
                        direct_deps.push(dep_key);
                    }
                }

                let entry = entries
                    .get_mut(key)
                    .expect("missing scan entry while storing dependencies");
                entry.direct_deps = direct_deps.into_boxed_slice();
                entry.resolved = true;
                Ok(())
            })
        })();

        let plan = result.map(|()| {
            let modules = entries
                .into_iter()
                .map(|(key, entry)| (key, PlannedModule::new(entry.module, entry.direct_deps)))
                .collect();
            LinkPlan::new(root, group_order, modules)
        });
        plan
    }
}

fn stage_discovered_module<K, D: 'static>(
    module: ResolvedScan<K, D>,
    entries: &mut BTreeMap<K, ScanEntry<K, D>>,
) -> K
where
    K: Clone + Ord,
{
    match module {
        ResolvedScan::Existing(key) => {
            assert!(
                entries.contains_key(&key),
                "scan resolver referenced an unknown key without attaching metadata"
            );
            key
        }
        ResolvedScan::Scanned(key, module) => {
            assert!(
                !entries.contains_key(&key),
                "scan resolver attached metadata to an already-known key; use ResolvedScan::Existing to reuse it"
            );
            entries.insert(key.clone(), ScanEntry::new(module));
            key
        }
    }
}
