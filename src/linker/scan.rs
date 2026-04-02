use super::{
    api::{KeyResolver, ResolvedKey},
    plan::{LinkPlan, PlannedModule},
    request::DependencyRequest,
    session::{collect_unique_deps, extend_breadth_first},
    view::LinkContextView,
};
use crate::{
    LinkerError, Loader, Result, UnresolvedDependencyError, image::ScannedDylib, loader::LoadHook,
    os::Mmap, tls::TlsResolver,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

struct ScanEntry<K, D: 'static> {
    module: Option<ScannedDylib<D>>,
    direct_deps: Box<[K]>,
    resolved: bool,
}

impl<K, D: 'static> ScanEntry<K, D> {
    #[inline]
    fn existing() -> Self {
        Self {
            module: None,
            direct_deps: Vec::new().into_boxed_slice(),
            resolved: false,
        }
    }

    #[inline]
    fn scanned(module: ScannedDylib<D>) -> Self {
        Self {
            module: Some(module),
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

    /// Returns the scanned metadata for `key`, when the key belongs to a newly
    /// scanned module in the current discovery session.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&'a ScannedDylib<D>> {
        self.entries
            .get(key)
            .and_then(|entry| entry.module.as_ref())
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
    /// Discovers the root module and all of its dependencies before any of the
    /// newly scanned modules are mapped into memory.
    ///
    /// Visible committed modules may still participate in the resulting graph
    /// through `ResolvedKey::Existing`, but only newly scanned modules
    /// contribute metadata to the returned [`LinkPlan`].
    pub(crate) fn discover<M, H, Tls>(
        &mut self,
        key: K,
        visible: LinkContextView<'_, K, D>,
        loader: &mut Loader<M, H, D, Tls>,
        resolver: &mut impl KeyResolver<'static, K, D>,
    ) -> Result<LinkPlan<K, D>>
    where
        M: Mmap,
        H: LoadHook,
        Tls: TlsResolver,
    {
        let mut entries = BTreeMap::new();
        let root =
            stage_discovered_module(resolver.load_root(&key)?, visible, loader, &mut entries)?;
        let mut group_order = Vec::new();

        let result = extend_breadth_first(&mut group_order, root.clone(), |key| {
            let direct_deps = if entries.get(key).is_some_and(|entry| entry.module.is_some()) {
                let needed_len = entries
                    .get(key)
                    .and_then(|entry| entry.module.as_ref())
                    .expect("missing scan entry while resolving dependencies")
                    .needed_libs()
                    .len();

                collect_unique_deps(needed_len, |idx| {
                    let dependency = {
                        let owner = entries
                            .get(key)
                            .and_then(|entry| entry.module.as_ref())
                            .expect("missing scan entry while building request");
                        let req = DependencyRequest::new_scanned(
                            key,
                            owner,
                            idx,
                            ScanContextView::new(&entries),
                        );
                        resolver.resolve_dependency(&req)?
                    };
                    let dependency = dependency.ok_or_else(|| {
                        let owner = entries
                            .get(key)
                            .and_then(|entry| entry.module.as_ref())
                            .expect("missing scan entry while building error");
                        let req = DependencyRequest::new_scanned(
                            key,
                            owner,
                            idx,
                            ScanContextView::new(&entries),
                        );
                        LinkerError::UnresolvedDependency(Box::new(UnresolvedDependencyError::new(
                            req.owner_name(),
                            req.needed(),
                        )))
                    })?;
                    stage_discovered_module(dependency, visible, loader, &mut entries)
                })?
            } else {
                visible
                    .direct_deps(key)
                    .map_or_else(Vec::new, |deps| deps.to_vec())
            };

            let entry = entries
                .get_mut(key)
                .expect("missing scan entry while storing dependencies");
            entry.direct_deps = direct_deps.clone().into_boxed_slice();
            entry.resolved = true;
            Ok(direct_deps)
        });

        result.map(|()| {
            let entries = entries
                .into_iter()
                .map(|(key, entry)| (key, PlannedModule::new(entry.module, entry.direct_deps)))
                .collect();
            LinkPlan::new(root, group_order, entries)
        })
    }
}

fn stage_discovered_module<K, D: 'static, M, H, Tls>(
    resolved: ResolvedKey<'static, K>,
    visible: LinkContextView<'_, K, D>,
    loader: &mut Loader<M, H, D, Tls>,
    entries: &mut BTreeMap<K, ScanEntry<K, D>>,
) -> Result<K>
where
    K: Clone + Ord,
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
{
    match resolved {
        ResolvedKey::Existing(key) => {
            if entries.contains_key(&key) {
                return Ok(key);
            }
            if !visible.contains_key(&key) {
                return Err(crate::custom_error(
                    "scan resolver referenced an unknown visible key",
                ));
            }
            entries.insert(key.clone(), ScanEntry::existing());
            Ok(key)
        }
        ResolvedKey::Load(key, reader) => {
            if entries.contains_key(&key) || visible.contains_key(&key) {
                return Err(crate::custom_error(
                    "scan resolver attached metadata to an already-known key; use Existing to reuse it",
                ));
            }
            let module = loader.scan_dylib_impl(reader)?;
            entries.insert(key.clone(), ScanEntry::scanned(module));
            Ok(key)
        }
    }
}
