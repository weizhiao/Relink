use super::plan::{LinkPlan, PlannedModule};
use crate::{Result, image::ScannedDylib};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::mem;

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
        self.owner.needed_libs()[self.needed_index].as_str()
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
    scratch_group_order: Vec<K>,
    _marker: core::marker::PhantomData<D>,
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
            scratch_group_order: Vec::new(),
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
    pub fn discover<S>(&mut self, key: K, scanner: &mut S) -> Result<LinkPlan<K, D>>
    where
        S: ModuleScanner<K, D>,
    {
        let mut entries = BTreeMap::new();
        let root = stage_discovered_module(scanner.scan(&key)?, &mut entries);
        let mut group_order = mem::take(&mut self.scratch_group_order);

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
                                    .needed_libs()[idx]
                                    .as_str(),
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
            LinkPlan::new(root, mem::take(&mut group_order), modules)
        });
        group_order.clear();
        self.scratch_group_order = group_order;
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

fn walk_breadth_first<K, E, F>(queue: &mut Vec<K>, mut visit: F) -> core::result::Result<(), E>
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
    use super::{ModuleScanner, ResolvedScan, ScanContext};
    use crate::{
        Result,
        elf::{ElfEhdr, ElfHeader},
        image::{ScannedDylib, ScannedDynamicInfo},
        linker::LinkPipeline,
    };
    use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
    use core::cell::RefCell;

    fn dummy_scanned(name: &str, needed: &[&str]) -> ScannedDylib<()> {
        let mut ehdr = unsafe { core::mem::zeroed::<ElfEhdr>() };
        ehdr.e_ident[0..4].copy_from_slice(&elf::abi::ELFMAGIC);
        ehdr.e_ident[elf::abi::EI_CLASS] = crate::elf::E_CLASS;
        ehdr.e_ident[elf::abi::EI_VERSION] = elf::abi::EV_CURRENT;
        ehdr.e_type = elf::abi::ET_DYN as _;
        ehdr.e_machine = crate::arch::EM_ARCH;
        ehdr.e_version = elf::abi::EV_CURRENT as _;
        ehdr.e_ehsize = crate::elf::EHDR_SIZE as _;

        ScannedDylib::from_parts(
            name.into(),
            ElfHeader::from_raw(ehdr).expect("header should parse"),
            Vec::new().into_boxed_slice(),
            None,
            None,
            None,
            needed
                .iter()
                .map(|s| String::from(*s))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            ScannedDynamicInfo::new(false, false),
            (),
        )
    }

    struct GraphScanner {
        graph: BTreeMap<&'static str, Vec<&'static str>>,
    }

    impl ModuleScanner<&'static str, ()> for GraphScanner {
        fn scan(&mut self, key: &&'static str) -> Result<ResolvedScan<&'static str, ()>> {
            Ok(ResolvedScan::new_scanned(
                *key,
                dummy_scanned(key, self.graph.get(key).map_or(&[], Vec::as_slice)),
            ))
        }

        fn resolve(
            &mut self,
            req: &super::ScanRequest<'_, &'static str, ()>,
        ) -> Result<Option<ResolvedScan<&'static str, ()>>> {
            let key = self
                .graph
                .keys()
                .copied()
                .find(|candidate| *candidate == req.needed())
                .expect("dependency should exist in test graph");
            Ok(Some(ResolvedScan::new_scanned(
                key,
                dummy_scanned(key, self.graph.get(key).map_or(&[], Vec::as_slice)),
            )))
        }
    }

    #[test]
    fn discover_builds_breadth_first_metadata_plan() {
        let mut scanner = GraphScanner {
            graph: BTreeMap::from([
                ("root", vec!["a", "b"]),
                ("a", vec!["c"]),
                ("b", vec![]),
                ("c", vec![]),
            ]),
        };
        let mut ctx = ScanContext::new();

        let plan = ctx
            .discover("root", &mut scanner)
            .expect("scan should succeed");

        assert_eq!(plan.root_key(), &"root");
        assert_eq!(plan.group_order(), ["root", "a", "b", "c"]);
        assert_eq!(
            plan.direct_deps(&"root").expect("root deps should exist"),
            ["a", "b"]
        );
        assert_eq!(plan.get(&"a").expect("a should exist").needed_libs(), ["c"]);
    }

    #[test]
    fn discovered_plan_can_be_rewritten_by_link_passes() {
        let mut scanner = GraphScanner {
            graph: BTreeMap::from([("root", vec!["dep"]), ("dep", vec![])]),
        };
        let mut ctx = ScanContext::new();
        let visited = RefCell::new(vec![]);

        let mut pass = |plan: &mut crate::linker::LinkPlan<_, _>| {
            visited.borrow_mut().push("planned");
            plan.set_scope(&"root", vec!["dep", "root"]);
            Ok(())
        };
        let mut pipeline = LinkPipeline::new();
        pipeline.push(&mut pass);

        let mut plan = ctx
            .discover("root", &mut scanner)
            .expect("scan should succeed");
        pipeline
            .run(&mut plan)
            .expect("link pipeline should run after discovery");

        assert_eq!(*visited.borrow(), vec!["planned"]);
        assert_eq!(plan.scope_keys(&"root"), ["dep", "root"]);
    }
}
