use super::{LayoutPhysicalImage, LayoutSectionDataId, MemoryLayoutPlan};
use crate::{
    Result,
    image::{ScannedDylib, ScannedSectionId},
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

/// A pass that inspects or rewrites a pre-map global link plan.
pub trait LinkPass<K: Ord, D: 'static, Q: ?Sized> {
    /// Executes the pass over the current plan and caller-supplied query state.
    fn run(&mut self, plan: &mut LinkPlan<K, D>, queries: &mut Q) -> Result<()>;
}

impl<K: Ord, D: 'static, Q: ?Sized, F> LinkPass<K, D, Q> for F
where
    F: FnMut(&mut LinkPlan<K, D>, &mut Q) -> Result<()>,
{
    #[inline]
    fn run(&mut self, plan: &mut LinkPlan<K, D>, queries: &mut Q) -> Result<()> {
        (self)(plan, queries)
    }
}

/// An ordered collection of [`LinkPass`]es.
///
/// This is the pass manager used with a discovered [`LinkPlan`] after
/// [`super::ScanContext`] finishes metadata discovery and before any module is
/// mapped into memory.
pub struct LinkPipeline<'a, K: Ord, D: 'static, Q: ?Sized> {
    passes: Vec<&'a mut dyn LinkPass<K, D, Q>>,
}

impl<'a, K: Ord, D: 'static, Q: ?Sized> Default for LinkPipeline<'a, K, D, Q> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K: Ord, D: 'static, Q: ?Sized> LinkPipeline<'a, K, D, Q> {
    /// Creates an empty pipeline.
    #[inline]
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    /// Appends a pass to the pipeline.
    #[inline]
    pub fn push(&mut self, pass: &'a mut dyn LinkPass<K, D, Q>) -> &mut Self {
        self.passes.push(pass);
        self
    }

    /// Runs the pipeline with caller-supplied query state.
    pub fn run(&mut self, plan: &mut LinkPlan<K, D>, queries: &mut Q) -> Result<()> {
        for pass in &mut self.passes {
            pass.run(plan, queries)?;
        }
        Ok(())
    }
}

pub(crate) struct PlannedModule<K, D: 'static> {
    pub(crate) module: Option<ScannedDylib<D>>,
    pub(crate) direct_deps: Box<[K]>,
}

impl<K, D: 'static> PlannedModule<K, D> {
    #[inline]
    pub(crate) fn new(module: Option<ScannedDylib<D>>, direct_deps: Box<[K]>) -> Self {
        Self {
            module,
            direct_deps,
        }
    }
}

/// A global, pre-map link plan built from metadata discovery.
///
/// This plan owns the discovered logical module graph and accumulates later
/// planning decisions such as custom relocation-scope order, physical
/// memory-layout plans, or future materialization policies.
pub struct LinkPlan<K, D: 'static> {
    root: K,
    group_order: Vec<K>,
    entries: BTreeMap<K, PlannedModule<K, D>>,
    scope_overrides: BTreeMap<K, Box<[K]>>,
    memory_layout: Option<MemoryLayoutPlan<K>>,
}

impl<K, D: 'static> LinkPlan<K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn new(
        root: K,
        group_order: Vec<K>,
        entries: BTreeMap<K, PlannedModule<K, D>>,
    ) -> Self {
        Self {
            root,
            group_order,
            entries,
            scope_overrides: BTreeMap::new(),
            memory_layout: None,
        }
    }

    /// Returns the canonical root key of the plan.
    #[inline]
    pub fn root_key(&self) -> &K {
        &self.root
    }

    /// Returns the breadth-first module order discovered from the root.
    #[inline]
    pub fn group_order(&self) -> &[K] {
        &self.group_order
    }

    /// Returns whether the plan contains `key`.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// Returns the scanned metadata for `key`.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&ScannedDylib<D>> {
        self.entries
            .get(key)
            .and_then(|entry| entry.module.as_ref())
    }

    /// Returns the scanned metadata for `key` mutably.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut ScannedDylib<D>> {
        self.entries
            .get_mut(key)
            .and_then(|entry| entry.module.as_mut())
    }

    /// Returns the canonical direct dependencies of `key`.
    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<&[K]> {
        self.entries
            .get(key)
            .map(|entry| entry.direct_deps.as_ref())
    }

    /// Iterates over all modules in the plan.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&K, &ScannedDylib<D>)> {
        self.entries
            .iter()
            .filter_map(|(key, entry)| entry.module.as_ref().map(|module| (key, module)))
    }

    /// Iterates over all modules in the plan mutably.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut ScannedDylib<D>)> {
        self.entries
            .iter_mut()
            .filter_map(|(key, entry)| entry.module.as_mut().map(|module| (&*key, module)))
    }

    /// Returns the planned relocation-scope order for `key`.
    ///
    /// By default this is the discovery-time breadth-first order.
    #[inline]
    pub fn scope_keys(&self, key: &K) -> &[K] {
        self.scope_overrides
            .get(key)
            .map(Box::as_ref)
            .unwrap_or(self.group_order.as_slice())
    }

    /// Returns the optional physical memory-layout plan associated with this graph.
    #[inline]
    pub fn memory_layout(&self) -> Option<&MemoryLayoutPlan<K>> {
        self.memory_layout.as_ref()
    }

    /// Returns the optional physical memory-layout plan mutably.
    #[inline]
    pub fn memory_layout_mut(&mut self) -> Option<&mut MemoryLayoutPlan<K>> {
        self.memory_layout.as_mut()
    }
}

impl<K, D: 'static> LinkPlan<K, D>
where
    K: Clone + Ord,
{
    /// Overrides the relocation-scope order for one module.
    #[inline]
    pub fn set_scope<I>(&mut self, key: &K, scope: I)
    where
        I: Into<Box<[K]>>,
    {
        self.scope_overrides.insert(key.clone(), scope.into());
    }

    /// Clears a previously installed scope override.
    #[inline]
    pub fn clear_scope(&mut self, key: &K) -> Option<Box<[K]>> {
        self.scope_overrides.remove(key)
    }

    /// Replaces the current physical memory-layout plan.
    #[inline]
    pub fn replace_memory_layout(
        &mut self,
        layout: MemoryLayoutPlan<K>,
    ) -> Option<MemoryLayoutPlan<K>> {
        self.memory_layout.replace(layout)
    }

    /// Clears the current physical memory-layout plan.
    #[inline]
    pub fn clear_memory_layout(&mut self) -> Option<MemoryLayoutPlan<K>> {
        self.memory_layout.take()
    }

    /// Builds a section-granularity layout seed from every allocatable section.
    ///
    /// Each module gets one [`ModuleLayout`] where every allocatable section is
    /// represented as a distinct planned section. No physical placement is
    /// assigned yet.
    pub fn build_section_layout(&self) -> MemoryLayoutPlan<K> {
        MemoryLayoutPlan::seed_from_scanned_modules(self.iter())
    }

    /// Returns the existing memory-layout plan or seeds one from alloc sections.
    pub fn ensure_section_layout(&mut self) -> &mut MemoryLayoutPlan<K> {
        if self.memory_layout.is_none() {
            self.memory_layout = Some(self.build_section_layout());
        }
        self.memory_layout
            .as_mut()
            .expect("memory layout must exist after seeding")
    }

    /// Materializes one section's data into the current memory-layout plan on demand.
    pub fn ensure_section_data(
        &mut self,
        key: &K,
        section: ScannedSectionId,
    ) -> Result<Option<LayoutSectionDataId>> {
        let Some(layout_section) = self
            .memory_layout
            .as_ref()
            .and_then(|layout| layout.module_section_id(key, section))
        else {
            return Ok(None);
        };

        if let Some(data_id) = self
            .memory_layout
            .as_ref()
            .and_then(|layout| layout.section_metadata(layout_section))
            .and_then(|metadata| metadata.data())
        {
            return Ok(Some(data_id));
        }

        let Some(snapshot) = ({
            let Some(module) = self.get_mut(key) else {
                return Ok(None);
            };
            module.snapshot_memory_section(section)?
        }) else {
            return Ok(None);
        };

        Ok(self
            .memory_layout
            .as_mut()
            .and_then(|layout| layout.install_section_data(layout_section, snapshot)))
    }

    pub(crate) fn prepare_layout(&mut self) -> Result<()> {
        let keys = self.group_order().to_vec();
        self.ensure_section_layout();

        for key in keys {
            let relocation_sections = {
                let Some(module) = self.get_mut(&key) else {
                    continue;
                };
                module.snapshot_relocation_sections()?
            };

            let layout = self
                .memory_layout_mut()
                .expect("layout preparation requires a seeded memory layout");
            for section in relocation_sections.into_vec() {
                layout.push_relocation_section(&key, section);
            }
        }

        Ok(())
    }

    #[inline]
    pub(crate) fn finalize_layout(&mut self) {
        if let Some(layout) = self.memory_layout_mut() {
            layout.rebuild_addresses();
        }
    }

    /// Materializes the currently planned physical arenas into byte buffers.
    ///
    /// This keeps logical DSO ownership in the plan, but realizes the chosen
    /// region/arena packing as shared physical arena bytes.
    pub fn materialize_physical_image(&mut self) -> Result<Option<LayoutPhysicalImage<K>>> {
        let jobs = {
            let Some(layout) = self.memory_layout.as_ref() else {
                return Ok(None);
            };
            if !layout.has_region_placements() {
                return Ok(None);
            }

            self.group_order()
                .iter()
                .flat_map(|key| {
                    layout.module(key).into_iter().flat_map(move |module| {
                        module
                            .section_entries()
                            .map(move |(id, _)| (key.clone(), *id))
                    })
                })
                .filter(|(key, section)| layout.section_placement(key, *section).is_some())
                .collect::<Vec<_>>()
        };

        for (key, section) in jobs {
            let _ = self.ensure_section_data(&key, section)?;
        }

        self.memory_layout
            .as_ref()
            .expect("physical image materialization requires a memory layout")
            .build_physical_image()
    }
}
