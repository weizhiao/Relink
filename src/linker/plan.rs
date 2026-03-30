use crate::{Result, image::ScannedDylib};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

/// A pass that inspects or rewrites a pre-map global link plan.
pub trait LinkPass<K, D: 'static> {
    /// Executes the pass over the current plan.
    fn run(&mut self, plan: &mut LinkPlan<K, D>) -> Result<()>;
}

impl<K, D: 'static, F> LinkPass<K, D> for F
where
    F: FnMut(&mut LinkPlan<K, D>) -> Result<()>,
{
    #[inline]
    fn run(&mut self, plan: &mut LinkPlan<K, D>) -> Result<()> {
        (self)(plan)
    }
}

/// An ordered collection of [`LinkPass`]es.
///
/// This is the pass manager used with a discovered [`LinkPlan`] after
/// [`super::ScanContext`] finishes metadata discovery and before any module is
/// mapped into memory.
pub struct LinkPipeline<'a, K, D: 'static> {
    passes: Vec<&'a mut dyn LinkPass<K, D>>,
}

impl<'a, K, D: 'static> Default for LinkPipeline<'a, K, D> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K, D: 'static> LinkPipeline<'a, K, D> {
    /// Creates an empty pipeline.
    #[inline]
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    /// Appends a pass to the pipeline.
    #[inline]
    pub fn push(&mut self, pass: &'a mut dyn LinkPass<K, D>) -> &mut Self {
        self.passes.push(pass);
        self
    }

    pub(crate) fn run(&mut self, plan: &mut LinkPlan<K, D>) -> Result<()> {
        for pass in &mut self.passes {
            pass.run(plan)?;
        }
        Ok(())
    }
}

pub(crate) struct PlannedModule<K, D: 'static> {
    pub(crate) module: ScannedDylib<D>,
    pub(crate) direct_deps: Box<[K]>,
}

impl<K, D: 'static> PlannedModule<K, D> {
    #[inline]
    pub(crate) fn new(module: ScannedDylib<D>, direct_deps: Box<[K]>) -> Self {
        Self {
            module,
            direct_deps,
        }
    }
}

/// A global, pre-map link plan built from metadata discovery.
///
/// This plan owns the discovered module graph and accumulates later planning
/// decisions such as custom relocation-scope order or future materialization
/// policies.
pub struct LinkPlan<K, D: 'static> {
    root: K,
    group_order: Vec<K>,
    modules: BTreeMap<K, PlannedModule<K, D>>,
    scope_overrides: BTreeMap<K, Box<[K]>>,
}

impl<K, D: 'static> LinkPlan<K, D>
where
    K: Ord,
{
    #[inline]
    pub(crate) fn new(
        root: K,
        group_order: Vec<K>,
        modules: BTreeMap<K, PlannedModule<K, D>>,
    ) -> Self {
        Self {
            root,
            group_order,
            modules,
            scope_overrides: BTreeMap::new(),
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
        self.modules.contains_key(key)
    }

    /// Returns the scanned metadata for `key`.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&ScannedDylib<D>> {
        self.modules.get(key).map(|entry| &entry.module)
    }

    /// Returns the canonical direct dependencies of `key`.
    #[inline]
    pub fn direct_deps(&self, key: &K) -> Option<&[K]> {
        self.modules
            .get(key)
            .map(|entry| entry.direct_deps.as_ref())
    }

    /// Iterates over all modules in the plan.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&K, &ScannedDylib<D>)> {
        self.modules.iter().map(|(key, entry)| (key, &entry.module))
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
}

#[cfg(test)]
mod tests {
    use super::{LinkPipeline, LinkPlan};
    use alloc::{collections::BTreeMap, vec};
    use core::cell::RefCell;

    #[test]
    fn pipeline_runs_passes_in_order() {
        let modules = BTreeMap::<&'static str, super::PlannedModule<&'static str, ()>>::new();
        let root = "root";
        let visited = RefCell::new(vec![]);

        let mut pass_a = |_: &mut LinkPlan<_, _>| {
            visited.borrow_mut().push("a");
            Ok(())
        };
        let mut pass_b = |plan: &mut LinkPlan<_, _>| {
            visited.borrow_mut().push("b");
            assert_eq!(plan.root_key(), &"root");
            assert_eq!(plan.group_order(), ["root"]);
            assert!(plan.iter().next().is_none());
            Ok(())
        };

        let mut pipeline = LinkPipeline::new();
        pipeline.push(&mut pass_a).push(&mut pass_b);

        let mut plan = LinkPlan::new(root, vec!["root"], modules);
        pipeline.run(&mut plan).expect("pipeline should succeed");

        assert_eq!(*visited.borrow(), vec!["a", "b"]);
    }
}
