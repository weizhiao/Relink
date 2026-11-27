use super::{
    context::LinkContext,
    storage::{ModuleId, ModuleKey, ModuleLease, ModuleSlot, StoredEntry},
};
use crate::{
    LinkContextError, LinkerError, Result,
    arch::NativeArch,
    entity::{EntitySet, SecondaryMap},
    image::{ModuleHandle, ModuleInstanceId, ModuleScope},
    input::ModuleSourceId,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};

struct PreparedModule<Meta, Arch: RelocationArch> {
    key: ModuleKey,
    instance: ModuleInstanceId,
    module: ModuleHandle<Arch>,
    deps: Box<[ModuleInstanceId]>,
    direct_deps: Box<[ModuleSlot]>,
    retained: ModuleScope<Arch>,
    meta: Meta,
}

/// One module and its direct edges in a graph imported into a [`LinkContext`].
///
/// Dependencies use concrete module instance identities rather than source ids
/// or names. This preserves bindings across unload/reload cycles and remains
/// unambiguous when several modules share a key. Use [`LinkContext::add_alias`]
/// separately for additional names.
pub struct GraphModule<Meta = (), Arch: RelocationArch = NativeArch> {
    key: ModuleKey,
    module: ModuleHandle<Arch>,
    deps: Box<[ModuleInstanceId]>,
    meta: Meta,
}

impl<Arch> GraphModule<(), Arch>
where
    Arch: RelocationArch,
{
    /// Creates a graph node without context-specific metadata.
    #[inline]
    pub fn new(key: impl Into<ModuleKey>, module: impl Into<ModuleHandle<Arch>>) -> Self {
        Self::with_meta(key, module, ())
    }
}

impl<Meta, Arch> GraphModule<Meta, Arch>
where
    Arch: RelocationArch,
{
    /// Creates a graph node with context-specific metadata.
    #[inline]
    pub fn with_meta(
        key: impl Into<ModuleKey>,
        module: impl Into<ModuleHandle<Arch>>,
        meta: Meta,
    ) -> Self {
        Self {
            key: key.into(),
            module: module.into(),
            deps: Box::new([]),
            meta,
        }
    }

    /// Sets the direct dependency instances of this node.
    #[inline]
    pub fn dependencies(mut self, deps: impl IntoIterator<Item = ModuleInstanceId>) -> Self {
        self.deps = deps.into_iter().collect();
        self
    }
}

fn collect_modules<Arch, Tls, TargetMeta, SourceMeta>(
    target: &LinkContext<TargetMeta, Arch, Tls>,
    source: &LinkContext<SourceMeta, Arch, Tls>,
    slot: ModuleSlot,
    visited: &mut EntitySet<ModuleSlot>,
    mapped: &mut SecondaryMap<ModuleSlot, ModuleSlot>,
    modules: &mut Vec<ModuleSlot>,
    bindings: &mut Vec<(ModuleKey, ModuleSlot)>,
) -> Result<()>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    if !visited.insert(slot) {
        return Ok(());
    }

    let module = source
        .committed
        .module(slot)
        .expect("import traversal must only contain committed modules");
    target.domain_id().ensure(module.handle().domain_id())?;
    let key = module.entry_key();

    if let Some(target_slot) = target
        .committed
        .module_for_source(module.handle().source_id())
    {
        let target_module = target
            .committed
            .module(target_slot)
            .expect("source index must refer to a committed module");
        if target_module.handle().state().instance_id() != module.handle().state().instance_id() {
            return Err(LinkerError::context(LinkContextError::SourceOccupied {
                source: module.handle().source_id(),
            })
            .into());
        }
        bindings.push((key.clone(), target_slot));
        mapped.insert(slot, target_slot);
        return Ok(());
    }

    for dep in module.direct_deps().iter().copied() {
        collect_modules(target, source, dep, visited, mapped, modules, bindings)?;
    }
    let providers = module.handle().state().with_effects(|bindings, pins| {
        bindings
            .iter()
            .chain(pins)
            .map(|binding| {
                source
                    .committed
                    .module_for_binding(*binding)
                    .expect("bound module must remain committed with its dependent")
            })
            .collect::<Vec<_>>()
    });
    for dep in providers {
        collect_modules(target, source, dep, visited, mapped, modules, bindings)?;
    }
    modules.push(slot);
    Ok(())
}

fn copy_modules<Arch, Tls, TargetMeta, SourceMeta>(
    target: &mut LinkContext<TargetMeta, Arch, Tls>,
    source: &LinkContext<SourceMeta, Arch, Tls>,
    modules: &[ModuleSlot],
    mapped: &SecondaryMap<ModuleSlot, ModuleSlot>,
    bindings: Vec<(ModuleKey, ModuleSlot)>,
) where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    TargetMeta: Default,
{
    target.committed.publish(modules.len(), |publication| {
        let mut pins = Vec::new();
        for &slot in modules {
            let module = source
                .committed
                .module(slot)
                .expect("collected imports must only contain committed modules");
            let deps = module
                .direct_deps()
                .iter()
                .map(|dep| {
                    *mapped
                        .get(*dep)
                        .expect("dependency closure must contain every bound module")
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let target_slot = *mapped
                .get(slot)
                .expect("collected module must have a target slot");
            publication.insert(
                target_slot,
                StoredEntry::new(
                    module.entry_key().clone(),
                    module.handle().clone(),
                    module
                        .loader()
                        .and_then(|loader| mapped.get(loader).copied()),
                    deps,
                    module.retained().clone(),
                    0,
                    TargetMeta::default(),
                ),
            );
            module.handle().state().with_effects(|_, requested| {
                for provider in requested {
                    let source_slot = source
                        .committed
                        .module_for_binding(*provider)
                        .expect("pinned provider must remain committed with its dependent");
                    let target_slot = *mapped
                        .get(source_slot)
                        .expect("import closure must contain every pinned provider");
                    if !pins.contains(&target_slot) {
                        pins.push(target_slot);
                    }
                }
            });
        }
        for (key, module) in bindings {
            publication.bind_key(key, module);
        }
        for slot in pins {
            publication.pin(slot);
        }
    });
}

fn copy_closure<Arch, Tls, TargetMeta, SourceMeta>(
    target: &mut LinkContext<TargetMeta, Arch, Tls>,
    source: &LinkContext<SourceMeta, Arch, Tls>,
    roots: &[ModuleSlot],
) -> Result<SecondaryMap<ModuleSlot, ModuleSlot>>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    TargetMeta: Default,
{
    let mut mapped = SecondaryMap::default();
    let mut visited = EntitySet::default();
    let mut modules = Vec::new();
    let mut bindings = Vec::new();
    for &root in roots {
        collect_modules(
            target,
            source,
            root,
            &mut visited,
            &mut mapped,
            &mut modules,
            &mut bindings,
        )?;
    }
    target.committed.reclaim_returned_slots();
    for &slot in &modules {
        let module = source
            .committed
            .module(slot)
            .expect("collected imports must only contain committed modules");
        let module_key = module.entry_key().clone();
        let target_slot = target.committed.alloc_module();
        bindings.push((module_key, target_slot));
        mapped.insert(slot, target_slot);
    }
    copy_modules(target, source, &modules, &mapped, bindings);
    Ok(mapped)
}

fn reusable_root<Arch, Tls, TargetMeta, SourceMeta>(
    target: &LinkContext<TargetMeta, Arch, Tls>,
    source: &LinkContext<SourceMeta, Arch, Tls>,
    slot: ModuleSlot,
) -> Option<(ModuleSlot, ModuleKey)>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    let module = source
        .committed
        .module(slot)
        .expect("import roots must refer to committed modules");
    target
        .committed
        .module_for_source(module.handle().source_id())
        .map(|target| (target, module.entry_key().clone()))
}

impl<Meta, Arch, Tls> LinkContext<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Inserts one retained graph node.
    ///
    /// This is the single-node form of [`insert_batch`](Self::insert_batch).
    #[inline]
    pub fn insert(&mut self, module: GraphModule<Meta, Arch>) -> Result<ModuleLease> {
        Ok(self
            .insert_batch([module])?
            .into_vec()
            .pop()
            .expect("single-node batch must return one lease"))
    }

    /// Inserts a module graph as one validated batch.
    ///
    /// Dependencies may refer to committed modules or other nodes in the batch,
    /// including cycles. Each input node adds one direct acquisition and returns
    /// one lease in input order. Modules sharing a key become ordered lookup
    /// candidates. Sources must be unique within the batch and absent from this
    /// context, even when the supplied handle is the same instance. Reference
    /// committed modules through dependencies; use `add_alias` for extra names.
    /// New entries retain their dependency and runtime-binding
    /// closure so detached modules keep their providers alive after release.
    pub fn insert_batch(
        &mut self,
        modules: impl IntoIterator<Item = GraphModule<Meta, Arch>>,
    ) -> Result<Box<[ModuleLease]>> {
        let domain = self.domain.id();
        let mut sources = BTreeSet::<ModuleSourceId>::new();
        let mut indices = BTreeMap::<ModuleInstanceId, usize>::new();
        let mut planned = Vec::new();

        // Collect and admit the complete batch before following forward edges.
        for GraphModule {
            key,
            module,
            deps,
            meta,
        } in modules
        {
            self.committed.ensure_domain(module.domain_id())?;
            let instance = module.state().instance_id();
            let source = instance.source_id();
            if !sources.insert(source) || self.committed.module_for_source(source).is_some() {
                return Err(
                    LinkerError::context(LinkContextError::SourceOccupied { source }).into(),
                );
            }
            indices.insert(instance, planned.len());
            planned.push(PreparedModule {
                key,
                instance,
                module,
                deps,
                meta,
                direct_deps: Box::new([]),
                retained: ModuleScope::new(domain),
            });
        }

        // Validate and retain each new node's dependency/binding closure before
        // changing storage. Scopes belong to entries, not modules, so cycles do
        // not create Arc cycles between module handles.
        let mut requested_pins = BTreeSet::new();
        for index in 0..planned.len() {
            planned[index].module.state().with_effects(|_, pins| {
                requested_pins.extend(pins.iter().copied());
            });
            let mut scope = Vec::new();
            let mut visited = BTreeSet::new();
            let mut pending = VecDeque::from([planned[index].instance]);
            while let Some(id) = pending.pop_front() {
                if !visited.insert(id) {
                    continue;
                }
                let node = indices.get(&id).map(|&index| &planned[index]);
                let handle = if let Some(node) = node {
                    pending.extend(node.deps.iter().copied());
                    &node.module
                } else {
                    let entry = self
                        .committed
                        .module_for_binding(id)
                        .and_then(|slot| self.committed.module(slot))
                        .ok_or_else(|| {
                            LinkerError::context(LinkContextError::DependencyMissing { id })
                        })?;
                    pending.extend(entry.direct_deps().iter().map(|&slot| {
                        self.committed
                            .module(slot)
                            .unwrap()
                            .handle()
                            .state()
                            .instance_id()
                    }));
                    scope.extend(entry.retained().iter().cloned());
                    entry.handle()
                };
                scope.push(handle.clone());
                handle.state().with_effects(|bindings, pins| {
                    pending.extend(bindings.iter().chain(pins).copied());
                });
            }
            let mut retained = BTreeSet::new();
            scope.retain(|module| retained.insert(module.state().instance_id()));
            planned[index].retained = ModuleScope::from_admitted(domain, scope);
        }

        // All fallible admission is complete. Assign slots, resolve edges, then
        // publish in input order so leases and duplicate-key ordering stay stable.
        self.committed.reclaim_returned_slots();
        let mut slots = BTreeMap::new();
        for node in &planned {
            slots.insert(node.instance, self.committed.alloc_module());
        }
        let resolve = |id: ModuleInstanceId| {
            slots
                .get(&id)
                .copied()
                .or_else(|| self.committed.module_for_binding(id))
                .expect("validated dependency must have a module slot")
        };
        for node in &mut planned {
            node.direct_deps = node.deps.iter().copied().map(&resolve).collect();
        }
        let pins = requested_pins.into_iter().map(resolve).collect::<Vec<_>>();
        let mut leases = Vec::with_capacity(planned.len());
        self.committed.publish(planned.len(), |publication| {
            for node in planned {
                let slot = slots[&node.instance];
                let id = publication.insert(
                    slot,
                    StoredEntry::new(
                        node.key.clone(),
                        node.module,
                        None,
                        node.direct_deps,
                        node.retained,
                        1,
                        node.meta,
                    ),
                );
                publication.bind_key(node.key, slot);
                leases.push(ModuleLease::new(id));
            }
            for slot in pins {
                publication.pin(slot);
            }
        });
        Ok(leases.into_boxed_slice())
    }

    /// Imports one module and its bound dependency closure from another context.
    ///
    /// The imported modules share their underlying [`ModuleHandle`] allocations
    /// with `source`, but receive ids in this context. The selected module gains
    /// one direct acquisition; imported dependencies do not become roots.
    /// A root whose source is already present reuses the target context's
    /// instance. Within a copied dependency closure, only exact module instances
    /// are reused because the relocated parent may already contain addresses
    /// from that incarnation. Modules sharing an entry key retain insertion
    /// order. Source aliases are not imported.
    pub fn import<SourceMeta>(
        &mut self,
        source: &LinkContext<SourceMeta, Arch, Tls>,
        id: ModuleId,
    ) -> Result<ModuleLease>
    where
        Meta: Default,
    {
        self.committed.ensure_domain(source.committed.domain())?;
        let source_root = source.committed.module_slot(id)?;
        if let Some((root, key)) = reusable_root(self, source, source_root) {
            self.committed.bind_key(key, root);
            let id = self.committed.make_module_id(root);
            self.committed
                .module_mut(root)
                .expect("reused import root must remain committed")
                .acquire_root();
            return Ok(ModuleLease::new(id));
        }

        let mapped = copy_closure(self, source, &[source_root])?;
        let root = *mapped
            .get(source_root)
            .expect("imported root must have a target slot");
        let id = self.committed.make_module_id(root);
        self.committed
            .module_mut(root)
            .expect("copied import root must be committed")
            .acquire_root();
        Ok(ModuleLease::new(id))
    }

    /// Imports every acquired or pinned root from another context.
    ///
    /// Each source root receives one acquisition in this context, regardless of
    /// its acquisition count in `source`. Shared dependencies are copied once
    /// and remain dependency-only. Each returned lease represents one direct
    /// acquisition in this context. Roots already present by source are reused;
    /// copied dependency closures still require exact instances. Source aliases
    /// are not imported because they belong to the source namespace.
    pub fn import_roots<SourceMeta>(
        &mut self,
        source: &LinkContext<SourceMeta, Arch, Tls>,
    ) -> Result<Box<[ModuleLease]>>
    where
        Meta: Default,
    {
        self.committed.ensure_domain(source.committed.domain())?;
        let roots = source
            .committed
            .lifecycle()
            .filter(|slot| {
                source
                    .committed
                    .module(*slot)
                    .is_some_and(|module| module.is_root())
            })
            .collect::<Vec<_>>();
        let mut reused = Vec::new();
        let mut copied = Vec::new();
        for &root in &roots {
            if let Some((target, key)) = reusable_root(self, source, root) {
                reused.push((root, target, key));
            } else {
                copied.push(root);
            }
        }
        let mut mapped = copy_closure(self, source, &copied)?;
        for (source, target, key) in reused {
            self.committed.bind_key(key, target);
            mapped.insert(source, target);
        }
        let mut imported = Vec::with_capacity(roots.len());
        for root in roots {
            let root = *mapped
                .get(root)
                .expect("imported root must have a target slot");
            let id = self.committed.make_module_id(root);
            self.committed
                .module_mut(root)
                .expect("imported root must be committed")
                .acquire_root();
            imported.push(ModuleLease::new(id));
        }
        Ok(imported.into_boxed_slice())
    }
}
