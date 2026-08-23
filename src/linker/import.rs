use super::{
    context::LinkContext,
    storage::{ModuleId, ModuleKey, ModuleLease, ModuleSlot, StoredEntry},
};
use crate::{
    LinkContextError, LinkerError, Result,
    arch::NativeArch,
    entity::{EntitySet, SecondaryMap},
    image::{LookupScope, ModuleHandle, ModuleInstanceId},
    input::ModuleSourceId,
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

struct PreparedModule<Meta, Arch: RelocationArch, Tls: TlsResolver<Arch>> {
    key: ModuleKey,
    existing: Option<ModuleSlot>,
    instance: ModuleInstanceId,
    module: ModuleHandle<Arch, Tls>,
    deps: Box<[ModuleInstanceId]>,
    meta: Meta,
}

/// One module and its direct edges in a graph imported into a [`LinkContext`].
///
/// Dependencies use concrete module instance identities rather than source ids
/// or names. This preserves bindings across unload/reload cycles and remains
/// unambiguous when several modules share a key. Use [`LinkContext::add_alias`]
/// separately for additional names.
pub struct GraphModule<Meta = (), Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    key: ModuleKey,
    module: ModuleHandle<Arch, Tls>,
    deps: Box<[ModuleInstanceId]>,
    meta: Meta,
}

impl<Arch, Tls> GraphModule<(), Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Creates a graph node without context-specific metadata.
    #[inline]
    pub fn new(key: impl Into<ModuleKey>, module: impl Into<ModuleHandle<Arch, Tls>>) -> Self {
        Self::with_meta(key, module, ())
    }
}

impl<Meta, Arch, Tls> GraphModule<Meta, Arch, Tls>
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    /// Creates a graph node with context-specific metadata.
    #[inline]
    pub fn with_meta(
        key: impl Into<ModuleKey>,
        module: impl Into<ModuleHandle<Arch, Tls>>,
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
    let providers = module.handle().state().with_bindings(|bindings| {
        bindings
            .iter()
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
) where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
    TargetMeta: Default,
{
    let mut lifecycle = Vec::with_capacity(modules.len());
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
        target.committed.insert(
            target_slot,
            StoredEntry::new(
                module.entry_key().clone(),
                module.handle().clone(),
                deps,
                module.scope().clone(),
                0,
                TargetMeta::default(),
            ),
        );
        lifecycle.push(target_slot);
    }
    target.committed.extend_lifecycle(&lifecycle);
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
    copy_modules(target, source, &modules, &mapped);
    for (key, module) in bindings {
        target.committed.bind_key(key, module);
    }
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
    pub fn insert(&mut self, module: GraphModule<Meta, Arch, Tls>) -> Result<ModuleLease> {
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
    /// candidates. An exact instance already in this context is reused and its
    /// new key is bound to the existing module; the supplied metadata and
    /// dependency list are then ignored. A different instance of an occupied
    /// source is rejected.
    pub fn insert_batch(
        &mut self,
        modules: impl IntoIterator<Item = GraphModule<Meta, Arch, Tls>>,
    ) -> Result<Box<[ModuleLease]>> {
        let modules = modules.into_iter().collect::<Vec<_>>();
        for node in &modules {
            self.committed.ensure_domain(node.module.domain_id())?;
        }

        let mut sources = BTreeSet::<ModuleSourceId>::new();
        let mut instances = BTreeSet::<ModuleInstanceId>::new();
        let mut planned = Vec::with_capacity(modules.len());

        for GraphModule {
            key: module_key,
            module,
            deps,
            meta,
        } in modules
        {
            let instance = module.state().instance_id();
            let source = instance.source_id();
            if !sources.insert(source) {
                return Err(
                    LinkerError::context(LinkContextError::SourceOccupied { source }).into(),
                );
            }

            let existing = match self.committed.module_for_source(source) {
                Some(slot) => {
                    let committed = self
                        .committed
                        .module(slot)
                        .expect("source index must refer to a committed module");
                    if committed.handle().state().instance_id() != instance {
                        return Err(LinkerError::context(LinkContextError::SourceOccupied {
                            source,
                        })
                        .into());
                    }
                    Some(slot)
                }
                None => None,
            };
            instances.insert(instance);
            planned.push(PreparedModule {
                key: module_key,
                existing,
                instance,
                module,
                deps,
                meta,
            });
        }

        for node in &planned {
            if node.existing.is_some() {
                continue;
            }
            let validate = |id| -> Result<()> {
                (instances.contains(&id) || self.committed.module_for_binding(id).is_some())
                    .then_some(())
                    .ok_or_else(|| {
                        LinkerError::context(LinkContextError::DependencyMissing { id }).into()
                    })
            };
            node.deps.iter().copied().try_for_each(&validate)?;
            node.module
                .state()
                .with_bindings(|bindings| bindings.iter().copied().try_for_each(validate))?;
        }

        let mut slots = BTreeMap::<ModuleInstanceId, ModuleSlot>::new();
        for node in &planned {
            let slot = match node.existing {
                Some(slot) => slot,
                None => self.committed.alloc_module(),
            };
            slots.insert(node.instance, slot);
        }
        let resolved = planned
            .iter()
            .map(|node| {
                if node.existing.is_some() {
                    return Vec::new().into_boxed_slice();
                }
                node.deps
                    .iter()
                    .copied()
                    .map(|id| {
                        slots
                            .get(&id)
                            .copied()
                            .or_else(|| self.committed.module_for_binding(id))
                            .expect("validated dependency must have a module slot")
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            })
            .collect::<Vec<_>>();

        let mut lifecycle = Vec::with_capacity(planned.len());
        let mut leases = Vec::with_capacity(planned.len());
        for (node, deps) in planned.into_iter().zip(resolved) {
            let slot = slots[&node.instance];
            if node.existing.is_none() {
                let scope = LookupScope::empty(node.module.domain_id());
                self.committed.insert(
                    slot,
                    StoredEntry::new(node.key.clone(), node.module, deps, scope, 1, node.meta),
                );
                lifecycle.push(slot);
            } else {
                self.committed
                    .module_mut(slot)
                    .expect("reused module must remain committed")
                    .acquire_root();
            }
            self.committed.bind_key(node.key, slot);
            leases.push(ModuleLease::new(self.committed.make_module_id(slot)));
        }
        self.committed.extend_lifecycle(&lifecycle);
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

#[cfg(test)]
mod tests {
    use super::{GraphModule, LinkContext};
    use crate::{
        Error, LinkContextError, LinkerError,
        arch::NativeArch,
        image::{ModuleHandle, SyntheticModule},
        runtime::DomainId,
    };
    use alloc::vec::Vec;

    fn module(name: &str) -> ModuleHandle<NativeArch> {
        ModuleHandle::new(SyntheticModule::empty(name))
    }

    #[test]
    fn inserts_cycle() {
        let first = module("first");
        let second = module("second");
        let first_instance = first.state().instance_id();
        let second_instance = second.state().instance_id();
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);

        let leases = context
            .insert_batch([
                GraphModule::new("first", first).dependencies([second_instance]),
                GraphModule::new("second", second).dependencies([first_instance]),
            ])
            .unwrap();
        let mut leases = leases.into_vec().into_iter();
        let first = leases.next().unwrap();
        let second = leases.next().unwrap();

        assert_eq!(
            context.direct_deps(first.id()).unwrap().collect::<Vec<_>>(),
            [second.id()]
        );
        assert_eq!(
            context
                .direct_deps(second.id())
                .unwrap()
                .collect::<Vec<_>>(),
            [first.id()]
        );
        assert!(context.release(first).unwrap().is_empty());
        assert_eq!(context.release(second).unwrap().len(), 2);
        assert!(context.is_empty());
    }

    #[test]
    fn duplicate_keys_keep_order() {
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let leases = context
            .insert_batch([
                GraphModule::new("shared", module("first")),
                GraphModule::new("shared", module("second")),
            ])
            .unwrap();
        let mut leases = leases.into_vec().into_iter();
        let first = leases.next().unwrap();
        let second = leases.next().unwrap();

        assert_eq!(context.module_id("shared"), Some(first.id()));
        assert_eq!(context.release(first).unwrap().len(), 1);
        assert_eq!(context.module_id("shared"), Some(second.id()));
        assert_eq!(context.release(second).unwrap().len(), 1);
    }

    #[test]
    fn uses_committed_dependency() {
        let dependency = module("dependency");
        let dependency_instance = dependency.state().instance_id();
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let dependency = context
            .insert(GraphModule::new("dependency", dependency))
            .unwrap();

        let root = context
            .insert_batch([
                GraphModule::new("root", module("root")).dependencies([dependency_instance])
            ])
            .unwrap()
            .into_vec()
            .pop()
            .unwrap();

        assert_eq!(
            context.direct_deps(root.id()).unwrap().collect::<Vec<_>>(),
            [dependency.id()]
        );
        assert!(context.release(dependency).unwrap().is_empty());
        assert_eq!(context.release(root).unwrap().len(), 2);
    }

    #[test]
    fn missing_dependency_does_not_publish() {
        let missing = module("missing").state().instance_id();
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let error = match context
            .insert_batch([GraphModule::new("root", module("root")).dependencies([missing])])
        {
            Ok(_) => panic!("missing dependency should fail"),
            Err(error) => error,
        };

        let Error::Linker(LinkerError::Context { reason }) = error else {
            panic!("unexpected graph error: {error}");
        };
        assert!(matches!(
            *reason,
            LinkContextError::DependencyMissing { id } if id == missing
        ));
        assert!(context.is_empty());
        assert_eq!(context.module_id("root"), None);
    }

    #[test]
    fn reuses_exact_instance() {
        let module = module("shared");
        let mut context = LinkContext::<()>::new(DomainId::PROCESS);
        let first = context
            .insert(GraphModule::new("first", module.clone()))
            .unwrap();
        let second = context
            .insert_batch([GraphModule::new("second", module)])
            .unwrap()
            .into_vec()
            .pop()
            .unwrap();

        assert_eq!(first.id(), second.id());
        assert_eq!(context.module_id("second"), Some(first.id()));
        assert!(context.release(first).unwrap().is_empty());
        assert_eq!(context.release(second).unwrap().len(), 1);
    }
}
