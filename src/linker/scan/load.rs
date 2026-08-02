use super::{
    GotPltTarget, LinkPlan, MappedRuntimeMemory, Materialization, MemoryLayoutPlan,
    ModuleId as PlanModuleId, build_arena_raw_dynamic,
};
use crate::{
    ByteRepr, LinkerError, Loader, Result,
    elf::ElfRelType,
    entity::EntitySet,
    image::{RawDynamic, ScannedDynamic},
    lazy::LazyBinder,
    linker::{
        context::LinkContext,
        driver::LoadResult,
        resolve::ScanResolveContext,
        resolver::KeyResolver,
        run::{LinkerRun, PreparedLoad},
        session::ResolveSession,
    },
    memory::{ImageMemory, RegionAccess, VmOffset},
    observer::{LinkerObserver, LoadObserver, RelocationObserver},
    os::Mmap,
    relocation::{RelocationArch, RelocationValueProvider},
    runtime::CodeExecutor,
    tls::TlsResolver,
};
use alloc::{borrow::ToOwned, collections::BTreeMap, vec::Vec};
use core::borrow::Borrow;

#[allow(private_bounds)]
impl<'run, 'pipe, K, D: Send + Sync + 'static, Tls, Arch, M, Exec, Resolver, RelocBinder, Obs>
    LinkerRun<'run, 'pipe, K, Arch, Loader<D, Tls, Arch, M, Exec>, Resolver, RelocBinder, Tls, Obs>
where
    K: Clone + Ord,
    D: Default + Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch + RelocationValueProvider + GotPltTarget,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
    ElfRelType<Arch>: ByteRepr,
    Obs: LinkerObserver<D, Arch, M::Region, Tls> + LoadObserver<D, Arch> + RelocationObserver<Arch>,
    RelocBinder: LazyBinder<Arch> + Clone,
{
    /// Discovers, plans, and loads one module through the scan-first path.
    pub fn load_scan_first<Q>(
        &mut self,
        context: &mut LinkContext<K, Arch, Tls>,
        key: K,
    ) -> Result<LoadResult<Arch, Tls>>
    where
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
    {
        if let Some(id) = context.module_id(key.borrow()) {
            let module = context.get(id)?.clone();
            let lease = context.acquire(id)?;
            return Ok(LoadResult::new(
                lease,
                module,
                Vec::new().into_boxed_slice(),
            ));
        }

        let prepared = self.prepare_scan_load::<Q>(context, &key)?;
        let relocated = self.relocate(prepared)?;
        let published = relocated.publish(context)?;
        match published.initialize() {
            Ok(result) => Ok(result),
            Err(failed) => Err(failed.rollback(context)),
        }
    }

    /// Resolves and maps a scan-first module group without relocating it.
    pub fn prepare_scan_load<Q>(
        &mut self,
        context: &mut LinkContext<K, Arch, Tls>,
        key: &K,
    ) -> Result<PreparedLoad<D, Arch, M::Region, Tls>>
    where
        K: 'static + Borrow<Q>,
        Q: ToOwned<Owned = K> + Ord + ?Sized,
        Resolver: KeyResolver<K, Arch, Q, Tls>,
    {
        context
            .committed
            .ensure_domain(self.linker.loader.domain_id())?;
        let mut session = ResolveSession::new();

        let mut loader = self.linker.loader.run().with_observer(&mut self.observer);
        let mut resolve_context = ScanResolveContext::new(&mut context.committed, &mut session);
        let resolved = resolve_context.resolve_root::<Q>(key, None, &self.linker.resolver)?;
        let root = resolve_context.stage(resolved, &mut loader)?;
        if !resolve_context.contains_pending(root) {
            return PreparedLoad::new(root, ResolveSession::new(), None, context);
        }
        resolve_context.resolve_dependency_graph::<D, _, _, _, Q>(
            root,
            &mut loader,
            &self.linker.resolver,
        )?;

        let (dynamics, mut session) = session.split_dynamics();
        let dynamic_ids = dynamics.keys().copied().collect::<EntitySet<_>>();
        let entries: BTreeMap<_, _> = dynamics
            .into_iter()
            .map(|(id, entry)| {
                let key_slot = context.committed.entry_key(id);
                let key = context.committed.key(key_slot).clone();
                let (module, full_deps) = entry.into_parts();
                let full_deps =
                    full_deps.expect("missing resolved dependencies while building scan plan");
                Ok((id, (key, module, full_deps)))
            })
            .collect::<Result<_>>()?;
        let mut mapped_runtime = None;
        let planned = if entries.is_empty() {
            None
        } else {
            let plan_root = if dynamic_ids.contains(root) {
                root
            } else {
                session
                    .group_order()
                    .iter()
                    .copied()
                    .find(|id| dynamic_ids.contains(*id))
                    .expect("dynamic id set must contain at least one group id")
            };
            let plan_group_order = session
                .group_order()
                .iter()
                .copied()
                .filter(|id| dynamic_ids.contains(*id))
                .collect::<Vec<_>>();
            let mut plan = LinkPlan::new(plan_root, plan_group_order, entries);
            self.pipeline.run(&mut plan)?;
            mapped_runtime = self.prepare_mapped_runtime(&mut plan)?;
            let (_, _, entries, memory_layout) = plan.into_parts();
            Some((entries, memory_layout))
        };
        if let Some((entries, memory_layout)) = planned {
            for (module_id, entry) in entries {
                let (id, _key, module, direct_deps) = entry.into_parts();
                let raw = self.materialize_planned_raw(
                    &memory_layout,
                    &mut mapped_runtime,
                    module_id,
                    module,
                )?;
                session.restore_dynamic(id, raw, direct_deps);
            }
        }

        PreparedLoad::new(root, session, mapped_runtime, context)
    }

    fn prepare_mapped_runtime(
        &mut self,
        plan: &mut LinkPlan<K, Arch, Tls>,
    ) -> Result<Option<MappedRuntimeMemory<M::Region>>> {
        plan.normalize()?;
        let mut mapped_runtime = MappedRuntimeMemory::map(self.linker.loader.mapper(), plan)?;

        if let Some(runtime) = mapped_runtime.as_mut() {
            let modules = plan
                .modules_with_materialization(Materialization::SectionRegions)
                .collect::<Vec<_>>();
            for &module_id in &modules {
                runtime.build_module(module_id, plan.memory_layout())?;
            }
            runtime.populate(plan)?;
            for module_id in modules {
                runtime.repair_module(module_id, plan)?;
            }
        }

        Ok(mapped_runtime)
    }

    fn materialize_planned_raw(
        &mut self,
        plan: &MemoryLayoutPlan,
        mapped_runtime: &mut Option<MappedRuntimeMemory<M::Region>>,
        module_id: PlanModuleId,
        scanned: ScannedDynamic<Arch>,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        match plan
            .materialization(module_id)
            .unwrap_or(Materialization::WholeDsoRegion)
        {
            Materialization::SectionRegions => {
                self.materialize_arena_raw(mapped_runtime, module_id, scanned)
            }
            Materialization::WholeDsoRegion => {
                let mut raw = self.linker.loader.load_scanned_dynamic(scanned)?;
                apply_section_overrides(&mut raw, module_id, plan)?;
                Ok(raw)
            }
        }
    }

    fn materialize_arena_raw(
        &mut self,
        mapped_runtime: &mut Option<MappedRuntimeMemory<M::Region>>,
        module_id: PlanModuleId,
        scanned: ScannedDynamic<Arch>,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        let runtime = mapped_runtime
            .as_mut()
            .ok_or_else(|| {
                LinkerError::runtime_memory(
                    "section-region planned load is missing mapped runtime memory",
                )
            })?
            .take_module(module_id)?;
        let force_static_tls = self.linker.loader.force_static_tls();

        let raw = build_arena_raw_dynamic::<D, Tls, Arch, M::Region>(
            scanned,
            runtime,
            force_static_tls,
            self.linker.loader.domain_id(),
            self.linker.loader.tls_resolver(),
        )?;
        Ok(raw)
    }
}

fn apply_section_overrides<D: Send + Sync + 'static, Arch, R, Tls>(
    raw: &mut RawDynamic<D, Arch, R, Tls>,
    module_id: PlanModuleId,
    plan: &MemoryLayoutPlan,
) -> Result<()>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
    let module = plan.module(module_id);
    let core = raw.core_ref();
    let segments = core.segments();

    for section_id in module.alloc_sections().iter().copied() {
        if !plan.section_is_override(section_id) {
            continue;
        }
        let metadata = plan.section(section_id);
        let data = plan
            .data(section_id)
            .ok_or_else(|| LinkerError::section_data("planned override section data is missing"))?;
        if data.len() != metadata.size() {
            return Err(LinkerError::section_data(
                "planned section override size does not match the loaded section",
            )
            .into());
        }
        segments.write_bytes(
            segments.base() + VmOffset::new(metadata.source_address()),
            data.as_ref(),
        )?;
    }
    Ok(())
}
