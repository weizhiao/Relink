use super::{
    DtDebugEntry, DynamicLoadedEvent, IfuncBindingEvent, LifecycleEvent, LinkActivity,
    ModuleRelocatedEvent, ObjectMetadataEvent, ProgramHeaderEvent, ResolveDependencyEvent,
    ResolveRootEvent, StagedDynamic, SymbolBindingEvent, TlsDescBindingEvent,
};
use crate::{
    Result, arch::NativeArch, elf::ElfHashTable, os::RegionAccess, relocation::RelocationArch,
};
use alloc::boxed::Box;

/// Event hook for images as they are loaded.
pub trait LoadObserver<D: 'static = (), Arch: RelocationArch = NativeArch> {
    /// Called as each program header is processed during loading.
    #[inline]
    fn on_program_header<R: RegionAccess>(
        &mut self,
        _event: ProgramHeaderEvent<'_, Arch::Layout, R>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when a mutable `DT_DEBUG` entry is available during dynamic parsing.
    #[inline]
    fn on_dt_debug<R: RegionAccess>(&mut self, _entry: DtDebugEntry<'_, Arch, R>) -> Result<()> {
        Ok(())
    }

    /// Called after relocatable-object section headers have been validated,
    /// before section contents are mapped.
    #[inline]
    fn on_object_metadata(
        &mut self,
        _event: ObjectMetadataEvent<'_, D, Arch::Layout>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called after a dynamic image has been mapped and parsed, before relocation.
    #[inline]
    fn on_dynamic_loaded<R: RegionAccess>(
        &mut self,
        _event: DynamicLoadedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        Ok(())
    }
}

/// Event hook for relocation-time and runtime-linker state changes.
///
/// Implementations can patch `r_debug`, emit `LD_DEBUG`-style logs, audit
/// module loading, or keep external debugger state without Relink owning those
/// structures.
pub trait RelocationObserver<Arch: RelocationArch = NativeArch> {
    /// Called when the visible loaded-module set changes state.
    #[inline]
    fn on_activity(&mut self, _activity: LinkActivity) -> Result<()> {
        Ok(())
    }

    /// Called before lifecycle functions are executed or recorded for finalization.
    #[inline]
    fn on_lifecycle<R: RegionAccess>(&mut self, _event: &mut LifecycleEvent<'_, R>) -> Result<()> {
        Ok(())
    }

    /// Called when a regular symbol relocation needs runtime binding.
    #[inline]
    fn on_symbol_binding<D: 'static, R: RegionAccess, H>(
        &mut self,
        _event: &mut SymbolBindingEvent<'_, D, Arch, R, H>,
    ) -> Result<()>
    where
        H: ElfHashTable<Arch::Layout> + 'static,
    {
        Ok(())
    }

    /// Called when an IFUNC resolver needs runtime binding.
    #[inline]
    fn on_ifunc_binding<D: 'static, R: RegionAccess, H>(
        &mut self,
        _event: &mut IfuncBindingEvent<'_, D, Arch, R, H>,
    ) -> Result<()>
    where
        H: ElfHashTable<Arch::Layout> + 'static,
    {
        Ok(())
    }

    /// Called when a TLSDESC relocation needs runtime binding.
    #[inline]
    fn on_tlsdesc_binding<D: 'static, R: RegionAccess, H>(
        &mut self,
        _event: &mut TlsDescBindingEvent<'_, D, Arch, R, H>,
    ) -> Result<()>
    where
        H: ElfHashTable<Arch::Layout> + 'static,
    {
        Ok(())
    }

    /// Called after a dynamic image has been relocated and registered.
    ///
    /// Implementations may install a per-module unload hook on the event.
    #[inline]
    fn on_module_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        _event: &mut ModuleRelocatedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        Ok(())
    }
}

/// Event hook for linker-level dependency and staging events.
pub trait LinkObserver<Arch: RelocationArch = NativeArch> {
    /// Called before the root key is passed to the configured resolver.
    #[inline]
    fn on_resolve_root<K: Clone>(&mut self, _event: ResolveRootEvent<'_, K>) -> Result<()> {
        Ok(())
    }

    /// Called before one `DT_NEEDED` edge is passed to the configured resolver.
    #[inline]
    fn on_resolve_dependency<K: Clone>(
        &mut self,
        _event: ResolveDependencyEvent<'_, K>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when a dynamic image has been mapped and staged into the link session.
    #[inline]
    fn on_staged_dynamic<K, D: 'static, R: RegionAccess>(
        &mut self,
        _event: StagedDynamic<'_, K, D, Arch, R>,
    ) -> Result<()> {
        Ok(())
    }
}

impl<Arch: RelocationArch> LinkObserver<Arch> for () {}

impl<D: 'static, Arch: RelocationArch> LoadObserver<D, Arch> for () {}

impl<Arch: RelocationArch> RelocationObserver<Arch> for () {}

impl<D, Arch, O> LoadObserver<D, Arch> for &mut O
where
    D: 'static,
    Arch: RelocationArch,
    O: LoadObserver<D, Arch> + ?Sized,
{
    #[inline]
    fn on_program_header<R: RegionAccess>(
        &mut self,
        event: ProgramHeaderEvent<'_, Arch::Layout, R>,
    ) -> Result<()> {
        (**self).on_program_header(event)
    }

    #[inline]
    fn on_dt_debug<R: RegionAccess>(&mut self, entry: DtDebugEntry<'_, Arch, R>) -> Result<()> {
        (**self).on_dt_debug(entry)
    }

    #[inline]
    fn on_object_metadata(
        &mut self,
        event: ObjectMetadataEvent<'_, D, Arch::Layout>,
    ) -> Result<()> {
        (**self).on_object_metadata(event)
    }

    #[inline]
    fn on_dynamic_loaded<R: RegionAccess>(
        &mut self,
        event: DynamicLoadedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_dynamic_loaded(event)
    }
}

impl<Arch, O> RelocationObserver<Arch> for &mut O
where
    Arch: RelocationArch,
    O: RelocationObserver<Arch> + ?Sized,
{
    #[inline]
    fn on_activity(&mut self, activity: LinkActivity) -> Result<()> {
        (**self).on_activity(activity)
    }

    #[inline]
    fn on_lifecycle<R: RegionAccess>(&mut self, event: &mut LifecycleEvent<'_, R>) -> Result<()> {
        (**self).on_lifecycle(event)
    }

    #[inline]
    fn on_symbol_binding<D: 'static, R: RegionAccess, H>(
        &mut self,
        event: &mut SymbolBindingEvent<'_, D, Arch, R, H>,
    ) -> Result<()>
    where
        H: ElfHashTable<Arch::Layout> + 'static,
    {
        (**self).on_symbol_binding(event)
    }

    #[inline]
    fn on_ifunc_binding<D: 'static, R: RegionAccess, H>(
        &mut self,
        event: &mut IfuncBindingEvent<'_, D, Arch, R, H>,
    ) -> Result<()>
    where
        H: ElfHashTable<Arch::Layout> + 'static,
    {
        (**self).on_ifunc_binding(event)
    }

    #[inline]
    fn on_tlsdesc_binding<D: 'static, R: RegionAccess, H>(
        &mut self,
        event: &mut TlsDescBindingEvent<'_, D, Arch, R, H>,
    ) -> Result<()>
    where
        H: ElfHashTable<Arch::Layout> + 'static,
    {
        (**self).on_tlsdesc_binding(event)
    }

    #[inline]
    fn on_module_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut ModuleRelocatedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_module_relocated(event)
    }
}

impl<D, Arch, O> LoadObserver<D, Arch> for Box<O>
where
    D: 'static,
    Arch: RelocationArch,
    O: LoadObserver<D, Arch> + ?Sized,
{
    #[inline]
    fn on_program_header<R: RegionAccess>(
        &mut self,
        event: ProgramHeaderEvent<'_, Arch::Layout, R>,
    ) -> Result<()> {
        (**self).on_program_header(event)
    }

    #[inline]
    fn on_dt_debug<R: RegionAccess>(&mut self, entry: DtDebugEntry<'_, Arch, R>) -> Result<()> {
        (**self).on_dt_debug(entry)
    }

    #[inline]
    fn on_object_metadata(
        &mut self,
        event: ObjectMetadataEvent<'_, D, Arch::Layout>,
    ) -> Result<()> {
        (**self).on_object_metadata(event)
    }

    #[inline]
    fn on_dynamic_loaded<R: RegionAccess>(
        &mut self,
        event: DynamicLoadedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_dynamic_loaded(event)
    }
}

impl<Arch, O> LinkObserver<Arch> for &mut O
where
    Arch: RelocationArch,
    O: LinkObserver<Arch> + ?Sized,
{
    #[inline]
    fn on_resolve_root<K: Clone>(&mut self, event: ResolveRootEvent<'_, K>) -> Result<()> {
        (**self).on_resolve_root(event)
    }

    #[inline]
    fn on_resolve_dependency<K: Clone>(
        &mut self,
        event: ResolveDependencyEvent<'_, K>,
    ) -> Result<()> {
        (**self).on_resolve_dependency(event)
    }

    #[inline]
    fn on_staged_dynamic<K, D: 'static, R: RegionAccess>(
        &mut self,
        event: StagedDynamic<'_, K, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_staged_dynamic(event)
    }
}

impl<Arch, O> LinkObserver<Arch> for Box<O>
where
    Arch: RelocationArch,
    O: LinkObserver<Arch> + ?Sized,
{
    #[inline]
    fn on_resolve_root<K: Clone>(&mut self, event: ResolveRootEvent<'_, K>) -> Result<()> {
        (**self).on_resolve_root(event)
    }

    #[inline]
    fn on_resolve_dependency<K: Clone>(
        &mut self,
        event: ResolveDependencyEvent<'_, K>,
    ) -> Result<()> {
        (**self).on_resolve_dependency(event)
    }

    #[inline]
    fn on_staged_dynamic<K, D: 'static, R: RegionAccess>(
        &mut self,
        event: StagedDynamic<'_, K, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_staged_dynamic(event)
    }
}

impl<Arch, O> RelocationObserver<Arch> for Box<O>
where
    Arch: RelocationArch,
    O: RelocationObserver<Arch> + ?Sized,
{
    #[inline]
    fn on_activity(&mut self, activity: LinkActivity) -> Result<()> {
        (**self).on_activity(activity)
    }

    #[inline]
    fn on_lifecycle<R: RegionAccess>(&mut self, event: &mut LifecycleEvent<'_, R>) -> Result<()> {
        (**self).on_lifecycle(event)
    }

    #[inline]
    fn on_symbol_binding<D: 'static, R: RegionAccess, H>(
        &mut self,
        event: &mut SymbolBindingEvent<'_, D, Arch, R, H>,
    ) -> Result<()>
    where
        H: ElfHashTable<Arch::Layout> + 'static,
    {
        (**self).on_symbol_binding(event)
    }

    #[inline]
    fn on_ifunc_binding<D: 'static, R: RegionAccess, H>(
        &mut self,
        event: &mut IfuncBindingEvent<'_, D, Arch, R, H>,
    ) -> Result<()>
    where
        H: ElfHashTable<Arch::Layout> + 'static,
    {
        (**self).on_ifunc_binding(event)
    }

    #[inline]
    fn on_tlsdesc_binding<D: 'static, R: RegionAccess, H>(
        &mut self,
        event: &mut TlsDescBindingEvent<'_, D, Arch, R, H>,
    ) -> Result<()>
    where
        H: ElfHashTable<Arch::Layout> + 'static,
    {
        (**self).on_tlsdesc_binding(event)
    }

    #[inline]
    fn on_module_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut ModuleRelocatedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_module_relocated(event)
    }
}
