use super::{
    DtDebugEntry, LifecycleEvent, LinkActivity, ModuleRelocatedEvent, ProgramHeaderEvent,
    ResolveDependencyEvent, ResolveRootEvent, StagedDynamic,
};
use crate::{Result, arch::NativeArch, os::RegionAccess, relocation::RelocationArch};
use alloc::boxed::Box;

/// Event hook for images as they are loaded.
pub trait LoadObserver<Arch: RelocationArch = NativeArch> {
    /// Called as each program header is processed during loading.
    #[inline]
    fn on_program_header(&mut self, _event: ProgramHeaderEvent<'_, Arch::Layout>) -> Result<()> {
        Ok(())
    }

    /// Called when a mutable `DT_DEBUG` entry is available during dynamic parsing.
    #[inline]
    fn on_dt_debug<R: RegionAccess>(&mut self, _entry: DtDebugEntry<'_, Arch, R>) -> Result<()> {
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
    fn on_staged_dynamic<K, D: 'static>(
        &mut self,
        _event: StagedDynamic<'_, K, D, Arch>,
    ) -> Result<()> {
        Ok(())
    }
}

impl<Arch: RelocationArch> LinkObserver<Arch> for () {}

impl<Arch: RelocationArch> LoadObserver<Arch> for () {}

impl<Arch: RelocationArch> RelocationObserver<Arch> for () {}

impl<Arch, O> LoadObserver<Arch> for &mut O
where
    Arch: RelocationArch,
    O: LoadObserver<Arch> + ?Sized,
{
    #[inline]
    fn on_program_header(&mut self, event: ProgramHeaderEvent<'_, Arch::Layout>) -> Result<()> {
        (**self).on_program_header(event)
    }

    #[inline]
    fn on_dt_debug<R: RegionAccess>(&mut self, entry: DtDebugEntry<'_, Arch, R>) -> Result<()> {
        (**self).on_dt_debug(entry)
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
    fn on_module_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut ModuleRelocatedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_module_relocated(event)
    }
}

impl<Arch, O> LoadObserver<Arch> for Box<O>
where
    Arch: RelocationArch,
    O: LoadObserver<Arch> + ?Sized,
{
    #[inline]
    fn on_program_header(&mut self, event: ProgramHeaderEvent<'_, Arch::Layout>) -> Result<()> {
        (**self).on_program_header(event)
    }

    #[inline]
    fn on_dt_debug<R: RegionAccess>(&mut self, entry: DtDebugEntry<'_, Arch, R>) -> Result<()> {
        (**self).on_dt_debug(entry)
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
    fn on_staged_dynamic<K, D: 'static>(
        &mut self,
        event: StagedDynamic<'_, K, D, Arch>,
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
    fn on_staged_dynamic<K, D: 'static>(
        &mut self,
        event: StagedDynamic<'_, K, D, Arch>,
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
    fn on_module_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut ModuleRelocatedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_module_relocated(event)
    }
}
