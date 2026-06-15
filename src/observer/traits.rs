use super::{
    AfterDynamicLoadEvent, BeforeDynamicLoadEvent, DynamicRelocatedEvent, IfuncBindingEvent,
    InitEvent, LinkActivity, ResolveDependencyEvent, ResolveRootEvent, StagedDynamic,
    SymbolBindingEvent, TlsDescBindingEvent,
};
#[cfg(feature = "object")]
use super::{
    AfterObjectLoadEvent, BeforeObjectLoadEvent, ObjectRelocatedEvent, SectionLayoutEvent,
};
#[cfg(feature = "object")]
use crate::relocation::ObjectRelocationArch;
use crate::{Result, arch::NativeArch, memory::RegionAccess, relocation::RelocationArch};
use alloc::boxed::Box;

/// Event hook for images as they are loaded.
pub trait LoadObserver<D: 'static = (), Arch: RelocationArch = NativeArch> {
    /// Called after ELF program headers are available and before `PT_LOAD`
    /// segments are mapped.
    #[inline]
    fn on_before_dynamic_load(
        &mut self,
        _event: BeforeDynamicLoadEvent<'_, D, Arch::Layout>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called after relocatable-object section headers have been validated,
    /// before section contents are mapped.
    #[cfg(feature = "object")]
    #[inline]
    fn on_before_object_load(
        &mut self,
        _event: BeforeObjectLoadEvent<'_, D, Arch::Layout>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called before relocatable-object section addresses are assigned.
    #[cfg(feature = "object")]
    #[inline]
    fn on_section_layout(
        &mut self,
        _event: &mut SectionLayoutEvent<'_, Arch::Layout>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called after a relocatable object has been mapped and parsed, before relocation.
    #[cfg(feature = "object")]
    #[inline]
    fn on_after_object_load<R: RegionAccess>(
        &mut self,
        _event: AfterObjectLoadEvent<'_, D, Arch, R>,
    ) -> Result<()>
    where
        Arch: ObjectRelocationArch,
    {
        Ok(())
    }

    /// Called after a dynamic image has been mapped and parsed, before relocation.
    #[inline]
    fn on_after_dynamic_load<R: RegionAccess>(
        &mut self,
        _event: AfterDynamicLoadEvent<'_, D, Arch, R>,
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

    /// Called before initialization functions are executed.
    #[inline]
    fn on_init<D: 'static, R: RegionAccess>(
        &mut self,
        _event: &mut InitEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when a regular symbol relocation needs runtime binding.
    #[inline]
    fn on_symbol_binding<D: 'static, R: RegionAccess>(
        &mut self,
        _event: &mut SymbolBindingEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when an IFUNC resolver needs runtime binding.
    #[inline]
    fn on_ifunc_binding<D: 'static, R: RegionAccess>(
        &mut self,
        _event: &mut IfuncBindingEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when a TLSDESC relocation needs runtime binding.
    #[inline]
    fn on_tlsdesc_binding<D: 'static, R: RegionAccess>(
        &mut self,
        _event: &mut TlsDescBindingEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called after relocatable-object relocation and before memory protection and initialization.
    #[cfg(feature = "object")]
    #[inline]
    fn on_object_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        _event: &mut ObjectRelocatedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called after a dynamic image has been relocated and before initialization.
    ///
    /// Implementations may adjust the retained finalizer before it is stored
    /// with the relocated image.
    #[inline]
    fn on_dynamic_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        _event: &mut DynamicRelocatedEvent<'_, D, Arch, R>,
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
    fn on_before_dynamic_load(
        &mut self,
        event: BeforeDynamicLoadEvent<'_, D, Arch::Layout>,
    ) -> Result<()> {
        (**self).on_before_dynamic_load(event)
    }

    #[cfg(feature = "object")]
    #[inline]
    fn on_before_object_load(
        &mut self,
        event: BeforeObjectLoadEvent<'_, D, Arch::Layout>,
    ) -> Result<()> {
        (**self).on_before_object_load(event)
    }

    #[cfg(feature = "object")]
    #[inline]
    fn on_section_layout(
        &mut self,
        event: &mut SectionLayoutEvent<'_, Arch::Layout>,
    ) -> Result<()> {
        (**self).on_section_layout(event)
    }

    #[cfg(feature = "object")]
    #[inline]
    fn on_after_object_load<R: RegionAccess>(
        &mut self,
        event: AfterObjectLoadEvent<'_, D, Arch, R>,
    ) -> Result<()>
    where
        Arch: ObjectRelocationArch,
    {
        (**self).on_after_object_load(event)
    }

    #[inline]
    fn on_after_dynamic_load<R: RegionAccess>(
        &mut self,
        event: AfterDynamicLoadEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_after_dynamic_load(event)
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
    fn on_init<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut InitEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_init(event)
    }

    #[inline]
    fn on_symbol_binding<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut SymbolBindingEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_symbol_binding(event)
    }

    #[inline]
    fn on_ifunc_binding<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut IfuncBindingEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_ifunc_binding(event)
    }

    #[inline]
    fn on_tlsdesc_binding<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut TlsDescBindingEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_tlsdesc_binding(event)
    }

    #[cfg(feature = "object")]
    #[inline]
    fn on_object_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut ObjectRelocatedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_object_relocated(event)
    }

    #[inline]
    fn on_dynamic_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_dynamic_relocated(event)
    }
}

impl<D, Arch, O> LoadObserver<D, Arch> for Box<O>
where
    D: 'static,
    Arch: RelocationArch,
    O: LoadObserver<D, Arch> + ?Sized,
{
    #[inline]
    fn on_before_dynamic_load(
        &mut self,
        event: BeforeDynamicLoadEvent<'_, D, Arch::Layout>,
    ) -> Result<()> {
        (**self).on_before_dynamic_load(event)
    }

    #[cfg(feature = "object")]
    #[inline]
    fn on_before_object_load(
        &mut self,
        event: BeforeObjectLoadEvent<'_, D, Arch::Layout>,
    ) -> Result<()> {
        (**self).on_before_object_load(event)
    }

    #[cfg(feature = "object")]
    #[inline]
    fn on_section_layout(
        &mut self,
        event: &mut SectionLayoutEvent<'_, Arch::Layout>,
    ) -> Result<()> {
        (**self).on_section_layout(event)
    }

    #[cfg(feature = "object")]
    #[inline]
    fn on_after_object_load<R: RegionAccess>(
        &mut self,
        event: AfterObjectLoadEvent<'_, D, Arch, R>,
    ) -> Result<()>
    where
        Arch: ObjectRelocationArch,
    {
        (**self).on_after_object_load(event)
    }

    #[inline]
    fn on_after_dynamic_load<R: RegionAccess>(
        &mut self,
        event: AfterDynamicLoadEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_after_dynamic_load(event)
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
    fn on_init<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut InitEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_init(event)
    }

    #[inline]
    fn on_symbol_binding<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut SymbolBindingEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_symbol_binding(event)
    }

    #[inline]
    fn on_ifunc_binding<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut IfuncBindingEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_ifunc_binding(event)
    }

    #[inline]
    fn on_tlsdesc_binding<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut TlsDescBindingEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_tlsdesc_binding(event)
    }

    #[cfg(feature = "object")]
    #[inline]
    fn on_object_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut ObjectRelocatedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_object_relocated(event)
    }

    #[inline]
    fn on_dynamic_relocated<D: 'static, R: RegionAccess>(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, Arch, R>,
    ) -> Result<()> {
        (**self).on_dynamic_relocated(event)
    }
}
