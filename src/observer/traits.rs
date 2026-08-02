use super::{
    AfterDynamicLoadEvent, BeforeLoadEvent, DynamicRelocatedEvent, HandleResult,
    LinkerRelocationEvent, RelocationEvent, SymbolBindingEvent,
};
#[cfg(feature = "object")]
use super::{
    AfterObjectLoadEvent, BeforeObjectLoadEvent, ObjectRelocatedEvent, SectionLayoutEvent,
};
#[cfg(feature = "object")]
use crate::relocation::ObjectArch;
use crate::{
    Result,
    arch::NativeArch,
    memory::{HostRegion, RegionAccess},
    relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::boxed::Box;

/// Event hook for images as they are loaded.
pub trait LoadObserver<D: Send + Sync + 'static = (), Arch: RelocationArch = NativeArch> {
    /// Called after ELF program headers are available and before `PT_LOAD`
    /// segments are mapped.
    #[inline]
    fn on_before_load(&mut self, _event: BeforeLoadEvent<'_, D, Arch::Layout>) -> Result<()> {
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
    fn on_after_object_load<R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        _event: AfterObjectLoadEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()>
    where
        Arch: ObjectArch,
    {
        Ok(())
    }

    /// Called after a dynamic image has been mapped and parsed, before relocation.
    #[inline]
    fn on_after_dynamic_load<R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        _event: AfterDynamicLoadEvent<'_, D, Arch, R, Tls>,
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
    /// Called before built-in relocation handling.
    #[inline]
    fn on_relocation_pre<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>, H>(
        &mut self,
        _ctx: &RelocationEvent<'_, D, Arch, R, Tls, H>,
    ) -> Result<HandleResult> {
        Ok(HandleResult::Unhandled)
    }

    /// Called after built-in relocation handling did not handle a relocation.
    #[inline]
    fn on_relocation_post<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>, H>(
        &mut self,
        _ctx: &RelocationEvent<'_, D, Arch, R, Tls, H>,
    ) -> Result<HandleResult> {
        Ok(HandleResult::Unhandled)
    }

    /// Called when a regular symbol relocation needs runtime binding.
    #[inline]
    fn on_symbol_binding<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        _event: &mut SymbolBindingEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called after relocatable-object relocation and before memory protection and initialization.
    #[cfg(feature = "object")]
    #[inline]
    fn on_object_relocated<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        _event: &mut ObjectRelocatedEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called after a dynamic image has been relocated and before initialization.
    ///
    /// Implementations may adjust lifecycle tables or install retained
    /// initialization and finalization hooks before they are stored.
    #[inline]
    fn on_dynamic_relocated<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        _event: &mut DynamicRelocatedEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()> {
        Ok(())
    }
}

/// Policy hooks for linker-specific stages.
pub trait LinkerObserver<
    D: Send + Sync + 'static = (),
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver<Arch> = (),
>
{
    /// Adjusts the scope and binding mode for one module before relocation.
    #[inline]
    fn on_relocation(&mut self, _event: &mut LinkerRelocationEvent<D, Arch, R, Tls>) -> Result<()> {
        Ok(())
    }
}

impl<D: Send + Sync + 'static, Arch: RelocationArch> LoadObserver<D, Arch> for () {}

impl<Arch: RelocationArch> RelocationObserver<Arch> for () {}

impl<D: Send + Sync + 'static, Arch, R, Tls> LinkerObserver<D, Arch, R, Tls> for ()
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
{
}

impl<D: Send + Sync + 'static, Arch, O> LoadObserver<D, Arch> for &mut O
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    O: LoadObserver<D, Arch> + ?Sized,
{
    #[inline]
    fn on_before_load(&mut self, event: BeforeLoadEvent<'_, D, Arch::Layout>) -> Result<()> {
        (**self).on_before_load(event)
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
    fn on_after_object_load<R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        event: AfterObjectLoadEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()>
    where
        Arch: ObjectArch,
    {
        (**self).on_after_object_load(event)
    }

    #[inline]
    fn on_after_dynamic_load<R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        event: AfterDynamicLoadEvent<'_, D, Arch, R, Tls>,
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
    fn on_relocation_pre<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>, H>(
        &mut self,
        ctx: &RelocationEvent<'_, D, Arch, R, Tls, H>,
    ) -> Result<HandleResult> {
        (**self).on_relocation_pre(ctx)
    }

    #[inline]
    fn on_relocation_post<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>, H>(
        &mut self,
        ctx: &RelocationEvent<'_, D, Arch, R, Tls, H>,
    ) -> Result<HandleResult> {
        (**self).on_relocation_post(ctx)
    }

    #[inline]
    fn on_symbol_binding<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        event: &mut SymbolBindingEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()> {
        (**self).on_symbol_binding(event)
    }

    #[cfg(feature = "object")]
    #[inline]
    fn on_object_relocated<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        event: &mut ObjectRelocatedEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()> {
        (**self).on_object_relocated(event)
    }

    #[inline]
    fn on_dynamic_relocated<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()> {
        (**self).on_dynamic_relocated(event)
    }
}

impl<D: Send + Sync + 'static, Arch, R, Tls, O> LinkerObserver<D, Arch, R, Tls> for &mut O
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    O: LinkerObserver<D, Arch, R, Tls> + ?Sized,
{
    #[inline]
    fn on_relocation(&mut self, event: &mut LinkerRelocationEvent<D, Arch, R, Tls>) -> Result<()> {
        (**self).on_relocation(event)
    }
}

impl<D: Send + Sync + 'static, Arch, O> LoadObserver<D, Arch> for Box<O>
where
    D: Send + Sync + 'static,
    Arch: RelocationArch,
    O: LoadObserver<D, Arch> + ?Sized,
{
    #[inline]
    fn on_before_load(&mut self, event: BeforeLoadEvent<'_, D, Arch::Layout>) -> Result<()> {
        (**self).on_before_load(event)
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
    fn on_after_object_load<R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        event: AfterObjectLoadEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()>
    where
        Arch: ObjectArch,
    {
        (**self).on_after_object_load(event)
    }

    #[inline]
    fn on_after_dynamic_load<R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        event: AfterDynamicLoadEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()> {
        (**self).on_after_dynamic_load(event)
    }
}

impl<Arch, O> RelocationObserver<Arch> for Box<O>
where
    Arch: RelocationArch,
    O: RelocationObserver<Arch> + ?Sized,
{
    #[inline]
    fn on_relocation_pre<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>, H>(
        &mut self,
        ctx: &RelocationEvent<'_, D, Arch, R, Tls, H>,
    ) -> Result<HandleResult> {
        (**self).on_relocation_pre(ctx)
    }

    #[inline]
    fn on_relocation_post<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>, H>(
        &mut self,
        ctx: &RelocationEvent<'_, D, Arch, R, Tls, H>,
    ) -> Result<HandleResult> {
        (**self).on_relocation_post(ctx)
    }

    #[inline]
    fn on_symbol_binding<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        event: &mut SymbolBindingEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()> {
        (**self).on_symbol_binding(event)
    }

    #[cfg(feature = "object")]
    #[inline]
    fn on_object_relocated<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        event: &mut ObjectRelocatedEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()> {
        (**self).on_object_relocated(event)
    }

    #[inline]
    fn on_dynamic_relocated<D: Send + Sync + 'static, R: RegionAccess, Tls: TlsResolver<Arch>>(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, Arch, R, Tls>,
    ) -> Result<()> {
        (**self).on_dynamic_relocated(event)
    }
}

impl<D: Send + Sync + 'static, Arch, R, Tls, O> LinkerObserver<D, Arch, R, Tls> for Box<O>
where
    Arch: RelocationArch,
    R: RegionAccess,
    Tls: TlsResolver<Arch>,
    O: LinkerObserver<D, Arch, R, Tls> + ?Sized,
{
    #[inline]
    fn on_relocation(&mut self, event: &mut LinkerRelocationEvent<D, Arch, R, Tls>) -> Result<()> {
        (**self).on_relocation(event)
    }
}
