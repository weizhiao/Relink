use super::defs::{LazyBindingEntries, LazyRuntime};
use crate::{
    LazyBindingError, RelocationError, Result,
    elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord},
    image::RawDynamic,
    memory::{ImageMemory, ImageMemoryExt, RegionAccess, VmAddr, VmOffset},
    relocation::{BindingMode, RelocationArch},
    sync::Arc,
    tls::TlsResolver,
};
use core::mem::size_of;

/// Marker trait for raw image types that support lazy-binding fixup hooks.
pub trait SupportLazy {}

impl SupportLazy for () {}

/// Supplies lazy PLT runtime entries for a mapped image.
pub trait LazyBinder<Arch: RelocationArch>: Send + Sync + 'static {
    /// Resolves the requested binding mode into whether PLT entries should bind lazily.
    #[inline]
    fn resolve_binding(&self, binding: BindingMode, default_lazy: bool) -> bool {
        match binding {
            BindingMode::Default => default_lazy,
            BindingMode::Eager => false,
            BindingMode::Lazy => true,
        }
    }

    /// Builds the runtime entries installed into this image's lazy PLT state.
    fn prepare_entries(&self, runtime: LazyRuntime<Arch>) -> Result<LazyBindingEntries>;
}

impl<Arch: RelocationArch> LazyBinder<Arch> for () {
    #[inline]
    fn resolve_binding(&self, binding: BindingMode, _default_lazy: bool) -> bool {
        matches!(binding, BindingMode::Lazy)
    }

    #[inline]
    fn prepare_entries(&self, _runtime: LazyRuntime<Arch>) -> Result<LazyBindingEntries> {
        Err(RelocationError::LazyBinding(LazyBindingError::MissingBinder).into())
    }
}

impl<Arch, B> LazyBinder<Arch> for Arc<B>
where
    Arch: RelocationArch,
    B: LazyBinder<Arch> + ?Sized,
{
    #[inline]
    fn resolve_binding(&self, binding: BindingMode, default_lazy: bool) -> bool {
        (**self).resolve_binding(binding, default_lazy)
    }

    #[inline]
    fn prepare_entries(&self, runtime: LazyRuntime<Arch>) -> Result<LazyBindingEntries> {
        (**self).prepare_entries(runtime)
    }
}

impl<Arch: RelocationArch> dyn LazyBinder<Arch> {
    pub(crate) fn prepare_plt<D, R, Tls>(
        &self,
        lazy: bool,
        image: &RawDynamic<D, Arch, R, Tls>,
    ) -> Result<()>
    where
        D: 'static,
        R: RegionAccess,
        Tls: TlsResolver<Arch>,
    {
        if lazy {
            let pltrel = image.relocation().pltrel();
            if pltrel.is_empty() {
                return Ok(());
            }

            let runtime = LazyRuntime::<Arch>::new(image.core_ref().inner.runtime());
            let entries = self.prepare_entries(runtime)?;
            let (runtime_entry, resolver, state) = entries.into_parts();
            if let Some(state) = state {
                assert!(
                    runtime.core().lazy_runtime.set(state).is_ok(),
                    "lazy binding runtime must be installed only once",
                );
            }

            let word_size = size_of::<<Arch::Layout as ElfLayout>::Word>();
            let slots = Arch::LAZY_BINDING_SLOTS;
            let got_plt = image.got_plt().ok_or(RelocationError::LazyBinding(
                LazyBindingError::MissingGotPlt,
            ))?;
            let runtime_slot = got_plt
                + VmOffset::new(slots.runtime().checked_mul(word_size).ok_or(
                    RelocationError::LazyBinding(LazyBindingError::SlotOffsetOverflow),
                )?);
            let resolver_slot = got_plt
                + VmOffset::new(slots.resolver().checked_mul(word_size).ok_or(
                    RelocationError::LazyBinding(LazyBindingError::SlotOffsetOverflow),
                )?);
            let runtime_entry = <Arch::Layout as ElfLayout>::Word::from_usize(runtime_entry.get());
            let resolver = <Arch::Layout as ElfLayout>::Word::from_usize(resolver.get());
            unsafe {
                runtime.memory().write_value(runtime_slot, runtime_entry)?;
                runtime.memory().write_value(resolver_slot, resolver)?;
            }
        }
        Ok(())
    }

    pub(crate) fn relocate_jump_slot<Memory>(
        &self,
        lazy: bool,
        memory: &Memory,
        base: VmAddr,
        rel: &ElfRelType<Arch>,
    ) -> Result<bool>
    where
        Memory: ImageMemory,
        <Arch::Layout as ElfLayout>::Word: crate::ByteRepr,
    {
        if !lazy {
            return Ok(false);
        }

        unsafe {
            memory.update_value(
                base + rel.r_offset(),
                |word: <Arch::Layout as ElfLayout>::Word| {
                    <Arch::Layout as ElfLayout>::Word::from_usize(
                        (base + VmOffset::new(word.to_usize())).get(),
                    )
                },
            )?
        };
        Ok(true)
    }
}
