//! Data structures shared by lazy binders and the runtime resolver.

use crate::{
    ByteRepr, LazyBindingError, RelocationError, Result,
    elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord, SymbolEntry},
    image::CoreRuntime,
    memory::{ImageMemory, ImageMemoryExt, VmAddr},
    relocation::RelocationArch,
};
use alloc::boxed::Box;
use core::{any::Any, ptr::NonNull};

/// PLTGOT slots used by an architecture's lazy binding entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LazySlots {
    context: usize,
    resolver: usize,
}

impl LazySlots {
    /// Creates a pair of GOT/PLT slot indexes used by a lazy binding ABI.
    #[inline]
    pub const fn new(context: usize, resolver: usize) -> Self {
        Self { context, resolver }
    }

    /// Returns the slot index that receives binder context.
    #[inline]
    pub const fn context(self) -> usize {
        self.context
    }

    /// Returns the slot index that receives the resolver entry point.
    #[inline]
    pub const fn resolver(self) -> usize {
        self.resolver
    }
}

/// Selects how an architecture installs lazy-binding runtime entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LazyPlacement {
    /// Lazy binding is not implemented for this architecture.
    Unsupported,
    /// The context and resolver use fixed indexes relative to `DT_PLTGOT`.
    Slots(LazySlots),
    /// The architecture installs entries through its custom relocation handler.
    Custom,
}

/// Target-visible values supplied by a lazy binder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LazyValues {
    context: VmAddr,
    resolver: VmAddr,
}

impl LazyValues {
    /// Returns the binder context value.
    #[inline]
    pub const fn context(self) -> VmAddr {
        self.context
    }

    /// Returns the resolver entry point.
    #[inline]
    pub const fn resolver(self) -> VmAddr {
        self.resolver
    }
}

/// Values and retained state prepared for an image's lazy PLT runtime.
pub struct LazySetup {
    values: LazyValues,
    _state: Option<Box<dyn Any + Send + Sync>>,
}

impl LazySetup {
    /// Creates a setup from target-visible context and resolver values.
    #[inline]
    pub const fn new(context: VmAddr, resolver: VmAddr) -> Self {
        Self {
            values: LazyValues { context, resolver },
            _state: None,
        }
    }

    /// Creates a setup whose context points at retained host-side state.
    pub fn with_state<T>(state: T, resolver: VmAddr) -> Self
    where
        T: Send + Sync + 'static,
    {
        let state = Box::new(state);
        let context = VmAddr::from_ptr(state.as_ref());
        let state = state as Box<dyn Any + Send + Sync>;
        Self {
            values: LazyValues { context, resolver },
            _state: Some(state),
        }
    }

    #[inline]
    pub(crate) const fn values(&self) -> LazyValues {
        self.values
    }
}

/// Public facade over Relink's lazy binding runtime state.
///
/// This handle lets custom lazy binders inspect PLT relocation context and reuse
/// Relink's symbol lookup / jump-slot writeback without exposing the internal
/// core runtime layout.
#[derive(Debug)]
pub struct LazyRuntime<Arch: RelocationArch> {
    runtime: NonNull<CoreRuntime<Arch>>,
}

impl<Arch: RelocationArch> Copy for LazyRuntime<Arch> {}

impl<Arch: RelocationArch> Clone for LazyRuntime<Arch> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<Arch: RelocationArch> LazyRuntime<Arch> {
    #[inline]
    pub(crate) fn new(runtime: &CoreRuntime<Arch>) -> Self {
        Self {
            runtime: NonNull::from(runtime),
        }
    }

    /// Rebuilds a lazy runtime handle from a context entry passed to a resolver.
    ///
    /// # Safety
    ///
    /// `runtime` must be a value previously returned by [`Self::runtime`] for a
    /// live module with the same `Arch` type.
    #[inline]
    pub unsafe fn from_runtime(runtime: VmAddr) -> Self {
        Self {
            runtime: NonNull::new(runtime.as_mut_ptr::<CoreRuntime<Arch>>())
                .expect("lazy resolver context entry must not be null"),
        }
    }

    #[inline]
    pub(super) fn core(&self) -> &CoreRuntime<Arch> {
        unsafe { self.runtime.as_ref() }
    }

    /// Returns the native resolver context entry for this runtime handle.
    #[inline]
    pub fn runtime(&self) -> VmAddr {
        VmAddr::from_ptr(self.runtime.as_ptr())
    }

    /// Returns the mapped image memory owned by the module.
    #[inline]
    pub fn memory(&self) -> &dyn ImageMemory {
        self.core().module().memory()
    }

    /// Returns one PLT relocation by lazy relocation index.
    #[inline]
    pub fn plt_relocation(&self, rela_idx: usize) -> Option<LazyPltReloc<'_, Arch>> {
        let plt = self.core().lazy_plt()?;
        let rel = plt.relocs.as_slice().get(rela_idx)?;
        let symbol = plt.symbols.view().entry(rel.r_symbol());
        Some(LazyPltReloc { rel, symbol })
    }

    /// Looks up a symbol through Relink's normal lazy binding lookup path.
    #[inline]
    pub fn lookup_symbol(&self, symbol: &SymbolEntry<'_, Arch::Layout>) -> Result<Option<VmAddr>> {
        self.core().module().lookup_symbol(symbol)
    }

    /// Writes a resolved address into the relocation's jump slot.
    pub fn write_jump_slot(&self, reloc: &LazyPltReloc<'_, Arch>, value: VmAddr) -> Result<()>
    where
        <Arch::Layout as ElfLayout>::Word: ByteRepr,
    {
        let word = <Arch::Layout as ElfLayout>::Word::from_usize(value.get());
        let place = self.memory().base() + reloc.rel.r_offset();
        unsafe { self.memory().write_value(place, word) }
    }

    /// Performs Relink's default lazy binding flow and writes the jump slot.
    pub fn resolve_default(&self, rela_idx: usize) -> Result<VmAddr>
    where
        <Arch::Layout as ElfLayout>::Word: ByteRepr,
    {
        let reloc = self
            .plt_relocation(rela_idx)
            .ok_or(RelocationError::LazyBinding(
                LazyBindingError::RelocIndexOutOfRange,
            ))?;

        if reloc.rel.r_type() != Arch::JUMP_SLOT || reloc.rel.r_symbol() == 0 {
            return Err(RelocationError::LazyBinding(LazyBindingError::InvalidPltReloc).into());
        }

        let symbol = reloc.symbol();
        let resolved = self
            .lookup_symbol(symbol)?
            .ok_or(RelocationError::LazyBinding(
                LazyBindingError::UnknownSymbol,
            ))?;
        self.write_jump_slot(&reloc, resolved)?;
        Ok(resolved)
    }
}

/// One lazy PLT relocation and its referenced symbol.
pub struct LazyPltReloc<'a, Arch: RelocationArch> {
    rel: &'a ElfRelType<Arch>,
    symbol: SymbolEntry<'a, Arch::Layout>,
}

impl<'a, Arch: RelocationArch> LazyPltReloc<'a, Arch> {
    /// Returns the raw ELF relocation entry.
    #[inline]
    pub const fn relocation(&self) -> &'a ElfRelType<Arch> {
        self.rel
    }

    /// Returns the referenced symbol entry.
    #[inline]
    pub const fn symbol(&self) -> &SymbolEntry<'a, Arch::Layout> {
        &self.symbol
    }
}
