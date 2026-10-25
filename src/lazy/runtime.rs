//! Borrowed access to lazy binding runtime state and PLT relocations.

use crate::{
    ByteRepr, LazyBindingError, RelocationError, Result,
    elf::{ElfLayout, ElfRelEntry, ElfRelType, ElfWord, SymbolEntry},
    image::CoreRuntime,
    memory::{ImageMemory, ImageMemoryExt, VmAddr},
    relocation::RelocationArch,
};

/// Public facade over Relink's lazy binding runtime state.
///
/// This handle lets custom lazy binders inspect PLT relocation context and reuse
/// Relink's symbol lookup / jump-slot writeback without exposing the internal
/// core runtime layout. The handle borrows the module and cannot outlive it.
/// Retaining a raw context address does not extend the module lifetime.
pub struct LazyRuntime<'a, Arch: RelocationArch> {
    runtime: &'a CoreRuntime<Arch>,
}

impl<Arch: RelocationArch> core::fmt::Debug for LazyRuntime<'_, Arch> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LazyRuntime")
            .field("runtime", &(self.runtime as *const CoreRuntime<Arch>))
            .finish()
    }
}

impl<Arch: RelocationArch> Copy for LazyRuntime<'_, Arch> {}

impl<Arch: RelocationArch> Clone for LazyRuntime<'_, Arch> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, Arch: RelocationArch> LazyRuntime<'a, Arch> {
    #[inline]
    pub(crate) fn new(runtime: &'a CoreRuntime<Arch>) -> Self {
        Self { runtime }
    }

    /// Rebuilds a lazy runtime handle from a context entry passed to a resolver.
    ///
    /// # Safety
    ///
    /// `runtime` must be a value previously returned by [`Self::runtime`] for a
    /// live module with the same `Arch` type. The caller must keep that module
    /// alive and its runtime valid for the entire chosen lifetime `'a`.
    #[inline]
    pub unsafe fn from_runtime(runtime: VmAddr) -> Self {
        Self {
            runtime: unsafe { runtime.as_mut_ptr::<CoreRuntime<Arch>>().as_ref() }
                .expect("lazy resolver context entry must not be null"),
        }
    }

    #[inline]
    pub(super) fn core(&self) -> &CoreRuntime<Arch> {
        self.runtime
    }

    /// Returns the native resolver context entry for this runtime handle.
    #[inline]
    pub fn runtime(&self) -> VmAddr {
        VmAddr::from_ptr(self.runtime as *const CoreRuntime<Arch>)
    }

    /// Returns the mapped image memory owned by the module.
    #[inline]
    pub fn memory(&self) -> &dyn ImageMemory {
        self.core().module().memory()
    }

    /// Returns one PLT relocation by lazy relocation index.
    #[inline]
    pub fn plt_relocation(&self, rela_idx: usize) -> Option<LazyPltReloc<'_, Arch>> {
        let rel = self.core().plt()?.as_slice().get(rela_idx)?;
        let symbol = self
            .core()
            .module()
            .exports()
            .elf_symbols()
            .view()
            .entry(rel.r_symbol());
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
