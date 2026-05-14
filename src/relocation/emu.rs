use super::RelocationArch;
use crate::tls::{TlsModuleId, TlsTpOffset};
use crate::{
    Result,
    elf::{ElfRelType, Lifecycle},
    image::ElfCore,
    segment::ElfSegments,
};
use core::marker::PhantomData;

/// Marker for architecture backends that may be driven through an emulator.
///
/// Built-in architecture markers implement this trait only when they are not
/// the host architecture. Native relocation already has a real host ABI
/// runtime, so the emulator hook is intentionally unavailable there.
pub trait EmulatedArch: RelocationArch {}

/// Image context visible to an emulator.
pub struct EmuContext<'a, Arch: RelocationArch> {
    name: &'a str,
    base: usize,
    segments: &'a ElfSegments,
    _marker: PhantomData<fn() -> Arch>,
}

impl<'a, Arch: RelocationArch> EmuContext<'a, Arch> {
    #[inline]
    pub(crate) fn new<D: 'static>(core: &'a ElfCore<D, Arch>) -> Self {
        Self::from_parts(core.name(), core.base_addr().into_inner(), core.segments())
    }

    #[inline]
    pub(crate) const fn from_parts(name: &'a str, base: usize, segments: &'a ElfSegments) -> Self {
        Self {
            name,
            base,
            segments,
            _marker: PhantomData,
        }
    }

    /// Module name being relocated.
    #[inline]
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Runtime base address of the mapped image.
    #[inline]
    pub fn base(&self) -> usize {
        self.base
    }

    /// Returns whether an absolute address is covered by this image.
    #[inline]
    pub fn contains_addr(&self, addr: usize) -> bool {
        self.segments.contains_addr(addr)
    }
}

/// Relocation-specific context visible to an emulator.
pub struct EmuRelocationContext<'a, Arch: RelocationArch> {
    image: EmuContext<'a, Arch>,
    rel: &'a ElfRelType<Arch>,
}

impl<'a, Arch: RelocationArch> EmuRelocationContext<'a, Arch> {
    #[inline]
    pub(crate) fn new<D: 'static>(core: &'a ElfCore<D, Arch>, rel: &'a ElfRelType<Arch>) -> Self {
        Self {
            image: EmuContext::new(core),
            rel,
        }
    }

    /// Image context for the relocation.
    #[inline]
    pub fn image(&self) -> &EmuContext<'a, Arch> {
        &self.image
    }

    /// ELF relocation entry currently being processed.
    #[inline]
    pub fn rel(&self) -> &'a ElfRelType<Arch> {
        self.rel
    }
}

/// Input data for an emulated TLSDESC relocation.
#[derive(Clone, Copy, Debug)]
pub struct TlsDescEmuRequest {
    symbol_value: usize,
    addend: isize,
    module_id: Option<TlsModuleId>,
    tp_offset: Option<TlsTpOffset>,
    tls_get_addr: usize,
}

impl TlsDescEmuRequest {
    #[inline]
    pub const fn new(
        symbol_value: usize,
        addend: isize,
        module_id: Option<TlsModuleId>,
        tp_offset: Option<TlsTpOffset>,
        tls_get_addr: usize,
    ) -> Self {
        Self {
            symbol_value,
            addend,
            module_id,
            tp_offset,
            tls_get_addr,
        }
    }

    /// Symbol value from the TLS symbol referenced by the relocation.
    #[inline]
    pub const fn symbol_value(&self) -> usize {
        self.symbol_value
    }

    /// Relocation addend.
    #[inline]
    pub const fn addend(&self) -> isize {
        self.addend
    }

    /// Dynamic TLS module id when the symbol has one.
    #[inline]
    pub const fn module_id(&self) -> Option<TlsModuleId> {
        self.module_id
    }

    /// Static TLS thread-pointer offset when available.
    #[inline]
    pub const fn tp_offset(&self) -> Option<TlsTpOffset> {
        self.tp_offset
    }

    /// Address of the loader-provided `__tls_get_addr` entry point.
    #[inline]
    pub const fn tls_get_addr(&self) -> usize {
        self.tls_get_addr
    }
}

/// Two-word TLSDESC value produced by an emulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsDescEmuValue {
    resolver: usize,
    arg: usize,
}

impl TlsDescEmuValue {
    /// Creates a TLSDESC pair.
    #[inline]
    pub const fn new(resolver: usize, arg: usize) -> Self {
        Self { resolver, arg }
    }

    /// Resolver function pointer written to the first TLSDESC word.
    #[inline]
    pub const fn resolver(&self) -> usize {
        self.resolver
    }

    /// Resolver argument written to the second TLSDESC word.
    #[inline]
    pub const fn arg(&self) -> usize {
        self.arg
    }
}

/// Guest execution hooks used while relocating a non-native image.
///
/// This is intentionally exposed only through
/// [`Relocator::emulator`](crate::relocation::Relocator::emulator), which is
/// available for [`EmulatedArch`] backends. Implementors are expected to provide
/// the complete guest-side behavior for every hook in this trait.
pub trait Emulator<Arch: RelocationArch>: Send + Sync + 'static {
    /// Executes an IFUNC resolver in the guest environment and returns its value.
    fn resolve_ifunc(&self, ctx: &EmuRelocationContext<'_, Arch>, resolver: usize)
    -> Result<usize>;

    /// Executes `.init` / `.init_array` functions in the guest environment.
    fn call_init(&self, ctx: &EmuContext<'_, Arch>, lifecycle: &Lifecycle<'_>) -> Result<()>;

    /// Executes `.fini` / `.fini_array` functions in the guest environment.
    ///
    /// This mirrors the native finalizer contract: finalization runs during
    /// drop and therefore cannot report errors to the caller.
    fn call_fini(&self, ctx: &EmuContext<'_, Arch>, lifecycle: &Lifecycle<'_>);

    /// Builds the guest TLSDESC pair for a TLSDESC relocation.
    fn resolve_tlsdesc(
        &self,
        ctx: &EmuRelocationContext<'_, Arch>,
        request: TlsDescEmuRequest,
    ) -> Result<TlsDescEmuValue>;
}
