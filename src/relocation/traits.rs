#[cfg(feature = "object")]
use super::RelocHelper;
use super::{Emulator, RelocAddr, RelocValue, RelocationValueKind, SymDef, find_symdef_impl};
use crate::{
    RelocReason, Result,
    arch::{ArchKind, NativeArch},
    elf::{ElfLayout, ElfMachine, ElfRelEntry, ElfRelType, ElfRelocationType},
    image::{ElfCore, ModuleScope},
    sync::Arc,
};
use alloc::boxed::Box;
use core::marker::PhantomData;

/// Architecture-specific dynamic relocation numbering.
///
/// This trait describes the relocation type numbers for one ELF target
/// architecture without changing the in-memory relocation entry representation.
/// Most users get the native implementation automatically through
/// [`crate::Loader`]; cross-architecture callers select a target architecture
/// with [`crate::Loader::for_arch`].
pub trait RelocationArch: 'static {
    /// Runtime tag for this target architecture.
    const KIND: ArchKind;

    /// ELF machine value accepted by this architecture.
    const MACHINE: ElfMachine;

    /// ELF class/layout used by this architecture.
    type Layout: ElfLayout;

    /// Dynamic relocation entry format used by this architecture.
    type Relocation: ElfRelEntry<Self::Layout> + 'static;

    /// Relocation type that performs no operation.
    const NONE: ElfRelocationType;
    /// Relative relocation type.
    const RELATIVE: ElfRelocationType;
    /// GOT entry relocation type.
    const GOT: ElfRelocationType;
    /// Symbolic absolute relocation type.
    const SYMBOLIC: ElfRelocationType;
    /// PLT jump-slot relocation type.
    const JUMP_SLOT: ElfRelocationType;
    /// IFUNC relative relocation type.
    const IRELATIVE: ElfRelocationType;
    /// COPY relocation type.
    const COPY: ElfRelocationType;

    /// TLS module-id relocation type.
    const DTPMOD: ElfRelocationType;
    /// TLS dynamic offset relocation type.
    const DTPOFF: ElfRelocationType;
    /// TLS static thread-pointer offset relocation type.
    const TPOFF: ElfRelocationType;
    /// TLSDESC relocation type, if the architecture defines one.
    const TLSDESC: Option<ElfRelocationType> = None;
    /// DTV offset used by this architecture's TLS ABI.
    const TLS_DTV_OFFSET: usize = 0;

    /// Whether relocation may execute target code or install target runtime
    /// hooks directly in the current process.
    ///
    /// Native relocation enables this so IFUNC resolvers, TLS resolver stubs,
    /// lazy binding trampolines, and init arrays keep their current behavior.
    /// Cross-architecture implementations normally leave this as `false`.
    const SUPPORTS_NATIVE_RUNTIME: bool = false;

    /// Returns whether `r_type` is this architecture's TLSDESC relocation.
    #[inline]
    fn is_tlsdesc(r_type: ElfRelocationType) -> bool {
        Self::TLSDESC.is_some_and(|tlsdesc| r_type == tlsdesc)
    }

    /// Returns whether `r_type` is one of this architecture's TLS relocations.
    #[inline]
    fn is_tls(r_type: ElfRelocationType) -> bool {
        r_type == Self::DTPMOD
            || r_type == Self::DTPOFF
            || r_type == Self::TPOFF
            || Self::is_tlsdesc(r_type)
    }

    /// Returns a diagnostic name for a relocation type.
    #[inline]
    fn rel_type_to_str(_r_type: ElfRelocationType) -> &'static str {
        "UNKNOWN"
    }

    #[cfg(feature = "object")]
    #[doc(hidden)]
    #[allow(private_interfaces)]
    fn relocate_object<D, PreH, PostH>(
        helper: &mut RelocHelper<'_, D, Self, PreH, PostH>,
        rel: &ElfRelType<Self>,
        _pltgot: &mut crate::object::layout::PltGotSection,
    ) -> Result<()>
    where
        Self: Sized,
        D: 'static,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
    {
        Err(super::reloc_error::<Self, _>(
            rel,
            RelocReason::Unsupported,
            helper.core,
        ))
    }

    #[cfg(feature = "object")]
    #[doc(hidden)]
    #[inline]
    fn object_needs_got(_r_type: ElfRelocationType) -> bool
    where
        Self: Sized,
    {
        false
    }

    #[cfg(feature = "object")]
    #[doc(hidden)]
    #[inline]
    fn object_needs_plt(_r_type: ElfRelocationType) -> bool
    where
        Self: Sized,
    {
        false
    }
}

pub(crate) trait RelocationValueProvider {
    fn relocation_value_kind(
        _relocation_type: usize,
    ) -> core::result::Result<RelocationValueKind, RelocReason> {
        Err(RelocReason::Unsupported)
    }

    fn relocation_value<T>(
        relocation_type: usize,
        target: usize,
        addend: isize,
        place: usize,
        skip: impl FnOnce(RelocValue<()>) -> T,
        write_addr: impl FnOnce(RelocAddr) -> T,
        write_word32: impl FnOnce(RelocValue<u32>) -> T,
        write_sword32: impl FnOnce(RelocValue<i32>) -> T,
    ) -> core::result::Result<T, RelocReason> {
        let kind = Self::relocation_value_kind(relocation_type)?;
        match kind {
            RelocationValueKind::None => Ok(skip(RelocValue::new(()))),
            RelocationValueKind::Address(formula) => Ok(write_addr(RelocAddr::new(
                formula.compute(target, addend, place) as usize,
            ))),
            RelocationValueKind::Word32(formula) => {
                u32::try_from(formula.compute(target, addend, place))
                    .map(RelocValue::new)
                    .map(write_word32)
                    .map_err(|_| RelocReason::IntConversionOutOfRange)
            }
            RelocationValueKind::SWord32(formula) => {
                i32::try_from(formula.compute(target, addend, place))
                    .map(RelocValue::new)
                    .map(write_sword32)
                    .map_err(|_| RelocReason::IntConversionOutOfRange)
            }
        }
    }
}

/// A trait for intercepting relocations during relocation.
///
/// Implement this to override specific relocations, record relocation activity,
/// or provide custom handling before or after the default relocation logic runs.
///
/// # Examples
///
/// ```rust
/// use elf_loader::elf::ElfRelocationType;
/// use elf_loader::relocation::{HandleResult, RelocationContext, RelocationHandler};
/// use elf_loader::Result;
///
/// struct CustomHandler;
///
/// impl RelocationHandler for CustomHandler {
///     fn handle<D>(&self, ctx: &RelocationContext<'_, D>) -> Result<HandleResult> {
///         let rel = ctx.rel();
///         // Handle specific relocation types
///         match rel.r_type() {
///             value if value == ElfRelocationType::new(0x1234) => {
///                 // Custom relocation logic
///                 Ok(HandleResult::Handled)
///             }
///             _ => Ok(HandleResult::Unhandled), // Fall through to default
///         }
///     }
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleResult {
    /// The handler did not process this relocation.
    Unhandled,
    /// The handler processed this relocation.
    Handled,
}

impl HandleResult {
    /// Returns whether the handler left the relocation for the default path.
    #[inline]
    pub const fn is_unhandled(self) -> bool {
        matches!(self, Self::Unhandled)
    }
}

/// Hook trait for observing or overriding relocation processing.
pub trait RelocationHandler<Arch: RelocationArch = NativeArch> {
    /// Handles a relocation.
    ///
    /// # Arguments
    /// * `ctx` - Context containing relocation details and scope.
    ///
    /// # Returns
    /// * `Ok(HandleResult::Unhandled)` - Not handled, fall through to default behavior.
    /// * `Ok(HandleResult::Handled)` - Handled successfully.
    /// * `Err(e)` - The handler failed.
    fn handle<D: 'static>(&self, ctx: &RelocationContext<'_, D, Arch>) -> Result<HandleResult>;
}

/// Context passed to [`RelocationHandler::handle`].
///
/// This struct provides access to the relocation entry, the module being relocated,
/// and the current symbol resolution scope.
pub struct RelocationContext<'a, D: 'static, Arch: RelocationArch = NativeArch> {
    rel: &'a ElfRelType<Arch>,
    lib: &'a ElfCore<D, Arch>,
    scope: &'a ModuleScope<Arch>,
}

impl<'a, D: 'static, Arch: RelocationArch> RelocationContext<'a, D, Arch> {
    /// Construct a new `RelocationContext`.
    #[inline]
    pub(crate) fn new(
        rel: &'a ElfRelType<Arch>,
        lib: &'a ElfCore<D, Arch>,
        scope: &'a ModuleScope<Arch>,
    ) -> Self {
        Self { rel, lib, scope }
    }

    /// Access the relocation entry.
    #[inline]
    pub fn rel(&self) -> &ElfRelType<Arch> {
        self.rel
    }

    /// Access the core component where the relocation appears.
    #[inline]
    pub fn lib(&self) -> &ElfCore<D, Arch> {
        self.lib
    }

    /// Access the current resolution scope.
    #[inline]
    pub fn scope(&self) -> &ModuleScope<Arch> {
        &self.scope
    }

    /// Find symbol definition in the current scope
    #[inline]
    pub fn find_symdef(&self, r_sym: usize) -> Option<SymDef<'a, D, Arch>> {
        let symbol = self.lib.symtab();
        let (sym, syminfo) = symbol.symbol_idx(r_sym);
        find_symdef_impl(self.lib, self.scope, sym, &syminfo)
    }
}

impl<Arch: RelocationArch> RelocationHandler<Arch> for () {
    fn handle<D: 'static>(&self, _ctx: &RelocationContext<'_, D, Arch>) -> Result<HandleResult> {
        Ok(HandleResult::Unhandled)
    }
}

impl<Arch: RelocationArch, H: RelocationHandler<Arch> + ?Sized> RelocationHandler<Arch> for &H {
    fn handle<D: 'static>(&self, ctx: &RelocationContext<'_, D, Arch>) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

impl<Arch: RelocationArch, H: RelocationHandler<Arch> + ?Sized> RelocationHandler<Arch> for &mut H {
    fn handle<D: 'static>(&self, ctx: &RelocationContext<'_, D, Arch>) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

impl<Arch: RelocationArch, H: RelocationHandler<Arch> + ?Sized> RelocationHandler<Arch> for Box<H> {
    fn handle<D: 'static>(&self, ctx: &RelocationContext<'_, D, Arch>) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

impl<Arch: RelocationArch, H: RelocationHandler<Arch> + ?Sized> RelocationHandler<Arch> for Arc<H> {
    fn handle<D: 'static>(&self, ctx: &RelocationContext<'_, D, Arch>) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

/// Binding mode configuration for relocation.
///
/// This controls whether the loader follows the ELF object's default binding mode
/// or overrides it when lazy binding support is enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BindingMode {
    /// Follow the ELF object's default binding behavior.
    #[default]
    Default,
    /// Force eager binding.
    Eager,
    /// Force lazy binding.
    Lazy,
}

/// Internal relocation configuration shared across raw image types.
pub struct RelocateArgs<'a, D: 'static, Arch: RelocationArch, PreH: ?Sized, PostH: ?Sized> {
    pub(crate) scope: ModuleScope<Arch>,
    pub(crate) binding: BindingMode,
    pub(crate) pre_handler: &'a PreH,
    pub(crate) post_handler: &'a PostH,
    pub(crate) emu: Option<Arc<dyn Emulator<Arch>>>,
    _marker: PhantomData<fn() -> (D, Arch)>,
}

impl<'a, D: 'static, Arch: RelocationArch, PreH: ?Sized, PostH: ?Sized>
    RelocateArgs<'a, D, Arch, PreH, PostH>
{
    #[inline]
    pub(crate) fn new(
        scope: ModuleScope<Arch>,
        binding: BindingMode,
        pre_handler: &'a PreH,
        post_handler: &'a PostH,
        emu: Option<Arc<dyn Emulator<Arch>>>,
    ) -> Self {
        Self {
            scope,
            binding,
            pre_handler,
            post_handler,
            emu,
            _marker: PhantomData,
        }
    }
}

/// A trait for raw image types that can undergo relocation.
///
/// In normal use, callers do not invoke this trait directly. Instead, they load a raw
/// image with [`crate::Loader`] and then call `.relocator().relocate()`.
///
/// The target architecture is selected by the implementor through the `Arch`
/// associated type, so [`Relocator::relocate`] can dispatch automatically
/// without callers having to specify a turbofish.
///
/// [`Relocator::relocate`]: crate::relocation::Relocator::relocate
pub trait Relocatable<D = ()>: Sized {
    /// The type of the relocated object.
    type Output;

    /// Relocation type numbering used when relocating this image.
    ///
    /// Defaults to [`crate::arch::NativeArch`] for images loaded for the host.
    /// Cross-architecture images use the architecture selected on the loader.
    type Arch: RelocationArch;

    /// Executes relocation using the implementor's target architecture.
    fn relocate<PreH, PostH>(
        self,
        args: RelocateArgs<'_, D, Self::Arch, PreH, PostH>,
    ) -> Result<Self::Output>
    where
        PreH: RelocationHandler<Self::Arch> + ?Sized,
        PostH: RelocationHandler<Self::Arch> + ?Sized;
}

/// Marker trait for raw image types that support lazy-binding fixup hooks.
pub trait SupportLazy {}

impl SupportLazy for () {}
