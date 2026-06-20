#[cfg(feature = "object")]
use super::{RelocHelper, reloc_error};
use super::{RelocValue, RelocationValueKind, SymDef, find_symdef_impl};
#[cfg(feature = "object")]
use crate::elf::ElfShdr;
use crate::{
    ByteRepr, RelocReason, Result,
    arch::{ArchKind, NativeArch},
    elf::{
        ElfLayout, ElfMachine, ElfRelEntry, ElfRelType, ElfRelocationType, ElfSymbol, HashTable,
        SymbolInfo, SymbolTableView,
    },
    image::{ElfCore, ModuleScope},
    memory::{HostRegion, RegionAccess, VmAddr},
    observer::RelocationObserver,
    runtime::CodeExecutor,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::boxed::Box;

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
    type Relocation: ByteRepr + ElfRelEntry<Self::Layout> + 'static;

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
}

/// Object-file (`ET_REL`) relocation support layered on top of [`RelocationArch`].
#[cfg(feature = "object")]
#[doc(hidden)]
pub trait ObjectRelocationArch: RelocationArch {
    type ObjectRelocationState: Default;

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn prepare_object_relocation<D, R, Tls, PreH, PostH, Obs, H, Memory>(
        _state: &mut Self::ObjectRelocationState,
        _helper: &mut RelocHelper<'_, D, Self, R, Tls, PreH, PostH, Obs, H, Memory>,
        _shdrs: &[ElfShdr<Self::Layout>],
    ) -> Result<()>
    where
        Self: Sized,
        D: 'static,
        R: RegionAccess,
        Tls: TlsResolver,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: crate::memory::ImageMemory,
    {
        Ok(())
    }

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn relocate_object<D, R, Tls, PreH, PostH, Obs, H, Memory>(
        _state: &mut Self::ObjectRelocationState,
        helper: &mut RelocHelper<'_, D, Self, R, Tls, PreH, PostH, Obs, H, Memory>,
        rel: &ElfRelType<Self>,
        _target: &ElfShdr<Self::Layout>,
        _pltgot: &mut crate::object::layout::PltGotSection,
    ) -> Result<()>
    where
        Self: Sized,
        D: 'static,
        R: RegionAccess,
        Tls: TlsResolver,
        PreH: RelocationHandler<Self> + ?Sized,
        PostH: RelocationHandler<Self> + ?Sized,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: crate::memory::ImageMemory,
    {
        Err(reloc_error::<Self, _, R, Tls, H>(
            rel,
            RelocReason::Unsupported,
            helper.core,
            helper.symbols(),
        ))
    }

    /// Returns whether this object relocation reserves a regular GOT entry.
    ///
    /// PLT relocations should report through [`Self::object_needs_plt`]; that
    /// reservation includes the associated GOT.PLT slot.
    #[inline]
    fn object_needs_got(_r_type: ElfRelocationType) -> bool
    where
        Self: Sized,
    {
        false
    }

    /// Returns whether this object relocation reserves a PLT entry and its
    /// associated GOT.PLT slot.
    #[inline]
    fn object_needs_plt(_r_type: ElfRelocationType) -> bool
    where
        Self: Sized,
    {
        false
    }
}

#[cfg(not(feature = "object"))]
#[doc(hidden)]
pub trait ObjectRelocationArch: RelocationArch {}

#[cfg(not(feature = "object"))]
impl<T: RelocationArch> ObjectRelocationArch for T {}

pub(crate) trait RelocationValueProvider {
    fn relocation_value_kind(
        _relocation_type: usize,
    ) -> core::result::Result<RelocationValueKind, RelocReason> {
        Err(RelocReason::Unsupported)
    }

    fn relocation_value<T>(
        input: RelocationValueInput,
        skip: impl FnOnce(RelocValue<()>) -> T,
        write_addr: impl FnOnce(VmAddr) -> T,
        write_word32: impl FnOnce(RelocValue<u32>) -> T,
        write_sword32: impl FnOnce(RelocValue<i32>) -> T,
    ) -> core::result::Result<T, RelocReason> {
        let kind = Self::relocation_value_kind(input.relocation_type)?;
        match kind {
            RelocationValueKind::None => Ok(skip(RelocValue::new(()))),
            RelocationValueKind::Address(formula) => {
                Ok(write_addr(VmAddr::new(
                    formula.compute(input.target, input.addend, input.place) as usize,
                )))
            }
            RelocationValueKind::Word32(formula) => {
                u32::try_from(formula.compute(input.target, input.addend, input.place))
                    .map(RelocValue::new)
                    .map(write_word32)
                    .map_err(|_| RelocReason::IntConversionOutOfRange)
            }
            RelocationValueKind::SWord32(formula) => {
                i32::try_from(formula.compute(input.target, input.addend, input.place))
                    .map(RelocValue::new)
                    .map(write_sword32)
                    .map_err(|_| RelocReason::IntConversionOutOfRange)
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RelocationValueInput {
    pub(crate) relocation_type: usize,
    pub(crate) target: usize,
    pub(crate) addend: isize,
    pub(crate) place: usize,
}

/// A trait for intercepting relocations during relocation.
///
/// Implement this to override specific relocations, record relocation activity,
/// or provide custom handling before or after the default relocation logic runs.
///
/// # Examples
///
/// ```ignore
/// use elf_loader::elf::ElfRelocationType;
/// use elf_loader::memory::RegionAccess;
/// use elf_loader::relocation::{HandleResult, RelocationContext, RelocationHandler};
/// use elf_loader::Result;
///
/// struct CustomHandler;
///
/// impl RelocationHandler for CustomHandler {
///     fn handle<D: 'static, R: RegionAccess, H>(
///         &self,
///         ctx: &RelocationContext<'_, D, elf_loader::arch::NativeArch, R, H>,
///     ) -> Result<HandleResult>
///     {
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
    fn handle<D: 'static, R: RegionAccess, Tls: TlsResolver, H>(
        &self,
        ctx: &RelocationContext<'_, D, Arch, R, Tls, H>,
    ) -> Result<HandleResult>;
}

/// Context passed to [`RelocationHandler::handle`].
///
/// This struct provides access to the relocation entry, the module being relocated,
/// and the current symbol resolution scope.
pub struct RelocationContext<
    'a,
    D: 'static,
    Arch: RelocationArch = NativeArch,
    R: RegionAccess = HostRegion,
    Tls: TlsResolver = (),
    H = HashTable<<Arch as RelocationArch>::Layout>,
> {
    rel: &'a ElfRelType<Arch>,
    lib: &'a ElfCore<D, Arch, R, Tls>,
    symbols: SymbolTableView<'a, Arch::Layout, H>,
    scope: &'a ModuleScope<Arch, Tls>,
}

impl<'a, D: 'static, Arch: RelocationArch, R: RegionAccess, Tls: TlsResolver, H>
    RelocationContext<'a, D, Arch, R, Tls, H>
{
    /// Construct a new `RelocationContext`.
    #[inline]
    pub(crate) fn new(
        rel: &'a ElfRelType<Arch>,
        lib: &'a ElfCore<D, Arch, R, Tls>,
        symbols: SymbolTableView<'a, Arch::Layout, H>,
        scope: &'a ModuleScope<Arch, Tls>,
    ) -> Self {
        Self {
            rel,
            lib,
            symbols,
            scope,
        }
    }

    /// Access the relocation entry.
    #[inline]
    pub fn rel(&self) -> &ElfRelType<Arch> {
        self.rel
    }

    /// Access the core component where the relocation appears.
    #[inline]
    pub fn lib(&self) -> &ElfCore<D, Arch, R, Tls> {
        self.lib
    }

    /// Access the current resolution scope.
    #[inline]
    pub fn scope(&self) -> &ModuleScope<Arch, Tls> {
        self.scope
    }

    /// Access a symbol table entry by index for this relocation context.
    #[inline]
    pub fn symbol(&self, r_sym: usize) -> (&'a ElfSymbol<Arch::Layout>, SymbolInfo<'a>) {
        self.symbols.symbol_idx(r_sym)
    }

    /// Access the symbol referenced by the current relocation, if it has one.
    #[inline]
    pub fn relocation_symbol(&self) -> Option<(&'a ElfSymbol<Arch::Layout>, SymbolInfo<'a>)> {
        let r_sym = self.rel.r_symbol();
        (r_sym != 0).then(|| self.symbol(r_sym))
    }

    /// Find symbol definition in the current scope
    #[inline]
    pub fn find_symdef(&self, r_sym: usize) -> Option<SymDef<'a, D, Arch, Tls>> {
        let (sym, syminfo) = self.symbol(r_sym);
        find_symdef_impl(self.lib, self.scope, sym, &syminfo)
    }
}

impl<Arch: RelocationArch> RelocationHandler<Arch> for () {
    fn handle<D: 'static, R: RegionAccess, Tls: TlsResolver, H>(
        &self,
        _ctx: &RelocationContext<'_, D, Arch, R, Tls, H>,
    ) -> Result<HandleResult> {
        Ok(HandleResult::Unhandled)
    }
}

impl<Arch: RelocationArch, H: RelocationHandler<Arch> + ?Sized> RelocationHandler<Arch> for &H {
    fn handle<D: 'static, R: RegionAccess, Tls: TlsResolver, Hash>(
        &self,
        ctx: &RelocationContext<'_, D, Arch, R, Tls, Hash>,
    ) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

impl<Arch: RelocationArch, H: RelocationHandler<Arch> + ?Sized> RelocationHandler<Arch> for &mut H {
    fn handle<D: 'static, R: RegionAccess, Tls: TlsResolver, Hash>(
        &self,
        ctx: &RelocationContext<'_, D, Arch, R, Tls, Hash>,
    ) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

impl<Arch: RelocationArch, H: RelocationHandler<Arch> + ?Sized> RelocationHandler<Arch> for Box<H> {
    fn handle<D: 'static, R: RegionAccess, Tls: TlsResolver, Hash>(
        &self,
        ctx: &RelocationContext<'_, D, Arch, R, Tls, Hash>,
    ) -> Result<HandleResult> {
        (**self).handle(ctx)
    }
}

impl<Arch: RelocationArch, H: RelocationHandler<Arch> + ?Sized> RelocationHandler<Arch> for Arc<H> {
    fn handle<D: 'static, R: RegionAccess, Tls: TlsResolver, Hash>(
        &self,
        ctx: &RelocationContext<'_, D, Arch, R, Tls, Hash>,
    ) -> Result<HandleResult> {
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
pub struct RelocateArgs<
    'a,
    Arch: RelocationArch,
    Tls: TlsResolver,
    PreH: ?Sized,
    PostH: ?Sized,
    Obs: ?Sized,
> {
    pub(crate) scope: ModuleScope<Arch, Tls>,
    pub(crate) binding: BindingMode,
    pub(crate) executor: Arc<dyn CodeExecutor<Arch>>,
    pub(crate) pre_handler: &'a PreH,
    pub(crate) post_handler: &'a PostH,
    pub(crate) observer: &'a mut Obs,
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

    /// TLS resolver used by this image and every module in its relocation scope.
    type Tls: TlsResolver;

    /// Executes relocation using the implementor's target architecture.
    fn relocate<PreH, PostH, Obs>(
        self,
        args: RelocateArgs<'_, Self::Arch, Self::Tls, PreH, PostH, Obs>,
    ) -> Result<Self::Output>
    where
        PreH: RelocationHandler<Self::Arch> + ?Sized,
        PostH: RelocationHandler<Self::Arch> + ?Sized,
        Obs: RelocationObserver<Self::Arch> + ?Sized;
}

/// Marker trait for raw image types that support lazy-binding fixup hooks.
pub trait SupportLazy {}

impl SupportLazy for () {}
