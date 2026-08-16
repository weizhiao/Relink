#[cfg(feature = "object")]
use super::RelocHelper;
use super::{HandleResult, RelocValue, RelocationValueKind};
#[cfg(feature = "object")]
use crate::elf::{ElfRelType, ElfShdr};
#[cfg(feature = "object")]
use crate::object::layout::PltGotSection;
use crate::{
    ByteRepr, RelocReason, Result,
    arch::ArchKind,
    elf::{ElfLayout, ElfMachine, ElfRelEntry, ElfRelocationType, ElfTarget, ElfWord},
    image::LookupScope,
    lazy::{LazyBinder, LazyPlacement},
    memory::{ImageMemory, ImageMemoryExt, RegionAccess, VmAddr},
    observer::{RelocationEvent, RelocationObserver},
    relocation::SymbolRegistry,
    runtime::DomainId,
    sync::Arc,
    tls::TlsResolver,
};

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

    /// Complete ELF target accepted by this relocation architecture.
    const TARGET: ElfTarget = ElfTarget::new(
        <Self::Layout as ElfLayout>::CLASS,
        <Self::Layout as ElfLayout>::DATA_ENCODING,
        Self::MACHINE,
    );

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
    /// IFUNC relative relocation type, if the architecture defines one.
    const IRELATIVE: Option<ElfRelocationType>;
    /// COPY relocation type, if the architecture defines one.
    const COPY: Option<ElfRelocationType>;

    /// TLS module-id relocation type, if the architecture defines one.
    const DTPMOD: Option<ElfRelocationType>;
    /// TLS dynamic offset relocation type.
    const DTPOFF: ElfRelocationType;
    /// TLS static thread-pointer offset relocation type.
    const TPOFF: ElfRelocationType;
    /// TLSDESC relocation type, if the architecture defines one.
    const TLSDESC: Option<ElfRelocationType> = None;
    /// DTV offset used by this architecture's TLS ABI.
    const TLS_DTV_OFFSET: usize = 0;
    /// How this architecture installs lazy-binding runtime entries.
    const LAZY_BINDING: LazyPlacement;

    /// Whether relocation may execute target code or install target runtime
    /// hooks directly in the current process.
    ///
    /// Native relocation enables this so IFUNC resolvers, TLS resolver stubs,
    /// lazy binding trampolines, and init arrays keep their current behavior.
    /// Cross-architecture implementations normally leave this as `false`.
    const SUPPORTS_NATIVE_RUNTIME: bool = false;

    /// Whether scan-first linking can repair retained relocations after
    /// section-level reordering for this architecture.
    const SUPPORTS_SECTION_REORDER: bool = false;

    /// Validates architecture-specific ELF header flags.
    #[inline]
    fn validate_e_flags(_flags: u32) -> Result<()> {
        Ok(())
    }

    /// Applies one relative dynamic relocation.
    ///
    /// Architectures may override this when their relative relocation keeps
    /// the addend somewhere other than the relocation entry.
    #[inline]
    fn apply_relative<Memory>(rel: &Self::Relocation, memory: &Memory) -> Result<()>
    where
        Self: Sized,
        Memory: ImageMemory,
        <Self::Layout as ElfLayout>::Word: ByteRepr,
    {
        let base = memory.base();
        let place = base + rel.r_offset();
        let addend = rel.read_addend(memory, place)?;
        let value = base.wrapping_add_signed(addend);
        let word = <Self::Layout as ElfLayout>::Word::from_usize(value.get());
        unsafe { memory.write_value(place, word) }
    }

    /// Returns whether `r_type` is one of this architecture's TLS relocations.
    #[inline]
    fn is_tls(r_type: ElfRelocationType) -> bool {
        Self::DTPMOD == Some(r_type)
            || Self::DTPOFF == r_type
            || Self::TPOFF == r_type
            || Self::TLSDESC == Some(r_type)
    }

    /// Handles a dynamic relocation not covered by the common relocation classes.
    ///
    /// This hook applies to both regular and PLT relocation tables and runs
    /// before the observer post-hook. Return [`HandleResult::Unhandled`] to
    /// leave the relocation to the observer.
    #[inline]
    fn relocate_custom<D, R, Tls, H>(
        _event: &RelocationEvent<'_, D, Self, R, Tls, H>,
    ) -> Result<HandleResult>
    where
        Self: Sized,
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<Self>,
    {
        Ok(HandleResult::Unhandled)
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
pub trait ObjectArch: RelocationArch {
    type State: Default;

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn prepare_relocation<D, R, Tls, Obs, H, Memory>(
        _state: &mut Self::State,
        _helper: &mut RelocHelper<'_, D, Self, R, Tls, Obs, H, Memory>,
        _shdrs: &[ElfShdr<Self::Layout>],
    ) -> Result<()>
    where
        Self: Sized,
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<Self>,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: ImageMemory,
    {
        Ok(())
    }

    #[allow(private_bounds)]
    #[allow(private_interfaces)]
    fn relocate<D, R, Tls, Obs, H, Memory>(
        _state: &mut Self::State,
        helper: &mut RelocHelper<'_, D, Self, R, Tls, Obs, H, Memory>,
        rel: &ElfRelType<Self>,
        _target: &ElfShdr<Self::Layout>,
        _pltgot: &mut PltGotSection,
    ) -> Result<()>
    where
        Self: Sized,
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<Self>,
        Obs: RelocationObserver<Self> + ?Sized,
        Memory: ImageMemory,
    {
        Err(helper.reloc_error(rel, RelocReason::Unsupported))
    }

    /// Returns whether this object relocation reserves a regular GOT entry.
    ///
    /// PLT relocations should report through [`Self::needs_plt`]; that reservation
    /// includes the associated GOT.PLT slot.
    #[inline]
    fn needs_got(_r_type: ElfRelocationType) -> bool
    where
        Self: Sized,
    {
        false
    }

    /// Returns whether this object relocation reserves a PLT entry and its
    /// associated GOT.PLT slot.
    #[inline]
    fn needs_plt(_r_type: ElfRelocationType) -> bool
    where
        Self: Sized,
    {
        false
    }
}

#[cfg(not(feature = "object"))]
#[doc(hidden)]
pub trait ObjectArch: RelocationArch {}

#[cfg(not(feature = "object"))]
impl<T: RelocationArch> ObjectArch for T {}

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
    Tls: TlsResolver<Arch>,
    Obs: ?Sized,
    Binder: ?Sized,
> {
    pub(crate) scope: LookupScope<Arch, Tls>,
    pub(crate) symbols: Option<Arc<SymbolRegistry<Arch, Tls>>>,
    pub(crate) binding: BindingMode,
    pub(crate) run_init: bool,
    pub(crate) lazy_binder: &'a Binder,
    pub(crate) observer: &'a mut Obs,
}

/// A trait for raw image types that can undergo relocation.
///
/// In normal use, callers do not invoke this trait directly. Instead, they load a raw
/// image with [`crate::Loader`] and pass it to [`Relocator::run`].
///
/// The target architecture is selected by the implementor through the `Arch`
/// associated type, so [`Relocator::relocate`] can dispatch automatically
/// without callers having to specify a turbofish.
///
/// [`Relocator::relocate`]: crate::Relocator::relocate
pub trait Relocatable<D = ()>: Sized {
    /// The type of the relocated object.
    type Output;

    /// Relocation type numbering used when relocating this image.
    ///
    /// Defaults to [`crate::arch::NativeArch`] for images loaded for the host.
    /// Cross-architecture images use the architecture selected on the loader.
    type Arch: RelocationArch;

    /// TLS resolver used by this image and every module in its relocation scope.
    type Tls: TlsResolver<Self::Arch>;

    /// Returns the runtime domain in which this image was loaded.
    fn domain_id(&self) -> DomainId;

    /// Executes relocation using the implementor's target architecture.
    fn relocate<Obs, Binder>(
        self,
        args: RelocateArgs<'_, Self::Arch, Self::Tls, Obs, Binder>,
    ) -> Result<Self::Output>
    where
        Obs: RelocationObserver<Self::Arch> + ?Sized,
        Binder: LazyBinder<Self::Arch> + ?Sized;
}
