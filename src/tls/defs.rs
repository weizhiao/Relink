use super::TlsModule;
use alloc::boxed::Box;

use crate::{
    Result, TlsError,
    elf::{ElfLayout, ElfPhdr, ElfProgramType},
    memory::VmAddr,
    sync::Arc,
};

pub(crate) const TLS_GET_ADDR_SYMBOL: &[u8] = b"__tls_get_addr";

/// Information about a TLS segment from ELF headers.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct TlsInfo {
    /// Virtual address of the TLS template in the ELF file.
    pub vaddr: usize,
    /// Size of the initialized TLS data.
    pub filesz: usize,
    /// Total size of the TLS block in memory.
    pub memsz: usize,
    /// Alignment requirement of the TLS block.
    pub align: usize,
}

impl core::fmt::Debug for TlsInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsInfo")
            .field("vaddr", &format_args!("0x{:x}", self.vaddr))
            .field("filesz", &self.filesz)
            .field("memsz", &self.memsz)
            .field("align", &self.align)
            .finish()
    }
}

impl TlsInfo {
    /// Creates a new `TlsInfo` from an ELF program header.
    pub fn new<L: ElfLayout>(phdr: &ElfPhdr<L>) -> Self {
        assert_eq!(phdr.program_type(), ElfProgramType::TLS);
        Self {
            vaddr: phdr.p_vaddr().get(),
            filesz: phdr.p_filesz(),
            memsz: phdr.p_memsz(),
            align: phdr.p_align(),
        }
    }

    /// Validates the TLS image size and alignment requirements.
    pub fn validate(&self) -> Result<()> {
        if !self.align.max(1).is_power_of_two() || self.filesz > self.memsz {
            return Err(TlsError::InvalidInfo.into());
        }
        Ok(())
    }
}

/// Shared TLS initialization bytes copied after relocation.
/// Contains only `filesz` bytes and does not retain the ELF image.
#[derive(Clone, Debug)]
pub struct TlsTemplate(Arc<[u8]>);

impl TlsTemplate {
    /// Copies the relocated initialization bytes into shared owned storage.
    pub fn new(bytes: &[u8]) -> Self {
        Self(Arc::from(bytes))
    }
}

impl AsRef<[u8]> for TlsTemplate {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for TlsTemplate {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

/// Two-word TLSDESC binding written into a loaded image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsDescBinding {
    resolver: VmAddr,
    arg: usize,
}

impl TlsDescBinding {
    /// Creates a TLSDESC pair.
    #[inline]
    pub const fn new(resolver: VmAddr, arg: usize) -> Self {
        Self { resolver, arg }
    }

    /// Resolver function pointer written to the first TLSDESC word.
    #[inline]
    pub const fn resolver(&self) -> VmAddr {
        self.resolver
    }

    /// Resolver argument written to the second TLSDESC word.
    #[inline]
    pub const fn arg(&self) -> usize {
        self.arg
    }
}

/// TLS module ID assigned by a [`TlsResolver`](crate::tls::TlsResolver).
///
/// ID 0 is reserved by the platform TLS ABI; dynamically loaded modules start
/// at non-zero IDs. The value is opaque outside its resolver's namespace.
/// [`TlsRegistry`](crate::tls::TlsRegistry) encodes a slot and an incarnation;
/// host and custom resolvers may use a different encoding.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TlsModuleId(usize);

impl TlsModuleId {
    // The registry uses a one-based slot in the low half and its incarnation
    // in the high half. Keep this private: other resolvers own their ID format.
    const SLOT_BITS: u32 = usize::BITS / 2;
    pub(super) const SLOT_MASK: usize = (1 << Self::SLOT_BITS) - 1;

    #[inline]
    pub(super) const fn slot(self) -> Option<usize> {
        (self.0 & Self::SLOT_MASK).checked_sub(1)
    }

    pub(super) const fn next_incarnation(self) -> Option<Self> {
        match self.0.checked_add(1 << Self::SLOT_BITS) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    /// The reserved module ID used when no TLS module is present.
    pub const RESERVED: Self = Self(0);

    /// Creates a module ID from its raw ABI value.
    #[inline]
    pub const fn new(raw: usize) -> Self {
        Self(raw)
    }

    /// Returns the raw ABI value.
    #[inline]
    pub const fn get(self) -> usize {
        self.0
    }

    /// Returns whether this is the reserved zero module ID.
    #[inline]
    pub const fn is_reserved(self) -> bool {
        self.0 == Self::RESERVED.0
    }
}

impl core::fmt::Display for TlsModuleId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// Signed offset from the thread pointer to a static TLS block.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TlsTpOffset(isize);

impl TlsTpOffset {
    /// Creates a thread-pointer offset from its raw ABI value.
    #[inline]
    pub const fn new(raw: isize) -> Self {
        Self(raw)
    }

    /// Returns the raw signed offset from the thread pointer.
    #[inline]
    pub const fn get(self) -> isize {
        self.0
    }
}

impl core::fmt::Display for TlsTpOffset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// ABI metadata for a registered TLS module, independent of its storage owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsBinding {
    mod_id: TlsModuleId,
    tp_offset: Option<TlsTpOffset>,
}

impl TlsBinding {
    /// Creates metadata with an optional, stable thread-pointer offset.
    pub const fn new(mod_id: TlsModuleId, tp_offset: Option<TlsTpOffset>) -> Self {
        Self { mod_id, tp_offset }
    }

    /// Returns the ID in this runtime's TLS namespace.
    pub const fn mod_id(self) -> TlsModuleId {
        self.mod_id
    }

    /// Returns the static thread-pointer offset, when supported.
    pub const fn tp_offset(self) -> Option<TlsTpOffset> {
        self.tp_offset
    }
}

/// A descriptor and the state retained by the image containing that descriptor.
pub struct TlsDescSetup {
    binding: TlsDescBinding,
    state: Option<Box<dyn Send + Sync>>,
}

impl TlsDescSetup {
    /// Creates a descriptor that requires no retained state.
    pub const fn new(binding: TlsDescBinding) -> Self {
        Self {
            binding,
            state: None,
        }
    }

    /// Keeps state alive until the image containing the descriptor is dropped.
    pub fn with_state(mut self, state: Box<dyn Send + Sync>) -> Self {
        self.state = Some(state);
        self
    }

    pub(crate) fn into_parts(self) -> (TlsDescBinding, Option<Box<dyn Send + Sync>>) {
        (self.binding, self.state)
    }
}

/// Request for a target-visible TLSDESC binding.
#[derive(Clone, Debug)]
pub enum TlsDescRequest {
    /// A defined TLS symbol at `offset` within its module's TLS block.
    Defined {
        /// Non-owning registration metadata. The caller must keep the defining
        /// module and runtime alive while the descriptor is in use.
        module: TlsModule,
        /// Symbol offset including the relocation addend.
        offset: usize,
    },
    /// An undefined weak TLS symbol.
    UndefinedWeak {
        /// Relocation addend preserved in the descriptor argument.
        addend: usize,
    },
}

/// Requested TLS placement for a module registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsRequest {
    /// Dynamic TLS is allowed. The resolver may still choose static storage.
    Dynamic,
    /// Static TLS is required. An existing thread-pointer offset may be supplied.
    Static(Option<TlsTpOffset>),
}

/// The TLS Index structure passed to `__tls_get_addr`.
/// This matches the C ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsIndex {
    /// TLS module id.
    pub ti_module: TlsModuleId,
    /// Offset inside the module's TLS block.
    pub ti_offset: usize,
}
