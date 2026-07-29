use crate::{
    Result, TlsError,
    elf::{ElfLayout, ElfPhdr, ElfProgramType},
    memory::VmAddr,
    sync::Weak,
};

pub(crate) const TLS_GET_ADDR_SYMBOL: &str = "__tls_get_addr";

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

/// A cloneable source for a relocated TLS initialization image.
///
/// The source may refer back to the loaded image instead of owning a copy of the
/// image bytes. Users must consume the borrowed image inside
/// [`with_image`](Self::with_image).
#[derive(Clone)]
pub struct TlsImageSource {
    provider: Weak<dyn TlsImageProvider>,
}

impl core::fmt::Debug for TlsImageSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsImageSource").finish_non_exhaustive()
    }
}

impl TlsImageSource {
    #[inline]
    pub(crate) fn new(provider: Weak<dyn TlsImageProvider>) -> Self {
        Self { provider }
    }

    /// Borrows the TLS initialization image while the backing image is alive.
    #[inline]
    pub fn with_image(&self, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let Some(provider) = self.provider.upgrade() else {
            return Err(TlsError::TemplateUnavailable.into());
        };
        provider.with_tls_image(f)
    }
}

pub(crate) trait TlsImageProvider: Send + Sync {
    fn with_tls_image(&self, f: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>;
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
/// at non-zero IDs.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TlsModuleId(usize);

impl TlsModuleId {
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

/// TLS metadata associated with a runtime module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleTls {
    /// The module has a static TLS block at a fixed thread-pointer offset.
    Static {
        /// Runtime TLS module identifier.
        mod_id: TlsModuleId,
        /// Offset of this module's static TLS block relative to the thread pointer.
        tp_offset: TlsTpOffset,
    },
    /// The module uses dynamic TLS and resolves addresses through `__tls_get_addr`.
    Dynamic {
        /// Runtime TLS module identifier.
        mod_id: TlsModuleId,
    },
}

impl ModuleTls {
    /// Returns the registered TLS module ID.
    #[inline]
    pub const fn mod_id(self) -> TlsModuleId {
        match self {
            Self::Static { mod_id, .. } | Self::Dynamic { mod_id, .. } => mod_id,
        }
    }

    /// Returns the static TLS thread-pointer offset, when available.
    #[inline]
    pub const fn tp_offset(self) -> Option<TlsTpOffset> {
        match self {
            Self::Static { tp_offset, .. } => Some(tp_offset),
            Self::Dynamic { .. } => None,
        }
    }
}

/// Request for a target-visible TLSDESC binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsDescRequest {
    /// A defined TLS symbol at `offset` within its module's TLS block.
    Defined {
        /// Runtime TLS module metadata.
        module: ModuleTls,
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
