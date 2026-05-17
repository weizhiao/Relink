use crate::{
    elf::{ElfLayout, ElfPhdr, ElfProgramType},
    sync::Arc,
};
use alloc::boxed::Box;

/// Information about a TLS segment from ELF headers.
#[derive(Clone)]
pub struct TlsInfo {
    /// Virtual address of the TLS template in the ELF file.
    pub vaddr: usize,
    /// Size of the initialized TLS data.
    pub filesz: usize,
    /// Total size of the TLS block in memory.
    pub memsz: usize,
    /// Alignment requirement of the TLS block.
    pub align: usize,
    /// The initial TLS data (template).
    image: Arc<Box<[u8]>>,
}

impl Default for TlsInfo {
    #[inline]
    fn default() -> Self {
        Self {
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
            image: Arc::new(Box::default()),
        }
    }
}

impl core::fmt::Debug for TlsInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsInfo")
            .field("vaddr", &format_args!("0x{:x}", self.vaddr))
            .field("filesz", &self.filesz)
            .field("memsz", &self.memsz)
            .field("align", &self.align)
            .field("image_len", &self.image().len())
            .finish()
    }
}

impl TlsInfo {
    /// Creates a new `TlsInfo` from an ELF program header.
    pub fn new<L: ElfLayout>(phdr: &ElfPhdr<L>, image: impl Into<Box<[u8]>>) -> Self {
        assert_eq!(phdr.program_type(), ElfProgramType::TLS);
        Self {
            vaddr: phdr.p_vaddr(),
            filesz: phdr.p_filesz(),
            memsz: phdr.p_memsz(),
            align: phdr.p_align(),
            image: Arc::new(image.into()),
        }
    }

    /// Returns the initial TLS image.
    #[inline]
    pub fn image(&self) -> &[u8] {
        self.image.as_ref().as_ref()
    }

    #[inline]
    pub(crate) fn image_arc(&self) -> Arc<Box<[u8]>> {
        self.image.clone()
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

/// Dynamic TLSDESC resolver argument.
///
/// This structure is used as the second word of a TLSDESC descriptor
/// when dynamic resolution is required. It contains a pointer to the
/// `tls_get_addr` function and the actual `TlsIndex` data.
#[repr(C)]
#[derive(Debug)]
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) struct TlsDescDynamicArg {
    pub tls_get_addr: usize,
    pub ti: TlsIndex,
}
