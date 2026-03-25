use crate::elf::{ElfClass, ElfFileType, ElfMachine};
use alloc::{borrow::Cow, boxed::Box};
use core::fmt::{self, Display};

const TLS_DISABLED_MESSAGE: &str = if cfg!(feature = "tls") {
    "TLS is not supported by this resolver. Use `with_default_tls_resolver()` to enable TLS support."
} else {
    "TLS support is not compiled into this build. Enable the `tls` cargo feature."
};

const STATIC_TLS_DISABLED_MESSAGE: &str = if cfg!(feature = "tls") {
    "Static TLS is not supported by this resolver. Use `with_default_tls_resolver()` to enable TLS support."
} else {
    "TLS support is not compiled into this build. Enable the `tls` cargo feature."
};

const UNSUPPORTED_STATIC_TLS_MESSAGE: &str = "unsupport static tls";

/// Structured I/O error details.
#[derive(Debug)]
pub enum IoError {
    /// The provided path contains an interior NUL byte.
    NullByteInPath,
    /// `open failed: {path}`
    Open { path: Box<str> },
    /// `openat failed: {path}`
    OpenAt { path: Box<str> },
    /// `CreateFileW failed for {path}: error {code}`
    CreateFileW { path: Box<str>, code: u32 },
    /// `SetFilePointerEx failed with error: {code}`
    SetFilePointerEx { code: u32 },
    /// `ReadFile failed with error: {code}`
    ReadFile { code: u32 },
    /// `lseek failed`
    SeekFailed,
    /// `read failed`
    ReadFailed,
    /// `failed to fill buffer`
    FailedToFillBuffer,
    /// `read offset out of bounds: offset {offset}, len {len}, available {available}`
    ReadOffsetOutOfBounds {
        offset: usize,
        len: usize,
        available: usize,
    },
    /// `close failed`
    CloseFailed,
}

impl Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullByteInPath => f.write_str("path contains an interior NUL byte"),
            Self::Open { path } => write!(f, "open failed: {path}"),
            Self::OpenAt { path } => write!(f, "openat failed: {path}"),
            Self::CreateFileW { path, code } => {
                write!(f, "CreateFileW failed for {path}: error {code}")
            }
            Self::SetFilePointerEx { code } => {
                write!(f, "SetFilePointerEx failed with error: {code}")
            }
            Self::ReadFile { code } => write!(f, "ReadFile failed with error: {code}"),
            Self::SeekFailed => f.write_str("lseek failed"),
            Self::ReadFailed => f.write_str("read failed"),
            Self::FailedToFillBuffer => f.write_str("failed to fill buffer"),
            Self::ReadOffsetOutOfBounds {
                offset,
                len,
                available,
            } => write!(
                f,
                "read offset out of bounds: offset {offset}, len {len}, available {available}"
            ),
            Self::CloseFailed => f.write_str("close failed"),
        }
    }
}

/// Structured memory-mapping error details.
#[derive(Debug)]
pub enum MmapError {
    /// `mmap failed`
    MmapFailed,
    /// `mmap anonymous failed`
    MmapAnonymousFailed,
    /// `munmap failed`
    MunmapFailed,
    /// `MapViewOfFile3 failed with error: {code}`
    MapViewOfFile3 { code: u32 },
    /// `VirtualAlloc failed with error: {code}`
    VirtualAlloc { code: u32 },
    /// `mprotect failed`
    MprotectFailed,
    /// `mprotect error! error code: {code}`
    Mprotect { code: u32 },
    /// `CreateFileMappingW failed with error: {code}`
    CreateFileMappingW { code: u32 },
    /// `VirtualFree failed with error: {code}`
    VirtualFree { code: u32 },
}

impl Display for MmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MmapFailed => f.write_str("mmap failed"),
            Self::MmapAnonymousFailed => f.write_str("mmap anonymous failed"),
            Self::MunmapFailed => f.write_str("munmap failed"),
            Self::MapViewOfFile3 { code } => {
                write!(f, "MapViewOfFile3 failed with error: {code}")
            }
            Self::VirtualAlloc { code } => {
                write!(f, "VirtualAlloc failed with error: {code}")
            }
            Self::MprotectFailed => f.write_str("mprotect failed"),
            Self::Mprotect { code } => write!(f, "mprotect error! error code: {code}"),
            Self::CreateFileMappingW { code } => {
                write!(f, "CreateFileMappingW failed with error: {code}")
            }
            Self::VirtualFree { code } => {
                write!(f, "VirtualFree failed with error: {code}")
            }
        }
    }
}

/// Structured dynamic-section parsing error details.
#[derive(Debug)]
pub enum ParseDynamicError {
    /// The dynamic section omitted both `DT_GNU_HASH` and `DT_HASH`.
    MissingHashTable,
}

impl Display for ParseDynamicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHashTable => {
                f.write_str("dynamic section does not have DT_GNU_HASH nor DT_HASH")
            }
        }
    }
}

/// Structured ELF header parsing error details.
#[derive(Debug)]
pub enum ParseEhdrError {
    /// The ELF magic bytes do not match `0x7fELF`.
    InvalidMagic,
    /// `file class mismatch: expected {expected}, found {found}`
    FileClassMismatch { expected: ElfClass, found: ElfClass },
    /// The ELF version is not `EV_CURRENT`.
    InvalidVersion,
    /// `file arch mismatch: expected {expected}, found {found}`
    FileArchMismatch {
        expected: ElfMachine,
        found: ElfMachine,
    },
    /// A shared object was required but the file type was different.
    ExpectedDylib { found: ElfFileType },
    /// An executable or PIE-compatible file was required but the file type was different.
    ExpectedExecutable { found: ElfFileType },
    /// A relocatable object was expected to carry section headers.
    MissingSectionHeaders,
}

impl Display for ParseEhdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("invalid ELF magic"),
            Self::FileClassMismatch { expected, found } => {
                write!(f, "file class mismatch: expected {expected}, found {found}")
            }
            Self::InvalidVersion => f.write_str("invalid ELF version"),
            Self::FileArchMismatch { expected, found } => write!(
                f,
                "file arch mismatch: expected {}, found {}",
                expected, found,
            ),
            Self::ExpectedDylib { found } => {
                write!(f, "file type mismatch: expected ET_DYN, found {found}")
            }
            Self::ExpectedExecutable { found } => write!(
                f,
                "file type mismatch: expected ET_EXEC or ET_DYN, found {}",
                found,
            ),
            Self::MissingSectionHeaders => f.write_str("object file must have section headers"),
        }
    }
}

/// Structured program-header parsing error details.
#[derive(Debug)]
pub enum ParsePhdrError {
    /// The program header table is malformed.
    MalformedProgramHeaders,
}

impl Display for ParsePhdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedProgramHeaders => f.write_str("program headers are malformed"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RelocationFailureReason {
    UnknownSymbol,
    Unhandled,
    IntegralConversionOutOfRange,
}

impl Display for RelocationFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSymbol => f.write_str("unknown symbol"),
            Self::Unhandled => f.write_str("Unhandled relocation"),
            Self::IntegralConversionOutOfRange => {
                f.write_str("out of range integral type conversion attempted")
            }
        }
    }
}

/// Relocation context carried separately so the top-level [`Error`] stays compact.
#[derive(Debug)]
pub struct RelocationContextError {
    file: Box<str>,
    r_type: &'static str,
    symbol: Option<Box<str>>,
    reason: RelocationFailureReason,
}

impl RelocationContextError {
    #[inline]
    pub(crate) fn new(
        file: &str,
        r_type: &'static str,
        symbol: Option<&str>,
        reason: RelocationFailureReason,
    ) -> Self {
        Self {
            file: file.into(),
            r_type,
            symbol: symbol.map(Into::into),
            reason,
        }
    }
}

impl Display for RelocationContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "file: {}, relocation type: {}, ", self.file, self.r_type)?;
        if let Some(symbol) = &self.symbol {
            write!(f, "symbol name: {symbol}, ")?;
        } else {
            f.write_str("no symbol, ")?;
        }
        write!(f, "error: {}", self.reason)
    }
}

/// Structured lazy-binding setup error details.
#[derive(Debug)]
pub enum LazyBindingError {
    /// `lazy binding requires a GOT/PLTGOT entry`
    MissingGot,
}

impl Display for LazyBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingGot => f.write_str("lazy binding requires a GOT/PLTGOT entry"),
        }
    }
}

/// Structured relocation error details.
#[derive(Debug)]
pub enum RelocationError {
    /// `out of range integral type conversion attempted`
    IntegralConversionOutOfRange,
    /// Detailed relocation context, formatted lazily in `Display`.
    Context(Box<RelocationContextError>),
    /// Lazy-binding setup failed before the hot path was installed.
    LazyBinding(LazyBindingError),
}

impl Display for RelocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegralConversionOutOfRange => {
                f.write_str("out of range integral type conversion attempted")
            }
            Self::Context(ctx) => Display::fmt(ctx, f),
            Self::LazyBinding(err) => Display::fmt(err, f),
        }
    }
}

/// Structured user-defined error details.
#[derive(Debug)]
pub enum CustomError {
    /// A plain message supplied by the caller.
    Message(Cow<'static, str>),
}

impl Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(msg) => f.write_str(msg),
        }
    }
}

/// Structured TLS error details.
#[derive(Debug)]
pub enum TlsError {
    /// The current resolver does not support dynamic TLS.
    ResolverUnsupported,
    /// The current resolver does not support static TLS registration.
    StaticResolverUnsupported,
    /// The active TLS backend cannot satisfy static TLS registration.
    UnsupportedStaticTls,
}

impl Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResolverUnsupported => f.write_str(TLS_DISABLED_MESSAGE),
            Self::StaticResolverUnsupported => f.write_str(STATIC_TLS_DISABLED_MESSAGE),
            Self::UnsupportedStaticTls => f.write_str(UNSUPPORTED_STATIC_TLS_MESSAGE),
        }
    }
}

/// Error types used throughout the `elf_loader` library.
/// These errors represent various failure conditions that can occur during
/// ELF file loading, parsing, and relocation operations.
#[derive(Debug)]
pub enum Error {
    /// An error occurred while opening, reading, or writing ELF files.
    Io(IoError),

    /// An error occurred during memory mapping operations.
    Mmap(MmapError),

    /// An error occurred during dynamic library relocation.
    Relocation(RelocationError),

    /// An error occurred while parsing the dynamic section.
    ParseDynamic(ParseDynamicError),

    /// An error occurred while parsing the ELF header.
    ParseEhdr(ParseEhdrError),

    /// An error occurred while parsing program headers.
    ParsePhdr(ParsePhdrError),

    /// An error occurred in a user-defined callback or handler.
    Custom(CustomError),

    /// An error occurred during TLS (Thread Local Storage) processing.
    Tls(TlsError),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Mmap(err) => write!(f, "Memory mapping error: {err}"),
            Self::Relocation(err) => write!(f, "Relocation error: {err}"),
            Self::ParseDynamic(err) => write!(f, "Dynamic section parsing error: {err}"),
            Self::ParseEhdr(err) => write!(f, "ELF header parsing error: {err}"),
            Self::ParsePhdr(err) => write!(f, "Program header parsing error: {err}"),
            Self::Custom(err) => write!(f, "Custom error: {err}"),
            Self::Tls(err) => write!(f, "TLS error: {err}"),
        }
    }
}

impl core::error::Error for Error {}

#[cold]
#[inline(never)]
pub(crate) fn io_null_byte_in_path_error() -> Error {
    Error::Io(IoError::NullByteInPath)
}

#[cold]
#[inline(never)]
#[allow(dead_code)]
pub(crate) fn io_open_error(path: &str) -> Error {
    Error::Io(IoError::Open { path: path.into() })
}

#[cold]
#[inline(never)]
#[allow(dead_code)]
pub(crate) fn io_openat_error(path: &str) -> Error {
    Error::Io(IoError::OpenAt { path: path.into() })
}

#[cold]
#[inline(never)]
#[cfg(windows)]
pub(crate) fn io_create_file_w_error(path: &str, code: u32) -> Error {
    Error::Io(IoError::CreateFileW {
        path: path.into(),
        code,
    })
}

#[cold]
#[inline(never)]
#[cfg(windows)]
pub(crate) fn io_set_file_pointer_error(code: u32) -> Error {
    Error::Io(IoError::SetFilePointerEx { code })
}

#[cold]
#[inline(never)]
#[cfg(windows)]
pub(crate) fn io_read_file_error(code: u32) -> Error {
    Error::Io(IoError::ReadFile { code })
}

#[cold]
#[inline(never)]
pub(crate) fn io_seek_error() -> Error {
    Error::Io(IoError::SeekFailed)
}

#[cold]
#[inline(never)]
pub(crate) fn io_read_error() -> Error {
    Error::Io(IoError::ReadFailed)
}

#[cold]
#[inline(never)]
pub(crate) fn io_failed_to_fill_buffer_error() -> Error {
    Error::Io(IoError::FailedToFillBuffer)
}

#[cold]
#[inline(never)]
pub(crate) fn io_read_offset_out_of_bounds_error(
    offset: usize,
    len: usize,
    available: usize,
) -> Error {
    Error::Io(IoError::ReadOffsetOutOfBounds {
        offset,
        len,
        available,
    })
}

#[cold]
#[inline(never)]
#[allow(dead_code)]
pub(crate) fn io_close_error() -> Error {
    Error::Io(IoError::CloseFailed)
}

#[cold]
#[inline(never)]
pub(crate) fn mmap_failed_error() -> Error {
    Error::Mmap(MmapError::MmapFailed)
}

#[cold]
#[inline(never)]
pub(crate) fn mmap_anonymous_failed_error() -> Error {
    Error::Mmap(MmapError::MmapAnonymousFailed)
}

#[cold]
#[inline(never)]
pub(crate) fn mmap_munmap_failed_error() -> Error {
    Error::Mmap(MmapError::MunmapFailed)
}

#[cold]
#[inline(never)]
pub(crate) fn mmap_mprotect_failed_error() -> Error {
    Error::Mmap(MmapError::MprotectFailed)
}

#[cold]
#[inline(never)]
#[cfg(windows)]
pub(crate) fn mmap_map_view_of_file3_error(code: u32) -> Error {
    Error::Mmap(MmapError::MapViewOfFile3 { code })
}

#[cold]
#[inline(never)]
#[cfg(windows)]
pub(crate) fn mmap_virtual_alloc_error(code: u32) -> Error {
    Error::Mmap(MmapError::VirtualAlloc { code })
}

#[cold]
#[inline(never)]
#[cfg(windows)]
pub(crate) fn mmap_mprotect_error(code: u32) -> Error {
    Error::Mmap(MmapError::Mprotect { code })
}

#[cold]
#[inline(never)]
#[cfg(windows)]
pub(crate) fn mmap_create_file_mapping_error(code: u32) -> Error {
    Error::Mmap(MmapError::CreateFileMappingW { code })
}

#[cold]
#[inline(never)]
#[cfg(windows)]
pub(crate) fn mmap_virtual_free_error(code: u32) -> Error {
    Error::Mmap(MmapError::VirtualFree { code })
}

#[cold]
#[inline(never)]
pub(crate) fn relocate_integral_conversion_out_of_range_error() -> Error {
    Error::Relocation(RelocationError::IntegralConversionOutOfRange)
}

#[cold]
#[inline(never)]
pub(crate) fn relocate_context_error(
    file: &str,
    r_type: &'static str,
    symbol: Option<&str>,
    reason: RelocationFailureReason,
) -> Error {
    Error::Relocation(RelocationError::Context(Box::new(
        RelocationContextError::new(file, r_type, symbol, reason),
    )))
}

#[cold]
#[inline(never)]
#[cfg(feature = "lazy-binding")]
pub(crate) fn relocate_lazy_binding_missing_got_error() -> Error {
    Error::Relocation(RelocationError::LazyBinding(LazyBindingError::MissingGot))
}

#[cold]
#[inline(never)]
pub(crate) fn parse_dynamic_missing_hash_table_error() -> Error {
    Error::ParseDynamic(ParseDynamicError::MissingHashTable)
}

#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_invalid_magic_error() -> Error {
    Error::ParseEhdr(ParseEhdrError::InvalidMagic)
}

#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_invalid_version_error() -> Error {
    Error::ParseEhdr(ParseEhdrError::InvalidVersion)
}

#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_class_mismatch_error(expected: ElfClass, found: ElfClass) -> Error {
    Error::ParseEhdr(ParseEhdrError::FileClassMismatch { expected, found })
}

#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_arch_mismatch_error(expected: ElfMachine, found: ElfMachine) -> Error {
    Error::ParseEhdr(ParseEhdrError::FileArchMismatch { expected, found })
}

#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_expected_dylib_error(found: ElfFileType) -> Error {
    Error::ParseEhdr(ParseEhdrError::ExpectedDylib { found })
}

#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_expected_executable_error(found: ElfFileType) -> Error {
    Error::ParseEhdr(ParseEhdrError::ExpectedExecutable { found })
}

#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_missing_section_headers_error() -> Error {
    Error::ParseEhdr(ParseEhdrError::MissingSectionHeaders)
}

#[cold]
#[inline(never)]
#[allow(dead_code)]
pub fn custom_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Custom(CustomError::Message(msg.into()))
}

#[cold]
#[inline(never)]
pub(crate) fn tls_resolver_unsupported_error() -> Error {
    Error::Tls(TlsError::ResolverUnsupported)
}

#[cold]
#[inline(never)]
pub(crate) fn tls_static_resolver_unsupported_error() -> Error {
    Error::Tls(TlsError::StaticResolverUnsupported)
}

#[cold]
#[inline(never)]
pub(crate) fn tls_unsupported_static_tls_error() -> Error {
    Error::Tls(TlsError::UnsupportedStaticTls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn error_stays_compact() {
        assert!(
            size_of::<Error>() <= 40,
            "Error grew to {} bytes",
            size_of::<Error>()
        );
    }
}
