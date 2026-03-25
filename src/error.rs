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
    /// A dynamic-section address calculation overflowed.
    AddressOverflow,
    /// `{tag} was present without its required count tag`
    MissingVersionCount { tag: &'static str },
}

impl Display for ParseDynamicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHashTable => {
                f.write_str("dynamic section does not have DT_GNU_HASH nor DT_HASH")
            }
            Self::AddressOverflow => f.write_str("dynamic section address calculation overflowed"),
            Self::MissingVersionCount { tag } => {
                write!(f, "{tag} is missing its required version-count tag")
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
    /// A dynamic image was expected to carry `PT_DYNAMIC`.
    MissingDynamicSection,
    /// `{field} contains invalid UTF-8`
    InvalidUtf8 { field: &'static str },
}

impl Display for ParsePhdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedProgramHeaders => f.write_str("program headers are malformed"),
            Self::MissingDynamicSection => f.write_str("program headers do not contain PT_DYNAMIC"),
            Self::InvalidUtf8 { field } => write!(f, "{field} contains invalid UTF-8"),
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
    /// `lazy binding requires dynamic metadata`
    MissingDynamicInfo,
}

impl Display for LazyBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingGot => f.write_str("lazy binding requires a GOT/PLTGOT entry"),
            Self::MissingDynamicInfo => f.write_str("lazy binding requires dynamic metadata"),
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
    /// `object relocation sections use {found}, but this target expects {expected}`
    UnsupportedObjectSection {
        expected: &'static str,
        found: &'static str,
    },
    /// `{section} entries have size {found}, expected {expected}`
    InvalidObjectEntrySize {
        section: &'static str,
        expected: usize,
        found: usize,
    },
    /// `object file missing symbol table`
    MissingObjectSymbolTable,
}

impl Display for RelocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegralConversionOutOfRange => {
                f.write_str("out of range integral type conversion attempted")
            }
            Self::Context(ctx) => Display::fmt(ctx, f),
            Self::LazyBinding(err) => Display::fmt(err, f),
            Self::UnsupportedObjectSection { expected, found } => write!(
                f,
                "object relocation sections use {found}, but this target expects {expected}"
            ),
            Self::InvalidObjectEntrySize {
                section,
                expected,
                found,
            } => write!(
                f,
                "{section} entries have size {found}, expected {expected}"
            ),
            Self::MissingObjectSymbolTable => f.write_str("object file missing symbol table"),
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

impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}

impl From<MmapError> for Error {
    fn from(err: MmapError) -> Self {
        Self::Mmap(err)
    }
}

impl From<RelocationContextError> for RelocationError {
    fn from(err: RelocationContextError) -> Self {
        Self::Context(Box::new(err))
    }
}

impl From<LazyBindingError> for RelocationError {
    fn from(err: LazyBindingError) -> Self {
        Self::LazyBinding(err)
    }
}

impl From<RelocationError> for Error {
    fn from(err: RelocationError) -> Self {
        Self::Relocation(err)
    }
}

impl From<RelocationContextError> for Error {
    fn from(err: RelocationContextError) -> Self {
        RelocationError::from(err).into()
    }
}

impl From<LazyBindingError> for Error {
    fn from(err: LazyBindingError) -> Self {
        RelocationError::from(err).into()
    }
}

impl From<ParseDynamicError> for Error {
    fn from(err: ParseDynamicError) -> Self {
        Self::ParseDynamic(err)
    }
}

impl From<ParseEhdrError> for Error {
    fn from(err: ParseEhdrError) -> Self {
        Self::ParseEhdr(err)
    }
}

impl From<ParsePhdrError> for Error {
    fn from(err: ParsePhdrError) -> Self {
        Self::ParsePhdr(err)
    }
}

impl From<CustomError> for Error {
    fn from(err: CustomError) -> Self {
        Self::Custom(err)
    }
}

impl From<TlsError> for Error {
    fn from(err: TlsError) -> Self {
        Self::Tls(err)
    }
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
#[allow(dead_code)]
pub fn custom_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Custom(CustomError::Message(msg.into()))
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
