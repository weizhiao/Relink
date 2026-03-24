use alloc::{borrow::Cow, boxed::Box};
use core::fmt::{self, Display};

const PARSE_DYNAMIC_MISSING_HASH_TABLE_MESSAGE: &str =
    "dynamic section does not have DT_GNU_HASH nor DT_HASH";

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
    /// A plain message, used when no deferred formatting is needed.
    Message(Cow<'static, str>),
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
}

impl Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(msg) => f.write_str(msg),
            Self::Open { path } => write!(f, "open failed: {path}"),
            Self::OpenAt { path } => write!(f, "openat failed: {path}"),
            Self::CreateFileW { path, code } => {
                write!(f, "CreateFileW failed for {path}: error {code}")
            }
            Self::SetFilePointerEx { code } => {
                write!(f, "SetFilePointerEx failed with error: {code}")
            }
            Self::ReadFile { code } => write!(f, "ReadFile failed with error: {code}"),
        }
    }
}

/// Structured memory-mapping error details.
#[derive(Debug)]
pub enum MmapError {
    /// A plain message, used when no deferred formatting is needed.
    Message(Cow<'static, str>),
    /// `MapViewOfFile3 failed with error: {code}`
    MapViewOfFile3 { code: u32 },
    /// `VirtualAlloc failed with error: {code}`
    VirtualAlloc { code: u32 },
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
            Self::Message(msg) => f.write_str(msg),
            Self::MapViewOfFile3 { code } => {
                write!(f, "MapViewOfFile3 failed with error: {code}")
            }
            Self::VirtualAlloc { code } => {
                write!(f, "VirtualAlloc failed with error: {code}")
            }
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
    /// A plain message, used when no deferred formatting is needed.
    Message(Cow<'static, str>),
    /// The dynamic section omitted both `DT_GNU_HASH` and `DT_HASH`.
    MissingHashTable,
}

impl Display for ParseDynamicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(msg) => f.write_str(msg),
            Self::MissingHashTable => f.write_str(PARSE_DYNAMIC_MISSING_HASH_TABLE_MESSAGE),
        }
    }
}

/// Structured ELF header parsing error details.
#[derive(Debug)]
pub enum ParseEhdrError {
    /// A plain message, used when no deferred formatting is needed.
    Message(Cow<'static, str>),
    /// `file class mismatch: expected {expected}, found {found}`
    FileClassMismatch { expected: u8, found: u8 },
    /// `file arch mismatch: expected {expected}, found {found}`
    FileArchMismatch { expected: u16, found: u16 },
}

impl Display for ParseEhdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(msg) => f.write_str(msg),
            Self::FileClassMismatch { expected, found } => {
                write!(f, "file class mismatch: expected {expected}, found {found}")
            }
            Self::FileArchMismatch { expected, found } => write!(
                f,
                "file arch mismatch: expected {}, found {}",
                crate::elf::machine_to_str(*expected),
                crate::elf::machine_to_str(*found),
            ),
        }
    }
}

/// Structured program-header parsing error details.
#[derive(Debug)]
pub enum ParsePhdrError {
    /// A plain message, used when no deferred formatting is needed.
    Message(Cow<'static, str>),
}

impl Display for ParsePhdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(msg) => f.write_str(msg),
        }
    }
}

/// Relocation context carried separately so the top-level [`Error`] stays compact.
#[derive(Debug)]
pub struct RelocationContextError {
    file: Box<str>,
    r_type: &'static str,
    symbol: Option<Box<str>>,
    err: &'static str,
}

impl RelocationContextError {
    #[inline]
    pub(crate) fn new(
        file: &str,
        r_type: &'static str,
        symbol: Option<&str>,
        err: &'static str,
    ) -> Self {
        Self {
            file: file.into(),
            r_type,
            symbol: symbol.map(Into::into),
            err,
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
        write!(f, "error: {}", self.err)
    }
}

/// Structured relocation error details.
#[derive(Debug)]
pub enum RelocationError {
    /// A plain message, used when no deferred formatting is needed.
    Message(Cow<'static, str>),
    /// Detailed relocation context, formatted lazily in `Display`.
    Context(Box<RelocationContextError>),
}

impl Display for RelocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(msg) => f.write_str(msg),
            Self::Context(ctx) => Display::fmt(ctx, f),
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
    /// A plain message, used for uncommon or fully custom cases.
    Message(Cow<'static, str>),
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
            Self::Message(msg) => f.write_str(msg),
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
#[allow(unused)]
pub(crate) fn io_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Io(IoError::Message(msg.into()))
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
pub(crate) fn mmap_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Mmap(MmapError::Message(msg.into()))
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
pub(crate) fn relocate_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Relocation(RelocationError::Message(msg.into()))
}

#[cold]
#[inline(never)]
pub(crate) fn relocate_context_error(
    file: &str,
    r_type: &'static str,
    symbol: Option<&str>,
    err: &'static str,
) -> Error {
    Error::Relocation(RelocationError::Context(Box::new(
        RelocationContextError::new(file, r_type, symbol, err),
    )))
}

#[cold]
#[inline(never)]
#[allow(dead_code)]
pub(crate) fn parse_dynamic_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::ParseDynamic(ParseDynamicError::Message(msg.into()))
}

#[cold]
#[inline(never)]
pub(crate) fn parse_dynamic_missing_hash_table_error() -> Error {
    Error::ParseDynamic(ParseDynamicError::MissingHashTable)
}

#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::ParseEhdr(ParseEhdrError::Message(msg.into()))
}

#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_class_mismatch_error(expected: u8, found: u8) -> Error {
    Error::ParseEhdr(ParseEhdrError::FileClassMismatch { expected, found })
}

#[cold]
#[inline(never)]
pub(crate) fn parse_ehdr_arch_mismatch_error(expected: u16, found: u16) -> Error {
    Error::ParseEhdr(ParseEhdrError::FileArchMismatch { expected, found })
}

#[cold]
#[inline(never)]
#[allow(dead_code)]
pub(crate) fn parse_phdr_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::ParsePhdr(ParsePhdrError::Message(msg.into()))
}

#[cold]
#[inline(never)]
#[allow(unused)]
pub fn custom_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Custom(CustomError::Message(msg.into()))
}

#[cold]
#[inline(never)]
#[allow(dead_code)]
pub(crate) fn tls_error(msg: impl Into<Cow<'static, str>>) -> Error {
    Error::Tls(TlsError::Message(msg.into()))
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
