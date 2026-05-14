use crate::elf::abi::{STB_GLOBAL, STB_WEAK, STT_FUNC, STT_NOTYPE, STT_OBJECT, STT_TLS};
use alloc::{string::String, vec::Vec};

/// The exported symbol kind to encode in `st_info`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsoSymbolKind {
    NoType,
    Function,
    Object,
    Tls,
}

impl DsoSymbolKind {
    #[inline]
    pub(super) const fn st_type(self) -> u8 {
        match self {
            Self::NoType => STT_NOTYPE,
            Self::Function => STT_FUNC,
            Self::Object => STT_OBJECT,
            Self::Tls => STT_TLS,
        }
    }
}

/// The exported symbol binding to encode in `st_info`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsoSymbolBind {
    Global,
    Weak,
}

impl DsoSymbolBind {
    #[inline]
    pub(super) const fn st_bind(self) -> u8 {
        match self {
            Self::Global => STB_GLOBAL,
            Self::Weak => STB_WEAK,
        }
    }
}

/// One symbol requested by the DSO builder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsoExport {
    pub name: String,
    /// Offset within the builder's text payload.
    pub text_offset: usize,
    pub size: usize,
    pub kind: DsoSymbolKind,
    pub bind: DsoSymbolBind,
}

impl DsoExport {
    /// Creates a global function export at `text_offset`.
    #[inline]
    pub fn function(name: impl Into<String>, text_offset: usize, size: usize) -> Self {
        Self {
            name: name.into(),
            text_offset,
            size,
            kind: DsoSymbolKind::Function,
            bind: DsoSymbolBind::Global,
        }
    }

    /// Creates a global object export at `text_offset`.
    #[inline]
    pub fn object(name: impl Into<String>, text_offset: usize, size: usize) -> Self {
        Self {
            name: name.into(),
            text_offset,
            size,
            kind: DsoSymbolKind::Object,
            bind: DsoSymbolBind::Global,
        }
    }
}

/// Final layout assigned to an exported symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsoExportLayout {
    pub name: String,
    /// Offset within the text payload.
    pub text_offset: usize,
    /// ELF `st_value`, relative to the load base for `ET_DYN`.
    pub value: usize,
    pub size: usize,
    pub kind: DsoSymbolKind,
    pub bind: DsoSymbolBind,
}

/// Bytes and metadata for a generated DSO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsoImage {
    pub soname: String,
    pub bytes: Vec<u8>,
    pub exports: Vec<DsoExportLayout>,
}
