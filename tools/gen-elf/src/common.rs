use crate::Arch;
use object::elf::RelocationType as ObjectRelocationType;

/// Type of an ELF symbol.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SymbolType {
    /// Function symbol.
    Func,
    /// Data object symbol.
    Object,
    /// Thread-local storage symbol.
    Tls,
}

/// Visibility and binding scope of an ELF symbol.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SymbolScope {
    /// Global symbol, visible to other objects.
    Global,
    /// Local symbol, visible only within the defining object.
    Local,
    /// Weak symbol, can be overridden by a global symbol.
    Weak,
}

/// Purpose or category of an ELF section.
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum SectionKind {
    /// Mandatory null section.
    Null,
    /// Dynamic string table.
    DynStr,
    /// Dynamic symbol table.
    DynSym,
    /// General RELA relocation table.
    RelaDyn,
    /// PLT RELA relocation table.
    RelaPlt,
    /// Retained data relocation section using RELA entries.
    RetainedRelaData,
    /// General REL relocation table.
    RelDyn,
    /// PLT REL relocation table.
    RelPlt,
    /// Retained data relocation section using REL entries.
    RetainedRelData,
    /// Dynamic linking metadata.
    Dynamic,
    /// ELF symbol hash table.
    Hash,
    /// Section-name string table.
    ShStrTab,
    /// Procedure linkage table.
    Plt,
    /// Executable code.
    Text,
    /// Writable data.
    Data,
    /// Global offset table.
    Got,
    /// PLT portion of the global offset table.
    GotPlt,
    /// Thread-local data.
    Tls,
}

/// Section kinds that can carry generated symbol content.
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum ContentKind {
    /// Executable code content.
    Text,
    /// Writable data content.
    Data,
    /// Procedure linkage table content.
    Plt,
    /// Thread-local data content.
    Tls,
}

impl ContentKind {
    /// Returns the corresponding ELF section category.
    pub fn section(self) -> SectionKind {
        match self {
            Self::Text => SectionKind::Text,
            Self::Data => SectionKind::Data,
            Self::Plt => SectionKind::Plt,
            Self::Tls => SectionKind::Tls,
        }
    }
}

/// Content of an ELF section.
#[derive(Debug, Clone)]
pub struct Content {
    /// Raw bytes of the section.
    pub data: Vec<u8>,
    /// The kind of section this content belongs to.
    pub kind: ContentKind,
}

/// Description of an ELF symbol to be generated.
#[derive(Clone, Debug)]
pub struct SymbolDesc {
    /// Name of the symbol.
    pub name: String,
    /// Type of the symbol (Func, Object, etc.).
    pub sym_type: SymbolType,
    /// Scope of the symbol (Global, Local, etc.).
    pub scope: SymbolScope,
    /// Optional content associated with the symbol.
    pub content: Option<Content>,
    /// Optional size of the symbol. If None, it may be calculated from content.
    pub size: Option<u64>,
}

impl SymbolDesc {
    /// Create a global function symbol with associated code.
    pub fn global_func(name: impl Into<String>, code: &[u8]) -> Self {
        Self {
            name: name.into(),
            sym_type: SymbolType::Func,
            scope: SymbolScope::Global,
            content: Some(Content {
                data: code.to_vec(),
                kind: ContentKind::Text,
            }),
            size: Some(code.len() as u64),
        }
    }

    /// Create a global data object symbol.
    pub fn global_object(name: impl Into<String>, data: &[u8]) -> Self {
        Self {
            name: name.into(),
            sym_type: SymbolType::Object,
            scope: SymbolScope::Global,
            content: Some(Content {
                data: data.to_vec(),
                kind: ContentKind::Data,
            }),
            size: Some(data.len() as u64),
        }
    }

    /// Create an undefined function symbol.
    pub fn undefined_func(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sym_type: SymbolType::Func,
            scope: SymbolScope::Global,
            content: None,
            size: None,
        }
    }

    /// Create an undefined data object symbol.
    pub fn undefined_object(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sym_type: SymbolType::Object,
            scope: SymbolScope::Global,
            content: None,
            size: None,
        }
    }

    /// Create a global TLS symbol with associated data.
    pub fn global_tls(name: impl Into<String>, data: &[u8]) -> Self {
        Self {
            name: name.into(),
            sym_type: SymbolType::Tls,
            scope: SymbolScope::Global,
            content: Some(Content {
                data: data.to_vec(),
                kind: ContentKind::Tls,
            }),
            size: Some(data.len() as u64),
        }
    }

    /// Create an undefined TLS symbol.
    pub fn undefined_tls(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sym_type: SymbolType::Tls,
            scope: SymbolScope::Global,
            content: None,
            size: None,
        }
    }

    /// Create a function symbol located in the PLT section.
    pub fn plt_func(name: impl Into<String>, code: Vec<u8>) -> Self {
        let size = code.len() as u64;
        Self {
            name: name.into(),
            sym_type: SymbolType::Func,
            scope: SymbolScope::Global,
            content: Some(Content {
                data: code,
                kind: ContentKind::Plt,
            }),
            size: Some(size),
        }
    }

    /// Set a custom size for the symbol.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Set a custom scope for the symbol.
    pub fn with_scope(mut self, scope: SymbolScope) -> Self {
        self.scope = scope;
        self
    }
}

/// Wrapper for architecture-specific relocation types.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RelocType(u32);

impl RelocType {
    /// Creates a relocation type from its architecture-specific raw value.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the architecture-specific raw value.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for RelocType {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ObjectRelocationType> for RelocType {
    fn from(value: ObjectRelocationType) -> Self {
        Self(value.0)
    }
}

impl From<RelocType> for ObjectRelocationType {
    fn from(value: RelocType) -> Self {
        Self(value.0)
    }
}

impl PartialEq<ObjectRelocationType> for RelocType {
    fn eq(&self, other: &ObjectRelocationType) -> bool {
        self.0 == other.0
    }
}

/// Represents a relocation entry to be generated.
#[derive(Clone, Debug)]
pub struct RelocEntry {
    /// Symbol name that this relocation references.
    pub symbol_name: String,
    /// Architecture-specific relocation type.
    pub r_type: RelocType,
    /// Addend for the relocation.
    pub addend: i64,
}

impl RelocEntry {
    /// Create a new relocation entry referencing a symbol.
    pub fn with_name(symbol_name: impl Into<String>, r_type: impl Into<RelocType>) -> Self {
        Self {
            symbol_name: symbol_name.into(),
            r_type: r_type.into(),
            addend: 0,
        }
    }

    /// Create a new relocation entry without a symbol reference (e.g., RELATIVE).
    pub fn new(r_type: impl Into<RelocType>) -> Self {
        Self {
            symbol_name: String::new(),
            r_type: r_type.into(),
            addend: 0,
        }
    }

    /// Set the addend for the relocation.
    pub fn with_addend(mut self, addend: i64) -> Self {
        self.addend = addend;
        self
    }

    /// Create a JUMP_SLOT relocation for the given architecture.
    pub fn jump_slot(symbol_name: impl Into<String>, arch: Arch) -> Self {
        Self::with_name(symbol_name, arch.jump_slot_reloc())
    }

    /// Create a GLOB_DAT relocation for the given architecture.
    pub fn glob_dat(symbol_name: impl Into<String>, arch: Arch) -> Self {
        Self::with_name(symbol_name, arch.glob_dat_reloc())
    }

    /// Create a RELATIVE relocation for the given architecture.
    pub fn relative(arch: Arch) -> Self {
        Self::new(arch.relative_reloc())
    }

    /// Create an IRELATIVE relocation for the given architecture.
    pub fn irelative(arch: Arch) -> Self {
        Self::new(arch.irelative_reloc())
    }

    /// Create a COPY relocation for the given architecture.
    pub fn copy(symbol_name: impl Into<String>, arch: Arch) -> Self {
        Self::with_name(symbol_name, arch.copy_reloc())
    }

    /// Create a DTPOFF relocation for the given architecture.
    pub fn dtpoff(symbol_name: impl Into<String>, arch: Arch) -> Self {
        Self::with_name(symbol_name, arch.dtpoff_reloc())
    }

    /// Create a DTPMOD relocation for the given architecture.
    pub fn dtpmod(symbol_name: impl Into<String>, arch: Arch) -> Self {
        Self::with_name(symbol_name, arch.dtpmod_reloc())
    }

    /// Create an absolute relocation for the given architecture.
    pub fn abs(symbol_name: impl Into<String>, arch: Arch) -> Self {
        Self::with_name(symbol_name, arch.abs_reloc())
    }
}
