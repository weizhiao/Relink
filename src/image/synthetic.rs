use super::{ExportTable, Module, ModuleHandle, ModuleState, SymbolMap, SyntheticSymbol};
use crate::{
    Result,
    arch::NativeArch,
    custom_error,
    elf::{ElfSymbol, ElfSymbolType},
    input::ModuleSourceId,
    memory::{ImageMemory, VmAddr, VmOffset},
    relocation::RelocationArch,
    runtime::{CodeContext, CodeExecutor, Domain},
    sync::{Arc, arc_unsize},
    tls::{TlsModule, TlsRegistration, TlsResolver},
};
use alloc::string::String;
use core::ptr::NonNull;

#[derive(Clone, Copy)]
struct UnmappedImageMemory {
    base: VmAddr,
}

impl Default for UnmappedImageMemory {
    #[inline]
    fn default() -> Self {
        Self {
            base: VmAddr::null(),
        }
    }
}

impl ImageMemory for UnmappedImageMemory {
    #[inline]
    fn base(&self) -> VmAddr {
        self.base
    }

    #[inline]
    fn range_at(&self, _addr: VmAddr) -> Option<core::ops::Range<VmAddr>> {
        None
    }

    fn visit_ranges(&self, _visit: &mut dyn FnMut(core::ops::Range<VmAddr>)) {}

    #[inline]
    fn host_ptr(&self, _addr: VmAddr) -> Option<NonNull<u8>> {
        None
    }

    #[inline]
    fn host_ptr_range(&self, _addr: VmAddr, _len: usize) -> Option<NonNull<u8>> {
        None
    }

    #[inline]
    fn read_bytes(&self, _addr: VmAddr, dst: &mut [u8]) -> Result<()> {
        if dst.is_empty() {
            return Ok(());
        }

        Err(custom_error(
            "synthetic modules do not expose readable image bytes",
        ))
    }

    #[inline]
    fn write_bytes(&self, _addr: VmAddr, src: &[u8]) -> Result<()> {
        if src.is_empty() {
            return Ok(());
        }

        Err(custom_error(
            "synthetic modules do not expose writable image bytes",
        ))
    }
}

/// A module of caller-provided symbols, usable in a [`ModuleScope`](crate::ModuleScope).
/// Owns its symbol metadata without loading an ELF image.
pub struct SyntheticModule<Arch: RelocationArch = NativeArch, D = (), R = ()> {
    state: ModuleState,
    name: String,
    memory: Arc<dyn ImageMemory>,
    tls: Option<TlsRegistration>,
    executor: Arc<dyn CodeExecutor<Arch>>,
    resolve_hook: R,
    user_data: D,
    exports: ExportTable<Arch::Layout>,
}

/// Runtime callback invoked when a synthetic symbol is resolved.
pub trait ResolveHook<Arch: RelocationArch>: Send + Sync {
    /// Prepares runtime state associated with `symbol` and its stable address.
    fn resolve(&self, symbol: &ElfSymbol<Arch::Layout>, address: VmAddr) -> Result<()>;
}

impl<Arch: RelocationArch> ResolveHook<Arch> for () {
    #[inline]
    fn resolve(&self, _symbol: &ElfSymbol<Arch::Layout>, _address: VmAddr) -> Result<()> {
        Ok(())
    }
}

impl<Arch, F> ResolveHook<Arch> for F
where
    Arch: RelocationArch,
    F: Fn(&ElfSymbol<Arch::Layout>, VmAddr) -> Result<()> + Send + Sync,
{
    #[inline]
    fn resolve(&self, symbol: &ElfSymbol<Arch::Layout>, address: VmAddr) -> Result<()> {
        self(symbol, address)
    }
}

impl<Arch: RelocationArch> SyntheticModule<Arch> {
    /// Creates a module from an ordered list of synthetic symbols in `domain`.
    pub fn new<I, Tls: TlsResolver<Arch>>(
        domain: &Domain<Arch, Tls>,
        name: impl Into<String>,
        symbols: I,
    ) -> Self
    where
        I: IntoIterator<Item = SyntheticSymbol>,
    {
        let mut module = Self::empty(domain, name);
        for symbol in symbols {
            module.insert(symbol);
        }
        module
    }

    /// Creates an empty synthetic module bound to an immutable runtime domain.
    pub fn empty<Tls: TlsResolver<Arch>>(
        domain: &Domain<Arch, Tls>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            state: ModuleState::new(ModuleSourceId::fresh(), domain.id()),
            name: name.into(),
            memory: arc_unsize!(
                Arc::new(UnmappedImageMemory::default()) => dyn ImageMemory
            ),
            tls: None,
            executor: domain.shared_executor(),
            resolve_hook: (),
            user_data: (),
            exports: SymbolMap::empty().into(),
        }
    }
}

impl<Arch: RelocationArch, D, R> SyntheticModule<Arch, D, R> {
    /// Replaces the user data associated with this synthetic module.
    #[inline]
    pub fn with_data<NewD>(self, user_data: NewD) -> SyntheticModule<Arch, NewD, R> {
        SyntheticModule {
            state: self.state,
            name: self.name,
            memory: self.memory,
            tls: self.tls,
            executor: self.executor,
            resolve_hook: self.resolve_hook,
            user_data,
            exports: self.exports,
        }
    }

    /// Returns immutable user data for this synthetic module.
    #[inline]
    pub const fn user_data(&self) -> &D {
        &self.user_data
    }

    /// Returns mutable user data for this synthetic module.
    #[inline]
    pub fn user_data_mut(&mut self) -> &mut D {
        &mut self.user_data
    }

    /// Uses a real image-memory backend for this synthetic module.
    ///
    /// This is required when synthetic symbols may be used as byte sources, such
    /// as for COPY relocations against synthetic object symbols.
    #[inline]
    pub fn with_memory<M>(mut self, memory: M) -> Self
    where
        M: ImageMemory + 'static,
    {
        self.memory = arc_unsize!(Arc::new(memory) => dyn ImageMemory);
        self
    }

    /// Transfers a TLS registration into this module. Its provider and runtime
    /// remain alive until the module is released. Returns an error if the entry
    /// belongs to a different TLS runtime than this domain.
    #[inline]
    pub fn with_tls(mut self, tls: TlsRegistration) -> Result<Self> {
        tls.module().check_domain(self.state.domain_id())?;
        self.tls = Some(tls);
        Ok(self)
    }

    /// Runs a callback when a synthetic symbol is resolved.
    ///
    /// The callback receives the symbol's stable address and may prepare lazy
    /// runtime state before that address is returned.
    #[inline]
    pub fn with_resolve_hook<F>(self, hook: F) -> SyntheticModule<Arch, D, F>
    where
        F: Fn(&ElfSymbol<Arch::Layout>, VmAddr) -> Result<()> + Send + Sync,
    {
        SyntheticModule {
            state: self.state,
            name: self.name,
            memory: self.memory,
            tls: self.tls,
            executor: self.executor,
            resolve_hook: hook,
            user_data: self.user_data,
            exports: self.exports,
        }
    }

    /// Inserts one symbol, returning the definition it replaced.
    pub fn insert(&mut self, symbol: SyntheticSymbol) -> Option<SyntheticSymbol> {
        self.exports.symbols_mut().insert(symbol)
    }

    /// Returns whether this module exports a synthetic symbol with `name`.
    #[inline]
    pub fn contains(&self, name: impl AsRef<[u8]>) -> bool {
        self.exports.symbols().contains(name)
    }

    /// Returns the number of synthetic symbols.
    #[inline]
    pub fn len(&self) -> usize {
        self.exports.symbols().len()
    }

    /// Returns whether this module contains no symbols.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.exports.symbols().is_empty()
    }
}

impl<Arch, D, R> From<SyntheticModule<Arch, D, R>> for ModuleHandle<Arch>
where
    Arch: RelocationArch,
    D: Send + Sync + 'static,
    R: ResolveHook<Arch> + 'static,
{
    #[inline]
    fn from(module: SyntheticModule<Arch, D, R>) -> Self {
        Self::new(module)
    }
}

impl<Arch, D, R> Module<Arch> for SyntheticModule<Arch, D, R>
where
    Arch: RelocationArch,
    D: Send + Sync + 'static,
    R: ResolveHook<Arch> + 'static,
{
    #[inline]
    fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    #[inline]
    fn exports(&self) -> &ExportTable<Arch::Layout> {
        &self.exports
    }

    #[inline]
    fn memory(&self) -> &dyn ImageMemory {
        &*self.memory
    }

    fn resolve_symbol(&self, symbol: &ElfSymbol<Arch::Layout>) -> Result<VmAddr> {
        match symbol.symbol_type() {
            ElfSymbolType::TLS => {
                return self
                    .tls
                    .as_ref()
                    .ok_or(crate::TlsError::TemplateUnavailable)?
                    .module()
                    .resolve(
                        self.executor.as_ref(),
                        CodeContext::new(self.name.as_bytes(), self.memory.as_ref()),
                        symbol.st_value(),
                    );
            }
            ElfSymbolType::GNU_IFUNC => {
                return Err(custom_error(
                    "synthetic module cannot execute IFUNC resolvers",
                ));
            }
            _ => {}
        }

        let address = if symbol.st_shndx().is_abs() {
            VmAddr::new(symbol.st_value())
        } else {
            self.memory.base() + VmOffset::new(symbol.st_value())
        };
        self.resolve_hook.resolve(symbol, address)?;
        Ok(address)
    }

    #[inline]
    fn tls(&self) -> Option<&TlsModule> {
        self.tls.as_ref().map(TlsRegistration::module)
    }

    #[inline]
    fn state(&self) -> &ModuleState {
        &self.state
    }
}
