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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{AddressSpaceId, Domain};
    use crate::tls::TlsResolver;
    use crate::{
        elf::{ElfSectionIndex, ElfSymbolBind, ElfSymbolVisibility},
        image::{ModuleScope, SymbolLookup},
        memory::{MappedRegion, VmOffset},
        segment::ElfSegments,
        tls::TlsTpOffset,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn synthetic_module_resolves_absolute_symbols_from_scope() {
        let module = SyntheticModule::<NativeArch>::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "__bridge",
            [SyntheticSymbol::function(
                c"host_double",
                0x1234usize as *const (),
            )],
        );
        assert_eq!(
            <SyntheticModule<NativeArch> as Module<NativeArch>>::memory(&module).base(),
            VmAddr::null()
        );

        let mut scope = ModuleScope::<NativeArch>::new(
            Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id(),
        );
        scope.extend([module]).unwrap();
        let mut lookup = SymbolLookup::new("host_double");

        let module = scope
            .iter()
            .find(|module| module.name() == b"__bridge")
            .expect("synthetic module should be retained in scope");
        assert_eq!(module.memory().base(), VmAddr::null());
        let symbol = module
            .exports()
            .lookup(&mut lookup)
            .expect("synthetic symbol should resolve");

        assert_eq!(symbol.st_value(), 0x1234);
        assert_eq!(symbol.st_size(), 0);
        assert_eq!(symbol.bind(), ElfSymbolBind::GLOBAL);
        assert_eq!(symbol.symbol_type(), ElfSymbolType::FUNC);
        assert!(symbol.st_shndx().is_abs());
        assert_eq!(module.exports().symbol_name(symbol), Some(c"host_double"));
    }

    #[test]
    fn resolve_hook_observes_address_and_propagates_errors() {
        let observed = Arc::new(AtomicUsize::new(0));
        let hook_observed = Arc::clone(&observed);
        let module = SyntheticModule::<NativeArch>::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "__hook",
            [SyntheticSymbol::function(
                c"entry",
                0x1234usize as *const (),
            )],
        )
        .with_resolve_hook(move |symbol: &ElfSymbol<_>, address| {
            assert_eq!(symbol.st_value(), 0x1234);
            hook_observed.store(address.get(), Ordering::Relaxed);
            Ok(())
        });
        let mut lookup = SymbolLookup::new("entry");
        let symbol = module.exports().lookup(&mut lookup).unwrap();

        let address = Module::<NativeArch>::resolve_symbol(&module, symbol).unwrap();
        assert_eq!(address, VmAddr::new(0x1234));
        assert_eq!(observed.load(Ordering::Relaxed), 0x1234);

        let failing = SyntheticModule::<NativeArch>::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "__failing_hook",
            [SyntheticSymbol::function(
                c"entry",
                0x1234usize as *const (),
            )],
        )
        .with_resolve_hook(|_: &ElfSymbol<_>, _| Err(crate::custom_error("hook failed")));
        let symbol = failing.exports().lookup(&mut lookup).unwrap();
        assert!(Module::<NativeArch>::resolve_symbol(&failing, symbol).is_err());
    }

    #[test]
    fn synthetic_symbol_can_use_non_absolute_section() {
        let module = SyntheticModule::<NativeArch>::new(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "__tls",
            [SyntheticSymbol::from_fields(
                c"tls_slot",
                0x20,
                8,
                ElfSymbolBind::WEAK,
                ElfSymbolType::TLS,
                3,
                ElfSectionIndex::new(1),
                None,
            )],
        );
        let mut scope = ModuleScope::<NativeArch>::new(
            Domain::<NativeArch>::native(AddressSpaceId::PROCESS).id(),
        );
        scope.extend([module]).unwrap();
        let mut lookup = SymbolLookup::new("tls_slot");

        let module = scope
            .iter()
            .find(|module| module.name() == b"__tls")
            .expect("synthetic module should be retained in scope");
        let symbol = module
            .exports()
            .lookup(&mut lookup)
            .expect("synthetic TLS symbol should resolve");

        assert_eq!(symbol.st_value(), 0x20);
        assert_eq!(symbol.st_size(), 8);
        assert_eq!(symbol.bind(), ElfSymbolBind::WEAK);
        assert_eq!(symbol.symbol_type(), ElfSymbolType::TLS);
        assert_eq!(symbol.st_other(), 3);
        assert_eq!(symbol.visibility(), ElfSymbolVisibility::PROTECTED);
        assert_eq!(symbol.st_shndx(), ElfSectionIndex::new(1));
    }

    #[test]
    fn synthetic_module_carries_metadata() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct SyntheticData {
            tag: usize,
        }

        let tls = crate::tls::DefaultTlsResolver::new()
            .register(
                crate::tls::TlsInfo::default(),
                crate::tls::TlsRequest::Static(Some(TlsTpOffset::new(-0x80))),
            )
            .unwrap();
        let binding = tls.module().binding();
        let mut module = SyntheticModule::<NativeArch>::empty(
            &Domain::native(AddressSpaceId::PROCESS)
                .with_tls(crate::tls::DefaultTlsResolver::new())
                .unwrap(),
            "__tls",
        )
        .with_tls(tls)
        .unwrap()
        .with_data(SyntheticData { tag: 7 });

        assert_eq!(
            <SyntheticModule<NativeArch, SyntheticData> as Module<NativeArch>>::tls(&module)
                .map(TlsModule::binding),
            Some(binding)
        );
        assert_eq!(module.user_data().tag, 7);
        module.user_data_mut().tag = 11;
        assert_eq!(module.user_data(), &SyntheticData { tag: 11 });
    }

    #[test]
    fn synthetic_module_can_delegate_image_memory() {
        let bytes = alloc::boxed::Box::leak(alloc::boxed::Box::new([1u8, 2, 3, 4]));
        let region = unsafe {
            MappedRegion::local_alias_no_unmap(bytes.as_ptr().cast_mut().cast(), bytes.len())
        };
        let base = VmAddr::from_ptr(bytes.as_ptr());
        let memory = ElfSegments::new(region, base, VmOffset::new(0));
        let module = SyntheticModule::<NativeArch>::empty(
            &Domain::<NativeArch>::native(AddressSpaceId::PROCESS),
            "__data",
        )
        .with_memory(memory);
        let memory = <SyntheticModule<NativeArch> as Module<NativeArch>>::memory(&module);
        let mut out = [0u8; 2];

        memory
            .read_bytes(base + VmOffset::new(1), &mut out)
            .expect("synthetic module should delegate readable image memory");

        assert_eq!(memory.base(), base);
        assert_eq!(out, [2, 3]);
    }
}
