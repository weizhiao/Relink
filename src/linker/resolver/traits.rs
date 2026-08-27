use super::{super::ModuleKey, ResolveRequest};
use crate::{
    Result, arch::NativeArch, image::ModuleHandle, input::ElfReader, relocation::RelocationArch,
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};

pub(crate) enum ResolvedKind<'cfg, Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    /// Provides an ELF reader for the requested key.
    Load(Box<dyn ElfReader + 'cfg>),
    /// Provides a module candidate and its dependencies.
    ///
    /// The underlying allocation may already be shared elsewhere. A visible
    /// module with the requested key is reused; otherwise this module is
    /// published and initialized with the transaction.
    Module {
        /// Module exposed for symbol lookup.
        module: ModuleHandle<Arch, Tls>,
        /// Dependencies resolved as part of this graph fragment.
        deps: Vec<ResolvedDependency<'cfg, Arch, Tls>>,
    },
}

/// A key-resolution result chosen by caller policy.
pub struct ResolvedKey<'cfg, Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    kind: ResolvedKind<'cfg, Arch, Tls>,
    pinned: bool,
}

/// One named dependency in a pre-resolved module graph.
///
/// The key belongs to the dependency edge, while [`ResolvedKey`] describes the
/// module selected for it.
pub struct ResolvedDependency<'cfg, Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()>
{
    pub(crate) key: ModuleKey,
    pub(crate) resolved: ResolvedKey<'cfg, Arch, Tls>,
}

impl<'cfg, Arch: RelocationArch, Tls: TlsResolver<Arch>> ResolvedDependency<'cfg, Arch, Tls> {
    /// Creates a named dependency from a resolver result.
    #[inline]
    pub fn new(key: impl Into<ModuleKey>, resolved: ResolvedKey<'cfg, Arch, Tls>) -> Self {
        Self {
            key: key.into(),
            resolved,
        }
    }
}

impl<'cfg, Arch: RelocationArch, Tls: TlsResolver<Arch>> ResolvedKey<'cfg, Arch, Tls> {
    /// Creates a result that loads a new module from the provided reader.
    #[inline]
    pub fn load(reader: impl ElfReader + 'cfg) -> Self {
        Self {
            kind: ResolvedKind::Load(Box::new(reader)),
            pinned: false,
        }
    }

    /// Creates a result backed by a module not yet committed to this context.
    #[inline]
    pub fn module(
        module: impl Into<ModuleHandle<Arch, Tls>>,
        deps: impl Into<Vec<ResolvedDependency<'cfg, Arch, Tls>>>,
    ) -> Self {
        Self {
            kind: ResolvedKind::Module {
                module: module.into(),
                deps: deps.into(),
            },
            pinned: false,
        }
    }

    /// Keeps the resolved module committed for the lifetime of its context.
    ///
    /// The pin is applied transactionally when the load is published. It is
    /// removed if publication is rolled back.
    #[inline]
    pub const fn pinned(mut self) -> Self {
        self.pinned = true;
        self
    }

    #[inline]
    pub(crate) fn into_parts(self) -> (ResolvedKind<'cfg, Arch, Tls>, bool) {
        (self.kind, self.pinned)
    }
}

/// Key-resolution policy used by [`super::super::Linker`].
pub trait KeyResolver<Arch: RelocationArch = NativeArch, Tls: TlsResolver<Arch> = ()> {
    /// Root input owned by one linker load operation.
    ///
    /// It may carry non-cloneable resources such as an already-open file.
    type Root;

    /// Maps a root input to the key used for an existing-module lookup.
    fn root_key<'a>(&self, root: &'a Self::Root) -> &'a str;

    /// Resolves a root input or one `DT_NEEDED` dependency.
    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, Self::Root>,
    ) -> Result<ResolvedKey<'cfg, Arch, Tls>>;
}
