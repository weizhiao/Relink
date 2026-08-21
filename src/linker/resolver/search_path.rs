use super::{
    KeyResolver, ResolveInput, ResolveRequest, ResolvedKey,
    request::{LoaderProvider, LoaderVisitor},
};
use crate::{
    Error, IoError, ParseEhdrError, Result,
    elf::{ElfHeader, ElfLayout},
    image::{ModuleSearch, PathTokens, SharedDir, normalize_dir},
    input::{ElfFile, ElfReader, Path, PathBuf},
    relocation::RelocationArch,
    sync::{Arc, arc_unsize},
    tls::TlsResolver,
};
use alloc::vec::Vec;
use core::{fmt, marker::PhantomData, mem::MaybeUninit};

/// Runtime directory provider used by
/// [`SearchPathResolver::push_search_dir_provider`].
///
/// Implementations append directories to `out` in the order they should be
/// searched for `request.requested()`.
type SearchDirProvider = dyn for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()>
    + Send
    + Sync
    + 'static;

#[derive(Clone)]
enum SearchPathEntry {
    Rpath,
    Runpath,
    Dir(SharedDir),
    Dynamic(Arc<SearchDirProvider>),
}

impl fmt::Debug for SearchPathEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpath => f.write_str("Rpath"),
            Self::Runpath => f.write_str("Runpath"),
            Self::Dir(dir) => f.debug_tuple("Dir").field(dir).finish(),
            Self::Dynamic(_) => f.write_str("Dynamic(..)"),
        }
    }
}

/// Search request used to build filesystem candidates for a root or dependency.
#[derive(Clone, Copy)]
pub struct CandidateRequest<'a> {
    requested: &'a Path,
    owner: &'a ModuleSearch,
    tokens: &'a PathTokens,
    loaders: &'a LoaderProvider<'a>,
}

impl<'a> CandidateRequest<'a> {
    #[inline]
    const fn new(
        requested: &'a Path,
        owner: &'a ModuleSearch,
        tokens: &'a PathTokens,
        loaders: &'a LoaderProvider<'a>,
    ) -> Self {
        Self {
            requested,
            owner,
            tokens,
            loaders,
        }
    }

    /// Returns the requested root path or dependency name/path.
    #[inline]
    pub const fn requested(&self) -> &'a Path {
        self.requested
    }

    #[inline]
    const fn owner(&self) -> &'a ModuleSearch {
        self.owner
    }

    #[inline]
    const fn tokens(&self) -> &'a PathTokens {
        self.tokens
    }

    fn visit_loaders(
        &self,
        mut visitor: impl for<'search> FnMut(&'search ModuleSearch) -> Result<bool>,
    ) -> Result<()> {
        (self.loaders)(&mut visitor)
    }

    /// Returns the owner name for caller-aware roots and dependencies.
    #[inline]
    pub fn owner_name(&self) -> &'a str {
        self.owner().name()
    }

    /// Returns the owner path for caller-aware roots and dependencies.
    #[inline]
    pub fn owner_path(&self) -> &'a Path {
        self.owner().path()
    }

    /// Returns the owner directory used for `$ORIGIN` expansion.
    #[inline]
    pub fn origin(&self) -> &'a Path {
        self.owner_path().parent()
    }
}

/// Context passed to existing-candidate reuse callbacks.
pub struct CandidateContext<'a, LinkKey> {
    candidate: &'a Path,
    key: &'a LinkKey,
}

// Keep these impls manual so callback contexts remain copyable for any LinkKey.
impl<LinkKey> Clone for CandidateContext<'_, LinkKey> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<LinkKey> Copy for CandidateContext<'_, LinkKey> {}

impl<'a, LinkKey> CandidateContext<'a, LinkKey> {
    #[inline]
    fn new(candidate: &'a Path, key: &'a LinkKey) -> Self {
        Self { candidate, key }
    }

    /// Returns the concrete filesystem candidate currently being considered.
    #[inline]
    pub const fn candidate(&self) -> &'a Path {
        self.candidate
    }

    /// Returns the key that would be used if the current candidate were loaded.
    #[inline]
    pub const fn key(&self) -> &'a LinkKey {
        self.key
    }
}

impl<LinkKey: fmt::Debug> fmt::Debug for CandidateContext<'_, LinkKey> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateContext")
            .field("candidate", &self.candidate)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for CandidateRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateRequest")
            .field("requested", &self.requested)
            .field("owner", &self.owner)
            .finish()
    }
}

/// Maps a resolved filesystem candidate to its [`LinkContext`](crate::LinkContext) key.
pub trait KeyMapper<LinkKey> {
    /// Maps a resolved filesystem path to its linker key.
    fn map_path(&self, candidate: &Path) -> LinkKey;

    /// Maps an ELF module name to the same key namespace.
    ///
    /// Override this when path keys and `DT_SONAME`/`DT_NEEDED` keys use
    /// different representations.
    #[inline]
    fn map_name(&self, name: &str) -> LinkKey {
        self.map_path(Path::new(name))
    }
}

/// Default filesystem key behavior for [`SearchPathResolver`].
///
/// Loads use the concrete resolved candidate path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathKey;

impl<LinkKey> KeyMapper<LinkKey> for PathKey
where
    LinkKey: From<PathBuf>,
{
    #[inline]
    fn map_path(&self, candidate: &Path) -> LinkKey {
        LinkKey::from(PathBuf::from(candidate))
    }
}

/// Uses the resolved candidate's last path component as the linker key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileNameKey;

impl<LinkKey> KeyMapper<LinkKey> for FileNameKey
where
    LinkKey: From<PathBuf>,
{
    #[inline]
    fn map_path(&self, candidate: &Path) -> LinkKey {
        LinkKey::from(PathBuf::from(candidate.file_name()))
    }
}

/// Filesystem-backed dependency resolver for [`Linker`](crate::Linker).
///
/// `SearchPathResolver` is an opt-in convenience resolver for callers whose
/// linker keys can be viewed as loader paths and constructed from resolved
/// paths. Root requests and dependencies with directory separators are tried
/// directly. Plain-name searches walk the configured sources in insertion
/// order.
///
/// This resolver intentionally does not model the host dynamic linker's global
/// policy: it does not read `LD_LIBRARY_PATH`, system cache files, or default
/// system library directories unless callers add runtime directory providers
/// for them.
///
/// Module-owned `DT_RPATH` and `DT_RUNPATH` entries have their dynamic string
/// tokens expanded by the loader and are shared between modules. File existence
/// and final lookup results are not cached.
pub struct SearchPathResolver<LinkKey = PathBuf, Mapper = PathKey> {
    entries: Vec<SearchPathEntry>,
    mapper: Mapper,
    _marker: PhantomData<fn() -> LinkKey>,
}

// Keep this impl manual so cloning a resolver does not require LinkKey to be Clone.
impl<LinkKey, Mapper: Clone> Clone for SearchPathResolver<LinkKey, Mapper> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            mapper: self.mapper.clone(),
            _marker: PhantomData,
        }
    }
}

impl<LinkKey, Mapper: Default> Default for SearchPathResolver<LinkKey, Mapper> {
    fn default() -> Self {
        Self::with_mapper(Mapper::default())
    }
}

impl<LinkKey, Mapper> fmt::Debug for SearchPathResolver<LinkKey, Mapper> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchPathResolver")
            .field("entries", &self.entries)
            .field("link_key", &core::any::type_name::<LinkKey>())
            .field("key_mapper", &core::any::type_name::<Mapper>())
            .finish()
    }
}

impl<LinkKey> SearchPathResolver<LinkKey, PathKey> {
    /// Creates an empty search-path resolver using the default path key rule.
    #[inline]
    pub const fn new() -> Self {
        Self::with_mapper(PathKey)
    }
}

impl<LinkKey, Mapper> SearchPathResolver<LinkKey, Mapper> {
    /// Creates an empty resolver with a custom key-mapping policy.
    #[inline]
    pub const fn with_mapper(mapper: Mapper) -> Self {
        Self {
            entries: Vec::new(),
            mapper,
            _marker: PhantomData,
        }
    }

    fn push_entry(&mut self, entry: SearchPathEntry) -> &mut Self {
        let entry = match entry {
            SearchPathEntry::Rpath => {
                if self
                    .entries
                    .iter()
                    .any(|entry| matches!(entry, SearchPathEntry::Rpath))
                {
                    return self;
                }
                SearchPathEntry::Rpath
            }
            SearchPathEntry::Runpath => {
                if self
                    .entries
                    .iter()
                    .any(|entry| matches!(entry, SearchPathEntry::Runpath))
                {
                    return self;
                }
                SearchPathEntry::Runpath
            }
            SearchPathEntry::Dir(dir) => {
                if self.entries.iter().any(|entry| {
                    matches!(entry, SearchPathEntry::Dir(existing) if existing.as_ref() == dir.as_ref())
                }) {
                    return self;
                }
                SearchPathEntry::Dir(dir)
            }
            SearchPathEntry::Dynamic(provider) => SearchPathEntry::Dynamic(provider),
        };
        self.entries.push(entry);
        self
    }

    /// Appends inherited `DT_RPATH` directories.
    ///
    /// The direct loader is visited first, followed by its loader chain. The
    /// entire source is skipped when the direct loader has `DT_RUNPATH`.
    pub fn push_rpath(&mut self) -> &mut Self {
        self.push_entry(SearchPathEntry::Rpath)
    }

    /// Appends the direct loader's `DT_RUNPATH` directories.
    ///
    /// Unlike `DT_RPATH`, this source is not inherited by indirect
    /// dependencies.
    pub fn push_runpath(&mut self) -> &mut Self {
        self.push_entry(SearchPathEntry::Runpath)
    }

    /// Appends a fixed search directory.
    pub fn push_fixed_dir(&mut self, dir: impl Into<PathBuf>) -> &mut Self {
        self.push_entry(SearchPathEntry::Dir(Arc::from(
            normalize_dir(dir.into()).into_string(),
        )))
    }

    /// Appends a callback that can provide search directories per request.
    pub fn push_search_dir_provider<F>(&mut self, provider: F) -> &mut Self
    where
        F: for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()>
            + Send
            + Sync
            + 'static,
    {
        self.push_entry(SearchPathEntry::Dynamic(
            arc_unsize!(Arc::new(provider) => SearchDirProvider),
        ))
    }

    fn find_candidate_with<T>(
        &self,
        request: CandidateRequest<'_>,
        mut inspect: impl FnMut(&Path, bool) -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        let requested_value = request.requested().as_str();
        let expanded = if requested_value.contains('$') {
            let Some(expanded) = request
                .tokens()
                .expand(requested_value, Some(request.origin()))
            else {
                return Ok(None);
            };
            Some(expanded)
        } else {
            None
        };
        let requested = expanded
            .as_ref()
            .map_or_else(|| request.requested(), PathBuf::as_path);
        if requested.has_dir_separator() {
            return inspect(requested, false);
        }

        let mut dirs = Vec::new();
        let mut candidate = PathBuf::default();
        for entry in &self.entries {
            match entry {
                SearchPathEntry::Rpath => {
                    if request.owner().runpath().is_some() {
                        continue;
                    }
                    let mut found = None;
                    request.visit_loaders(|owner| {
                        let Some(dirs) = owner.rpath() else {
                            return Ok(true);
                        };
                        for dir in dirs {
                            candidate.set_joined(dir, requested.as_str());
                            if let Some(value) = inspect(candidate.as_path(), true)? {
                                found = Some(value);
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    })?;
                    if found.is_some() {
                        return Ok(found);
                    }
                }
                SearchPathEntry::Runpath => {
                    let Some(dirs) = request.owner().runpath() else {
                        continue;
                    };
                    for dir in dirs {
                        candidate.set_joined(dir, requested.as_str());
                        if let Some(found) = inspect(candidate.as_path(), true)? {
                            return Ok(Some(found));
                        }
                    }
                }
                SearchPathEntry::Dir(dir) => {
                    candidate.set_joined(Path::new(dir), requested.as_str());
                    if let Some(found) = inspect(candidate.as_path(), true)? {
                        return Ok(Some(found));
                    }
                }
                SearchPathEntry::Dynamic(resolver) => {
                    dirs.clear();
                    resolver(request, &mut dirs)?;
                    for dir in &dirs {
                        candidate.set_joined(dir, requested.as_str());
                        if let Some(found) = inspect(candidate.as_path(), true)? {
                            return Ok(Some(found));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    fn resolve_candidate<Arch, F>(
        &self,
        request: CandidateRequest<'_>,
        contains_key: &dyn Fn(&LinkKey) -> bool,
        reuse: &F,
    ) -> Result<Option<ResolvedCandidate<LinkKey>>>
    where
        Mapper: KeyMapper<LinkKey>,
        LinkKey: Clone,
        Arch: RelocationArch,
        F: for<'req> Fn(CandidateContext<'req, LinkKey>) -> Result<Option<LinkKey>> + ?Sized,
    {
        let mut incompatible = None;
        let mut try_candidate = |candidate: &Path,
                                 continue_on_incompatible: bool|
         -> Result<Option<ResolvedCandidate<LinkKey>>> {
            let key = self.mapper.map_path(candidate);
            if contains_key(&key) {
                return Ok(Some(ResolvedCandidate::Existing(key)));
            }

            let file = match Self::open_elf::<Arch>(candidate) {
                Ok(Some(file)) => file,
                Ok(None) => return Ok(None),
                Err(err) if continue_on_incompatible && Self::is_incompatible_elf(&err) => {
                    incompatible.get_or_insert(err);
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };

            let context = CandidateContext::new(candidate, &key);
            if let Some(existing) = reuse(context)? {
                return Ok(Some(ResolvedCandidate::Existing(existing)));
            }

            Ok(Some(ResolvedCandidate::Load { key, file }))
        };

        if let Some(resolved) = self.find_candidate_with(request, &mut try_candidate)? {
            return Ok(Some(resolved));
        }

        match incompatible {
            Some(err) => Err(err),
            None => Ok(None),
        }
    }

    /// Resolves a root or dependency using the configured search policy plus
    /// a per-operation reuse callback.
    pub fn resolve_with<'cfg, Arch, Tls, F, Request>(
        &self,
        req: &ResolveRequest<'_, Request, LinkKey>,
        reuse: &F,
    ) -> Result<ResolvedKey<'cfg, LinkKey, Arch, Tls>>
    where
        Mapper: KeyMapper<LinkKey>,
        LinkKey: Clone + 'cfg,
        Request: AsRef<Path>,
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
        F: for<'req> Fn(CandidateContext<'req, LinkKey>) -> Result<Option<LinkKey>> + ?Sized,
    {
        let requested = match req.input() {
            ResolveInput::Root { request, .. } => request.as_ref(),
            ResolveInput::Dependency { needed } => Path::new(needed),
        };
        let loaders = |visitor: &mut LoaderVisitor<'_>| req.visit_loaders(visitor);
        let contains_key = |key: &LinkKey| req.contains_key(key);
        let request = CandidateRequest::new(requested, req.search(), req.tokens(), &loaders);
        if let Some(resolved) = self.resolve_candidate::<Arch, _>(request, &contains_key, reuse)? {
            return Ok(resolved.into_resolved());
        }

        Err(req.unresolved())
    }

    /// Resolves a root or dependency using the configured search policy.
    pub fn resolve<'cfg, Arch, Tls, Request>(
        &self,
        req: &ResolveRequest<'_, Request, LinkKey>,
    ) -> Result<ResolvedKey<'cfg, LinkKey, Arch, Tls>>
    where
        Mapper: KeyMapper<LinkKey>,
        LinkKey: Clone + 'cfg,
        Request: AsRef<Path>,
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
    {
        self.resolve_with(req, &|_| Ok(None))
    }

    /// Opens and validates a target-compatible ELF candidate.
    fn open_elf<Arch: RelocationArch>(path: &Path) -> Result<Option<ElfFile>> {
        let file = match ElfFile::from_path(path) {
            Ok(file) => file,
            Err(Error::Io(IoError::OpenFailed { .. })) => return Ok(None),
            Err(err) => return Err(err),
        };

        let mut raw = MaybeUninit::<<Arch::Layout as ElfLayout>::Ehdr>::uninit();
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                raw.as_mut_ptr().cast::<u8>(),
                <Arch::Layout as ElfLayout>::EHDR_SIZE,
            )
        };
        file.read(bytes, 0)?;
        let ehdr = ElfHeader::<Arch::Layout>::from_raw(unsafe { raw.assume_init() }, Arch::TARGET)?;
        Arch::validate_e_flags(ehdr.e_flags())?;
        Ok(Some(file))
    }

    #[inline]
    fn is_incompatible_elf(err: &Error) -> bool {
        matches!(
            err,
            Error::ParseEhdr(
                ParseEhdrError::FileClassMismatch { .. }
                    | ParseEhdrError::FileEndianMismatch { .. }
                    | ParseEhdrError::FileArchMismatch { .. }
                    | ParseEhdrError::InvalidFlags { .. }
            )
        )
    }
}

enum ResolvedCandidate<LinkKey> {
    Existing(LinkKey),
    Load { key: LinkKey, file: ElfFile },
}

impl<LinkKey> ResolvedCandidate<LinkKey> {
    #[inline]
    fn into_resolved<'cfg, Arch, Tls>(self) -> ResolvedKey<'cfg, LinkKey, Arch, Tls>
    where
        LinkKey: 'cfg,
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
    {
        match self {
            Self::Existing(key) => ResolvedKey::existing(key),
            Self::Load { key, file } => ResolvedKey::load(key, file),
        }
    }
}

impl<LinkKey, Arch, Tls, Mapper> KeyResolver<LinkKey, Arch, Tls>
    for SearchPathResolver<LinkKey, Mapper>
where
    Mapper: KeyMapper<LinkKey>,
    LinkKey: Clone,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    type Request = PathBuf;

    #[inline]
    fn map_request(&self, request: &Self::Request) -> LinkKey {
        if request.has_dir_separator() {
            self.mapper.map_path(request)
        } else {
            self.mapper.map_name(request.as_str())
        }
    }

    #[inline]
    fn map_name(&self, name: &str) -> Option<LinkKey> {
        Some(self.mapper.map_name(name))
    }

    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, Self::Request, LinkKey>,
    ) -> Result<ResolvedKey<'cfg, LinkKey, Arch, Tls>>
    where
        LinkKey: 'cfg,
    {
        SearchPathResolver::resolve::<Arch, Tls, _>(self, &req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NonCloneKey;
    #[derive(Clone)]
    struct TestMapper;

    fn module_search(
        path: &str,
        soname: Option<&str>,
        runpath: Option<&str>,
        rpath: Option<&str>,
    ) -> ModuleSearch {
        ModuleSearch::from_dynamic(PathBuf::from(path), soname, runpath, rpath)
    }

    fn visit_chain(chain: &[&ModuleSearch], visitor: &mut LoaderVisitor<'_>) -> Result<()> {
        for &search in chain {
            if !visitor(search)? {
                break;
            }
        }
        Ok(())
    }

    #[test]
    fn clone_needs_no_key_clone() {
        fn assert_clone<T: Clone>() {}

        assert_clone::<SearchPathResolver<NonCloneKey, TestMapper>>();
    }

    #[test]
    fn fixed_dirs_are_shared_and_deduplicated() {
        let mut resolver = SearchPathResolver::<PathBuf>::new();
        resolver.push_fixed_dir("/usr/lib/");
        resolver.push_fixed_dir("/usr/lib");
        assert_eq!(resolver.entries.len(), 1);

        let cloned = resolver.clone();
        let SearchPathEntry::Dir(first) = &resolver.entries[0] else {
            panic!("expected fixed directory");
        };
        let SearchPathEntry::Dir(second) = &cloned.entries[0] else {
            panic!("expected fixed directory");
        };
        assert!(Arc::ptr_eq(first, second));
    }

    #[test]
    fn rpath_inherits_loader_chain() {
        let direct = module_search("/app/middle", None, None, None);
        let root = module_search("/app/root", None, None, Some("$ORIGIN/lib"));
        let chain = [&direct, &root];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request = CandidateRequest::new(Path::new("libleaf.so"), &direct, &tokens, &loaders);
        let mut resolver = SearchPathResolver::<PathBuf>::new();
        resolver.push_rpath();

        let found = resolver
            .find_candidate_with(request, |path, _| {
                Ok((path.as_str() == "/app/lib/libleaf.so").then_some(()))
            })
            .unwrap();
        assert_eq!(found, Some(()));
    }

    #[test]
    fn expands_dependency_origin() {
        let owner = module_search("/app/owner", None, None, None);
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request =
            CandidateRequest::new(Path::new("$ORIGIN/libvalue.so"), &owner, &tokens, &loaders);
        let resolver = SearchPathResolver::<PathBuf>::new();

        let found = resolver
            .find_candidate_with(request, |path, searched| {
                assert!(!searched);
                Ok((path.as_str() == "/app/libvalue.so").then_some(()))
            })
            .unwrap();
        assert_eq!(found, Some(()));
    }

    #[test]
    fn expands_target_tokens() {
        let mut paths = crate::image::SearchPathPool::new();
        paths.set_lib("lib64").set_platform("target-v1");
        let tokens = paths.tokens();
        let owner = paths.module_search(
            PathBuf::from("/app/owner"),
            None,
            Some("$ORIGIN/$LIB/${PLATFORM}"),
            None,
        );
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let request = CandidateRequest::new(Path::new("libleaf.so"), &owner, &tokens, &loaders);
        let mut resolver = SearchPathResolver::<PathBuf>::new();
        resolver.push_runpath();

        let found = resolver
            .find_candidate_with(request, |path, _| {
                Ok((path.as_str() == "/app/lib64/target-v1/libleaf.so").then_some(()))
            })
            .unwrap();
        assert_eq!(found, Some(()));
    }

    #[test]
    fn expands_tokens_in_dependency_name() {
        let owner = module_search("/app/owner", None, None, None);
        let mut paths = crate::image::SearchPathPool::new();
        paths.set_lib("lib64").set_platform("target-v1");
        let tokens = paths.tokens();
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let request = CandidateRequest::new(
            Path::new("$LIB/${PLATFORM}/libleaf.so"),
            &owner,
            &tokens,
            &loaders,
        );
        let resolver = SearchPathResolver::<PathBuf>::new();

        let found = resolver
            .find_candidate_with(request, |path, searched| {
                assert!(!searched);
                Ok((path.as_str() == "lib64/target-v1/libleaf.so").then_some(()))
            })
            .unwrap();
        assert_eq!(found, Some(()));
    }

    #[test]
    fn missing_target_token_discards_path() {
        let owner = module_search("/app/owner", None, Some("$ORIGIN/$PLATFORM"), None);
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request = CandidateRequest::new(Path::new("libleaf.so"), &owner, &tokens, &loaders);
        let mut resolver = SearchPathResolver::<PathBuf>::new();
        resolver.push_runpath();
        let mut inspected = false;

        let found = resolver
            .find_candidate_with(request, |_, _| {
                inspected = true;
                Ok(Some(()))
            })
            .unwrap();
        assert_eq!(found, None);
        assert!(!inspected);
    }

    #[test]
    fn runpath_suppresses_rpath_chain() {
        let direct = module_search("/app/middle", None, Some(""), Some("/direct"));
        let root = module_search("/app/root", None, None, Some("/root"));
        let chain = [&direct, &root];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request = CandidateRequest::new(Path::new("libleaf.so"), &direct, &tokens, &loaders);
        let mut resolver = SearchPathResolver::<PathBuf>::new();
        resolver.push_rpath();
        let mut candidates = Vec::new();

        let found = resolver
            .find_candidate_with(request, |path, _| {
                candidates.push(PathBuf::from(path));
                Ok(None::<()>)
            })
            .unwrap();
        assert_eq!(found, None);
        assert!(candidates.is_empty());
    }

    #[test]
    fn rpath_and_runpath_have_independent_order() {
        let direct = module_search("/app/middle", None, Some("/run"), None);
        let root = module_search("/app/root", None, None, Some("/root"));
        let chain = [&direct, &root];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request = CandidateRequest::new(Path::new("libleaf.so"), &direct, &tokens, &loaders);
        let mut resolver = SearchPathResolver::<PathBuf>::new();
        resolver.push_rpath();
        resolver.push_fixed_dir("/env");
        resolver.push_runpath();
        let mut candidates = Vec::new();

        resolver
            .find_candidate_with(request, |path, _| {
                candidates.push(PathBuf::from(path));
                Ok(None::<()>)
            })
            .unwrap();
        assert_eq!(
            candidates,
            [
                PathBuf::from("/env/libleaf.so"),
                PathBuf::from("/run/libleaf.so")
            ]
        );
    }

    #[test]
    fn path_lists_preserve_current_directory() {
        let owner = module_search("/app/owner", None, Some(":/fallback"), None);
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request = CandidateRequest::new(Path::new("libvalue.so"), &owner, &tokens, &loaders);
        let mut resolver = SearchPathResolver::<PathBuf>::new();
        resolver.push_runpath();
        let mut candidates = Vec::new();

        resolver
            .find_candidate_with(request, |path, _| {
                candidates.push(PathBuf::from(path));
                Ok(None::<()>)
            })
            .unwrap();
        assert_eq!(
            candidates,
            [
                PathBuf::from("libvalue.so"),
                PathBuf::from("/fallback/libvalue.so")
            ]
        );
    }

    #[test]
    fn origin_requires_a_token_boundary() {
        let owner = module_search(
            "/app/owner",
            None,
            Some("$ORIGIN/lib:$ORIGIN_SUFFIX:${ORIGIN}/alt"),
            None,
        );
        let paths = owner
            .runpath()
            .unwrap()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                PathBuf::from("/app/lib"),
                PathBuf::from("$ORIGIN_SUFFIX"),
                PathBuf::from("/app/alt"),
            ]
        );
    }
}
