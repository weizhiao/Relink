use super::{
    KeyResolver, ResolvedKey,
    request::{LoaderProvider, LoaderVisitor},
};
use crate::{
    Error, IoError, LinkResolverError, LinkerError, ParseEhdrError, Result,
    elf::{ElfHeader, ElfLayout},
    image::{ModuleSearch, SharedDir, expand_origin, normalize_dir},
    input::{ElfFile, ElfReader, Path, PathBuf},
    linker::{DependencyRequest, RootRequest},
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
    owner: Option<&'a ModuleSearch>,
    loaders: &'a LoaderProvider<'a>,
}

impl<'a> CandidateRequest<'a> {
    #[inline]
    const fn new(
        requested: &'a Path,
        owner: Option<&'a ModuleSearch>,
        loaders: &'a LoaderProvider<'a>,
    ) -> Self {
        Self {
            requested,
            owner,
            loaders,
        }
    }

    /// Returns the requested root path or dependency name/path.
    #[inline]
    pub const fn requested(&self) -> &'a Path {
        self.requested
    }

    #[inline]
    const fn owner(&self) -> Option<&'a ModuleSearch> {
        self.owner
    }

    fn visit_loaders(
        &self,
        mut visitor: impl for<'search> FnMut(&'search ModuleSearch) -> Result<bool>,
    ) -> Result<()> {
        (self.loaders)(&mut visitor)
    }

    /// Returns the owner name for caller-aware roots and dependencies.
    #[inline]
    pub fn owner_name(&self) -> Option<&'a str> {
        match self.owner() {
            Some(owner) => Some(owner.name()),
            None => None,
        }
    }

    /// Returns the owner path for caller-aware roots and dependencies.
    #[inline]
    pub fn owner_path(&self) -> Option<&'a Path> {
        match self.owner() {
            Some(owner) => Some(owner.path()),
            None => None,
        }
    }

    /// Returns the owner directory used for `$ORIGIN` expansion.
    #[inline]
    pub fn origin(&self) -> Option<&'a Path> {
        self.owner_path().map(Path::parent)
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
    /// Returns the key for a resolved filesystem candidate.
    fn map(candidate: &Path) -> LinkKey;
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
    fn map(candidate: &Path) -> LinkKey {
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
    fn map(candidate: &Path) -> LinkKey {
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
/// Module-owned `DT_RPATH` and `DT_RUNPATH` entries are already expanded and
/// shared by the loader. Resolver clones retain the configured search sources.
/// File existence and final lookup results are not cached.
pub struct SearchPathResolver<LinkKey = PathBuf, Mapper = PathKey> {
    entries: Vec<SearchPathEntry>,
    _marker: PhantomData<fn() -> (LinkKey, Mapper)>,
}

// Keep this impl manual so cloning a resolver does not require LinkKey or Mapper to be Clone.
impl<LinkKey, Mapper> Clone for SearchPathResolver<LinkKey, Mapper> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            _marker: PhantomData,
        }
    }
}

impl<LinkKey, Mapper> Default for SearchPathResolver<LinkKey, Mapper> {
    fn default() -> Self {
        Self::empty()
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
        Self::empty()
    }
}

impl<LinkKey, Mapper> SearchPathResolver<LinkKey, Mapper> {
    #[inline]
    const fn empty() -> Self {
        Self {
            entries: Vec::new(),
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
        let expanded = request
            .owner()
            .map(|owner| expand_origin(request.requested().as_str(), owner.path().parent()));
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
                    if request
                        .owner()
                        .is_some_and(|owner| owner.runpath().is_some())
                    {
                        continue;
                    }
                    let mut found = None;
                    request.visit_loaders(|owner| {
                        let Some(dirs) = owner.rpath_dirs() else {
                            return Ok(true);
                        };
                        for dir in dirs {
                            candidate.set_joined(Path::new(dir), requested.as_str());
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
                    let Some(owner) = request.owner() else {
                        continue;
                    };
                    let Some(dirs) = owner.runpath_dirs() else {
                        continue;
                    };
                    for dir in dirs {
                        candidate.set_joined(Path::new(dir), requested.as_str());
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

    fn resolve_key<Arch, F>(
        &self,
        request: CandidateRequest<'_>,
        contains_key: &dyn Fn(&LinkKey) -> bool,
        reuse: &F,
    ) -> Result<Option<ResolvedCandidate<LinkKey>>>
    where
        Mapper: KeyMapper<LinkKey>,
        Arch: RelocationArch,
        F: for<'req> Fn(CandidateContext<'req, LinkKey>) -> Result<Option<LinkKey>> + ?Sized,
    {
        let mut incompatible = None;
        let mut try_candidate = |candidate: &Path,
                                 continue_on_incompatible: bool|
         -> Result<Option<ResolvedCandidate<LinkKey>>> {
            let key = Mapper::map(candidate);
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

    fn resolved_key<'cfg, Arch, Tls>(
        resolved: ResolvedCandidate<LinkKey>,
    ) -> ResolvedKey<'cfg, LinkKey, Arch, Tls>
    where
        LinkKey: 'cfg,
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
    {
        match resolved {
            ResolvedCandidate::Existing(key) => ResolvedKey::existing(key),
            ResolvedCandidate::Load { key, file } => ResolvedKey::load(key, file),
        }
    }

    /// Resolves a root key using the configured search policy plus a
    /// per-operation reuse callback.
    pub fn resolve_root_with<'cfg, Arch, Tls, F>(
        &self,
        req: &RootRequest<'_, LinkKey>,
        reuse: &F,
    ) -> Result<ResolvedKey<'cfg, LinkKey, Arch, Tls>>
    where
        Mapper: KeyMapper<LinkKey>,
        LinkKey: Clone + AsRef<Path> + 'cfg,
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
        F: for<'req> Fn(CandidateContext<'req, LinkKey>) -> Result<Option<LinkKey>> + ?Sized,
    {
        let search = req.search();
        let loaders = |visitor: &mut LoaderVisitor<'_>| {
            if let Some(search) = search {
                visitor(search)?;
            }
            Ok(())
        };
        let contains_key = |key: &LinkKey| req.contains_key(key);
        let request = CandidateRequest::new(req.key().as_ref(), search, &loaders);
        if let Some(resolved) = self.resolve_key::<Arch, _>(request, &contains_key, reuse)? {
            return Ok(Self::resolved_key(resolved));
        }

        Err(LinkerError::resolver(LinkResolverError::RootNotFound).into())
    }

    /// Resolves a dependency using the configured search policy plus a
    /// per-operation reuse callback.
    pub fn resolve_dependency_with<'cfg, Arch, Tls, F>(
        &self,
        req: &DependencyRequest<'_, LinkKey>,
        reuse: &F,
    ) -> Result<ResolvedKey<'cfg, LinkKey, Arch, Tls>>
    where
        Mapper: KeyMapper<LinkKey>,
        LinkKey: Clone + 'cfg,
        Arch: RelocationArch,
        Tls: TlsResolver<Arch>,
        F: for<'req> Fn(CandidateContext<'req, LinkKey>) -> Result<Option<LinkKey>> + ?Sized,
    {
        let search = req.search();
        let loaders = |visitor: &mut LoaderVisitor<'_>| req.visit_loaders(visitor);
        let request = CandidateRequest::new(Path::new(req.needed()), Some(search), &loaders);
        let contains_key = |key: &LinkKey| req.contains_key(key);
        if let Some(resolved) = self.resolve_key::<Arch, _>(request, &contains_key, reuse)? {
            return Ok(Self::resolved_key(resolved));
        }

        Err(req.unresolved())
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
        let ehdr =
            ElfHeader::<Arch::Layout>::from_raw(unsafe { raw.assume_init() }, Some(Arch::MACHINE))?;
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

impl<LinkKey, Arch, Tls, Mapper> KeyResolver<LinkKey, Arch, LinkKey, Tls>
    for SearchPathResolver<LinkKey, Mapper>
where
    Mapper: KeyMapper<LinkKey>,
    LinkKey: Clone + AsRef<Path>,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn resolve_root<'cfg>(
        &self,
        req: &RootRequest<'_, LinkKey>,
    ) -> Result<ResolvedKey<'cfg, LinkKey, Arch, Tls>>
    where
        LinkKey: 'cfg,
    {
        let no_reuse = |_context: CandidateContext<'_, LinkKey>| Ok(None);
        self.resolve_root_with::<Arch, Tls, _>(req, &no_reuse)
    }

    fn resolve_dependency<'cfg>(
        &self,
        req: &DependencyRequest<'_, LinkKey>,
    ) -> Result<ResolvedKey<'cfg, LinkKey, Arch, Tls>>
    where
        LinkKey: 'cfg,
    {
        let no_reuse = |_context: CandidateContext<'_, LinkKey>| Ok(None);
        self.resolve_dependency_with::<Arch, Tls, _>(req, &no_reuse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::SearchPathPool;

    struct NonCloneKey;
    struct NonCloneMapper;

    fn visit_chain(chain: &[&ModuleSearch], visitor: &mut LoaderVisitor<'_>) -> Result<()> {
        for &search in chain {
            if !visitor(search)? {
                break;
            }
        }
        Ok(())
    }

    #[test]
    fn clone_needs_no_key_or_mapper_clone() {
        fn assert_clone<T: Clone>() {}

        assert_clone::<SearchPathResolver<NonCloneKey, NonCloneMapper>>();
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
    fn module_dirs_are_shared() {
        let paths = SearchPathPool::default();
        let first = ModuleSearch::from_dynamic_in(
            PathBuf::from("/opt/app/first.so"),
            None,
            Some("$ORIGIN/lib:$ORIGIN/lib/:/usr/lib/"),
            Some("/ignored"),
            &paths,
        );
        let second = ModuleSearch::from_dynamic_in(
            PathBuf::from("/opt/app/second.so"),
            None,
            Some("$ORIGIN/lib:/usr/lib"),
            None,
            &paths,
        );
        let first = first.runpath_dirs().unwrap();
        let second = second.runpath_dirs().unwrap();

        assert_eq!(first.len(), 2);
        assert_eq!(first[0].as_ref(), "/opt/app/lib");
        assert_eq!(first[1].as_ref(), "/usr/lib");
        assert!(Arc::ptr_eq(&first[0], &second[0]));
        assert!(Arc::ptr_eq(&first[1], &second[1]));
    }

    #[test]
    fn rpath_inherits_loader_chain() {
        let direct = ModuleSearch::from_dynamic(PathBuf::from("/app/middle"), None, None, None);
        let root =
            ModuleSearch::from_dynamic(PathBuf::from("/app/root"), None, None, Some("$ORIGIN/lib"));
        let chain = [&direct, &root];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let request = CandidateRequest::new(Path::new("libleaf.so"), Some(&direct), &loaders);
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
        let owner = ModuleSearch::from_dynamic(PathBuf::from("/app/owner"), None, None, None);
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let request =
            CandidateRequest::new(Path::new("$ORIGIN/libvalue.so"), Some(&owner), &loaders);
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
    fn runpath_suppresses_rpath_chain() {
        let direct = ModuleSearch::from_dynamic(
            PathBuf::from("/app/middle"),
            None,
            Some(""),
            Some("/direct"),
        );
        let root =
            ModuleSearch::from_dynamic(PathBuf::from("/app/root"), None, None, Some("/root"));
        let chain = [&direct, &root];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let request = CandidateRequest::new(Path::new("libleaf.so"), Some(&direct), &loaders);
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
        let direct =
            ModuleSearch::from_dynamic(PathBuf::from("/app/middle"), None, Some("/run"), None);
        let root =
            ModuleSearch::from_dynamic(PathBuf::from("/app/root"), None, None, Some("/root"));
        let chain = [&direct, &root];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let request = CandidateRequest::new(Path::new("libleaf.so"), Some(&direct), &loaders);
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
        let owner =
            ModuleSearch::from_dynamic(PathBuf::from("/app/owner"), None, Some(":/fallback"), None);
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let request = CandidateRequest::new(Path::new("libvalue.so"), Some(&owner), &loaders);
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
        let owner = ModuleSearch::from_dynamic(
            PathBuf::from("/app/owner"),
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
