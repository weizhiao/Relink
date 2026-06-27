use super::{KeyResolver, ResolvedKey};
use crate::{
    Error, IoError, LinkerError, ParseEhdrError, Result,
    input::{ElfFile, ElfReader, Path, PathBuf},
    linker::{DependencyRequest, RootRequest},
    relocation::RelocationArch,
    sync::Arc,
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt, marker::PhantomData};

fn expand_origin(value: &str, origin: &Path) -> PathBuf {
    PathBuf::from(
        value
            .replace("${ORIGIN}", origin.as_str())
            .replace("$ORIGIN", origin.as_str()),
    )
}

/// Runtime directory provider used by [`SearchPathEntry::Dynamic`].
///
/// Implementations append directories to `out` in the order they should be
/// searched for `request.requested()`.
pub type SearchDirProvider =
    dyn for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()> + 'static;

/// Callback used by [`SearchPathResolver`] to reuse already-linked modules
/// while considering a filesystem candidate.
pub type ReuseResolver<LinkKey> =
    dyn for<'req> Fn(CandidateContext<'req, LinkKey>) -> Result<Option<LinkKey>> + 'static;

/// One ordered search-path entry.
#[derive(Clone)]
pub enum SearchPathEntry {
    /// A fixed directory joined with the requested value when it has no
    /// directory separators.
    Dir(PathBuf),
    /// A runtime directory source that can inspect the current request.
    Dynamic(Arc<SearchDirProvider>),
}

impl SearchPathEntry {
    /// Creates a fixed search directory entry.
    #[inline]
    pub fn dir(dir: impl Into<PathBuf>) -> Self {
        Self::Dir(dir.into())
    }

    /// Creates a callback-backed search directory entry.
    #[inline]
    pub fn dynamic<F>(resolver: F) -> Self
    where
        F: for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()> + 'static,
    {
        Self::Dynamic(Arc::from(Box::new(resolver) as Box<SearchDirProvider>))
    }
}

impl fmt::Debug for SearchPathEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dir(dir) => f.debug_tuple("Dir").field(dir).finish(),
            Self::Dynamic(_) => f.write_str("Dynamic(..)"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum CandidateRequest<'a> {
    /// Resolving the root key passed to [`KeyResolver::load_root`].
    Root {
        /// Path requested by the root load.
        requested: &'a Path,
    },
    /// Resolving one `DT_NEEDED` entry for an already-loaded owner.
    Dependency {
        /// Dependency name after applying `$ORIGIN` to the requested value.
        requested: &'a Path,
        /// Diagnostic name of the owner that requested this dependency.
        owner_name: &'a str,
        /// Loaded path/key of the owner that requested this dependency.
        owner_path: &'a Path,
        /// Raw `DT_RUNPATH` value, when present.
        runpath: Option<&'a str>,
        /// Raw `DT_RPATH` value, when present.
        rpath: Option<&'a str>,
    },
}

impl<'a> CandidateRequest<'a> {
    /// Creates a root candidate request.
    #[inline]
    pub const fn root(requested: &'a Path) -> Self {
        Self::Root { requested }
    }

    /// Creates a dependency candidate request.
    #[inline]
    pub const fn dependency(
        requested: &'a Path,
        owner_name: &'a str,
        owner_path: &'a Path,
        runpath: Option<&'a str>,
        rpath: Option<&'a str>,
    ) -> Self {
        Self::Dependency {
            requested,
            owner_name,
            owner_path,
            runpath,
            rpath,
        }
    }
}

impl<'a> CandidateRequest<'a> {
    /// Returns the requested root path or dependency name/path.
    #[inline]
    pub const fn requested(&self) -> &'a Path {
        match self {
            Self::Root { requested } | Self::Dependency { requested, .. } => requested,
        }
    }

    /// Returns the owner name for dependency requests.
    #[inline]
    pub const fn owner_name(&self) -> Option<&'a str> {
        match self {
            Self::Root { .. } => None,
            Self::Dependency { owner_name, .. } => Some(owner_name),
        }
    }

    /// Returns the owner path for dependency requests.
    #[inline]
    pub const fn owner_path(&self) -> Option<&'a Path> {
        match self {
            Self::Root { .. } => None,
            Self::Dependency { owner_path, .. } => Some(owner_path),
        }
    }

    /// Returns the owner directory used for `$ORIGIN` expansion.
    #[inline]
    pub fn origin(&self) -> Option<&'a Path> {
        match self {
            Self::Root { .. } => None,
            Self::Dependency { owner_path, .. } => Some(owner_path.parent()),
        }
    }

    /// Returns expanded `DT_RUNPATH` directories for dependency requests.
    #[inline]
    pub fn runpath(&self) -> Option<Vec<PathBuf>> {
        match self {
            Self::Root { .. } => None,
            Self::Dependency { runpath, .. } => self.expand_dynamic_path_list(*runpath),
        }
    }

    /// Returns expanded `DT_RPATH` directories for dependency requests.
    #[inline]
    pub fn rpath(&self) -> Option<Vec<PathBuf>> {
        match self {
            Self::Root { .. } => None,
            Self::Dependency { rpath, .. } => self.expand_dynamic_path_list(*rpath),
        }
    }

    fn expand_dynamic_path_list(&self, path_list: Option<&str>) -> Option<Vec<PathBuf>> {
        let Self::Dependency {
            requested,
            owner_path,
            ..
        } = *self
        else {
            return None;
        };

        if requested.has_dir_separator() {
            return None;
        }

        let origin = owner_path.parent();
        Some(
            path_list?
                .split(':')
                .filter(|dir| !dir.is_empty())
                .map(|dir| expand_origin(dir, origin))
                .collect(),
        )
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
        match self {
            Self::Root { requested } => f
                .debug_struct("Root")
                .field("requested", requested)
                .finish(),
            Self::Dependency {
                requested,
                owner_name,
                owner_path,
                runpath,
                rpath,
            } => f
                .debug_struct("Dependency")
                .field("requested", requested)
                .field("owner_name", owner_name)
                .field("owner_path", owner_path)
                .field("runpath", runpath)
                .field("rpath", rpath)
                .finish(),
        }
    }
}

/// Chooses which linker key [`SearchPathResolver`] commits for a resolved file.
pub trait KeyRule<LinkKey> {
    /// Returns the key for a load resolved to `candidate`.
    fn key_for_candidate(candidate: &Path) -> LinkKey;
}

/// Default filesystem key behavior for [`SearchPathResolver`].
///
/// Loads use the concrete resolved candidate path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathKey;

impl<LinkKey> KeyRule<LinkKey> for PathKey
where
    LinkKey: From<PathBuf>,
{
    #[inline]
    fn key_for_candidate(candidate: &Path) -> LinkKey {
        LinkKey::from(PathBuf::from(candidate))
    }
}

/// Uses the resolved candidate's last path component as the linker key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileNameKey;

impl<LinkKey> KeyRule<LinkKey> for FileNameKey
where
    LinkKey: From<PathBuf>,
{
    #[inline]
    fn key_for_candidate(candidate: &Path) -> LinkKey {
        LinkKey::from(PathBuf::from(candidate.file_name()))
    }
}

/// Filesystem-backed dependency resolver for [`Linker`](crate::linker::Linker).
///
/// `SearchPathResolver` is an opt-in convenience resolver for callers whose
/// linker keys can be viewed as loader paths and constructed from resolved
/// paths. Root requests and dependencies with directory separators are tried
/// directly. Plain-name searches walk the ordered
/// [`SearchPathEntry`] list.
///
/// This resolver intentionally does not model the host dynamic linker's global
/// policy: it does not read `LD_LIBRARY_PATH`, system cache files, or default
/// system library directories unless callers add runtime directory providers
/// for them.
pub struct SearchPathResolver<LinkKey = PathBuf, Rule = PathKey> {
    entries: Vec<SearchPathEntry>,
    reuse_resolvers: Vec<Arc<ReuseResolver<LinkKey>>>,
    _rule: PhantomData<fn() -> Rule>,
}

// Keep this impl manual so cloning a resolver does not require LinkKey or Rule to be Clone.
impl<LinkKey, Rule> Clone for SearchPathResolver<LinkKey, Rule> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            reuse_resolvers: self.reuse_resolvers.clone(),
            _rule: PhantomData,
        }
    }
}

impl<LinkKey, Rule> Default for SearchPathResolver<LinkKey, Rule> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<LinkKey, Rule> fmt::Debug for SearchPathResolver<LinkKey, Rule> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchPathResolver")
            .field("entries", &self.entries)
            .field(
                "reuse_resolvers",
                &self
                    .reuse_resolvers
                    .iter()
                    .map(|_| "Reuse(..)")
                    .collect::<Vec<_>>(),
            )
            .field("link_key", &core::any::type_name::<LinkKey>())
            .field("rule", &core::any::type_name::<Rule>())
            .finish()
    }
}

impl<LinkKey> SearchPathResolver<LinkKey, PathKey> {
    /// Creates an empty search-path resolver using the default path key rule.
    #[inline]
    pub fn new() -> Self {
        Self::empty()
    }
}

impl<LinkKey, Rule> SearchPathResolver<LinkKey, Rule> {
    #[inline]
    fn empty() -> Self {
        Self {
            entries: Vec::new(),
            reuse_resolvers: Vec::new(),
            _rule: PhantomData,
        }
    }

    /// Appends one search-path entry.
    pub fn push_entry(&mut self, entry: SearchPathEntry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Appends a fixed search directory.
    pub fn push_fixed_dir(&mut self, dir: impl Into<PathBuf>) -> &mut Self {
        self.push_entry(SearchPathEntry::Dir(dir.into()))
    }

    /// Appends a callback that can provide search directories per request.
    pub fn push_search_dir_provider<F>(&mut self, provider: F) -> &mut Self
    where
        F: for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()> + 'static,
    {
        self.push_entry(SearchPathEntry::Dynamic(Arc::from(
            Box::new(provider) as Box<SearchDirProvider>
        )))
    }

    /// Appends a callback that can reuse an already-linked visible module
    /// after the candidate has been opened and verified as an ELF file.
    pub fn push_reuse_resolver<F>(&mut self, resolver: F) -> &mut Self
    where
        F: for<'req> Fn(CandidateContext<'req, LinkKey>) -> Result<Option<LinkKey>> + 'static,
    {
        self.reuse_resolvers
            .push(Arc::from(Box::new(resolver) as Box<ReuseResolver<LinkKey>>));
        self
    }

    /// Returns the configured search-path entries in lookup order.
    #[inline]
    pub fn entries(&self) -> &[SearchPathEntry] {
        &self.entries
    }

    fn resolve_reuse<'a>(
        &self,
        resolvers: &[Arc<ReuseResolver<LinkKey>>],
        candidate: &'a Path,
        key: &'a LinkKey,
    ) -> Result<Option<LinkKey>> {
        let context = CandidateContext::new(candidate, key);
        for resolver in resolvers {
            if let Some(existing) = resolver(context)? {
                return Ok(Some(existing));
            }
        }
        Ok(None)
    }

    fn resolve_key(
        &self,
        request: CandidateRequest<'_>,
        visible_key: &dyn Fn(&LinkKey) -> Option<LinkKey>,
    ) -> Result<Option<ResolvedCandidate<LinkKey>>>
    where
        Rule: KeyRule<LinkKey>,
        LinkKey: AsRef<Path>,
    {
        let try_candidate = |candidate: &Path| -> Result<Option<ResolvedCandidate<LinkKey>>> {
            let key = Rule::key_for_candidate(candidate);
            if let Some(existing) = visible_key(&key) {
                return Ok(Some(ResolvedCandidate::Existing(existing)));
            }

            let Some(file) = Self::open_elf(candidate)? else {
                return Ok(None);
            };

            if let Some(existing) = self.resolve_reuse(&self.reuse_resolvers, candidate, &key)? {
                return Ok(Some(ResolvedCandidate::Existing(existing)));
            }

            Ok(Some(ResolvedCandidate::Load { key, file }))
        };

        let requested = request.requested();
        let has_dir_separator = requested.has_dir_separator();
        if has_dir_separator {
            if let Some(resolved) = try_candidate(requested)? {
                return Ok(Some(resolved));
            }
            return Ok(None);
        }

        let mut dynamic_dirs = Vec::new();
        for entry in &self.entries {
            match entry {
                SearchPathEntry::Dir(dir) => {
                    let candidate = dir.join(requested.as_str());
                    if let Some(resolved) = try_candidate(candidate.as_path())? {
                        return Ok(Some(resolved));
                    }
                }
                SearchPathEntry::Dynamic(resolver) => {
                    dynamic_dirs.clear();
                    resolver(request, &mut dynamic_dirs)?;
                    for dir in &dynamic_dirs {
                        let candidate = dir.join(requested.as_str());
                        if let Some(resolved) = try_candidate(candidate.as_path())? {
                            return Ok(Some(resolved));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    #[inline]
    fn resolved_key<'cfg, Arch: RelocationArch, Tls: TlsResolver<Arch>>(
        key: LinkKey,
        file: ElfFile,
        visible_key: Option<LinkKey>,
    ) -> ResolvedKey<'cfg, LinkKey, Arch, Tls> {
        if let Some(key) = visible_key {
            ResolvedKey::existing(key)
        } else {
            ResolvedKey::load(key, file)
        }
    }

    /// Open `path` if it exists, returning `Ok(None)` for ordinary open
    /// failures and propagating parse/read errors for files that were found.
    fn open_elf(path: &Path) -> Result<Option<ElfFile>> {
        let file = match ElfFile::from_path(path) {
            Ok(file) => file,
            Err(Error::Io(IoError::OpenFailed { .. })) => return Ok(None),
            Err(err) => return Err(err),
        };

        let mut magic = [0; 4];
        file.read(&mut magic, 0)?;
        if magic == *b"\x7fELF" {
            Ok(Some(file))
        } else {
            Err(ParseEhdrError::InvalidMagic.into())
        }
    }
}

enum ResolvedCandidate<LinkKey> {
    Existing(LinkKey),
    Load { key: LinkKey, file: ElfFile },
}

impl<'cfg, LinkKey, Arch, Tls, Rule> KeyResolver<'cfg, LinkKey, Arch, LinkKey, Tls>
    for SearchPathResolver<LinkKey, Rule>
where
    Rule: KeyRule<LinkKey>,
    LinkKey: Clone + AsRef<Path>,
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    fn load_root(
        &mut self,
        req: &RootRequest<'_, LinkKey>,
    ) -> Result<ResolvedKey<'cfg, LinkKey, Arch, Tls>> {
        let visible_key = |key: &LinkKey| req.visible_key(key);
        if let Some(resolved) =
            self.resolve_key(CandidateRequest::root(req.key().as_ref()), &visible_key)?
        {
            return Ok(match resolved {
                ResolvedCandidate::Existing(key) => ResolvedKey::existing(key),
                ResolvedCandidate::Load { key, file } => {
                    let visible_key = req.visible_key(&key);
                    Self::resolved_key(key, file, visible_key)
                }
            });
        }

        Err(LinkerError::resolver("root module was not found by SearchPathResolver").into())
    }

    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, LinkKey>,
    ) -> Result<ResolvedKey<'cfg, LinkKey, Arch, Tls>> {
        let origin = req.owner_path().parent();
        let needed = expand_origin(req.needed(), origin);
        let request = CandidateRequest::dependency(
            needed.as_path(),
            req.owner_name(),
            req.owner_path(),
            req.runpath(),
            req.rpath(),
        );
        let visible_key = |key: &LinkKey| req.visible_key(key);
        if let Some(resolved) = self.resolve_key(request, &visible_key)? {
            return Ok(match resolved {
                ResolvedCandidate::Existing(key) => ResolvedKey::existing(key),
                ResolvedCandidate::Load { key, file } => {
                    let visible_key = req.visible_key(&key);
                    Self::resolved_key(key, file, visible_key)
                }
            });
        }

        Err(req.unresolved())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NonCloneKey;
    struct NonCloneRule;

    #[test]
    fn search_path_resolver_clone_does_not_require_key_or_rule_clone() {
        fn assert_clone<T: Clone>() {}

        assert_clone::<SearchPathResolver<NonCloneKey, NonCloneRule>>();
    }
}
