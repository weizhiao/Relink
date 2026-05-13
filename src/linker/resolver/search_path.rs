use super::{KeyResolver, ResolvedKey};
use crate::{
    Error, IoError, LinkerError, ParseEhdrError, Result,
    input::{ElfFile, ElfReader, Path, PathBuf},
    linker::{DependencyRequest, RootRequest},
    sync::Arc,
};
use alloc::vec::Vec;
use core::fmt;

/// Runtime directory provider used by [`SearchDirSource::Dynamic`].
///
/// Implementations append directories to `out` in the order they should be
/// searched for `request.requested()`.
pub type SearchDirProvider =
    dyn for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()> + 'static;

/// One ordered source of search directories.
#[derive(Clone)]
pub enum SearchDirSource {
    /// A fixed directory joined with the requested value when it has no
    /// directory separators.
    Fixed(PathBuf),
    /// A runtime directory source that can inspect the current request.
    Dynamic(Arc<SearchDirProvider>),
}

impl SearchDirSource {
    #[inline]
    pub fn fixed(dir: impl Into<PathBuf>) -> Self {
        Self::Fixed(dir.into())
    }

    #[inline]
    pub fn dynamic<F>(resolver: F) -> Self
    where
        F: for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()> + 'static,
    {
        Self::Dynamic(Arc::new(resolver))
    }
}

impl fmt::Debug for SearchDirSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed(dir) => f.debug_tuple("Fixed").field(dir).finish(),
            Self::Dynamic(_) => f.write_str("Dynamic(..)"),
        }
    }
}

/// Context passed to dynamic search directory providers.
#[derive(Clone, Copy, Debug)]
pub enum CandidateRequest<'a> {
    /// Resolving the root key passed to [`KeyResolver::load_root`].
    Root { requested: &'a Path },
    /// Resolving one `DT_NEEDED` entry for an already-loaded owner.
    Dependency {
        requested: &'a Path,
        owner_name: &'a str,
        origin: &'a Path,
        runpath: Option<&'a str>,
        rpath: Option<&'a str>,
    },
}

impl<'a> CandidateRequest<'a> {
    #[inline]
    pub const fn root(requested: &'a Path) -> Self {
        Self::Root { requested }
    }

    #[inline]
    pub const fn dependency(
        requested: &'a Path,
        owner_name: &'a str,
        origin: &'a Path,
        runpath: Option<&'a str>,
        rpath: Option<&'a str>,
    ) -> Self {
        Self::Dependency {
            requested,
            owner_name,
            origin,
            runpath,
            rpath,
        }
    }

    #[inline]
    pub const fn requested(&self) -> &'a Path {
        match self {
            Self::Root { requested } | Self::Dependency { requested, .. } => requested,
        }
    }

    #[inline]
    pub const fn owner_name(&self) -> Option<&'a str> {
        match self {
            Self::Root { .. } => None,
            Self::Dependency { owner_name, .. } => Some(owner_name),
        }
    }

    #[inline]
    pub const fn origin(&self) -> Option<&'a Path> {
        match self {
            Self::Root { .. } => None,
            Self::Dependency { origin, .. } => Some(origin),
        }
    }

    #[inline]
    pub const fn runpath(&self) -> Option<&'a str> {
        match self {
            Self::Root { .. } => None,
            Self::Dependency { runpath, .. } => *runpath,
        }
    }

    #[inline]
    pub const fn rpath(&self) -> Option<&'a str> {
        match self {
            Self::Root { .. } => None,
            Self::Dependency { rpath, .. } => *rpath,
        }
    }
}

/// Filesystem-backed dependency resolver for [`Linker`](crate::linker::Linker).
///
/// `SearchPathResolver` is an opt-in convenience resolver for callers whose
/// linker keys are [`PathBuf`]s. Root requests and dependencies with directory
/// separators are tried directly. Plain-name searches walk the ordered
/// [`SearchDirSource`] list.
///
/// This resolver intentionally does not model the host dynamic linker's global
/// policy: it does not read `LD_LIBRARY_PATH`, system cache files, or default
/// system library directories unless callers add runtime directory providers
/// for them.
pub struct SearchPathResolver {
    search_dir_sources: Vec<SearchDirSource>,
}

impl Clone for SearchPathResolver {
    fn clone(&self) -> Self {
        Self {
            search_dir_sources: self.search_dir_sources.clone(),
        }
    }
}

impl Default for SearchPathResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SearchPathResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchPathResolver")
            .field("search_dir_sources", &self.search_dir_sources)
            .finish()
    }
}

impl SearchPathResolver {
    #[inline]
    pub fn new() -> Self {
        Self {
            search_dir_sources: Vec::new(),
        }
    }

    pub fn push_search_dir_source(&mut self, source: SearchDirSource) -> &mut Self {
        self.search_dir_sources.push(source);
        self
    }

    pub fn push_fixed_dir(&mut self, dir: impl Into<PathBuf>) -> &mut Self {
        self.push_search_dir_source(SearchDirSource::Fixed(dir.into()))
    }

    pub fn push_search_dir_provider<F>(&mut self, provider: F) -> &mut Self
    where
        F: for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()> + 'static,
    {
        self.push_search_dir_source(SearchDirSource::Dynamic(Arc::new(provider)))
    }

    #[inline]
    pub fn search_dir_sources(&self) -> &[SearchDirSource] {
        &self.search_dir_sources
    }

    fn resolve_key(&self, request: CandidateRequest<'_>) -> Result<Option<(PathBuf, ElfFile)>> {
        let try_candidate = |candidate: PathBuf| -> Result<Option<(PathBuf, ElfFile)>> {
            let Some(file) = Self::open_elf(&candidate)? else {
                return Ok(None);
            };
            let key = match request {
                CandidateRequest::Root { requested } => PathBuf::from(requested),
                CandidateRequest::Dependency { .. } => candidate,
            };

            Ok(Some((key, file)))
        };

        let requested = request.requested();
        let has_dir_separator = requested.has_dir_separator();
        if matches!(request, CandidateRequest::Root { .. }) || has_dir_separator {
            if let Some(resolved) = try_candidate(PathBuf::from(requested))? {
                return Ok(Some(resolved));
            }
        }

        if has_dir_separator {
            return Ok(None);
        }

        let mut dynamic_dirs = Vec::new();
        for source in &self.search_dir_sources {
            match source {
                SearchDirSource::Fixed(dir) => {
                    if let Some(resolved) = try_candidate(dir.join(requested.as_str()))? {
                        return Ok(Some(resolved));
                    }
                }
                SearchDirSource::Dynamic(resolver) => {
                    dynamic_dirs.clear();
                    resolver(request, &mut dynamic_dirs)?;
                    for dir in &dynamic_dirs {
                        if let Some(resolved) = try_candidate(dir.join(requested.as_str()))? {
                            return Ok(Some(resolved));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    #[inline]
    fn resolved_key<'cfg>(
        key: PathBuf,
        file: ElfFile,
        is_visible: bool,
    ) -> ResolvedKey<'cfg, PathBuf> {
        if is_visible {
            ResolvedKey::existing(key)
        } else {
            ResolvedKey::load(key, file)
        }
    }

    /// Open `path` if it exists, returning `Ok(None)` for ordinary open
    /// failures and propagating parse/read errors for files that were found.
    fn open_elf(path: &Path) -> Result<Option<ElfFile>> {
        let mut file = match ElfFile::from_path(path) {
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

impl<'cfg> KeyResolver<'cfg, PathBuf> for SearchPathResolver {
    fn load_root(&mut self, req: &RootRequest<'_, PathBuf>) -> Result<ResolvedKey<'cfg, PathBuf>> {
        if let Some((key, file)) = self.resolve_key(CandidateRequest::root(req.key().as_path()))? {
            let is_visible = req.is_visible(&key);
            return Ok(Self::resolved_key(key, file, is_visible));
        }

        Err(LinkerError::resolver("root module was not found by SearchPathResolver").into())
    }

    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, PathBuf>,
    ) -> Result<ResolvedKey<'cfg, PathBuf>> {
        let owner = Path::new(req.owner_name());
        let origin = owner.origin_dir();
        let needed = Path::expand_origin(req.needed(), origin);
        let request = CandidateRequest::dependency(
            needed.as_path(),
            req.owner_name(),
            origin,
            req.runpath(),
            req.rpath(),
        );
        if let Some((key, file)) = self.resolve_key(request)? {
            let is_visible = req.is_visible(&key);
            return Ok(Self::resolved_key(key, file, is_visible));
        }

        Err(req.unresolved())
    }
}
