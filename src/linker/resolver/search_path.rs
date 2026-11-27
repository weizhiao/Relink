use super::request::LoaderVisitor;
use super::{
    KeyResolver, LdCache, ResolveInput, ResolveRequest, ResolvedKey, request::LoaderProvider,
};
use crate::{
    Error, IoError, ParseEhdrError, Result,
    image::{
        ModuleSearch, PathTokens, SharedDir, default_module_search, library_path_components,
        normalize_dir,
    },
    input::{BufferedElfFile, ElfReader, ModulePath, Path, PathBuf},
    loader::read_ehdr,
    os::path_is_dir,
    relocation::RelocationArch,
    sync::{Arc, arc_unsize},
};
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use core::fmt;

type PathProvider = dyn for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()>
    + Send
    + Sync
    + 'static;

type Opener = dyn Fn(&Path) -> Result<Box<dyn ElfReader>> + Send + Sync + 'static;

#[derive(Clone)]
enum SearchPathEntry {
    Rpath,
    Runpath,
    Dir(SharedDir),
    DirProvider(Arc<PathProvider>),
    CandidateProvider(Arc<PathProvider>),
}

impl SearchPathEntry {
    fn duplicates(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Rpath, Self::Rpath) | (Self::Runpath, Self::Runpath) => true,
            (Self::Dir(left), Self::Dir(right)) => left.as_ref() == right.as_ref(),
            _ => false,
        }
    }
}

impl fmt::Debug for SearchPathEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpath => f.write_str("Rpath"),
            Self::Runpath => f.write_str("Runpath"),
            Self::Dir(dir) => f.debug_tuple("Dir").field(dir).finish(),
            Self::DirProvider(_) => f.write_str("DirProvider(..)"),
            Self::CandidateProvider(_) => f.write_str("CandidateProvider(..)"),
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
    pub fn owner_name(&self) -> &'a [u8] {
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

impl fmt::Debug for CandidateRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateRequest")
            .field("requested", &self.requested)
            .field("owner", &self.owner)
            .finish()
    }
}

/// Search inputs for [`SearchPathResolver::with_config`].
/// Defaults to empty. Supply environment paths, cache contents, and target
/// library directories explicitly; no host settings are read automatically.
#[derive(Clone, Debug, Default)]
pub struct SearchConfig {
    library_path: Option<PathBuf>,
    cache: Option<LdCache>,
    default_dirs: Vec<PathBuf>,
}

impl SearchConfig {
    /// Creates a configuration with only module-owned RPATH and RUNPATH sources.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the raw `LD_LIBRARY_PATH` value.
    ///
    /// Both `:` and `;` separate directories; empty components mean the current
    /// working directory, while an entirely empty value adds no directories.
    /// `$ORIGIN` uses the main executable supplied to [`SearchPathResolver::with_config`].
    /// `$LIB` and `$PLATFORM` use the link context's [`SearchPathPool`](crate::image::SearchPathPool)
    /// token settings. Entries with unavailable token values are skipped.
    ///
    /// The caller must omit this input in secure-execution mode. This preset
    /// does not implement glibc's complete privileged-process loading policy.
    pub fn library_path(mut self, value: impl AsRef<Path>) -> Self {
        self.library_path = Some(value.as_ref().into());
        self
    }

    /// Sets a shared cache snapshot. Omit it when the target has no usable cache.
    pub fn cache(mut self, cache: LdCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Sets the final fallback directories in target-specific search order.
    ///
    /// These are literal directories, without dynamic token expansion. No
    /// architecture or distribution directory list is hard-coded by Relink.
    pub fn default_dirs<P: AsRef<Path>>(mut self, dirs: impl IntoIterator<Item = P>) -> Self {
        self.default_dirs = dirs.into_iter().map(|dir| dir.as_ref().into()).collect();
        self
    }
}

/// Finds dependencies using configured paths and [`LdCache`] snapshots.
///
/// Names containing directory separators are tried directly; other names use
/// the configured search order. No environment paths, caches, or system directories
/// are read automatically. [`Self::with_opener`] supports custom input sources.
///
/// Module RPATH/RUNPATH tokens are expanded by the loader. Missing absolute
/// directories are cached; relative directories and lookup results are not.
#[derive(Clone, Default)]
pub struct SearchPathResolver {
    entries: Vec<SearchPathEntry>,
    executable: Option<(ModulePath, Vec<SharedDir>)>,
    opener: Option<Arc<Opener>>,
}

impl fmt::Debug for SearchPathResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchPathResolver")
            .field("entries", &self.entries)
            .field("executable", &self.executable)
            .field("custom_opener", &self.opener.is_some())
            .finish()
    }
}

impl SearchPathResolver {
    /// Creates an empty search-path resolver.
    #[inline]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            executable: None,
            opener: None,
        }
    }

    /// Searches inherited RPATH, supplied executable RPATH, library paths, RUNPATH, cache,
    /// then default directories. Direct-loader RUNPATH suppresses inherited RPATH;
    /// names containing separators are opened directly.
    ///
    /// This ordering does not implement glibc's process namespace, hardware
    /// capabilities, `DF_1_NODEFLIB`, auditing, or secure-execution policy.
    ///
    /// `executable` supplies both fallback RPATH and the directory used for
    /// `$ORIGIN` in library paths. Supply the base namespace's main executable
    /// even when resolving another namespace. Its RPATH is ignored if it has
    /// RUNPATH. Expanded directories and their caches are shared with its metadata.
    pub fn with_config(executable: &ModuleSearch, config: SearchConfig) -> Self {
        let mut resolver = Self::new();
        let dirs = executable
            .rpath_dirs()
            .filter(|_| executable.runpath_dirs().is_none())
            .unwrap_or_default();
        resolver.executable = Some((executable.path().clone(), dirs.to_vec()));
        resolver.push_rpath();
        if let Some(value) = config.library_path {
            resolver.push_library_path(value, executable.path().parent());
        }
        resolver.push_runpath();
        if let Some(cache) = config.cache {
            resolver.push_ld_cache(cache);
        }
        for dir in config.default_dirs {
            resolver.push_fixed_dir(dir);
        }
        resolver
    }

    /// Uses a custom opener for every candidate, preserving search order and ELF validation.
    /// Disables filesystem fallback and directory-existence caching.
    ///
    /// Return [`crate::error::IoError::OpenFailed`] to skip an unavailable candidate.
    /// Other errors stop the search. Direct-path errors are always returned.
    pub fn with_opener<F>(mut self, opener: F) -> Self
    where
        F: Fn(&Path) -> Result<Box<dyn ElfReader>> + Send + Sync + 'static,
    {
        self.opener = Some(arc_unsize!(Arc::new(opener) => Opener));
        self
    }

    fn push_entry(&mut self, entry: SearchPathEntry) -> &mut Self {
        if self.entries.iter().any(|other| entry.duplicates(other)) {
            return self;
        }
        self.entries.push(entry);
        self
    }

    /// Appends inherited `DT_RPATH` directories.
    ///
    /// The direct loader is visited first, followed by its loader chain. The
    /// configured executable RPATH is tried next if not already visited. The
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
    pub fn push_fixed_dir(&mut self, dir: impl AsRef<Path>) -> &mut Self {
        self.push_entry(SearchPathEntry::Dir(SharedDir::new(normalize_dir(
            dir.as_ref().to_owned(),
        ))))
    }

    /// Appends the raw library-path value at this point in the search order.
    ///
    /// Parsing and token expansion follow [`SearchConfig::library_path`]. This
    /// allows custom policies to reuse the same environment-path semantics
    /// without adopting the full [`Self::with_config`] preset.
    pub fn push_library_path(
        &mut self,
        value: impl AsRef<Path>,
        executable_dir: impl AsRef<Path>,
    ) -> &mut Self {
        let origin = executable_dir.as_ref();
        for path in library_path_components(value.as_ref()) {
            if path.as_bytes().contains(&b'$') {
                let path = PathBuf::from(path);
                let origin = PathBuf::from(origin);
                self.push_search_dir_provider(move |request, dirs| {
                    if let Some(path) = request.tokens().expand(&path, &origin) {
                        dirs.push(path);
                    }
                    Ok(())
                });
            } else {
                self.push_fixed_dir(path);
            }
        }
        self
    }

    /// Appends generic library candidates from an explicit glibc cache snapshot.
    ///
    /// The snapshot is queried at this position in the search order. Candidate
    /// files are opened and checked against the selected relocation architecture.
    /// Missing or incompatible files are skipped. See [`LdCache`] for hardware
    /// capability and snapshot-lifetime semantics.
    pub fn push_ld_cache(&mut self, cache: LdCache) -> &mut Self {
        self.push_candidate_provider(move |request, candidates| {
            candidates.extend(
                cache
                    .candidates(request.requested().as_bytes())
                    .map(PathBuf::from),
            );
            Ok(())
        })
    }

    /// Appends a callback that can provide search directories per request.
    ///
    /// Provider results are treated as dynamic and are therefore not retained
    /// or negatively cached between requests.
    pub fn push_search_dir_provider<F>(&mut self, provider: F) -> &mut Self
    where
        F: for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()>
            + Send
            + Sync
            + 'static,
    {
        self.push_entry(SearchPathEntry::DirProvider(
            arc_unsize!(Arc::new(provider) => PathProvider),
        ))
    }

    /// Appends a callback that can provide complete file candidates per request.
    ///
    /// Candidates are opened in the order supplied and are not joined with the
    /// requested library name. This is suitable for sources such as
    /// `/etc/ld.so.cache` that have already selected an exact file path.
    pub fn push_candidate_provider<F>(&mut self, provider: F) -> &mut Self
    where
        F: for<'req> Fn(CandidateRequest<'req>, &mut Vec<PathBuf>) -> Result<()>
            + Send
            + Sync
            + 'static,
    {
        self.push_entry(SearchPathEntry::CandidateProvider(arc_unsize!(
            Arc::new(provider) => PathProvider
        )))
    }

    #[inline]
    fn is_incompatible(err: &Error) -> bool {
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

    /// Opens and validates a target-compatible ELF candidate.
    fn try_candidate<T>(
        &self,
        path: &Path,
        dir: Option<&SharedDir>,
        skip_incompatible: bool,
        incompatible: &mut Option<Error>,
        validate: &impl Fn(&dyn ElfReader) -> Result<T>,
    ) -> Result<Option<(Box<dyn ElfReader>, T)>> {
        let dir = dir.filter(|_| self.opener.is_none());
        let opened = match &self.opener {
            Some(open) => open(path),
            None => {
                BufferedElfFile::from_path(path).map(|file| Box::new(file) as Box<dyn ElfReader>)
            }
        };
        let file = match opened {
            Ok(file) => {
                if let Some(dir) = dir {
                    dir.mark_existing();
                }
                file
            }
            Err(err @ Error::Io(IoError::OpenFailed { .. })) => {
                if !skip_incompatible {
                    return Err(err);
                }
                if let Some(dir) = dir.filter(|dir| dir.needs_check()) {
                    if path_is_dir(dir.path()) {
                        dir.mark_existing();
                    } else {
                        dir.mark_missing();
                    }
                }
                return Ok(None);
            }
            Err(err) => return Err(err),
        };

        match validate(file.as_ref()) {
            Ok(value) => Ok(Some((file, value))),
            Err(err) if skip_incompatible && Self::is_incompatible(&err) => {
                incompatible.get_or_insert(err);
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    fn try_dir<T>(
        &self,
        dir: &SharedDir,
        requested: &Path,
        candidate: &mut PathBuf,
        incompatible: &mut Option<Error>,
        validate: &impl Fn(&dyn ElfReader) -> Result<T>,
    ) -> Result<Option<(Box<dyn ElfReader>, T)>> {
        if self.opener.is_none() && dir.is_missing() {
            return Ok(None);
        }
        candidate.set_joined(dir.path(), requested);
        self.try_candidate(candidate, Some(dir), true, incompatible, validate)
    }

    fn try_dirs<T>(
        &self,
        dirs: &[SharedDir],
        requested: &Path,
        candidate: &mut PathBuf,
        incompatible: &mut Option<Error>,
        validate: &impl Fn(&dyn ElfReader) -> Result<T>,
    ) -> Result<Option<(Box<dyn ElfReader>, T)>> {
        for dir in dirs {
            if let Some(file) = self.try_dir(dir, requested, candidate, incompatible, validate)? {
                return Ok(Some(file));
            }
        }
        Ok(None)
    }
    /// Open a root using the caller's search metadata and candidate validation.
    /// Handle existing modules and synthetic providers before calling this.
    /// Incompatible candidates are skipped for names; direct-path errors are returned.
    pub fn open_file(
        &self,
        root: impl Into<PathBuf>,
        search: Option<&ModuleSearch>,
        tokens: &PathTokens,
        validate: &impl Fn(&dyn ElfReader) -> Result<()>,
    ) -> Result<Box<dyn ElfReader>> {
        let loaders = |visitor: &mut LoaderVisitor<'_>| {
            search.map_or(Ok(()), |search| visitor(search).map(|_| ()))
        };
        let request = ResolveRequest::root(
            root.into(),
            search.unwrap_or_else(|| default_module_search()),
            tokens,
            &loaders,
        );
        self.search_file(request, validate).map(|(file, ())| file)
    }

    fn search_file<T>(
        &self,
        req: ResolveRequest<'_, PathBuf>,
        validate: &impl Fn(&dyn ElfReader) -> Result<T>,
    ) -> Result<(Box<dyn ElfReader>, T)> {
        let requested = match req.input() {
            ResolveInput::Root { root } => root.as_path(),
            ResolveInput::Dependency { needed } => {
                Path::from_elf_bytes(needed).ok_or_else(|| req.unresolved())?
            }
        };
        let request = CandidateRequest::new(requested, req.search(), req.tokens(), req.loaders());

        let mut incompatible = None;

        let requested_value = request.requested();
        let expanded = if requested_value.as_bytes().contains(&b'$') {
            let Some(expanded) = request.tokens().expand(requested_value, request.origin()) else {
                return Err(req.unresolved());
            };
            Some(expanded)
        } else {
            None
        };
        let requested = expanded
            .as_ref()
            .map_or_else(|| request.requested(), PathBuf::as_path);
        if requested.has_dir_separator() {
            return self
                .try_candidate(requested, None, false, &mut incompatible, validate)?
                .ok_or_else(|| req.unresolved());
        }

        let mut provided = Vec::new();
        let mut candidate = PathBuf::default();
        for entry in &self.entries {
            match entry {
                SearchPathEntry::Rpath => {
                    if request.owner().runpath_dirs().is_some() {
                        continue;
                    }
                    let mut found = None;
                    let mut visited_executable = false;
                    request.visit_loaders(|owner| {
                        let Some(dirs) = owner.rpath_dirs() else {
                            return Ok(true);
                        };
                        visited_executable |= self.executable.as_ref().is_some_and(|(path, _)| {
                            core::ptr::eq(owner.path().as_bytes(), path.as_bytes())
                        });
                        found = self.try_dirs(
                            dirs,
                            requested,
                            &mut candidate,
                            &mut incompatible,
                            validate,
                        )?;
                        Ok(found.is_none())
                    })?;
                    if let Some(file) = found {
                        return Ok(file);
                    }
                    if !visited_executable
                        && let Some((_, dirs)) = &self.executable
                        && let Some(file) = self.try_dirs(
                            dirs,
                            requested,
                            &mut candidate,
                            &mut incompatible,
                            validate,
                        )?
                    {
                        return Ok(file);
                    }
                }
                SearchPathEntry::Runpath => {
                    let Some(dirs) = request.owner().runpath_dirs() else {
                        continue;
                    };
                    if let Some(file) =
                        self.try_dirs(dirs, requested, &mut candidate, &mut incompatible, validate)?
                    {
                        return Ok(file);
                    }
                }
                SearchPathEntry::Dir(dir) => {
                    if let Some(file) =
                        self.try_dir(dir, requested, &mut candidate, &mut incompatible, validate)?
                    {
                        return Ok(file);
                    }
                }
                SearchPathEntry::DirProvider(provider) => {
                    provided.clear();
                    provider(request, &mut provided)?;
                    for dir in &provided {
                        candidate.set_joined(dir, requested);
                        if let Some(file) =
                            self.try_candidate(&candidate, None, true, &mut incompatible, validate)?
                        {
                            return Ok(file);
                        }
                    }
                }
                SearchPathEntry::CandidateProvider(provider) => {
                    provided.clear();
                    provider(request, &mut provided)?;
                    for candidate in &provided {
                        if let Some(file) =
                            self.try_candidate(candidate, None, true, &mut incompatible, validate)?
                        {
                            return Ok(file);
                        }
                    }
                }
            }
        }

        Err(incompatible.unwrap_or_else(|| req.unresolved()))
    }
}

impl<Arch> KeyResolver<Arch> for SearchPathResolver
where
    Arch: RelocationArch,
{
    type Root = PathBuf;

    #[inline]
    fn root_key<'a>(&self, root: &'a Self::Root) -> &'a [u8] {
        root.as_bytes()
    }

    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, Self::Root>,
    ) -> Result<ResolvedKey<'cfg, Arch>> {
        self.search_file(req, &|file| read_ehdr::<Arch>(file))
            .map(|(reader, ehdr)| ResolvedKey::load_with_ehdr(reader, ehdr))
    }
}
