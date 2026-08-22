use super::super::ModuleKey;
use super::{
    KeyResolver, ResolveInput, ResolveRequest, ResolvedKey,
    request::{LoaderProvider, LoaderVisitor},
};
use crate::{
    Error, IoError, ParseEhdrError, Result,
    image::{ModuleSearch, PathTokens, SharedDir, normalize_dir},
    input::{ElfFile, Path, PathBuf},
    loader::read_ehdr,
    relocation::RelocationArch,
    sync::{Arc, arc_unsize},
    tls::TlsResolver,
};
use alloc::vec::Vec;
use core::fmt;

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

impl fmt::Debug for CandidateRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateRequest")
            .field("requested", &self.requested)
            .field("owner", &self.owner)
            .finish()
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
#[derive(Clone, Default)]
pub struct SearchPathResolver {
    entries: Vec<SearchPathEntry>,
}

impl fmt::Debug for SearchPathResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchPathResolver")
            .field("entries", &self.entries)
            .finish()
    }
}

impl SearchPathResolver {
    /// Creates an empty search-path resolver.
    #[inline]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
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

    /// Opens and validates a target-compatible ELF candidate.
    fn open_elf<Arch: RelocationArch>(path: &Path) -> Result<Option<ElfFile>> {
        let file = match ElfFile::from_path(path) {
            Ok(file) => file,
            Err(Error::Io(IoError::OpenFailed { .. })) => return Ok(None),
            Err(err) => return Err(err),
        };

        read_ehdr::<Arch>(&file)?;
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

impl<Arch, Tls> KeyResolver<Arch, Tls> for SearchPathResolver
where
    Arch: RelocationArch,
    Tls: TlsResolver<Arch>,
{
    type Root = PathBuf;

    #[inline]
    fn root_key<'a>(&self, root: &'a Self::Root) -> &'a str {
        root.as_str()
    }

    fn resolve<'cfg>(
        &self,
        req: ResolveRequest<'_, Self::Root>,
    ) -> Result<ResolvedKey<'cfg, Arch, Tls>> {
        let requested = match req.input() {
            ResolveInput::Root { root } => root.as_path(),
            ResolveInput::Dependency { needed } => Path::new(needed),
        };
        let loaders = |visitor: &mut LoaderVisitor<'_>| req.visit_loaders(visitor);
        let request = CandidateRequest::new(requested, req.search(), req.tokens(), &loaders);

        let mut incompatible = None;
        let mut try_candidate = |candidate: &Path,
                                 continue_on_incompatible: bool|
         -> Result<Option<ResolvedKey<'cfg, Arch, Tls>>> {
            let file = match Self::open_elf::<Arch>(candidate) {
                Ok(Some(file)) => file,
                Ok(None) => return Ok(None),
                Err(err) if continue_on_incompatible && Self::is_incompatible_elf(&err) => {
                    incompatible.get_or_insert(err);
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };
            Ok(Some(ResolvedKey::load(ModuleKey::from(candidate), file)))
        };

        let requested_value = request.requested().as_str();
        let expanded = if requested_value.contains('$') {
            let Some(expanded) = request
                .tokens()
                .expand(requested_value, Some(request.origin()))
            else {
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
            return try_candidate(requested, false)?.ok_or_else(|| req.unresolved());
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
                            if let Some(value) = try_candidate(candidate.as_path(), true)? {
                                found = Some(value);
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    })?;
                    if let Some(found) = found {
                        return Ok(found);
                    }
                }
                SearchPathEntry::Runpath => {
                    let Some(dirs) = request.owner().runpath() else {
                        continue;
                    };
                    for dir in dirs {
                        candidate.set_joined(dir, requested.as_str());
                        if let Some(found) = try_candidate(candidate.as_path(), true)? {
                            return Ok(found);
                        }
                    }
                }
                SearchPathEntry::Dir(dir) => {
                    candidate.set_joined(Path::new(dir), requested.as_str());
                    if let Some(found) = try_candidate(candidate.as_path(), true)? {
                        return Ok(found);
                    }
                }
                SearchPathEntry::Dynamic(resolver) => {
                    dirs.clear();
                    resolver(request, &mut dirs)?;
                    for dir in &dirs {
                        candidate.set_joined(dir, requested.as_str());
                        if let Some(found) = try_candidate(candidate.as_path(), true)? {
                            return Ok(found);
                        }
                    }
                }
            }
        }

        match incompatible {
            Some(err) => Err(err),
            None => Err(req.unresolved()),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::arch::NativeArch;
    use std::{fs, path::Path as StdPath};

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

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(std::format!(
            "elf_loader_search_{name}_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn install_elf(path: &StdPath) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = std::env::current_exe().unwrap();
        if fs::hard_link(&source, path).is_err() {
            fs::copy(source, path).unwrap();
        }
    }

    fn resolve_path(
        resolver: &SearchPathResolver,
        request: CandidateRequest<'_>,
    ) -> Option<PathBuf> {
        let req = ResolveRequest::dependency(
            request.requested().as_str(),
            request.owner(),
            request.tokens(),
            request.loaders,
        );
        match <SearchPathResolver as KeyResolver<NativeArch>>::resolve(resolver, req) {
            Ok(ResolvedKey::Load { key, .. }) => Some(PathBuf::from(key.as_str())),
            Ok(_) | Err(_) => None,
        }
    }

    #[test]
    fn resolver_is_clone() {
        fn assert_clone<T: Clone>() {}

        assert_clone::<SearchPathResolver>();
    }

    #[test]
    fn fixed_dirs_are_shared_and_deduplicated() {
        let mut resolver = SearchPathResolver::new();
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
        let base = temp_dir("rpath_chain");
        let direct_path = base.join("middle");
        let root_path = base.join("root");
        let expected = base.join("lib/libleaf.so");
        install_elf(&expected);
        let direct = module_search(direct_path.to_str().unwrap(), None, None, None);
        let root = module_search(root_path.to_str().unwrap(), None, None, Some("$ORIGIN/lib"));
        let chain = [&direct, &root];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request = CandidateRequest::new(Path::new("libleaf.so"), &direct, &tokens, &loaders);
        let mut resolver = SearchPathResolver::new();
        resolver.push_rpath();

        assert_eq!(
            resolve_path(&resolver, request).unwrap().as_str(),
            expected.to_str().unwrap()
        );
    }

    #[test]
    fn expands_dependency_origin() {
        let base = temp_dir("dependency_origin");
        let owner_path = base.join("owner");
        let expected = base.join("libvalue.so");
        install_elf(&expected);
        let owner = module_search(owner_path.to_str().unwrap(), None, None, None);
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request =
            CandidateRequest::new(Path::new("$ORIGIN/libvalue.so"), &owner, &tokens, &loaders);
        let resolver = SearchPathResolver::new();

        assert_eq!(
            resolve_path(&resolver, request).unwrap().as_str(),
            expected.to_str().unwrap()
        );
    }

    #[test]
    fn expands_target_tokens() {
        let base = temp_dir("target_tokens");
        let owner_path = base.join("owner");
        let expected = base.join("lib64/target-v1/libleaf.so");
        install_elf(&expected);
        let mut paths = crate::image::SearchPathPool::new();
        paths.set_lib("lib64").set_platform("target-v1");
        let tokens = paths.tokens();
        let owner = paths.module_search(
            PathBuf::from(owner_path.to_str().unwrap()),
            None,
            Some("$ORIGIN/$LIB/${PLATFORM}"),
            None,
        );
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let request = CandidateRequest::new(Path::new("libleaf.so"), &owner, &tokens, &loaders);
        let mut resolver = SearchPathResolver::new();
        resolver.push_runpath();

        assert_eq!(
            resolve_path(&resolver, request).unwrap().as_str(),
            expected.to_str().unwrap()
        );
    }

    #[test]
    fn expands_tokens_in_dependency_name() {
        let base = temp_dir("dependency_tokens");
        let expected = base.join("target-v1/libleaf.so");
        install_elf(&expected);
        let owner = module_search("/app/owner", None, None, None);
        let mut paths = crate::image::SearchPathPool::new();
        paths
            .set_lib(base.to_str().unwrap())
            .set_platform("target-v1");
        let tokens = paths.tokens();
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let request = CandidateRequest::new(
            Path::new("$LIB/${PLATFORM}/libleaf.so"),
            &owner,
            &tokens,
            &loaders,
        );
        let resolver = SearchPathResolver::new();

        assert_eq!(
            resolve_path(&resolver, request).unwrap().as_str(),
            expected.to_str().unwrap()
        );
    }

    #[test]
    fn missing_target_token_discards_path() {
        let owner = module_search("/app/owner", None, Some("$ORIGIN/$PLATFORM"), None);
        let chain = [&owner];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request = CandidateRequest::new(Path::new("libleaf.so"), &owner, &tokens, &loaders);
        let mut resolver = SearchPathResolver::new();
        resolver.push_runpath();
        assert!(resolve_path(&resolver, request).is_none());
    }

    #[test]
    fn runpath_suppresses_rpath_chain() {
        let direct = module_search("/app/middle", None, Some(""), Some("/direct"));
        let root = module_search("/app/root", None, None, Some("/root"));
        let chain = [&direct, &root];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request = CandidateRequest::new(Path::new("libleaf.so"), &direct, &tokens, &loaders);
        let mut resolver = SearchPathResolver::new();
        resolver.push_rpath();
        assert!(resolve_path(&resolver, request).is_none());
    }

    #[test]
    fn rpath_and_runpath_have_independent_order() {
        let base = temp_dir("search_order");
        let fixed = base.join("fixed");
        let run = base.join("run");
        let fixed_candidate = fixed.join("libleaf.so");
        let run_candidate = run.join("libleaf.so");
        install_elf(&fixed_candidate);
        install_elf(&run_candidate);
        let direct = module_search("/app/middle", None, Some(run.to_str().unwrap()), None);
        let root = module_search("/app/root", None, None, Some("/unused"));
        let chain = [&direct, &root];
        let loaders = |visitor: &mut LoaderVisitor<'_>| visit_chain(&chain, visitor);
        let tokens = PathTokens::default();
        let request = CandidateRequest::new(Path::new("libleaf.so"), &direct, &tokens, &loaders);
        let mut resolver = SearchPathResolver::new();
        resolver.push_rpath();
        resolver.push_fixed_dir(fixed.to_str().unwrap());
        resolver.push_runpath();
        assert_eq!(
            resolve_path(&resolver, request).unwrap().as_str(),
            fixed_candidate.to_str().unwrap()
        );

        fs::remove_file(fixed_candidate).unwrap();
        assert_eq!(
            resolve_path(&resolver, request).unwrap().as_str(),
            run_candidate.to_str().unwrap()
        );
    }

    #[test]
    fn path_lists_preserve_current_directory() {
        let owner = module_search("/app/owner", None, Some(":/fallback"), None);
        assert_eq!(
            owner
                .runpath()
                .unwrap()
                .map(PathBuf::from)
                .collect::<Vec<_>>(),
            [PathBuf::from("."), PathBuf::from("/fallback")]
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
