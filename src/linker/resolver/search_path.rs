use super::{KeyResolver, ResolvedKey};
use crate::{
    Error, IoError, LinkerError, Result,
    input::{ElfFile, Path, PathBuf},
    linker::DependencyRequest,
};
use alloc::{string::String, vec::Vec};
use core::fmt;

/// Filesystem-backed dependency resolver for [`Linker`](crate::linker::Linker).
///
/// `SearchPathResolver` is an opt-in convenience resolver for callers whose
/// linker keys are path strings. The root key is opened as a path. Dependencies
/// are searched through the owner's `DT_RUNPATH`/`DT_RPATH` entries, with
/// `$ORIGIN` expanded from the owning object's file name, followed by any
/// explicitly configured search directories.
///
/// This resolver intentionally does not model the host dynamic linker's global
/// policy: it does not read `LD_LIBRARY_PATH`, system cache files, or default
/// system library directories.
#[derive(Default)]
pub struct SearchPathResolver {
    search_dirs: Vec<PathBuf>,
    candidates: Vec<PathBuf>,
}

impl Clone for SearchPathResolver {
    fn clone(&self) -> Self {
        Self {
            search_dirs: self.search_dirs.clone(),
            candidates: Vec::new(),
        }
    }
}

impl fmt::Debug for SearchPathResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchPathResolver")
            .field("search_dirs", &self.search_dirs)
            .finish()
    }
}

impl SearchPathResolver {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn with_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.push_dir(dir);
        self
    }

    pub fn push_dir(&mut self, dir: impl Into<PathBuf>) -> &mut Self {
        self.search_dirs.push(dir.into());
        self
    }

    #[inline]
    pub fn search_dirs(&self) -> &[PathBuf] {
        &self.search_dirs
    }

    fn prepare_root_candidates(&mut self, key: &str) {
        self.candidates.clear();
        self.candidates.push(PathBuf::from(key));
        if !Path::new(key).has_dir_separator() {
            for dir in &self.search_dirs {
                self.candidates.push(dir.join(key));
            }
        }
    }

    fn prepare_dependency_candidates<K: Clone>(&mut self, req: &DependencyRequest<'_, K>) {
        self.candidates.clear();
        let owner = Path::new(req.owner_name());
        let origin = owner.origin_dir();
        let needed = Path::expand_origin(req.needed(), origin);

        if needed.has_dir_separator() {
            self.candidates.push(needed);
            return;
        }

        if let Some(path_list) = req.runpath().or_else(|| req.rpath()) {
            for dir in path_list.split(':') {
                if dir.is_empty() {
                    continue;
                }
                let dir = Path::expand_origin(dir, origin);
                self.candidates.push(dir.join(needed.as_str()));
            }
        }
        for dir in &self.search_dirs {
            self.candidates.push(dir.join(needed.as_str()));
        }
    }
}

impl<'cfg> KeyResolver<'cfg, String> for SearchPathResolver {
    fn load_root(&mut self, key: &String) -> Result<ResolvedKey<'cfg, String>> {
        self.prepare_root_candidates(key);
        for candidate in &self.candidates {
            if let Some(file) = open_if_exists(&candidate)? {
                return Ok(ResolvedKey::load(key.clone(), file));
            }
        }

        Err(LinkerError::resolver("root module was not found by SearchPathResolver").into())
    }

    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, String>,
    ) -> Result<ResolvedKey<'cfg, String>> {
        self.prepare_dependency_candidates(req);
        for candidate in &self.candidates {
            if let Some(file) = open_if_exists(&candidate)? {
                return Ok(ResolvedKey::load(candidate.clone().into_string(), file));
            }
        }

        Err(req.unresolved())
    }
}

fn open_if_exists(path: &Path) -> Result<Option<ElfFile>> {
    match ElfFile::from_path(path) {
        Ok(file) => Ok(Some(file)),
        Err(Error::Io(IoError::OpenFailed { .. })) => Ok(None),
        Err(err) => Err(err),
    }
}
