use crate::{
    input::{Path, PathBuf},
    sync::Arc,
};
use alloc::{boxed::Box, collections::BTreeSet, string::String, vec::Vec};
use core::fmt;
use spin::Mutex;

pub(crate) type SharedDir = Arc<str>;

/// Shared storage for canonical module search directories.
///
/// Clones refer to the same directory set. A linker context uses one pool for
/// all of its modules, while a standalone loader run creates a private pool.
#[derive(Clone, Default)]
pub struct SearchPathPool {
    dirs: Arc<Mutex<BTreeSet<SharedDir>>>,
}

impl SearchPathPool {
    /// Creates an empty directory pool.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    fn expand(&self, value: &str, origin: &Path) -> Box<[SharedDir]> {
        if value.is_empty() {
            return Box::new([]);
        }
        let mut pool = self.dirs.lock();
        let mut dirs = Vec::new();
        for value in value.split(':') {
            let path = normalize_dir(if value.is_empty() {
                PathBuf::from(".")
            } else {
                expand_origin(value, origin)
            })
            .into_string();
            let dir = if let Some(dir) = pool.get(path.as_str()) {
                Arc::clone(dir)
            } else {
                let dir = Arc::from(path);
                pool.insert(Arc::clone(&dir));
                dir
            };
            if !dirs.iter().any(|existing| Arc::ptr_eq(existing, &dir)) {
                dirs.push(dir);
            }
        }
        dirs.into_boxed_slice()
    }
}

/// Filesystem identity and dynamic search metadata retained by a module.
///
/// `DT_RUNPATH` and `DT_RPATH` are expanded when this value is created. Their
/// directories are shared with other modules loaded through the same linker
/// context or loader run.
pub struct ModuleSearch {
    path: PathBuf,
    soname: Option<Box<str>>,
    runpath: Option<Box<[SharedDir]>>,
    rpath: Option<Box<[SharedDir]>>,
}

impl ModuleSearch {
    #[cfg(feature = "object")]
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            soname: None,
            runpath: None,
            rpath: None,
        }
    }

    /// Creates independently owned dynamic-section search metadata.
    ///
    /// Loader and linker paths use an internal shared pool so directories are
    /// also deduplicated across modules.
    pub(crate) fn from_dynamic(
        path: PathBuf,
        soname: Option<&str>,
        runpath: Option<&str>,
        rpath: Option<&str>,
    ) -> Self {
        Self::from_dynamic_in(path, soname, runpath, rpath, &SearchPathPool::default())
    }

    pub(crate) fn from_dynamic_in(
        path: PathBuf,
        soname: Option<&str>,
        runpath: Option<&str>,
        rpath: Option<&str>,
        paths: &SearchPathPool,
    ) -> Self {
        let origin = PathBuf::from(path.parent());
        let runpath = runpath.map(|value| paths.expand(value, origin.as_path()));
        let rpath = rpath.map(|value| paths.expand(value, origin.as_path()));
        Self {
            path,
            soname: soname.map(Box::from),
            runpath,
            rpath,
        }
    }

    /// Returns the module name used in diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        self.soname().unwrap_or_else(|| self.path.file_name())
    }

    /// Returns the module's loaded path.
    #[inline]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Returns `DT_SONAME`, if present.
    #[inline]
    pub fn soname(&self) -> Option<&str> {
        self.soname.as_deref()
    }

    /// Iterates over expanded `DT_RUNPATH` directories, if the tag is present.
    #[inline]
    pub fn runpath(&self) -> Option<impl ExactSizeIterator<Item = &Path>> {
        self.runpath
            .as_deref()
            .map(|dirs| dirs.iter().map(|dir| Path::new(dir.as_ref())))
    }

    /// Iterates over expanded `DT_RPATH` directories, if the tag is present.
    #[inline]
    pub fn rpath(&self) -> Option<impl ExactSizeIterator<Item = &Path>> {
        self.rpath
            .as_deref()
            .map(|dirs| dirs.iter().map(|dir| Path::new(dir.as_ref())))
    }

    #[inline]
    pub(crate) fn runpath_dirs(&self) -> Option<&[SharedDir]> {
        self.runpath.as_deref()
    }

    #[inline]
    pub(crate) fn rpath_dirs(&self) -> Option<&[SharedDir]> {
        self.rpath.as_deref()
    }
}

impl fmt::Debug for ModuleSearch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleSearch")
            .field("path", &self.path)
            .field("soname", &self.soname)
            .field("runpath", &self.runpath)
            .field("rpath", &self.rpath)
            .finish()
    }
}

fn origin_token(value: &str) -> Option<usize> {
    if value.starts_with("{ORIGIN}") {
        return Some("{ORIGIN}".len());
    }
    let rest = value.strip_prefix("ORIGIN")?;
    (!rest
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_'))
    .then_some("ORIGIN".len())
}

pub(crate) fn expand_origin(value: &str, origin: &Path) -> PathBuf {
    let mut expanded = String::with_capacity(value.len());
    let mut input = value;
    while let Some(pos) = input.find('$') {
        expanded.push_str(&input[..pos]);
        let token = &input[pos + 1..];
        if let Some(len) = origin_token(token) {
            expanded.push_str(origin.as_str());
            input = &token[len..];
        } else {
            expanded.push('$');
            input = token;
        }
    }
    expanded.push_str(input);
    PathBuf::from(expanded)
}

pub(crate) fn normalize_dir(path: PathBuf) -> PathBuf {
    let value = path.as_str();
    let bytes = value.as_bytes();
    let is_separator = |byte| byte == b'/' || byte == b'\\';
    let min_len = if bytes.len() >= 2 && is_separator(bytes[0]) && is_separator(bytes[1]) {
        2
    } else if bytes.first().is_some_and(|byte| is_separator(*byte)) {
        1
    } else if bytes.len() >= 3 && bytes[1] == b':' && is_separator(bytes[2]) {
        3
    } else {
        0
    };
    let mut len = bytes.len();
    while len > min_len && is_separator(bytes[len - 1]) {
        len -= 1;
    }
    if len == bytes.len() {
        path
    } else {
        PathBuf::from(&value[..len])
    }
}
