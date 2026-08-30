use crate::{
    input::{Path, PathBuf},
    sync::{Arc, AtomicU8, Ordering},
};
use alloc::{boxed::Box, collections::BTreeSet, string::String, vec::Vec};
use core::{borrow::Borrow, cmp::Ordering as CmpOrdering, fmt, ops::Deref};

#[repr(u8)]
enum DirStatus {
    Unknown,
    Existing,
    Missing,
}

struct SearchDir {
    path: String,
    status: AtomicU8,
}

#[derive(Clone)]
pub(crate) struct SharedDir(Arc<SearchDir>);

impl SharedDir {
    pub(crate) fn new(path: String) -> Self {
        let status = if Path::new(&path).is_absolute() {
            DirStatus::Unknown
        } else {
            DirStatus::Existing
        };
        Self(Arc::new(SearchDir {
            path,
            status: AtomicU8::new(status as u8),
        }))
    }

    #[inline]
    pub(crate) fn path(&self) -> &Path {
        Path::new(&self.0.path)
    }

    #[inline]
    pub(crate) fn is_missing(&self) -> bool {
        self.0.status.load(Ordering::Relaxed) == DirStatus::Missing as u8
    }

    #[inline]
    pub(crate) fn needs_check(&self) -> bool {
        self.0.status.load(Ordering::Relaxed) == DirStatus::Unknown as u8
    }

    #[inline]
    pub(crate) fn mark_existing(&self) {
        self.0
            .status
            .store(DirStatus::Existing as u8, Ordering::Relaxed);
    }

    pub(crate) fn mark_missing(&self) {
        let _ = self.0.status.compare_exchange(
            DirStatus::Unknown as u8,
            DirStatus::Missing as u8,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
}

impl Deref for SharedDir {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0.path
    }
}

impl AsRef<str> for SharedDir {
    #[inline]
    fn as_ref(&self) -> &str {
        self
    }
}

impl Borrow<str> for SharedDir {
    #[inline]
    fn borrow(&self) -> &str {
        self
    }
}

impl PartialEq for SharedDir {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for SharedDir {}

impl PartialOrd for SharedDir {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for SharedDir {
    #[inline]
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl fmt::Debug for SharedDir {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self)
    }
}

#[derive(Clone, Default)]
pub(crate) struct PathTokens {
    lib: Option<Arc<str>>,
    platform: Option<Arc<str>>,
}

impl PathTokens {
    fn set_lib(&mut self, lib: impl AsRef<str>) {
        self.lib = Some(Arc::from(lib.as_ref()));
    }

    fn set_platform(&mut self, platform: impl AsRef<str>) {
        self.platform = Some(Arc::from(platform.as_ref()));
    }

    pub(crate) fn expand(&self, value: &str, origin: Option<&Path>) -> Option<PathBuf> {
        let mut expanded = String::with_capacity(value.len());
        let mut input = value;
        while let Some(pos) = input.find('$') {
            expanded.push_str(&input[..pos]);
            let token = &input[pos + 1..];
            let (len, replacement) = if let Some(len) = token_len(token, "ORIGIN") {
                (len, origin.map(Path::as_str))
            } else if let Some(len) = token_len(token, "LIB") {
                (len, self.lib.as_deref())
            } else if let Some(len) = token_len(token, "PLATFORM") {
                (len, self.platform.as_deref())
            } else {
                expanded.push('$');
                input = token;
                continue;
            };
            expanded.push_str(replacement?);
            input = &token[len..];
        }
        expanded.push_str(input);
        Some(PathBuf::from(expanded))
    }
}

/// Storage for canonical module search directories.
#[derive(Default)]
pub struct SearchPathPool {
    dirs: BTreeSet<SharedDir>,
    tokens: PathTokens,
}

impl SearchPathPool {
    /// Creates an empty directory pool.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the target ABI directory substituted for `$LIB` in dynamic paths.
    ///
    /// This describes the target filesystem layout and is intentionally not
    /// inferred from the host running Relink.
    pub fn set_lib(&mut self, lib: impl AsRef<str>) -> &mut Self {
        self.tokens.set_lib(lib);
        self
    }

    /// Sets the target runtime string substituted for `$PLATFORM` in dynamic paths.
    ///
    /// Native ELF loaders commonly obtain this value from `AT_PLATFORM`.
    pub fn set_platform(&mut self, platform: impl AsRef<str>) -> &mut Self {
        self.tokens.set_platform(platform);
        self
    }

    #[inline]
    pub(crate) fn tokens(&self) -> PathTokens {
        self.tokens.clone()
    }

    fn intern(dirs: &mut BTreeSet<SharedDir>, path: String) -> SharedDir {
        if let Some(dir) = dirs.get(path.as_str()) {
            return dir.clone();
        }
        let dir = SharedDir::new(path);
        dirs.insert(dir.clone());
        dir
    }

    pub(crate) fn module_search(
        &mut self,
        path: PathBuf,
        soname: Option<&str>,
        runpath: Option<&str>,
        rpath: Option<&str>,
    ) -> ModuleSearch {
        let Self { dirs, tokens } = self;
        ModuleSearch::from_dynamic_with(path, soname, runpath, rpath, tokens, |path| {
            Self::intern(dirs, path)
        })
    }
}

/// Dynamic search metadata retained by a module.
///
/// Dynamic string tokens in `DT_RUNPATH` and `DT_RPATH` are expanded when this
/// value is created. Their directories may be shared with other modules through
/// a [`SearchPathPool`].
pub struct ModuleSearch {
    path: PathBuf,
    soname: Option<Box<str>>,
    runpath: Option<Box<[SharedDir]>>,
    rpath: Option<Box<[SharedDir]>>,
}

pub(crate) static DEFAULT_MODULE_SEARCH: ModuleSearch = ModuleSearch::empty();

impl ModuleSearch {
    const fn empty() -> Self {
        Self {
            path: PathBuf::empty(),
            soname: None,
            runpath: None,
            rpath: None,
        }
    }

    #[cfg(feature = "object")]
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            soname: None,
            runpath: None,
            rpath: None,
        }
    }

    pub(crate) fn from_dynamic(
        path: PathBuf,
        soname: Option<&str>,
        runpath: Option<&str>,
        rpath: Option<&str>,
    ) -> Self {
        Self::from_dynamic_with(
            path,
            soname,
            runpath,
            rpath,
            &PathTokens::default(),
            SharedDir::new,
        )
    }

    fn from_dynamic_with(
        path: PathBuf,
        soname: Option<&str>,
        runpath: Option<&str>,
        rpath: Option<&str>,
        tokens: &PathTokens,
        mut intern: impl FnMut(String) -> SharedDir,
    ) -> Self {
        let origin = path.parent();
        let runpath = runpath.map(|value| expand_dirs(value, origin, tokens, &mut intern));
        let rpath = rpath.map(|value| expand_dirs(value, origin, tokens, &mut intern));
        Self {
            path,
            soname: soname.map(Box::from),
            runpath,
            rpath,
        }
    }

    /// Returns the loaded path's file name for diagnostics.
    #[inline]
    pub fn name(&self) -> &str {
        self.path.file_name()
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
            .map(|dirs| dirs.iter().map(SharedDir::path))
    }

    /// Iterates over expanded `DT_RPATH` directories, if the tag is present.
    #[inline]
    pub fn rpath(&self) -> Option<impl ExactSizeIterator<Item = &Path>> {
        self.rpath
            .as_deref()
            .map(|dirs| dirs.iter().map(SharedDir::path))
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

fn expand_dirs(
    value: &str,
    origin: &Path,
    tokens: &PathTokens,
    intern: &mut impl FnMut(String) -> SharedDir,
) -> Box<[SharedDir]> {
    if value.is_empty() {
        return Box::new([]);
    }
    let mut dirs = Vec::new();
    for value in value.split(':') {
        let Some(path) = (if value.is_empty() {
            Some(PathBuf::from("."))
        } else {
            tokens.expand(value, Some(origin))
        }) else {
            continue;
        };
        let path = normalize_dir(path).into_string();
        let dir = intern(path);
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs.into_boxed_slice()
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

fn token_len(value: &str, name: &str) -> Option<usize> {
    if value
        .strip_prefix('{')
        .is_some_and(|value| value.starts_with(name))
        && value.as_bytes().get(name.len() + 1) == Some(&b'}')
    {
        return Some(name.len() + 2);
    }
    let rest = value.strip_prefix(name)?;
    (!rest
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_'))
    .then_some(name.len())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirs_are_shared() {
        let mut paths = SearchPathPool::default();
        let first = paths.module_search(
            PathBuf::from("/opt/app/first.so"),
            None,
            Some("$ORIGIN/lib:$ORIGIN/lib/:/usr/lib/"),
            Some("/ignored"),
        );
        let second = paths.module_search(
            PathBuf::from("/opt/app/second.so"),
            None,
            Some("$ORIGIN/lib:/usr/lib"),
            None,
        );
        let first = first.runpath.as_deref().unwrap();
        let second = second.runpath.as_deref().unwrap();

        assert_eq!(first.len(), 2);
        assert_eq!(first[0].as_ref(), "/opt/app/lib");
        assert_eq!(first[1].as_ref(), "/usr/lib");
        assert!(Arc::ptr_eq(&first[0].0, &second[0].0));
        assert!(Arc::ptr_eq(&first[1].0, &second[1].0));
    }
}
