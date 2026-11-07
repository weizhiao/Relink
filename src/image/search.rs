use crate::{
    input::{ModulePath, Path, PathBuf, PathStr, PathString},
    sync::{Arc, AtomicU8, OnceCell, Ordering},
};
use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};
use core::{borrow::Borrow, cmp::Ordering as CmpOrdering, fmt, ops::Deref};

#[repr(u8)]
enum DirStatus {
    Unknown,
    Existing,
    Missing,
}

struct SearchDir {
    path: PathBuf,
    status: AtomicU8,
}

#[derive(Clone)]
pub(crate) struct SharedDir(Arc<SearchDir>);

impl SharedDir {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();

        let status = if path.is_absolute() {
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
        &self.0.path
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
    type Target = Path;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0.path
    }
}

impl AsRef<Path> for SharedDir {
    #[inline]
    fn as_ref(&self) -> &Path {
        self
    }
}

impl Borrow<Path> for SharedDir {
    #[inline]
    fn borrow(&self) -> &Path {
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
        write!(f, r#""{}""#, self.as_bytes().escape_ascii())
    }
}

/// Target values used to expand dynamic search paths.
#[derive(Clone, Default)]
pub struct PathTokens {
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

    pub(crate) fn expand(&self, value: &Path, origin: &Path) -> Option<PathBuf> {
        let mut input = value.as_bytes();
        let mut expanded = PathString::new();
        expanded.reserve(input.len());
        while let Some(pos) = input.iter().position(|&x| x == b'$') {
            // SAFETY: `input` is split at a non-empty UTF-8 substring.
            expanded.push(unsafe { PathStr::new(&input[..pos]) });

            let token = &input[pos + 1..];
            let (len, replacement) = if let Some(len) = token_len(token, "ORIGIN") {
                (len, Some(origin))
            } else if let Some(len) = token_len(token, "LIB") {
                (len, self.lib.as_deref().map(|p| p.as_ref()))
            } else if let Some(len) = token_len(token, "PLATFORM") {
                (len, self.platform.as_deref().map(|p| p.as_ref()))
            } else {
                expanded.push("$");
                input = token;
                continue;
            };
            expanded.push(replacement?);
            input = &token[len..];
        }
        // SAFETY: `input` is split at a non-empty UTF-8 substring.
        expanded.push(unsafe { PathStr::new(input) });

        // SAFETY: `expanded` is created by replacing part a UTF-8 substring, so the result stays a UTF-8 string or superset.
        Some(PathBuf::from(expanded))
    }
}

pub(crate) fn library_path_components(value: &Path) -> impl Iterator<Item = &Path> {
    value
        .as_bytes()
        .split(|byte| matches!(byte, b':' | b';'))
        .filter(move |_| !value.as_bytes().is_empty())
        .filter_map(|component| {
            if component.is_empty() {
                Some(Path::new("."))
            } else {
                Path::from_elf_bytes(component)
            }
        })
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

    /// Expands a library path into directories using this context's target tokens.
    /// Uses the parsing and `$ORIGIN` rules of
    /// [`SearchConfig::library_path`](crate::linker::SearchConfig::library_path).
    pub fn library_path_dirs(
        &self,
        value: impl AsRef<Path>,
        executable_dir: impl AsRef<Path>,
    ) -> Vec<PathBuf> {
        library_path_components(value.as_ref())
            .filter_map(|path| self.tokens.expand(path, executable_dir.as_ref()))
            .collect()
    }

    /// Returns a snapshot of the configured path-token values.
    #[inline]
    pub fn tokens(&self) -> PathTokens {
        self.tokens.clone()
    }

    fn intern(dirs: &mut BTreeSet<SharedDir>, path: PathBuf) -> SharedDir {
        if let Some(dir) = dirs.get(path.as_path()) {
            return dir.clone();
        }
        let dir = SharedDir::new(path);
        dirs.insert(dir.clone());
        dir
    }

    /// Constructs search metadata from a module path and raw dynamic strings.
    ///
    /// `None` means the corresponding dynamic tag is absent; `Some(b"")`
    /// preserves an explicitly empty tag, including RUNPATH's RPATH suppression.
    /// `$ORIGIN` uses the path's parent directory. `$LIB` and `$PLATFORM` use
    /// this pool's configured values; paths requiring unavailable values are skipped.
    /// Expanded directories and their existence caches are shared within the pool.
    pub fn module_search(
        &mut self,
        path: ModulePath,
        soname: Option<&[u8]>,
        runpath: Option<&[u8]>,
        rpath: Option<&[u8]>,
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
    path: ModulePath,
    soname: Option<Box<[u8]>>,
    runpath: Option<Box<[SharedDir]>>,
    rpath: Option<Box<[SharedDir]>>,
}

pub(crate) fn default_module_search() -> &'static ModuleSearch {
    static DEFAULT: OnceCell<ModuleSearch> = OnceCell::new();
    DEFAULT.get_or_init(ModuleSearch::empty)
}

impl ModuleSearch {
    fn empty() -> Self {
        Self::from_dynamic(ModulePath::empty(), None, None, None)
    }

    pub(crate) fn from_dynamic(
        path: ModulePath,
        soname: Option<&[u8]>,
        runpath: Option<&[u8]>,
        rpath: Option<&[u8]>,
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
        path: ModulePath,
        soname: Option<&[u8]>,
        runpath: Option<&[u8]>,
        rpath: Option<&[u8]>,
        tokens: &PathTokens,
        mut intern: impl FnMut(PathBuf) -> SharedDir,
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
    pub fn name(&self) -> &[u8] {
        self.path.file_name()
    }

    /// Returns the module's shared, NUL-terminated loaded path.
    #[inline]
    pub fn path(&self) -> &ModulePath {
        &self.path
    }

    /// Returns `DT_SONAME`, if present.
    #[inline]
    pub fn soname(&self) -> Option<&[u8]> {
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
    value: &[u8],
    origin: &Path,
    tokens: &PathTokens,
    intern: &mut impl FnMut(PathBuf) -> SharedDir,
) -> Box<[SharedDir]> {
    if value.is_empty() {
        return Box::new([]);
    }
    let mut dirs = Vec::new();
    for value in value.split(|&byte| byte == b':') {
        let Some(path) = (if value.is_empty() {
            Some(PathBuf::from("."))
        } else {
            Path::from_elf_bytes(value).and_then(|path| tokens.expand(path, origin))
        }) else {
            continue;
        };
        let path = normalize_dir(path);
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

fn token_len(value: &[u8], name: &str) -> Option<usize> {
    if value.first() == Some(&b'{')
        && value.get(1..(1 + name.len())) == Some(name.as_bytes())
        && value.get(1 + name.len()) == Some(&b'}')
    {
        return Some(name.len() + 2);
    }

    let rest = if value.get(..name.len()) == Some(name.as_bytes()) {
        &value[name.len()..]
    } else {
        return None;
    };

    (!rest
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_'))
    .then_some(name.len())
}

pub(crate) fn normalize_dir(mut path: PathBuf) -> PathBuf {
    let bytes = path.as_bytes();
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
    path.trim_trailing_separators(min_len);
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_normalization_preserves_roots() {
        for (input, expected) in [
            ("", ""),
            ("/", "/"),
            ("///", "//"),
            (r"C:\", r"C:\"),
            (r"C:\\", r"C:\"),
            (r"\\server\share\\", r"\\server\share"),
            ("/opt/plugins///", "/opt/plugins"),
            ("plugins", "plugins"),
            ("插件/", "插件"),
        ] {
            let path = PathBuf::from(input);
            let normalized = normalize_dir(path);
            assert_eq!(normalized.as_bytes(), expected.as_bytes());
        }
    }

    #[test]
    fn dirs_are_shared() {
        let mut paths = SearchPathPool::default();
        let first = paths.module_search(
            ModulePath::try_from(PathBuf::from("/opt/app/first.so")).unwrap(),
            None,
            Some(b"$ORIGIN/lib:$ORIGIN/lib/:/usr/lib/"),
            Some(b"/ignored"),
        );
        let second = paths.module_search(
            ModulePath::try_from(PathBuf::from("/opt/app/second.so")).unwrap(),
            None,
            Some(b"$ORIGIN/lib:/usr/lib"),
            None,
        );
        let first = first.runpath.as_deref().unwrap();
        let second = second.runpath.as_deref().unwrap();

        assert_eq!(first.len(), 2);
        assert_eq!(first[0].as_bytes(), b"/opt/app/lib");
        assert_eq!(first[1].as_bytes(), b"/usr/lib");
        assert!(Arc::ptr_eq(&first[0].0, &second[0].0));
        assert!(Arc::ptr_eq(&first[1].0, &second[1].0));
    }
}
