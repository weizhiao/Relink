use crate::{
    input::{Path, PathBuf},
    sync::Arc,
};
use alloc::{boxed::Box, collections::BTreeSet, string::String, vec::Vec};
use core::fmt;

pub(crate) type SharedDir = Arc<str>;

/// Storage for canonical module search directories.
#[derive(Default)]
pub struct SearchPathPool {
    dirs: BTreeSet<SharedDir>,
}

impl SearchPathPool {
    /// Creates an empty directory pool.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    fn intern(&mut self, path: String) -> SharedDir {
        if let Some(dir) = self.dirs.get(path.as_str()) {
            return Arc::clone(dir);
        }
        let dir = Arc::from(path);
        self.dirs.insert(Arc::clone(&dir));
        dir
    }

    pub(crate) fn module_search(
        &mut self,
        path: PathBuf,
        soname: Option<&str>,
        runpath: Option<&str>,
        rpath: Option<&str>,
    ) -> ModuleSearch {
        ModuleSearch::from_dynamic_with(path, soname, runpath, rpath, |path| self.intern(path))
    }
}

/// Filesystem identity and dynamic search metadata retained by a module.
///
/// `DT_RUNPATH` and `DT_RPATH` are expanded when this value is created. Their
/// directories may be shared with other modules through a [`SearchPathPool`].
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

    pub(crate) fn from_dynamic(
        path: PathBuf,
        soname: Option<&str>,
        runpath: Option<&str>,
        rpath: Option<&str>,
    ) -> Self {
        Self::from_dynamic_with(path, soname, runpath, rpath, Arc::from)
    }

    fn from_dynamic_with(
        path: PathBuf,
        soname: Option<&str>,
        runpath: Option<&str>,
        rpath: Option<&str>,
        mut intern: impl FnMut(String) -> SharedDir,
    ) -> Self {
        let origin = path.parent();
        let runpath = runpath.map(|value| expand_dirs(value, origin, &mut intern));
        let rpath = rpath.map(|value| expand_dirs(value, origin, &mut intern));
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
            .map(|dirs| dirs.iter().map(|dir| Path::new(dir.as_ref())))
    }

    /// Iterates over expanded `DT_RPATH` directories, if the tag is present.
    #[inline]
    pub fn rpath(&self) -> Option<impl ExactSizeIterator<Item = &Path>> {
        self.rpath
            .as_deref()
            .map(|dirs| dirs.iter().map(|dir| Path::new(dir.as_ref())))
    }
}

fn expand_dirs(
    value: &str,
    origin: &Path,
    intern: &mut impl FnMut(String) -> SharedDir,
) -> Box<[SharedDir]> {
    if value.is_empty() {
        return Box::new([]);
    }
    let mut dirs = Vec::new();
    for value in value.split(':') {
        let path = normalize_dir(if value.is_empty() {
            PathBuf::from(".")
        } else {
            expand_origin(value, origin)
        })
        .into_string();
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
        assert!(Arc::ptr_eq(&first[0], &second[0]));
        assert!(Arc::ptr_eq(&first[1], &second[1]));
    }
}
