use alloc::string::{String, ToString};
use core::{fmt, ops::Deref};

/// Borrowed ELF loader path.
///
/// `Path` is a small `no_std` path view used by file-backed inputs and
/// linker resolvers. It intentionally models only the path operations needed by
/// ELF loading and `DT_NEEDED` search, rather than the full `std::path::Path`
/// API.
#[repr(transparent)]
pub struct Path(str);

impl Path {
    #[inline]
    pub fn new(path: &str) -> &Self {
        // `Path` is a transparent wrapper around `str`, so the metadata and
        // address are identical.
        unsafe { &*(path as *const str as *const Self) }
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[inline]
    pub fn has_dir_separator(&self) -> bool {
        self.as_str().contains('/') || self.as_str().contains('\\')
    }

    pub fn origin_dir(&self) -> &Self {
        let path = self.as_str();
        let slash = path.rfind('/');
        let backslash = path.rfind('\\');
        let Some(index) = slash.into_iter().chain(backslash).max() else {
            return Self::new(".");
        };
        if index == 0 {
            Self::new(&path[..1])
        } else {
            Self::new(&path[..index])
        }
    }

    pub fn file_name(&self) -> &str {
        let path = self.as_str();
        let slash = path.rfind('/');
        let backslash = path.rfind('\\');
        let Some(index) = slash.into_iter().chain(backslash).max() else {
            return path;
        };
        &path[index + 1..]
    }

    pub fn join(&self, name: impl AsRef<str>) -> PathBuf {
        let dir = self.as_str();
        let name = name.as_ref();
        if dir.is_empty() || dir == "." {
            return PathBuf::from(name);
        }

        let needs_separator = !dir.ends_with('/') && !dir.ends_with('\\');
        let mut path = String::with_capacity(dir.len() + usize::from(needs_separator) + name.len());
        path.push_str(dir);
        if needs_separator {
            path.push('/');
        }
        path.push_str(name);
        PathBuf::from(path)
    }

    pub fn expand_origin(value: &str, origin: &Self) -> PathBuf {
        PathBuf::from(
            value
                .replace("${ORIGIN}", origin.as_str())
                .replace("$ORIGIN", origin.as_str()),
        )
    }
}

impl AsRef<Path> for Path {
    #[inline]
    fn as_ref(&self) -> &Path {
        self
    }
}

impl AsRef<str> for Path {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Path {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Path {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl AsRef<Path> for str {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for String {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

/// Owned ELF loader path.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PathBuf(String);

impl PathBuf {
    #[inline]
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    #[inline]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[inline]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Deref for PathBuf {
    type Target = Path;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_path()
    }
}

impl AsRef<Path> for PathBuf {
    #[inline]
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl AsRef<str> for PathBuf {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for PathBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<String> for PathBuf {
    #[inline]
    fn from(path: String) -> Self {
        Self(path)
    }
}

impl From<&str> for PathBuf {
    #[inline]
    fn from(path: &str) -> Self {
        Self(path.to_string())
    }
}

impl From<&String> for PathBuf {
    #[inline]
    fn from(path: &String) -> Self {
        Self(path.clone())
    }
}

impl From<&Path> for PathBuf {
    #[inline]
    fn from(path: &Path) -> Self {
        Self(path.as_str().to_string())
    }
}

impl From<&PathBuf> for PathBuf {
    #[inline]
    fn from(path: &PathBuf) -> Self {
        path.clone()
    }
}

impl From<PathBuf> for String {
    #[inline]
    fn from(path: PathBuf) -> Self {
        path.into_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{Path, PathBuf};

    #[test]
    fn origin_expansion_handles_common_forms() {
        let origin = Path::new("target");
        assert_eq!(Path::expand_origin("$ORIGIN", origin).as_str(), "target");
        assert_eq!(
            Path::expand_origin("${ORIGIN}/deps", origin).as_str(),
            "target/deps"
        );
    }

    #[test]
    fn origin_dir_falls_back_to_current_directory() {
        assert_eq!(Path::new("liba.so").origin_dir().as_str(), ".");
        assert_eq!(Path::new("target/liba.so").origin_dir().as_str(), "target");
        assert_eq!(Path::new("/liba.so").origin_dir().as_str(), "/");
    }

    #[test]
    fn file_name_returns_last_component() {
        assert_eq!(Path::new("liba.so").file_name(), "liba.so");
        assert_eq!(Path::new("target/liba.so").file_name(), "liba.so");
        assert_eq!(Path::new("target\\liba.so").file_name(), "liba.so");
    }

    #[test]
    fn join_avoids_duplicate_separators() {
        assert_eq!(
            Path::new("target").join("liba.so").as_str(),
            "target/liba.so"
        );
        assert_eq!(
            Path::new("target/").join("liba.so").as_str(),
            "target/liba.so"
        );
        assert_eq!(Path::new(".").join("liba.so").as_str(), "liba.so");
    }

    #[test]
    fn owned_path_derefs_to_borrowed_path() {
        let path = PathBuf::from("target/liba.so");
        assert!(path.has_dir_separator());
        assert_eq!(path.origin_dir().as_str(), "target");
    }
}
