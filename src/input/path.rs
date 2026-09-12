use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::{borrow::Borrow, fmt, ops::Deref};

/// A string that can be part of a path.
///
/// This exists for compatibility with `std::ffi::OsStr` and must
/// contain UTF-8 or a superset of it.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
#[repr(transparent)]
pub struct PathStr([u8]);

impl PathStr {
    /// Creates a new path string from raw bytes.
    ///
    /// # Safety
    ///
    /// `bytes` must be either UTF-8 (`str`), or a superset of UTF-8 (`OsStr`).
    pub(crate) unsafe fn new(bytes: &[u8]) -> &Self {
        // `PathStr` is a transparent wrapper around `[u8]`, so the metadata and address are identical.
        unsafe { &*(bytes as *const [u8] as *const Self) }
    }

    /// Converts this path string to a byte slice.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<PathStr> for PathStr {
    fn as_ref(&self) -> &PathStr {
        self
    }
}

impl AsRef<PathStr> for str {
    fn as_ref(&self) -> &PathStr {
        // SAFETY: `self` is a UTF-8 string.
        unsafe { PathStr::new(self.as_bytes()) }
    }
}

impl AsRef<PathStr> for String {
    fn as_ref(&self) -> &PathStr {
        // SAFETY: `self` is a UTF-8 string.
        unsafe { PathStr::new(self.as_bytes()) }
    }
}

#[cfg(feature = "std")]
impl AsRef<PathStr> for std::ffi::OsStr {
    fn as_ref(&self) -> &PathStr {
        // SAFETY: `self` is a string that is a superset of UTF-8.
        unsafe { PathStr::new(self.as_encoded_bytes()) }
    }
}

#[cfg(feature = "std")]
impl AsRef<PathStr> for std::ffi::OsString {
    fn as_ref(&self) -> &PathStr {
        // SAFETY: `self` is a string that is a superset of UTF-8.
        unsafe { PathStr::new(self.as_encoded_bytes()) }
    }
}

impl AsRef<PathStr> for Path {
    fn as_ref(&self) -> &PathStr {
        &self.0
    }
}

impl AsRef<PathStr> for PathBuf {
    fn as_ref(&self) -> &PathStr {
        self.as_path().as_ref()
    }
}

/// Owned version of `PathStr`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PathString(Vec<u8>);

impl PathString {
    /// Creates an empty path string.
    pub(crate) const fn new() -> Self {
        Self(Vec::new())
    }

    /// Clears the string.
    fn clear(&mut self) {
        self.0.clear()
    }

    /// Reserves capacity for at least `additional` more bytes.
    pub(crate) fn reserve(&mut self, additional: usize) {
        self.0.reserve(additional)
    }

    /// Consumes `self` and returns its bytes.
    fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Extends `self` with `s`.
    pub(crate) fn push<P: AsRef<PathStr>>(&mut self, s: P) {
        self.0.extend_from_slice(s.as_ref().as_bytes());
    }
}

impl From<&PathStr> for PathString {
    fn from(s: &PathStr) -> Self {
        s.to_owned()
    }
}

impl AsRef<PathStr> for PathString {
    fn as_ref(&self) -> &PathStr {
        // SAFETY: `self` contains a UTF-8 string or a string that is a superset of UTF-8.
        unsafe { PathStr::new(self.0.as_slice()) }
    }
}

impl Borrow<PathStr> for PathString {
    fn borrow(&self) -> &PathStr {
        self.as_ref()
    }
}

impl ToOwned for PathStr {
    type Owned = PathString;

    fn to_owned(&self) -> Self::Owned {
        PathString(self.0.to_vec())
    }
}

impl Deref for PathString {
    type Target = PathStr;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

/// Borrowed ELF loader path.
///
/// `Path` is a small `no_std` path view used by file-backed inputs and
/// linker resolvers. It intentionally models only the path operations needed by
/// ELF loading and `DT_NEEDED` search, rather than the full `std::path::Path`
/// API.
#[derive(Ord, PartialOrd, Eq, PartialEq)] // FIXME: Implement comparison traits via `Components` like `std::path::Path`.
#[repr(transparent)]
pub struct Path(PathStr);

impl Path {
    /// Creates a borrowed loader path from a byte slice.
    #[inline]
    pub fn new<P: AsRef<PathStr> + ?Sized>(path: &P) -> &Self {
        // `Path` is a transparent wrapper around `PathStr`, so the metadata and address are identical.
        unsafe { &*(path.as_ref() as *const PathStr as *const Self) }
    }

    /// Converts this path to a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns whether the path contains `/` or `\`.
    #[inline]
    pub fn has_dir_separator(&self) -> bool {
        self.as_bytes().contains(&b'/') || self.as_bytes().contains(&b'\\')
    }

    #[cfg(not(windows))]
    #[inline]
    pub(crate) fn is_absolute(&self) -> bool {
        self.as_bytes().get(0) == Some(&b'/')
    }

    #[cfg(windows)]
    pub(crate) fn is_absolute(&self) -> bool {
        let bytes = self.as_bytes();
        let is_separator = |byte| byte == b'/' || byte == b'\\';
        (bytes.len() >= 2 && is_separator(bytes[0]) && is_separator(bytes[1]))
            || (bytes.len() >= 3 && bytes[1] == b':' && is_separator(bytes[2]))
    }

    /// Returns the parent directory used for `$ORIGIN` expansion.
    ///
    /// Paths without a directory separator return `"."`; paths directly under
    /// the filesystem root return `"/"`.
    pub fn parent(&self) -> &Self {
        let path = self.as_bytes();

        let slash = path.iter().rposition(|&x| x == b'/');
        let backslash = path.iter().rposition(|&x| x == b'\\');
        let Some(index) = slash.into_iter().chain(backslash).max() else {
            return Self::new(".");
        };

        // SAFTEY: `path` is split at a non-empty UTF-8 substring, so the preceding part is a valid path string.
        let parent = unsafe {
            PathStr::new(if index == 0 {
                &path[..1]
            } else {
                &path[..index]
            })
        };
        Self::new(parent)
    }

    /// Returns the last path component.
    pub fn file_name(&self) -> &[u8] {
        let path = self.as_bytes();
        let slash = path.iter().rposition(|&x| x == b'/');
        let backslash = path.iter().rposition(|&x| x == b'\\');
        let Some(index) = slash.into_iter().chain(backslash).max() else {
            return path;
        };
        &path[index + 1..]
    }

    /// Joins a child path or filename to this directory.
    pub fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        let mut path = PathBuf::default();
        path.set_joined(self, name.as_ref());
        path
    }
}

// Needed for `CString::new`.
impl From<&Path> for Vec<u8> {
    fn from(path: &Path) -> Self {
        path.as_bytes().to_vec()
    }
}

#[cfg(feature = "std")]
impl AsRef<Path> for std::path::Path {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(self.as_os_str())
    }
}

#[cfg(feature = "std")]
impl AsRef<Path> for std::path::PathBuf {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(self.as_os_str())
    }
}

impl AsRef<Path> for Path {
    #[inline]
    fn as_ref(&self) -> &Path {
        self
    }
}

impl fmt::Display for Path {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_bytes().escape_ascii().fmt(f)
    }
}

impl fmt::Debug for Path {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_bytes().escape_ascii().fmt(f)
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
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PathBuf(PathString);

impl PathBuf {
    /// Creates an owned loader path.
    #[inline]
    pub const fn new() -> Self {
        Self(PathString::new())
    }

    /// Returns this owned path as a borrowed [`Path`].
    #[inline]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Returns this path as its underlying bytes slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Consumes the path and returns the owned bytes.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    /// Extends `self` with `path`.
    pub fn push<P: AsRef<Path>>(&mut self, path: P) {
        self.0.push(path.as_ref());
    }

    pub(crate) fn set_joined(&mut self, dir: &Path, name: &Path) {
        self.0.clear();
        let dir_bytes = dir.as_bytes();
        let name_bytes = name.as_bytes();
        if dir_bytes.is_empty() || dir_bytes == b"." {
            self.0.push(name);
            return;
        }

        let needs_separator = !dir_bytes.ends_with(b"/") && !dir_bytes.ends_with(b"\\");
        self.0
            .reserve(dir_bytes.len() + usize::from(needs_separator) + name_bytes.len());
        self.0.push(dir);
        if needs_separator {
            self.0.push("/");
        }
        self.0.push(name);
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

impl fmt::Display for PathBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_path().fmt(f)
    }
}

impl Borrow<Path> for PathBuf {
    fn borrow(&self) -> &Path {
        self.as_ref()
    }
}

impl ToOwned for Path {
    type Owned = PathBuf;

    fn to_owned(&self) -> Self::Owned {
        PathBuf(self.0.to_owned())
    }
}

impl From<&PathStr> for PathBuf {
    #[inline]
    fn from(path: &PathStr) -> Self {
        Self(path.to_owned())
    }
}

impl From<PathString> for PathBuf {
    #[inline]
    fn from(path: PathString) -> Self {
        Self(path)
    }
}

impl From<String> for PathBuf {
    #[inline]
    fn from(path: String) -> Self {
        Self(PathString(path.into_bytes()))
    }
}

impl From<&str> for PathBuf {
    #[inline]
    fn from(path: &str) -> Self {
        Path::new(path).to_owned()
    }
}

impl From<&String> for PathBuf {
    #[inline]
    fn from(path: &String) -> Self {
        Path::new(path).to_owned()
    }
}

impl From<&Path> for PathBuf {
    #[inline]
    fn from(path: &Path) -> Self {
        Self(path.0.to_owned())
    }
}

impl From<&PathBuf> for PathBuf {
    #[inline]
    fn from(path: &PathBuf) -> Self {
        path.clone()
    }
}

impl From<PathBuf> for alloc::vec::Vec<u8> {
    #[inline]
    fn from(path: PathBuf) -> Self {
        path.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{Path, PathBuf};

    #[test]
    fn parent_falls_back_to_current_directory() {
        assert_eq!(Path::new("liba.so").parent().as_bytes(), b".");
        assert_eq!(Path::new("target/liba.so").parent().as_bytes(), b"target");
        assert_eq!(Path::new("/liba.so").parent().as_bytes(), b"/");
    }

    #[test]
    fn file_name_returns_last_component() {
        assert_eq!(Path::new("liba.so").file_name(), b"liba.so");
        assert_eq!(Path::new("target/liba.so").file_name(), b"liba.so");
        assert_eq!(Path::new("target\\liba.so").file_name(), b"liba.so");
    }

    #[test]
    fn join_avoids_duplicate_separators() {
        assert_eq!(
            Path::new("target").join("liba.so").as_bytes(),
            b"target/liba.so"
        );
        assert_eq!(
            Path::new("target/").join("liba.so").as_bytes(),
            b"target/liba.so"
        );
        assert_eq!(Path::new(".").join("liba.so").as_bytes(), b"liba.so");
    }

    #[test]
    fn owned_path_derefs_to_borrowed_path() {
        let path = PathBuf::from("target/liba.so");
        assert!(path.has_dir_separator());
        assert_eq!(path.parent().as_bytes(), b"target");
    }
}
