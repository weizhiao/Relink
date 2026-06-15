use crate::input::Path;

/// Root-module resolution event emitted by the linker.
pub struct ResolveRootEvent<'a, K> {
    key: &'a K,
}

impl<'a, K> ResolveRootEvent<'a, K> {
    #[inline]
    pub(crate) const fn new(key: &'a K) -> Self {
        Self { key }
    }

    /// Returns the root key requested by the caller.
    #[inline]
    pub const fn key(&self) -> &'a K {
        self.key
    }
}

/// Dependency-resolution event emitted for one `DT_NEEDED` edge.
pub struct ResolveDependencyEvent<'a, K> {
    owner_key: &'a K,
    owner_name: &'a str,
    owner_path: &'a Path,
    needed: &'a str,
    needed_index: usize,
    rpath: Option<&'a str>,
    runpath: Option<&'a str>,
    interp: Option<&'a str>,
}

impl<'a, K> ResolveDependencyEvent<'a, K> {
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        owner_key: &'a K,
        owner_name: &'a str,
        owner_path: &'a Path,
        needed: &'a str,
        needed_index: usize,
        rpath: Option<&'a str>,
        runpath: Option<&'a str>,
        interp: Option<&'a str>,
    ) -> Self {
        Self {
            owner_key,
            owner_name,
            owner_path,
            needed,
            needed_index,
            rpath,
            runpath,
            interp,
        }
    }

    /// Returns the key of the module that owns this dependency edge.
    #[inline]
    pub const fn owner_key(&self) -> &'a K {
        self.owner_key
    }

    /// Returns the owner name used in diagnostics.
    #[inline]
    pub const fn owner_name(&self) -> &'a str {
        self.owner_name
    }

    /// Returns the owner path or caller-provided source identifier.
    #[inline]
    pub const fn owner_path(&self) -> &'a Path {
        self.owner_path
    }

    /// Returns the requested `DT_NEEDED` library name.
    #[inline]
    pub const fn needed(&self) -> &'a str {
        self.needed
    }

    /// Returns the index of this dependency in the owner's `DT_NEEDED` list.
    #[inline]
    pub const fn needed_index(&self) -> usize {
        self.needed_index
    }

    /// Returns the owner's `DT_RPATH`, if present.
    #[inline]
    pub const fn rpath(&self) -> Option<&'a str> {
        self.rpath
    }

    /// Returns the owner's `DT_RUNPATH`, if present.
    #[inline]
    pub const fn runpath(&self) -> Option<&'a str> {
        self.runpath
    }

    /// Returns the owner's `PT_INTERP` path, if present.
    #[inline]
    pub const fn interp(&self) -> Option<&'a str> {
        self.interp
    }
}
