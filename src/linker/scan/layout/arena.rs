use crate::{entity::entity_ref, os::PageSize};

/// One computed arena usage summary derived from section placements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArenaUsage {
    section_count: usize,
    used_len: usize,
    mapped_len: usize,
}

impl ArenaUsage {
    #[inline]
    pub(crate) const fn new(section_count: usize, used_len: usize, mapped_len: usize) -> Self {
        Self {
            section_count,
            used_len,
            mapped_len,
        }
    }

    /// Returns the number of placed sections inside the arena.
    #[inline]
    pub const fn section_count(self) -> usize {
        self.section_count
    }

    /// Returns the highest occupied byte offset inside the arena.
    #[inline]
    pub const fn used_len(self) -> usize {
        self.used_len
    }

    /// Returns the arena length rounded up to its page size.
    #[inline]
    pub const fn mapped_len(self) -> usize {
        self.mapped_len
    }
}

/// Descriptor for one physical arena that can host sections from one or more modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArenaDescriptor {
    page_size: PageSize,
    memory_class: MemoryClass,
    sharing: ArenaSharing,
}

impl ArenaDescriptor {
    /// Creates a new arena descriptor.
    #[inline]
    pub const fn new(
        page_size: PageSize,
        memory_class: MemoryClass,
        sharing: ArenaSharing,
    ) -> Self {
        Self {
            page_size,
            memory_class,
            sharing,
        }
    }

    /// Returns the page size used by the arena.
    #[inline]
    pub const fn page_size(&self) -> PageSize {
        self.page_size
    }

    /// Returns the memory class hosted by the arena.
    #[inline]
    pub const fn memory_class(&self) -> MemoryClass {
        self.memory_class
    }

    /// Returns whether the arena is module-private or shared.
    #[inline]
    pub const fn sharing(&self) -> ArenaSharing {
        self.sharing
    }
}

/// A planner-assigned arena identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArenaId(usize);
entity_ref!(ArenaId, pub);

/// Whether an arena is reserved for one module or shared across modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArenaSharing {
    /// The arena belongs to one module only.
    Private,
    /// The arena may host sections from multiple modules.
    Shared,
}

/// The high-level memory class of one layout section or arena.
///
/// These classes are grouped by their final page-table permissions; TLS is
/// kept separate because it follows a different mapping model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryClass {
    /// Executable pages.
    Code,
    /// Read-only pages.
    ReadOnlyData,
    /// Writable pages.
    WritableData,
    /// Thread-local storage pages.
    ThreadLocalData,
}
