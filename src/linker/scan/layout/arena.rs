use crate::{entity::entity_ref, os::PageSize};

/// The packing policy used to place one memory class into physical arenas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassPolicy {
    page_size: PageSize,
    sharing: ArenaSharing,
}

impl ClassPolicy {
    /// Creates one class policy.
    #[inline]
    pub const fn new(page_size: PageSize, sharing: ArenaSharing) -> Self {
        Self { page_size, sharing }
    }

    /// Returns the page size used for arenas in this class.
    #[inline]
    pub const fn page_size(self) -> PageSize {
        self.page_size
    }

    /// Returns whether arenas in this class may be shared across modules.
    #[inline]
    pub const fn sharing(self) -> ArenaSharing {
        self.sharing
    }
}

/// The arena-packing policy used by section-placement passes.
///
/// The policy is primarily organized by final page-table permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackingPolicy {
    code: ClassPolicy,
    read_only_data: ClassPolicy,
    writable_data: ClassPolicy,
    thread_local_data: ClassPolicy,
}

impl Default for PackingPolicy {
    #[inline]
    fn default() -> Self {
        Self::shared_huge_pages()
    }
}

impl PackingPolicy {
    /// Creates a packing policy from explicit per-class rules.
    #[inline]
    pub const fn new(
        code: ClassPolicy,
        read_only_data: ClassPolicy,
        writable_data: ClassPolicy,
        thread_local_data: ClassPolicy,
    ) -> Self {
        Self {
            code,
            read_only_data,
            writable_data,
            thread_local_data,
        }
    }

    /// Returns a conservative base-page policy with private arenas.
    #[inline]
    pub const fn private_base_pages() -> Self {
        let base = ClassPolicy::new(PageSize::Base, ArenaSharing::Private);
        Self::new(base, base, base, base)
    }

    /// Returns a hugepage-oriented policy for executable and read-only pages.
    #[inline]
    pub const fn shared_huge_pages() -> Self {
        Self::new(
            ClassPolicy::new(PageSize::Huge2MiB, ArenaSharing::Shared),
            ClassPolicy::new(PageSize::Huge2MiB, ArenaSharing::Shared),
            ClassPolicy::new(PageSize::Base, ArenaSharing::Private),
            ClassPolicy::new(PageSize::Base, ArenaSharing::Private),
        )
    }

    /// Returns the packing rule for one memory class.
    #[inline]
    pub const fn class_policy(self, class: MemoryClass) -> ClassPolicy {
        match class {
            MemoryClass::Code => self.code,
            MemoryClass::ReadOnlyData => self.read_only_data,
            MemoryClass::WritableData => self.writable_data,
            MemoryClass::ThreadLocalData => self.thread_local_data,
        }
    }
}

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
entity_ref!(ArenaId);

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
