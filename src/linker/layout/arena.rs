use crate::entity::entity_ref;

/// The packing policy used to place one memory class into physical arenas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutClassPolicy {
    page_size: usize,
    sharing: LayoutArenaSharing,
}

impl LayoutClassPolicy {
    /// Creates one class policy.
    #[inline]
    pub const fn new(page_size: usize, sharing: LayoutArenaSharing) -> Self {
        Self {
            page_size: if page_size == 0 { 1 } else { page_size },
            sharing,
        }
    }

    /// Returns the page size used for arenas in this class.
    #[inline]
    pub const fn page_size(self) -> usize {
        self.page_size
    }

    /// Returns whether arenas in this class may be shared across modules.
    #[inline]
    pub const fn sharing(self) -> LayoutArenaSharing {
        self.sharing
    }
}

/// The arena-packing policy used by section-placement passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutPackingPolicy {
    code: LayoutClassPolicy,
    read_only_data: LayoutClassPolicy,
    relocation_read_only_data: LayoutClassPolicy,
    writable_data: LayoutClassPolicy,
    thread_local_data: LayoutClassPolicy,
}

impl Default for LayoutPackingPolicy {
    #[inline]
    fn default() -> Self {
        Self::shared_huge_pages()
    }
}

impl LayoutPackingPolicy {
    const BASE_PAGE_SIZE: usize = 4 * 1024;
    const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

    /// Creates a packing policy from explicit per-class rules.
    #[inline]
    pub const fn new(
        code: LayoutClassPolicy,
        read_only_data: LayoutClassPolicy,
        relocation_read_only_data: LayoutClassPolicy,
        writable_data: LayoutClassPolicy,
        thread_local_data: LayoutClassPolicy,
    ) -> Self {
        Self {
            code,
            read_only_data,
            relocation_read_only_data,
            writable_data,
            thread_local_data,
        }
    }

    /// Returns a conservative base-page policy with private arenas.
    #[inline]
    pub const fn private_base_pages() -> Self {
        let base = LayoutClassPolicy::new(Self::BASE_PAGE_SIZE, LayoutArenaSharing::Private);
        Self::new(base, base, base, base, base)
    }

    /// Returns a hugepage-oriented policy for cross-module code and rodata packing.
    #[inline]
    pub const fn shared_huge_pages() -> Self {
        Self::new(
            LayoutClassPolicy::new(Self::HUGE_PAGE_SIZE, LayoutArenaSharing::Shared),
            LayoutClassPolicy::new(Self::HUGE_PAGE_SIZE, LayoutArenaSharing::Shared),
            LayoutClassPolicy::new(Self::BASE_PAGE_SIZE, LayoutArenaSharing::Private),
            LayoutClassPolicy::new(Self::BASE_PAGE_SIZE, LayoutArenaSharing::Private),
            LayoutClassPolicy::new(Self::BASE_PAGE_SIZE, LayoutArenaSharing::Private),
        )
    }

    /// Returns the packing rule for one memory class.
    #[inline]
    pub const fn class_policy(self, class: LayoutMemoryClass) -> LayoutClassPolicy {
        match class {
            LayoutMemoryClass::Code => self.code,
            LayoutMemoryClass::ReadOnlyData => self.read_only_data,
            LayoutMemoryClass::RelocationReadOnlyData => self.relocation_read_only_data,
            LayoutMemoryClass::WritableData => self.writable_data,
            LayoutMemoryClass::ThreadLocalData => self.thread_local_data,
        }
    }
}

/// One computed arena usage summary derived from section placements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutArenaUsage {
    section_count: usize,
    used_len: usize,
    mapped_len: usize,
}

impl LayoutArenaUsage {
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

/// One physical arena that can host sections from one or more modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayoutArena {
    page_size: usize,
    memory_class: LayoutMemoryClass,
    sharing: LayoutArenaSharing,
}

impl LayoutArena {
    /// Creates a new arena descriptor.
    #[inline]
    pub const fn new(
        page_size: usize,
        memory_class: LayoutMemoryClass,
        sharing: LayoutArenaSharing,
    ) -> Self {
        Self {
            page_size,
            memory_class,
            sharing,
        }
    }

    /// Returns the page size used by the arena.
    #[inline]
    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    /// Returns the memory class hosted by the arena.
    #[inline]
    pub const fn memory_class(&self) -> LayoutMemoryClass {
        self.memory_class
    }

    /// Returns whether the arena is module-private or shared.
    #[inline]
    pub const fn sharing(&self) -> LayoutArenaSharing {
        self.sharing
    }
}

/// A planner-assigned arena identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayoutArenaId(usize);
entity_ref!(LayoutArenaId);

/// Whether an arena is reserved for one module or shared across modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LayoutArenaSharing {
    /// The arena belongs to one module only.
    Private,
    /// The arena may host sections from multiple modules.
    Shared,
}

/// The high-level memory class of one layout section or arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LayoutMemoryClass {
    /// Executable code.
    Code,
    /// Read-only data that can stay read-only after materialization.
    ReadOnlyData,
    /// Data that starts writable and may later become read-only.
    RelocationReadOnlyData,
    /// Writable process-global data.
    WritableData,
    /// Thread-local data or zero-fill TLS storage.
    ThreadLocalData,
}
