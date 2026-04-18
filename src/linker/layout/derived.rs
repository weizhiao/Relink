use super::arena::LayoutArenaId;

/// A derived address inside one placed section arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LayoutAddress {
    arena: LayoutArenaId,
    offset: usize,
}

impl LayoutAddress {
    /// Creates a new address inside one arena.
    #[inline]
    pub const fn new(arena: LayoutArenaId, offset: usize) -> Self {
        Self { arena, offset }
    }

    /// Returns the destination arena.
    #[inline]
    pub const fn arena(self) -> LayoutArenaId {
        self.arena
    }

    /// Returns the arena-relative byte offset.
    #[inline]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Adds `delta` bytes to the current address.
    #[inline]
    pub fn checked_add(self, delta: usize) -> Option<Self> {
        self.offset.checked_add(delta).map(|offset| Self {
            arena: self.arena,
            offset,
        })
    }
}
