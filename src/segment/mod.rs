//! The Memory mapping of elf object
//!
//! This module provides functionality for mapping ELF segments into memory.
//! It handles the creation of memory segments, mapping them from file or
//! anonymous sources, and managing their protection and lifecycle.

mod defs;
mod mapping;
mod space;
mod thp;

pub(crate) mod program;

pub use space::{ElfSegments, MappedRange};

pub(crate) use defs::{CopyRegion, ElfSegment, MemoryProtection, SegmentContent};
pub(crate) use mapping::{populate_segments, protect_segments};
