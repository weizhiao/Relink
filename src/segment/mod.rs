//! The Memory mapping of elf object
//!
//! This module provides functionality for mapping ELF segments into memory.
//! It handles the creation of memory segments, mapping them from file or
//! anonymous sources, and managing their protection and lifecycle.

mod layout;
mod mapping;
mod relro;
mod space;

pub(crate) mod program;

pub use layout::PAGE_SIZE;
pub use space::ElfSegments;

pub(crate) use layout::{MASK, align_up, rounddown, roundup};
pub(crate) use mapping::{Address, ElfSegment, FileMapInfo, SegmentBuilder};
pub(crate) use relro::ELFRelro;
pub(crate) use space::ElfMemoryBacking;
