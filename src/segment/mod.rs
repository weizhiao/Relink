//! The Memory mapping of elf object
//!
//! This module provides functionality for mapping ELF segments into memory.
//! It handles the creation of memory segments, mapping them from file or
//! anonymous sources, and managing their protection and lifecycle.

mod defs;
mod layout;
mod mapping;
mod relro;
mod space;

pub(crate) mod program;

pub use space::ElfSegments;

pub(crate) use defs::{Address, ElfSegment, ElfSegmentBacking, ElfSegmentSlice, FileMapInfo};
pub(crate) use layout::{align_up, rounddown, roundup};
pub(crate) use mapping::SegmentBuilder;
pub(crate) use relro::ELFRelro;
