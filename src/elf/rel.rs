//! ELF relocation-entry wrappers and Android packed relocation decoding.

use crate::{
    ByteRepr, Result,
    arch::NativeArch,
    error::RelocTableError,
    memory::{ImageMemory, ImageMemoryExt, VmAddr, VmOffset},
    relocation::RelocationArch,
};
use alloc::vec::Vec;
use core::fmt::{self, Display};

use super::{
    layout::{ElfLayout, NativeElfLayout},
    raw::{ElfRelRaw, ElfRelaRaw, ElfWord},
    shdr::ElfSectionType,
};

/// Semantic wrapper for the ELF relocation type encoded in `r_info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ElfRelocationType(u32);

impl ElfRelocationType {
    /// Creates a relocation type wrapper from a raw relocation number.
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw relocation number.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for ElfRelocationType {
    #[inline]
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<ElfRelocationType> for u32 {
    #[inline]
    fn from(value: ElfRelocationType) -> Self {
        value.raw()
    }
}

impl Display for ElfRelocationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<NativeArch as RelocationArch>::rel_type_to_str(*self))
    }
}

/// ELF RELR relocation entry.
#[repr(transparent)]
pub struct ElfRelr<L: ElfLayout = NativeElfLayout> {
    relr: L::Relr,
}

impl<L: ElfLayout> ElfRelr<L> {
    /// Returns the value of the relocation entry.
    #[inline]
    pub fn value(&self) -> usize {
        self.relr.to_usize()
    }
}

/// ELF RELA relocation entry.
#[repr(transparent)]
pub struct ElfRela<L: ElfLayout = NativeElfLayout> {
    rela: L::Rela,
}

impl<L: ElfLayout> ElfRela<L> {
    /// Wraps a raw layout relocation entry.
    #[inline]
    pub fn from_raw(rela: L::Rela) -> Self {
        Self { rela }
    }

    /// Returns the relocation type.
    #[inline]
    pub fn r_type(&self) -> ElfRelocationType {
        ElfRelocationType::new((self.rela.r_info() & L::REL_MASK) as u32)
    }

    /// Returns the symbol index.
    #[inline]
    pub fn r_symbol(&self) -> usize {
        self.rela.r_info() >> L::REL_BIT
    }

    /// Returns the relocation offset.
    #[inline]
    pub fn r_offset(&self) -> VmOffset {
        VmOffset::new(self.rela.r_offset())
    }

    /// Returns the relocation addend.
    #[inline]
    pub fn r_addend(&self) -> isize {
        self.rela.r_addend()
    }
}

/// ELF REL relocation entry.
#[repr(transparent)]
pub struct ElfRel<L: ElfLayout = NativeElfLayout> {
    rel: L::Rel,
}

impl<L: ElfLayout> ElfRel<L> {
    /// Returns the relocation type.
    #[inline]
    pub fn r_type(&self) -> ElfRelocationType {
        ElfRelocationType::new((self.rel.r_info() & L::REL_MASK) as u32)
    }

    /// Returns the symbol index.
    #[inline]
    pub fn r_symbol(&self) -> usize {
        self.rel.r_info() >> L::REL_BIT
    }

    /// Returns the relocation offset.
    #[inline]
    pub fn r_offset(&self) -> VmOffset {
        VmOffset::new(self.rel.r_offset())
    }
}

/// Common interface shared by ELF `REL` and `RELA` relocation entries.
pub trait ElfRelEntry<L: ElfLayout = NativeElfLayout> {
    /// Section type used by this relocation entry format.
    const SECTION_TYPE: ElfSectionType;

    /// Returns the relocation type number.
    fn r_type(&self) -> ElfRelocationType;
    /// Returns the symbol table index referenced by the relocation.
    fn r_symbol(&self) -> usize;
    /// Returns the relocation target offset.
    fn r_offset(&self) -> VmOffset;
    /// Reads the relocation addend, loading implicit addends from the relocation place.
    fn read_addend<Memory>(&self, memory: &Memory, place: VmAddr) -> Result<isize>
    where
        Memory: ImageMemory,
        L::Word: ByteRepr;
    /// Returns this entry as an explicit-addend relocation, when applicable.
    fn as_rela(&self) -> Option<&ElfRela<L>>;
    /// Returns this entry as an implicit-addend relocation, when applicable.
    fn as_rel(&self) -> Option<&ElfRel<L>>;
    /// Updates the relocation target offset.
    fn set_offset(&mut self, offset: VmOffset);
    /// Writes the relocation addend, storing implicit addends to the relocation place.
    fn write_addend<Memory>(&mut self, memory: &Memory, place: VmAddr, addend: isize) -> Result<()>
    where
        Memory: ImageMemory,
        L::Word: ByteRepr;

    /// Builds an entry from raw `r_offset`/`r_info`/`r_addend` fields, used when
    /// expanding Android packed relocations into plain entries.
    fn from_fields(r_offset: usize, r_info: usize, r_addend: isize) -> Self;
}

impl<L: ElfLayout> ElfRelEntry<L> for ElfRela<L> {
    const SECTION_TYPE: ElfSectionType = ElfSectionType::RELA;

    #[inline]
    fn from_fields(r_offset: usize, r_info: usize, r_addend: isize) -> Self {
        Self {
            rela: <L::Rela as ElfRelaRaw>::from_fields(r_offset, r_info, r_addend),
        }
    }

    #[inline]
    fn r_type(&self) -> ElfRelocationType {
        self.r_type()
    }

    #[inline]
    fn r_symbol(&self) -> usize {
        self.r_symbol()
    }

    #[inline]
    fn r_offset(&self) -> VmOffset {
        self.r_offset()
    }

    #[inline]
    fn read_addend<Memory>(&self, _memory: &Memory, _place: VmAddr) -> Result<isize>
    where
        Memory: ImageMemory,
        L::Word: ByteRepr,
    {
        Ok(ElfRela::r_addend(self))
    }

    #[inline]
    fn as_rela(&self) -> Option<&ElfRela<L>> {
        Some(self)
    }

    #[inline]
    fn as_rel(&self) -> Option<&ElfRel<L>> {
        None
    }

    #[inline]
    fn set_offset(&mut self, offset: VmOffset) {
        self.rela.set_r_offset(offset.get());
    }

    #[inline]
    fn write_addend<Memory>(
        &mut self,
        _memory: &Memory,
        _place: VmAddr,
        addend: isize,
    ) -> Result<()>
    where
        Memory: ImageMemory,
        L::Word: ByteRepr,
    {
        self.rela.set_r_addend(addend);
        Ok(())
    }
}

impl<L: ElfLayout> ElfRelEntry<L> for ElfRel<L> {
    #[inline]
    fn from_fields(r_offset: usize, r_info: usize, _r_addend: isize) -> Self {
        Self {
            rel: <L::Rel as ElfRelRaw>::from_fields(r_offset, r_info),
        }
    }
    const SECTION_TYPE: ElfSectionType = ElfSectionType::REL;

    #[inline]
    fn r_type(&self) -> ElfRelocationType {
        self.r_type()
    }

    #[inline]
    fn r_symbol(&self) -> usize {
        self.r_symbol()
    }

    #[inline]
    fn r_offset(&self) -> VmOffset {
        self.r_offset()
    }

    #[inline]
    fn read_addend<Memory>(&self, memory: &Memory, place: VmAddr) -> Result<isize>
    where
        Memory: ImageMemory,
        L::Word: ByteRepr,
    {
        let word = unsafe { memory.read_value::<L::Word>(place)? };
        Ok(word.to_usize() as isize)
    }

    #[inline]
    fn as_rela(&self) -> Option<&ElfRela<L>> {
        None
    }

    #[inline]
    fn as_rel(&self) -> Option<&ElfRel<L>> {
        Some(self)
    }

    #[inline]
    fn set_offset(&mut self, offset: VmOffset) {
        self.rel.set_r_offset(offset.get());
    }

    #[inline]
    fn write_addend<Memory>(&mut self, memory: &Memory, place: VmAddr, addend: isize) -> Result<()>
    where
        Memory: ImageMemory,
        L::Word: ByteRepr,
    {
        let word = L::Word::from_usize(addend as usize);
        unsafe { memory.write_value(place, word) }
    }
}

/// Relocation entry type selected by a target architecture.
pub type ElfRelType<Arch = NativeArch> = <Arch as RelocationArch>::Relocation;

const PACKED_MAGIC: &[u8; 4] = b"APS2";

const GROUPED_BY_INFO: usize = 1;
const GROUPED_BY_OFFSET_DELTA: usize = 2;
const GROUPED_BY_ADDEND: usize = 4;
const HAS_ADDEND: usize = 8;

/// Sign-extending LEB128 reader over a byte slice, matching bionic's
/// `sleb128_decoder` (used for every field of the packed stream).
struct Sleb128<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Sleb128<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read(&mut self) -> core::result::Result<isize, RelocTableError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = *self
                .bytes
                .get(self.pos)
                .ok_or(RelocTableError::PackedTruncated)?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && (byte & 0x40) != 0 {
                    value |= !((1u64 << shift) - 1);
                }
                return Ok(value as isize);
            }
            if shift >= 64 {
                return Err(RelocTableError::PackedLeb128Overflow);
            }
        }
    }
}

/// Expands a `DT_ANDROID_RELA` / `SHT_ANDROID_RELA` packed stream into plain entries.
///
/// The LEB128-encoded groups follow bionic's
/// `linker_reloc_iterators.h::for_all_packed_relocs` semantics.
pub(crate) fn decode_packed_rela<L: ElfLayout, R: ElfRelEntry<L>>(
    bytes: &[u8],
) -> core::result::Result<Vec<R>, RelocTableError> {
    let bytes = bytes
        .strip_prefix(PACKED_MAGIC as &[u8])
        .ok_or(RelocTableError::InvalidPackedHeader)?;
    let mut reader = Sleb128::new(bytes);
    let relocation_count = reader.read()? as usize;
    let mut offset = reader.read()? as usize;
    let mut addend: isize = 0;

    let mut relocations = Vec::with_capacity(relocation_count.min(1 << 20));
    while relocations.len() < relocation_count {
        // Group headers store any fields shared by all entries in the group.
        let group_size = reader.read()? as usize;
        let group_flags = reader.read()? as usize;
        let group_offset_delta = if group_flags & GROUPED_BY_OFFSET_DELTA != 0 {
            Some(reader.read()? as usize)
        } else {
            None
        };
        let group_info = if group_flags & GROUPED_BY_INFO != 0 {
            Some(reader.read()? as usize)
        } else {
            None
        };

        let has_addend = group_flags & HAS_ADDEND != 0;
        let grouped_addend = group_flags & GROUPED_BY_ADDEND != 0;
        if !has_addend {
            addend = 0;
        } else if grouped_addend {
            addend = addend.wrapping_add(reader.read()?);
        }

        // Offset and addend are cumulative across group boundaries.
        for _ in 0..group_size {
            if relocations.len() == relocation_count {
                return Err(RelocTableError::PackedGroupCountOverflow);
            }
            let offset_delta = match group_offset_delta {
                Some(delta) => delta,
                None => reader.read()? as usize,
            };
            offset = offset.wrapping_add(offset_delta);
            let info = match group_info {
                Some(info) => info,
                None => reader.read()? as usize,
            };
            if has_addend && !grouped_addend {
                addend = addend.wrapping_add(reader.read()?);
            }
            relocations.push(R::from_fields(offset, info, addend));
        }
    }
    Ok(relocations)
}
