//! ELF relocation-entry wrappers.

use crate::{
    ByteRepr, Result,
    arch::NativeArch,
    memory::{ImageMemory, ImageMemoryExt, VmAddr, VmOffset},
    relocation::RelocationArch,
};
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
}

impl<L: ElfLayout> ElfRelEntry<L> for ElfRela<L> {
    const SECTION_TYPE: ElfSectionType = ElfSectionType::RELA;

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
