//! ELF relocation-entry wrappers.

use crate::{arch::NativeArch, relocation::RelocationArch};

use super::{
    layout::{ElfLayout, NativeElfLayout},
    raw::{ElfRelRaw, ElfRelaRaw, ElfWord},
    types::{ElfRelocationType, ElfSectionType},
};

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
    pub fn r_offset(&self) -> usize {
        self.rela.r_offset()
    }

    /// Returns the relocation addend.
    #[inline]
    pub fn r_addend(&self, _base: usize) -> isize {
        self.rela.r_addend()
    }

    /// Sets the relocation offset.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.rela.set_r_offset(offset);
    }

    /// Sets the relocation addend.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    pub(crate) fn set_addend(&mut self, _base: usize, addend: isize) {
        self.rela.set_r_addend(addend);
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
    pub fn r_offset(&self) -> usize {
        self.rel.r_offset()
    }

    /// Returns the relocation addend.
    ///
    /// For REL entries, the addend is stored at the relocation offset.
    ///
    /// # Arguments
    /// * `base` - The base address to add to the offset.
    #[inline]
    pub fn r_addend(&self, base: usize) -> isize {
        let ptr = (self.r_offset() + base) as *const L::Word;
        unsafe { ptr.read_unaligned().to_usize() as isize }
    }

    /// Sets the relocation offset.
    /// This is used internally when adjusting relocation entries during loading.
    #[inline]
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.rel.set_r_offset(offset);
    }

    /// Sets the relocation addend.
    ///
    /// For REL entries, the addend is stored at the relocation offset.
    ///
    /// # Arguments
    /// * `base` - The base address to add to the offset.
    /// * `addend` - The new implicit addend value.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn set_addend(&mut self, base: usize, addend: isize) {
        let ptr = (self.r_offset() + base) as *mut L::Word;
        unsafe { ptr.write_unaligned(L::Word::from_usize(addend as usize)) };
    }
}

/// Common interface shared by ELF `REL` and `RELA` relocation entries.
pub trait ElfRelEntry<L: ElfLayout = NativeElfLayout> {
    /// Section type used by this relocation entry format.
    const SECTION_TYPE: ElfSectionType;
    /// Whether the addend is stored at the relocation target address.
    const HAS_IMPLICIT_ADDEND: bool;

    /// Returns the relocation type number.
    fn r_type(&self) -> ElfRelocationType;
    /// Returns the symbol table index referenced by the relocation.
    fn r_symbol(&self) -> usize;
    /// Returns the relocation target offset.
    fn r_offset(&self) -> usize;
    /// Returns the relocation addend, reading implicit addends relative to `base`.
    fn r_addend(&self, base: usize) -> isize;
    /// Updates the relocation target offset.
    fn set_offset(&mut self, offset: usize);
    /// Updates the relocation addend.
    fn set_addend(&mut self, base: usize, addend: isize);
}

impl<L: ElfLayout> ElfRelEntry<L> for ElfRela<L> {
    const SECTION_TYPE: ElfSectionType = ElfSectionType::RELA;
    const HAS_IMPLICIT_ADDEND: bool = false;

    #[inline]
    fn r_type(&self) -> ElfRelocationType {
        self.r_type()
    }

    #[inline]
    fn r_symbol(&self) -> usize {
        self.r_symbol()
    }

    #[inline]
    fn r_offset(&self) -> usize {
        self.r_offset()
    }

    #[inline]
    fn r_addend(&self, base: usize) -> isize {
        self.r_addend(base)
    }

    #[inline]
    fn set_offset(&mut self, offset: usize) {
        self.set_offset(offset);
    }

    #[inline]
    fn set_addend(&mut self, base: usize, addend: isize) {
        self.set_addend(base, addend);
    }
}

impl<L: ElfLayout> ElfRelEntry<L> for ElfRel<L> {
    const SECTION_TYPE: ElfSectionType = ElfSectionType::REL;
    const HAS_IMPLICIT_ADDEND: bool = true;

    #[inline]
    fn r_type(&self) -> ElfRelocationType {
        self.r_type()
    }

    #[inline]
    fn r_symbol(&self) -> usize {
        self.r_symbol()
    }

    #[inline]
    fn r_offset(&self) -> usize {
        self.r_offset()
    }

    #[inline]
    fn r_addend(&self, base: usize) -> isize {
        self.r_addend(base)
    }

    #[inline]
    fn set_offset(&mut self, offset: usize) {
        self.set_offset(offset);
    }

    #[inline]
    fn set_addend(&mut self, base: usize, addend: isize) {
        self.set_addend(base, addend);
    }
}

/// Relocation entry type selected by a target architecture.
pub type ElfRelType<Arch = NativeArch> = <Arch as RelocationArch>::Relocation;
