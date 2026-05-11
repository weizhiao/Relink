//! Section-header related ELF types
//!
//! This module contains section-header views used while scanning ELF sections.

use super::defs::{ElfLayout, ElfSectionFlags, ElfSectionType, ElfShdrRaw, NativeElfLayout};

/// ELF section header describing sections of the ELF file.
#[derive(Debug)]
#[repr(transparent)]
pub struct ElfShdr<L: ElfLayout = NativeElfLayout> {
    shdr: L::Shdr,
}

impl<L: ElfLayout> ElfShdr<L> {
    /// Returns the parsed ELF section type of this header.
    #[inline]
    pub fn section_type(&self) -> ElfSectionType {
        ElfSectionType::new(self.shdr.sh_type())
    }

    /// Returns the section name index (`sh_name`) field.
    #[inline]
    pub fn sh_name(&self) -> u32 {
        self.shdr.sh_name()
    }

    /// Returns the parsed ELF section flags of this header.
    #[inline]
    pub fn flags(&self) -> ElfSectionFlags {
        ElfSectionFlags::from_bits_retain(self.shdr.sh_flags())
    }

    /// Returns the section address (`sh_addr`) as a native-sized value.
    #[inline]
    pub fn sh_addr(&self) -> usize {
        self.shdr.sh_addr()
    }

    /// Returns the section file offset (`sh_offset`) as a native-sized value.
    #[inline]
    pub fn sh_offset(&self) -> usize {
        self.shdr.sh_offset()
    }

    /// Returns the section size (`sh_size`) as a native-sized value.
    #[inline]
    pub fn sh_size(&self) -> usize {
        self.shdr.sh_size()
    }

    /// Returns the section link (`sh_link`) field.
    #[inline]
    pub fn sh_link(&self) -> u32 {
        self.shdr.sh_link()
    }

    /// Returns the section info (`sh_info`) field.
    #[inline]
    pub fn sh_info(&self) -> u32 {
        self.shdr.sh_info()
    }

    /// Returns the section alignment (`sh_addralign`) as a native-sized value.
    #[inline]
    pub fn sh_addralign(&self) -> usize {
        self.shdr.sh_addralign()
    }

    /// Returns the section entry size (`sh_entsize`) as a native-sized value.
    #[inline]
    pub fn sh_entsize(&self) -> usize {
        self.shdr.sh_entsize()
    }

    /// Updates the section address (`sh_addr`) field.
    #[inline]
    #[cfg(feature = "object")]
    pub(crate) fn set_sh_addr(&mut self, addr: usize) {
        self.shdr.set_sh_addr(addr);
    }

    /// Adds an offset to the section address (`sh_addr`) field.
    #[inline]
    #[cfg(feature = "object")]
    pub(crate) fn add_sh_addr(&mut self, delta: usize) {
        self.shdr.add_sh_addr(delta);
    }

    /// Creates a new ELF section header with the specified parameters.
    ///
    /// # Arguments
    /// * `sh_name` - Section name string table index
    /// * `sh_type` - Section type (e.g., PROGBITS, SYMTAB, etc.)
    /// * `sh_flags` - Section flags (e.g., WRITE, ALLOC, EXECINSTR)
    /// * `sh_addr` - Address where section should be loaded
    /// * `sh_offset` - Offset of section in file
    /// * `sh_size` - Size of section in bytes
    /// * `sh_link` - Link to another section (interpretation depends on section type)
    /// * `sh_info` - Extra information (interpretation depends on section type)
    /// * `sh_addralign` - Address alignment constraint
    /// * `sh_entsize` - Size of each entry if section contains a table
    #[cfg(feature = "object")]
    pub(crate) fn new(
        sh_name: u32,
        sh_type: ElfSectionType,
        sh_flags: ElfSectionFlags,
        sh_addr: usize,
        sh_offset: usize,
        sh_size: usize,
        sh_link: u32,
        sh_info: u32,
        sh_addralign: usize,
        sh_entsize: usize,
    ) -> Self {
        let mut shdr: L::Shdr = unsafe { core::mem::zeroed() };
        shdr.set_sh_name(sh_name);
        shdr.set_sh_type(sh_type.raw());
        shdr.set_sh_flags(sh_flags.bits());
        shdr.set_sh_addr(sh_addr);
        shdr.set_sh_offset(sh_offset);
        shdr.set_sh_size(sh_size);
        shdr.set_sh_link(sh_link);
        shdr.set_sh_info(sh_info);
        shdr.set_sh_addralign(sh_addralign);
        shdr.set_sh_entsize(sh_entsize);
        Self { shdr }
    }
}

impl<L: ElfLayout> ElfShdr<L> {
    /// Returns a reference to the section content as a slice of the specified type.
    ///
    /// This method provides safe access to section data by interpreting the section
    /// as a contiguous array of elements of type `T`. The section must contain a table
    /// of fixed-size entries for this to be meaningful.
    ///
    /// # Safety
    /// The caller must ensure that the section actually contains valid data of type `T`
    /// and that the alignment and size constraints are met.
    ///
    /// # Panics
    /// Panics in debug builds if the element size doesn't match the section's entry size,
    /// if the section size is not divisible by the entry size, or if the address is not
    /// properly aligned.
    #[cfg(feature = "object")]
    pub(crate) fn content<T>(&self) -> &'static [T] {
        self.content_mut()
    }

    /// Returns a mutable reference to the section content as a slice of the specified type.
    ///
    /// This method provides mutable access to section data. Use with caution as it allows
    /// modification of the underlying ELF data.
    ///
    /// # Safety
    /// The caller must ensure that the section actually contains valid data of type `T`
    /// and that the alignment and size constraints are met. Modifying section data may
    /// corrupt the ELF file or cause runtime errors.
    ///
    /// # Panics
    /// Panics in debug builds if the element size doesn't match the section's entry size,
    /// if the section size is not divisible by the entry size, or if the address is not
    /// properly aligned.
    #[cfg(feature = "object")]
    pub(crate) fn content_mut<T>(&self) -> &'static mut [T] {
        let start = self.sh_addr();
        let len = self.sh_size() / self.sh_entsize();
        debug_assert!(core::mem::size_of::<T>() == self.sh_entsize());
        debug_assert!(self.sh_size().is_multiple_of(self.sh_entsize()));
        debug_assert!(self.sh_addr().is_multiple_of(self.sh_addralign()));
        unsafe { core::slice::from_raw_parts_mut(start as *mut T, len) }
    }
}
