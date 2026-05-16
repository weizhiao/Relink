//! Raw ELF32/ELF64 access traits used by layout-generic wrappers.

pub trait ElfWord: Copy + 'static {
    const BITS: usize;

    fn from_usize(value: usize) -> Self;
    fn to_usize(self) -> usize;
    fn to_u64(self) -> u64;
}

impl ElfWord for u32 {
    const BITS: usize = u32::BITS as usize;

    #[inline]
    fn from_usize(value: usize) -> Self {
        value as Self
    }

    #[inline]
    fn to_usize(self) -> usize {
        self as usize
    }

    #[inline]
    fn to_u64(self) -> u64 {
        self as u64
    }
}

impl ElfWord for u64 {
    const BITS: usize = u64::BITS as usize;

    #[inline]
    fn from_usize(value: usize) -> Self {
        value as Self
    }

    #[inline]
    fn to_usize(self) -> usize {
        self as usize
    }

    #[inline]
    fn to_u64(self) -> u64 {
        self
    }
}

pub trait ElfEhdrRaw: 'static {
    fn e_ident(&self) -> &[u8; elf::abi::EI_NIDENT];
    fn e_type(&self) -> u16;
    fn e_machine(&self) -> u16;
    fn e_entry(&self) -> usize;
    fn e_phoff(&self) -> usize;
    fn e_shoff(&self) -> usize;
    fn e_phentsize(&self) -> usize;
    fn e_phnum(&self) -> usize;
    fn e_shentsize(&self) -> usize;
    fn e_shnum(&self) -> usize;
    fn e_shstrndx(&self) -> usize;
}

macro_rules! impl_ehdr_raw {
    ($ty:ty) => {
        impl ElfEhdrRaw for $ty {
            #[inline]
            fn e_ident(&self) -> &[u8; elf::abi::EI_NIDENT] {
                &self.e_ident
            }

            #[inline]
            fn e_type(&self) -> u16 {
                self.e_type
            }

            #[inline]
            fn e_machine(&self) -> u16 {
                self.e_machine
            }

            #[inline]
            fn e_entry(&self) -> usize {
                self.e_entry as usize
            }

            #[inline]
            fn e_phoff(&self) -> usize {
                self.e_phoff as usize
            }

            #[inline]
            fn e_shoff(&self) -> usize {
                self.e_shoff as usize
            }

            #[inline]
            fn e_phentsize(&self) -> usize {
                self.e_phentsize as usize
            }

            #[inline]
            fn e_phnum(&self) -> usize {
                self.e_phnum as usize
            }

            #[inline]
            fn e_shentsize(&self) -> usize {
                self.e_shentsize as usize
            }

            #[inline]
            fn e_shnum(&self) -> usize {
                self.e_shnum as usize
            }

            #[inline]
            fn e_shstrndx(&self) -> usize {
                self.e_shstrndx as usize
            }
        }
    };
}

impl_ehdr_raw!(elf::file::Elf32_Ehdr);
impl_ehdr_raw!(elf::file::Elf64_Ehdr);

pub trait ElfPhdrRaw: 'static {
    fn set_p_type(&mut self, value: u32);
    fn set_p_flags(&mut self, value: u32);
    fn set_p_offset(&mut self, value: usize);
    fn set_p_vaddr(&mut self, value: usize);
    fn set_p_paddr(&mut self, value: usize);
    fn set_p_filesz(&mut self, value: usize);
    fn set_p_memsz(&mut self, value: usize);
    fn set_p_align(&mut self, value: usize);

    fn p_type(&self) -> u32;
    fn p_flags(&self) -> u32;
    fn p_offset(&self) -> usize;
    fn p_vaddr(&self) -> usize;
    fn p_paddr(&self) -> usize;
    fn p_filesz(&self) -> usize;
    fn p_memsz(&self) -> usize;
    fn p_align(&self) -> usize;
}

macro_rules! impl_phdr_raw {
    ($ty:ty) => {
        impl ElfPhdrRaw for $ty {
            #[inline]
            fn set_p_type(&mut self, value: u32) {
                self.p_type = value;
            }

            #[inline]
            fn set_p_flags(&mut self, value: u32) {
                self.p_flags = value;
            }

            #[inline]
            fn set_p_offset(&mut self, value: usize) {
                self.p_offset = value as _;
            }

            #[inline]
            fn set_p_vaddr(&mut self, value: usize) {
                self.p_vaddr = value as _;
            }

            #[inline]
            fn set_p_paddr(&mut self, value: usize) {
                self.p_paddr = value as _;
            }

            #[inline]
            fn set_p_filesz(&mut self, value: usize) {
                self.p_filesz = value as _;
            }

            #[inline]
            fn set_p_memsz(&mut self, value: usize) {
                self.p_memsz = value as _;
            }

            #[inline]
            fn set_p_align(&mut self, value: usize) {
                self.p_align = value as _;
            }

            #[inline]
            fn p_type(&self) -> u32 {
                self.p_type
            }

            #[inline]
            fn p_flags(&self) -> u32 {
                self.p_flags
            }

            #[inline]
            fn p_offset(&self) -> usize {
                self.p_offset as usize
            }

            #[inline]
            fn p_vaddr(&self) -> usize {
                self.p_vaddr as usize
            }

            #[inline]
            fn p_paddr(&self) -> usize {
                self.p_paddr as usize
            }

            #[inline]
            fn p_filesz(&self) -> usize {
                self.p_filesz as usize
            }

            #[inline]
            fn p_memsz(&self) -> usize {
                self.p_memsz as usize
            }

            #[inline]
            fn p_align(&self) -> usize {
                self.p_align as usize
            }
        }
    };
}

impl_phdr_raw!(elf::segment::Elf32_Phdr);
impl_phdr_raw!(elf::segment::Elf64_Phdr);

#[cfg_attr(not(feature = "object"), allow(dead_code))]
pub trait ElfShdrRaw: 'static {
    fn set_sh_name(&mut self, value: u32);
    fn set_sh_type(&mut self, value: u32);
    fn set_sh_flags(&mut self, value: u64);
    fn set_sh_addr(&mut self, value: usize);
    fn add_sh_addr(&mut self, value: usize);
    fn set_sh_offset(&mut self, value: usize);
    fn set_sh_size(&mut self, value: usize);
    fn set_sh_link(&mut self, value: u32);
    fn set_sh_info(&mut self, value: u32);
    fn set_sh_addralign(&mut self, value: usize);
    fn set_sh_entsize(&mut self, value: usize);

    fn sh_name(&self) -> u32;
    fn sh_type(&self) -> u32;
    fn sh_flags(&self) -> u64;
    fn sh_addr(&self) -> usize;
    fn sh_offset(&self) -> usize;
    fn sh_size(&self) -> usize;
    fn sh_link(&self) -> u32;
    fn sh_info(&self) -> u32;
    fn sh_addralign(&self) -> usize;
    fn sh_entsize(&self) -> usize;
}

macro_rules! impl_shdr_raw {
    ($ty:ty) => {
        impl ElfShdrRaw for $ty {
            #[inline]
            fn set_sh_name(&mut self, value: u32) {
                self.sh_name = value;
            }

            #[inline]
            fn set_sh_type(&mut self, value: u32) {
                self.sh_type = value;
            }

            #[inline]
            fn set_sh_flags(&mut self, value: u64) {
                self.sh_flags = value as _;
            }

            #[inline]
            fn set_sh_addr(&mut self, value: usize) {
                self.sh_addr = value as _;
            }

            #[inline]
            fn add_sh_addr(&mut self, value: usize) {
                self.sh_addr = self.sh_addr.wrapping_add(value as _);
            }

            #[inline]
            fn set_sh_offset(&mut self, value: usize) {
                self.sh_offset = value as _;
            }

            #[inline]
            fn set_sh_size(&mut self, value: usize) {
                self.sh_size = value as _;
            }

            #[inline]
            fn set_sh_link(&mut self, value: u32) {
                self.sh_link = value;
            }

            #[inline]
            fn set_sh_info(&mut self, value: u32) {
                self.sh_info = value;
            }

            #[inline]
            fn set_sh_addralign(&mut self, value: usize) {
                self.sh_addralign = value as _;
            }

            #[inline]
            fn set_sh_entsize(&mut self, value: usize) {
                self.sh_entsize = value as _;
            }

            #[inline]
            fn sh_name(&self) -> u32 {
                self.sh_name
            }

            #[inline]
            fn sh_type(&self) -> u32 {
                self.sh_type
            }

            #[inline]
            fn sh_flags(&self) -> u64 {
                self.sh_flags as u64
            }

            #[inline]
            fn sh_addr(&self) -> usize {
                self.sh_addr as usize
            }

            #[inline]
            fn sh_offset(&self) -> usize {
                self.sh_offset as usize
            }

            #[inline]
            fn sh_size(&self) -> usize {
                self.sh_size as usize
            }

            #[inline]
            fn sh_link(&self) -> u32 {
                self.sh_link
            }

            #[inline]
            fn sh_info(&self) -> u32 {
                self.sh_info
            }

            #[inline]
            fn sh_addralign(&self) -> usize {
                self.sh_addralign as usize
            }

            #[inline]
            fn sh_entsize(&self) -> usize {
                self.sh_entsize as usize
            }
        }
    };
}

impl_shdr_raw!(elf::section::Elf32_Shdr);
impl_shdr_raw!(elf::section::Elf64_Shdr);

pub trait ElfDynRaw: 'static {
    fn set_d_tag(&mut self, value: i64);
    fn set_d_un(&mut self, value: usize);
    fn d_tag(&self) -> i64;
    fn d_un(&self) -> usize;
}

macro_rules! impl_dyn_raw {
    ($ty:ty) => {
        impl ElfDynRaw for $ty {
            #[inline]
            fn set_d_tag(&mut self, value: i64) {
                self.d_tag = value as _;
            }

            #[inline]
            fn set_d_un(&mut self, value: usize) {
                self.d_un = value as _;
            }

            #[inline]
            fn d_tag(&self) -> i64 {
                self.d_tag as i64
            }

            #[inline]
            fn d_un(&self) -> usize {
                self.d_un as usize
            }
        }
    };
}

impl_dyn_raw!(elf::dynamic::Elf32_Dyn);
impl_dyn_raw!(elf::dynamic::Elf64_Dyn);

pub trait ElfRelRaw: 'static {
    fn set_r_offset(&mut self, value: usize);
    fn r_offset(&self) -> usize;
    fn r_info(&self) -> usize;
}

macro_rules! impl_rel_raw {
    ($ty:ty) => {
        impl ElfRelRaw for $ty {
            #[inline]
            fn set_r_offset(&mut self, value: usize) {
                self.r_offset = value as _;
            }

            #[inline]
            fn r_offset(&self) -> usize {
                self.r_offset as usize
            }

            #[inline]
            fn r_info(&self) -> usize {
                self.r_info as usize
            }
        }
    };
}

impl_rel_raw!(elf::relocation::Elf32_Rel);
impl_rel_raw!(elf::relocation::Elf64_Rel);

pub trait ElfRelaRaw: ElfRelRaw {
    fn set_r_addend(&mut self, value: isize);
    fn r_addend(&self) -> isize;
}

macro_rules! impl_rela_raw {
    ($ty:ty) => {
        impl ElfRelRaw for $ty {
            #[inline]
            fn set_r_offset(&mut self, value: usize) {
                self.r_offset = value as _;
            }

            #[inline]
            fn r_offset(&self) -> usize {
                self.r_offset as usize
            }

            #[inline]
            fn r_info(&self) -> usize {
                self.r_info as usize
            }
        }

        impl ElfRelaRaw for $ty {
            #[inline]
            fn set_r_addend(&mut self, value: isize) {
                self.r_addend = value as _;
            }

            #[inline]
            fn r_addend(&self) -> isize {
                self.r_addend as isize
            }
        }
    };
}

impl_rela_raw!(elf::relocation::Elf32_Rela);
impl_rela_raw!(elf::relocation::Elf64_Rela);

pub trait ElfSymRaw: Send + Sync + 'static {
    fn from_fields(
        st_name: usize,
        st_value: usize,
        st_size: usize,
        st_info: u8,
        st_other: u8,
        st_shndx: u16,
    ) -> Self;
    fn st_name(&self) -> usize;
    fn st_value(&self) -> usize;
    fn set_st_value(&mut self, value: usize);
    fn st_size(&self) -> usize;
    fn st_info(&self) -> u8;
    fn st_other(&self) -> u8;
    fn st_shndx(&self) -> u16;
}

macro_rules! impl_sym_raw {
    ($ty:ty) => {
        impl ElfSymRaw for $ty {
            #[inline]
            fn from_fields(
                st_name: usize,
                st_value: usize,
                st_size: usize,
                st_info: u8,
                st_other: u8,
                st_shndx: u16,
            ) -> Self {
                Self {
                    st_name: st_name as _,
                    st_value: st_value as _,
                    st_size: st_size as _,
                    st_info,
                    st_other,
                    st_shndx: st_shndx as _,
                }
            }

            #[inline]
            fn st_name(&self) -> usize {
                self.st_name as usize
            }

            #[inline]
            fn st_value(&self) -> usize {
                self.st_value as usize
            }

            #[inline]
            fn set_st_value(&mut self, value: usize) {
                self.st_value = value as _;
            }

            #[inline]
            fn st_size(&self) -> usize {
                self.st_size as usize
            }

            #[inline]
            fn st_info(&self) -> u8 {
                self.st_info
            }

            #[inline]
            fn st_other(&self) -> u8 {
                self.st_other
            }

            #[inline]
            fn st_shndx(&self) -> u16 {
                self.st_shndx as u16
            }
        }
    };
}

#[allow(unused)]
#[repr(C)]
/// 32-bit ELF symbol table entry.
/// This struct represents the native 32-bit symbol format used in ELF32 files.
/// For 64-bit targets, the active native symbol layout resolves to `elf::symbol::Elf64_Sym`.
pub struct Elf32Sym {
    /// Offset into the symbol string table.
    pub st_name: u32,
    /// Symbol value.
    pub st_value: u32,
    /// Symbol size in bytes.
    pub st_size: u32,
    /// Packed symbol binding and type.
    pub st_info: u8,
    /// Symbol visibility and target-specific flags.
    pub st_other: u8,
    /// Section index associated with this symbol.
    pub st_shndx: u16,
}

impl_sym_raw!(Elf32Sym);
impl_sym_raw!(elf::symbol::Elf64_Sym);
