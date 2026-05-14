use super::layout::{dyn_size, is_64, sym_size};
use crate::{
    Result, custom_error,
    elf::{
        ElfLayout, ElfMachine,
        abi::{
            EI_CLASS, EI_DATA, EI_NIDENT, EI_VERSION, ELFDATA2LSB, ELFMAGIC, ET_DYN, EV_CURRENT,
        },
    },
};

pub(super) struct ByteWriter<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}

impl<'a> ByteWriter<'a> {
    #[inline]
    pub(super) fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    #[inline]
    fn u8(&mut self, value: u8) {
        self.bytes[self.offset] = value;
        self.offset += 1;
    }

    #[inline]
    fn u16(&mut self, value: u16) {
        self.bytes[self.offset..self.offset + 2].copy_from_slice(&value.to_le_bytes());
        self.offset += 2;
    }

    #[inline]
    pub(super) fn u32(&mut self, value: u32) {
        self.bytes[self.offset..self.offset + 4].copy_from_slice(&value.to_le_bytes());
        self.offset += 4;
    }

    #[inline]
    fn i32(&mut self, value: i32) {
        self.bytes[self.offset..self.offset + 4].copy_from_slice(&value.to_le_bytes());
        self.offset += 4;
    }

    #[inline]
    fn u64(&mut self, value: u64) {
        self.bytes[self.offset..self.offset + 8].copy_from_slice(&value.to_le_bytes());
        self.offset += 8;
    }

    #[inline]
    fn i64(&mut self, value: i64) {
        self.bytes[self.offset..self.offset + 8].copy_from_slice(&value.to_le_bytes());
        self.offset += 8;
    }

    #[inline]
    fn bytes(&mut self, value: &[u8]) {
        self.bytes[self.offset..self.offset + value.len()].copy_from_slice(value);
        self.offset += value.len();
    }
}

pub(super) struct Writer<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}

impl<'a> Writer<'a> {
    #[inline]
    pub(super) fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    #[inline]
    pub(super) fn seek(&mut self, offset: usize) {
        self.offset = offset;
    }

    pub(super) fn write_ehdr<L: ElfLayout>(
        &mut self,
        machine: ElfMachine,
        ehdr_size: usize,
        phdr_size: usize,
        phnum: usize,
        phoff: usize,
        shoff: usize,
    ) -> Result<()> {
        let is_64 = is_64::<L>();
        let mut ident = [0u8; EI_NIDENT];
        ident[0..4].copy_from_slice(&ELFMAGIC);
        ident[EI_CLASS] = L::E_CLASS;
        ident[EI_DATA] = ELFDATA2LSB;
        ident[EI_VERSION] = EV_CURRENT;

        let mut out = ByteWriter::new(&mut self.bytes[self.offset..]);
        out.bytes(&ident);
        out.u16(ET_DYN as u16);
        out.u16(machine.raw());
        out.u32(EV_CURRENT as u32);
        if is_64 {
            out.u64(0);
            out.u64(phoff as u64);
            out.u64(shoff as u64);
        } else {
            out.u32(checked_u32(0)?);
            out.u32(checked_u32(phoff)?);
            out.u32(checked_u32(shoff)?);
        }
        out.u32(0);
        out.u16(checked_u16(ehdr_size)?);
        out.u16(checked_u16(phdr_size)?);
        out.u16(checked_u16(phnum)?);
        out.u16(0);
        out.u16(0);
        out.u16(0);
        self.offset += ehdr_size;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_phdr<L: ElfLayout>(
        &mut self,
        p_type: u32,
        p_flags: u32,
        p_offset: usize,
        p_vaddr: usize,
        p_paddr: usize,
        p_filesz: usize,
        p_memsz: usize,
        p_align: usize,
    ) -> Result<()> {
        let is_64 = is_64::<L>();
        let size = if is_64 { 56 } else { 32 };
        let mut out = ByteWriter::new(&mut self.bytes[self.offset..]);
        if is_64 {
            out.u32(p_type);
            out.u32(p_flags);
            out.u64(p_offset as u64);
            out.u64(p_vaddr as u64);
            out.u64(p_paddr as u64);
            out.u64(p_filesz as u64);
            out.u64(p_memsz as u64);
            out.u64(p_align as u64);
        } else {
            out.u32(p_type);
            out.u32(checked_u32(p_offset)?);
            out.u32(checked_u32(p_vaddr)?);
            out.u32(checked_u32(p_paddr)?);
            out.u32(checked_u32(p_filesz)?);
            out.u32(checked_u32(p_memsz)?);
            out.u32(p_flags);
            out.u32(checked_u32(p_align)?);
        }
        self.offset += size;
        Ok(())
    }

    pub(super) fn write_null_symbol<L: ElfLayout>(&mut self) -> Result<()> {
        self.write_symbol::<L>(0, 0, 0, 0, 0, 0)
    }

    pub(super) fn write_symbol<L: ElfLayout>(
        &mut self,
        st_name: usize,
        st_info: u8,
        st_other: u8,
        st_shndx: u16,
        st_value: usize,
        st_size: usize,
    ) -> Result<()> {
        let is_64 = is_64::<L>();
        let size = sym_size(is_64);
        let mut out = ByteWriter::new(&mut self.bytes[self.offset..]);
        if is_64 {
            out.u32(checked_u32(st_name)?);
            out.u8(st_info);
            out.u8(st_other);
            out.u16(st_shndx);
            out.u64(st_value as u64);
            out.u64(st_size as u64);
        } else {
            out.u32(checked_u32(st_name)?);
            out.u32(checked_u32(st_value)?);
            out.u32(checked_u32(st_size)?);
            out.u8(st_info);
            out.u8(st_other);
            out.u16(st_shndx);
        }
        self.offset += size;
        Ok(())
    }

    pub(super) fn write_dyn<L: ElfLayout>(&mut self, tag: i64, value: usize) -> Result<()> {
        let is_64 = is_64::<L>();
        let size = dyn_size(is_64);
        let mut out = ByteWriter::new(&mut self.bytes[self.offset..]);
        if is_64 {
            out.i64(tag);
            out.u64(value as u64);
        } else {
            out.i32(checked_i32(tag)?);
            out.u32(checked_u32(value)?);
        }
        self.offset += size;
        Ok(())
    }
}

#[inline]
fn checked_u16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| custom_error("generated DSO value exceeds u16 range"))
}

#[inline]
fn checked_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| custom_error("generated DSO value exceeds u32 range"))
}

#[inline]
fn checked_i32(value: i64) -> Result<i32> {
    i32::try_from(value).map_err(|_| custom_error("generated DSO value exceeds i32 range"))
}
