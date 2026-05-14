use super::{
    hash::{dynsym_bucket_count, sysv_hash_table_size, write_sysv_hash_table},
    layout::{
        DEFAULT_PAGE_SIZE, DEFAULT_TEXT_ALIGN, TEXT_SECTION_INDEX, align_up, align_up_checked,
        check_word_range, checked_add, dyn_size, is_64, sym_size,
    },
    string_table::StringTable,
    types::{DsoExport, DsoExportLayout, DsoImage, DsoSymbolBind, DsoSymbolKind},
    writer::Writer,
};
use crate::{
    Result, custom_error,
    elf::abi::{
        DF_BIND_NOW, DT_BIND_NOW, DT_FLAGS, DT_HASH, DT_NULL, DT_SONAME, DT_STRSZ, DT_STRTAB,
        DT_SYMENT, DT_SYMTAB, PF_R, PF_X, PT_DYNAMIC, PT_LOAD,
    },
    relocation::RelocationArch,
};
use alloc::{string::String, vec::Vec};
use core::marker::PhantomData;

/// Builder for a minimal `ET_DYN` image with caller-provided exports.
#[derive(Clone, Debug)]
pub struct DsoBuilder<Arch: RelocationArch> {
    soname: String,
    page_size: usize,
    bind_now: bool,
    text: Vec<u8>,
    exports: Vec<DsoExport>,
    _arch: PhantomData<Arch>,
}

impl<Arch: RelocationArch> DsoBuilder<Arch> {
    /// Creates a shared object builder for `Arch`.
    #[inline]
    pub fn new(soname: impl Into<String>) -> Self {
        Self {
            soname: soname.into(),
            page_size: DEFAULT_PAGE_SIZE,
            bind_now: false,
            text: Vec::new(),
            exports: Vec::new(),
            _arch: PhantomData,
        }
    }

    /// Overrides the segment page size/alignment used by the generated image.
    #[inline]
    pub fn with_page_size(mut self, page_size: usize) -> Self {
        self.page_size = page_size;
        self
    }

    /// Emits `DT_BIND_NOW`/`DF_BIND_NOW`.
    #[inline]
    pub fn with_bind_now(mut self, bind_now: bool) -> Self {
        self.bind_now = bind_now;
        self
    }

    /// Replaces the text payload. Export offsets are interpreted relative to
    /// this payload.
    #[inline]
    pub fn with_text(mut self, text: impl Into<Vec<u8>>) -> Self {
        self.text = text.into();
        self
    }

    /// Appends bytes to the text payload and returns their text-relative offset.
    pub fn append_text(&mut self, bytes: &[u8], align: usize) -> usize {
        let align = align.max(1);
        let offset = align_up(self.text.len(), align);
        self.text.resize(offset, 0);
        self.text.extend_from_slice(bytes);
        offset
    }

    /// Appends a function body and exports it.
    pub fn add_function(&mut self, name: impl Into<String>, code: &[u8]) -> usize {
        let offset = self.append_text(code, DEFAULT_TEXT_ALIGN);
        self.exports
            .push(DsoExport::function(name, offset, code.len()));
        offset
    }

    /// Adds an already-laid-out export.
    #[inline]
    pub fn export(mut self, export: DsoExport) -> Self {
        self.exports.push(export);
        self
    }

    /// Adds an already-laid-out export by mutable reference.
    #[inline]
    pub fn push_export(&mut self, export: DsoExport) {
        self.exports.push(export);
    }

    /// Builds the ELF image.
    pub fn build(&self) -> Result<DsoImage> {
        validate_page_size(self.page_size)?;
        validate_exports(&self.text, &self.exports)?;

        let is_64 = is_64::<Arch::Layout>();
        let word_size = if is_64 { 8 } else { 4 };
        let ehdr_size: usize = if is_64 { 64 } else { 52 };
        let phdr_size: usize = if is_64 { 56 } else { 32 };
        let phnum = 2usize;

        let mut dynstr = StringTable::new();
        let soname_offset = dynstr.add(&self.soname);
        let mut name_offsets = Vec::with_capacity(self.exports.len());
        for export in &self.exports {
            name_offsets.push(dynstr.add(&export.name));
        }

        let dynsym_count = self.exports.len() + 1;
        let dynsym_size = dynsym_count
            .checked_mul(sym_size(is_64))
            .ok_or_else(|| custom_error("generated DSO dynsym size overflow"))?;
        let hash_size = sysv_hash_table_size(dynsym_count, dynsym_bucket_count(dynsym_count))?;
        let dynamic_count = self.dynamic_entry_count();
        let dynamic_size = dynamic_count
            .checked_mul(dyn_size(is_64))
            .ok_or_else(|| custom_error("generated DSO dynamic size overflow"))?;

        let mut cursor = ehdr_size
            .checked_add(phdr_size * phnum)
            .ok_or_else(|| custom_error("generated DSO header size overflow"))?;
        cursor = align_up_checked(cursor, word_size)?;
        let dynstr_off = cursor;
        cursor = checked_add(cursor, dynstr.len(), "generated DSO dynstr size overflow")?;
        cursor = align_up_checked(cursor, word_size)?;
        let dynsym_off = cursor;
        cursor = checked_add(cursor, dynsym_size, "generated DSO dynsym size overflow")?;
        cursor = align_up_checked(cursor, 4)?;
        let hash_off = cursor;
        cursor = checked_add(cursor, hash_size, "generated DSO hash size overflow")?;
        cursor = align_up_checked(cursor, word_size)?;
        let dynamic_off = cursor;
        cursor = checked_add(cursor, dynamic_size, "generated DSO dynamic size overflow")?;
        cursor = align_up_checked(cursor, DEFAULT_TEXT_ALIGN)?;
        let text_off = cursor;
        cursor = checked_add(cursor, self.text.len(), "generated DSO text size overflow")?;
        let file_size = cursor;

        check_word_range::<Arch::Layout>(file_size)?;

        let mut bytes = Vec::new();
        bytes.resize(file_size, 0);

        let mut out = Writer::new(&mut bytes);
        out.write_ehdr::<Arch::Layout>(Arch::MACHINE, ehdr_size, phdr_size, phnum, ehdr_size, 0)?;
        out.seek(ehdr_size);
        out.write_phdr::<Arch::Layout>(
            PT_LOAD,
            PF_R | PF_X,
            0,
            0,
            0,
            file_size,
            file_size,
            self.page_size,
        )?;
        out.write_phdr::<Arch::Layout>(
            PT_DYNAMIC,
            PF_R,
            dynamic_off,
            dynamic_off,
            dynamic_off,
            dynamic_size,
            dynamic_size,
            word_size,
        )?;

        bytes[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(dynstr.as_slice());

        let mut out = Writer::new(&mut bytes);
        out.seek(dynsym_off);
        out.write_null_symbol::<Arch::Layout>()?;
        let mut layouts = Vec::with_capacity(self.exports.len());
        for (export, name_offset) in self.exports.iter().zip(name_offsets) {
            let value = text_off
                .checked_add(export.text_offset)
                .ok_or_else(|| custom_error("generated DSO symbol value overflow"))?;
            out.write_symbol::<Arch::Layout>(
                name_offset,
                symbol_info(export.bind, export.kind),
                0,
                TEXT_SECTION_INDEX,
                value,
                export.size,
            )?;
            layouts.push(DsoExportLayout {
                name: export.name.clone(),
                text_offset: export.text_offset,
                value,
                size: export.size,
                kind: export.kind,
                bind: export.bind,
            });
        }

        let symbol_names = self.exports.iter().map(|export| export.name.as_str());
        write_sysv_hash_table(
            &mut bytes[hash_off..hash_off + hash_size],
            dynsym_count,
            dynsym_bucket_count(dynsym_count),
            symbol_names,
        );

        let mut out = Writer::new(&mut bytes);
        out.seek(dynamic_off);
        out.write_dyn::<Arch::Layout>(DT_STRTAB, dynstr_off)?;
        out.write_dyn::<Arch::Layout>(DT_STRSZ, dynstr.len())?;
        out.write_dyn::<Arch::Layout>(DT_SYMTAB, dynsym_off)?;
        out.write_dyn::<Arch::Layout>(DT_SYMENT, sym_size(is_64))?;
        out.write_dyn::<Arch::Layout>(DT_HASH, hash_off)?;
        out.write_dyn::<Arch::Layout>(DT_SONAME, soname_offset)?;
        if self.bind_now {
            out.write_dyn::<Arch::Layout>(DT_BIND_NOW, 0)?;
            out.write_dyn::<Arch::Layout>(DT_FLAGS, DF_BIND_NOW as usize)?;
        }
        out.write_dyn::<Arch::Layout>(DT_NULL, 0)?;

        bytes[text_off..text_off + self.text.len()].copy_from_slice(&self.text);

        Ok(DsoImage {
            soname: self.soname.clone(),
            bytes,
            exports: layouts,
        })
    }

    #[inline]
    const fn dynamic_entry_count(&self) -> usize {
        7 + if self.bind_now { 2 } else { 0 }
    }
}

#[inline]
const fn symbol_info(bind: DsoSymbolBind, kind: DsoSymbolKind) -> u8 {
    (bind.st_bind() << 4) | kind.st_type()
}

#[inline]
fn validate_page_size(page_size: usize) -> Result<()> {
    if page_size == 0 || !page_size.is_power_of_two() {
        return Err(custom_error(
            "generated DSO page size must be a non-zero power of two",
        ));
    }
    Ok(())
}

fn validate_exports(text: &[u8], exports: &[DsoExport]) -> Result<()> {
    for export in exports {
        if export.name.is_empty() || export.name.as_bytes().contains(&0) {
            return Err(custom_error(
                "generated DSO export names must be non-empty and contain no NUL bytes",
            ));
        }
        let end = export
            .text_offset
            .checked_add(export.size)
            .ok_or_else(|| custom_error("generated DSO export range overflow"))?;
        if end > text.len() {
            return Err(custom_error("generated DSO export range exceeds text size"));
        }
    }
    Ok(())
}
