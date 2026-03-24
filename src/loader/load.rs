use super::{ElfBuf, LoadHook, Loader};
use crate::{
    Result,
    elf::{EHDR_SIZE, ElfHeader, ElfPhdr, ElfShdr},
    image::{RawDylib, RawElf, RawExec, RawObject},
    input::{ElfReader, IntoElfReader},
    logging,
    os::Mmap,
    parse_ehdr_error,
    tls::TlsResolver,
};
use elf::abi::{PT_DYNAMIC, PT_INTERP};

impl ElfBuf {
    pub(crate) fn new() -> Self {
        ElfBuf {
            buf: alloc::vec![0; EHDR_SIZE],
        }
    }

    fn ensure_len(&mut self, size: usize) {
        if size > self.buf.len() {
            self.buf.resize(size, 0);
        }
    }

    fn read_table(
        &mut self,
        object: &mut impl ElfReader,
        range: (usize, usize),
    ) -> Result<Option<usize>> {
        let (start, end) = range;
        let size = end - start;
        if size == 0 {
            return Ok(None);
        }

        self.ensure_len(size);
        object.read(&mut self.buf[..size], start)?;
        Ok(Some(size))
    }

    pub(crate) fn prepare_ehdr(&mut self, object: &mut impl ElfReader) -> Result<ElfHeader> {
        object.read(&mut self.buf[..EHDR_SIZE], 0)?;
        ElfHeader::new(&self.buf).cloned()
    }

    pub(crate) fn prepare_phdrs(
        &mut self,
        ehdr: &ElfHeader,
        object: &mut impl ElfReader,
    ) -> Result<Option<&[ElfPhdr]>> {
        let Some(size) = self.read_table(object, ehdr.phdr_range())? else {
            return Ok(None);
        };
        unsafe {
            Ok(Some(core::slice::from_raw_parts(
                self.buf.as_ptr().cast::<ElfPhdr>(),
                size / size_of::<ElfPhdr>(),
            )))
        }
    }

    pub(crate) fn prepare_shdrs_mut(
        &mut self,
        ehdr: &ElfHeader,
        object: &mut impl ElfReader,
    ) -> Result<Option<&mut [ElfShdr]>> {
        let Some(size) = self.read_table(object, ehdr.shdr_range())? else {
            return Ok(None);
        };
        unsafe {
            Ok(Some(core::slice::from_raw_parts_mut(
                self.buf.as_mut_ptr().cast::<ElfShdr>(),
                size / size_of::<ElfShdr>(),
            )))
        }
    }
}

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
{
    /// Reads the ELF header.
    pub fn read_ehdr(&mut self, object: &mut impl ElfReader) -> Result<ElfHeader> {
        self.buf.prepare_ehdr(object)
    }

    /// Reads the program header table.
    pub fn read_phdr(
        &mut self,
        object: &mut impl ElfReader,
        ehdr: &ElfHeader,
    ) -> Result<Option<&[ElfPhdr]>> {
        self.buf.prepare_phdrs(ehdr, object)
    }
}

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook,
    D: Default,
    Tls: TlsResolver,
{
    /// Load an ELF file into memory.
    ///
    /// # Arguments
    /// * `input` - The ELF object to load
    ///
    /// # Returns
    /// * `Ok(elf)` - The loaded ELF file
    /// * `Err(Error)` - If loading fails
    pub fn load<'a, I>(&mut self, input: I) -> Result<RawElf<D>>
    where
        D: 'static,
        I: IntoElfReader<'a>,
    {
        let mut object = input.into_reader()?;
        let ehdr = self.read_ehdr(&mut object)?;

        match ehdr.e_type {
            elf::abi::ET_REL => Ok(RawElf::Object(self.load_object_impl(object)?)),
            elf::abi::ET_EXEC => Ok(RawElf::Exec(self.load_exec_impl(object)?)),
            elf::abi::ET_DYN => {
                let phdrs = self.read_phdr(&mut object, &ehdr)?.unwrap_or_default();
                let has_dynamic = phdrs.iter().any(|p| p.p_type == PT_DYNAMIC);
                let is_pie = phdrs.iter().any(|p| p.p_type == PT_INTERP) || !has_dynamic;
                if is_pie {
                    Ok(RawElf::Exec(self.load_exec_impl(object)?))
                } else {
                    Ok(RawElf::Dylib(self.load_dylib_impl(object)?))
                }
            }
            _ => Ok(RawElf::Exec(self.load_exec_impl(object)?)),
        }
    }

    /// Loads a dynamic library into memory and prepares it for relocation.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::{Loader, input::ElfBinary};
    ///
    /// let mut loader = Loader::new();
    /// let bytes = &[]; // ELF file bytes
    /// let lib = loader.load_dylib(ElfBinary::new("liba.so", bytes)).unwrap();
    /// ```
    pub fn load_dylib<'a, I>(&mut self, input: I) -> Result<RawDylib<D>>
    where
        I: IntoElfReader<'a>,
    {
        self.load_dylib_impl(input.into_reader()?)
    }

    pub(crate) fn load_dylib_impl(&mut self, mut object: impl ElfReader) -> Result<RawDylib<D>> {
        logging::debug!("Loading dylib: {}", object.file_name());

        let ehdr = self.read_ehdr(&mut object)?;
        if !ehdr.is_dylib() {
            logging::error!(
                "[{}] Type mismatch: expected dylib, found {:?}",
                object.file_name(),
                ehdr.e_type
            );
            return Err(parse_ehdr_error("file type mismatch"));
        }

        let phdrs = self
            .buf
            .prepare_phdrs(&ehdr, &mut object)?
            .unwrap_or_default();
        let builder = self.inner.create_builder::<M, Tls>(ehdr, phdrs, object)?;
        let dylib = RawDylib::from_builder(builder, phdrs)?;

        logging::info!(
            "Loaded dylib: {} at [0x{:x}-0x{:x}]",
            dylib.name(),
            dylib.base(),
            dylib.base() + dylib.mapped_len()
        );

        Ok(dylib)
    }
    /// Loads an executable file into memory and prepares it for relocation.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::{Loader, input::ElfBinary};
    ///
    /// let mut loader = Loader::new();
    /// let bytes = &[]; // ELF executable bytes
    /// let exec = loader.load_exec(ElfBinary::new("my_exec", bytes)).unwrap();
    /// ```
    pub fn load_exec<'a, I>(&mut self, input: I) -> Result<RawExec<D>>
    where
        I: IntoElfReader<'a>,
    {
        self.load_exec_impl(input.into_reader()?)
    }

    pub(crate) fn load_exec_impl(&mut self, mut object: impl ElfReader) -> Result<RawExec<D>> {
        logging::info!("Loading executable: {}", object.file_name());

        let ehdr = self.read_ehdr(&mut object)?;
        if !ehdr.is_executable() {
            logging::error!(
                "File type mismatch for {}: expected executable, found {:?}",
                object.file_name(),
                ehdr.e_type
            );
            return Err(parse_ehdr_error("file type mismatch"));
        }

        let phdrs = self
            .buf
            .prepare_phdrs(&ehdr, &mut object)?
            .unwrap_or_default();
        let has_dynamic = phdrs.iter().any(|phdr| phdr.p_type == PT_DYNAMIC);

        let builder = self.inner.create_builder::<M, Tls>(ehdr, phdrs, object)?;
        let res = RawExec::from_builder(builder, phdrs, has_dynamic);

        if let Ok(ref exec) = res {
            logging::debug!(
                "Load executable: {} at [0x{:x}-0x{:x}] ({})",
                exec.name(),
                exec.base(),
                exec.base() + exec.mapped_len(),
                if has_dynamic { "dynamic" } else { "static" }
            );
        }

        res
    }
    /// Loads a relocatable object file into memory and prepares it for relocation.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::{Loader, input::ElfBinary};
    ///
    /// let mut loader = Loader::new();
    /// let bytes = &[]; // Relocatable ELF bytes
    /// let rel = loader.load_object(ElfBinary::new("liba.o", bytes)).unwrap();
    /// ```
    pub fn load_object<'a, I>(&mut self, input: I) -> Result<RawObject<D>>
    where
        D: 'static,
        I: IntoElfReader<'a>,
    {
        self.load_object_impl(input.into_reader()?)
    }

    pub(crate) fn load_object_impl(&mut self, mut object: impl ElfReader) -> Result<RawObject<D>>
    where
        D: 'static,
    {
        logging::debug!("Loading object: {}", object.file_name());

        let ehdr = self.read_ehdr(&mut object)?;
        let shdrs = self
            .buf
            .prepare_shdrs_mut(&ehdr, &mut object)?
            .ok_or_else(|| crate::parse_ehdr_error("object file must have section headers"))?;
        let builder = self
            .inner
            .create_object_builder::<M, Tls>(ehdr, shdrs, object)?;
        let raw = RawObject::from_builder(builder);

        logging::info!(
            "Loaded object: {} at [0x{:x}-0x{:x}]",
            raw.name(),
            raw.base(),
            raw.base() + raw.core.inner.segments.len()
        );

        Ok(raw)
    }
}
