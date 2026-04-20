use super::{LoadHook, Loader};
use crate::{
    ParseEhdrError, Result,
    elf::{ElfFileType, ElfHeader, ElfPhdr, ElfProgramType},
    image::{RawDylib, RawElf, RawExec, ScannedDylib},
    input::{ElfReader, IntoElfReader},
    logging,
    os::Mmap,
    tls::TlsResolver,
};

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
    D: 'static,
    Tls: TlsResolver,
{
    /// Scans a shared object and returns metadata without mapping its segments.
    pub fn scan_dylib<I>(&mut self, input: I) -> Result<ScannedDylib<D>>
    where
        I: IntoElfReader<'static>,
    {
        self.scan_dylib_impl(input.into_reader()?)
    }

    pub(crate) fn scan_dylib_impl(
        &mut self,
        mut object: impl ElfReader + 'static,
    ) -> Result<ScannedDylib<D>> {
        logging::debug!("Scanning dylib metadata: {}", object.file_name());

        let ehdr = self.read_ehdr(&mut object)?;
        if !ehdr.is_dylib() {
            let file_type = ehdr.file_type();
            return Err(ParseEhdrError::ExpectedDylib { found: file_type }.into());
        }

        let phdrs = self
            .buf
            .prepare_phdrs(&ehdr, &mut object)?
            .unwrap_or_default();
        let builder = self.inner.create_scan_builder(ehdr, phdrs, object);
        ScannedDylib::from_builder(builder)
    }
}

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook,
    D: Default,
    Tls: TlsResolver,
{
    /// Loads an ELF input and chooses the appropriate raw image type automatically.
    ///
    /// This is the most flexible entry point when the caller does not already know
    /// whether the input is a shared object, executable, or relocatable object.
    /// `ET_DYN` inputs are classified by inspecting the program headers.
    pub fn load<'a, I>(&mut self, input: I) -> Result<RawElf<D>>
    where
        D: 'static,
        I: IntoElfReader<'a>,
    {
        let mut object = input.into_reader()?;
        let ehdr = self.read_ehdr(&mut object)?;

        match ehdr.file_type() {
            ElfFileType::REL => self.load_rel(object),
            ElfFileType::EXEC => Ok(RawElf::Exec(self.load_exec_impl(object)?)),
            ElfFileType::DYN => {
                let phdrs = self.read_phdr(&mut object, &ehdr)?.unwrap_or_default();
                let has_dynamic = phdrs
                    .iter()
                    .any(|p| p.program_type() == ElfProgramType::DYNAMIC);
                let is_pie = phdrs
                    .iter()
                    .any(|p| p.program_type() == ElfProgramType::INTERP)
                    || !has_dynamic;
                if is_pie {
                    Ok(RawElf::Exec(self.load_exec_impl(object)?))
                } else {
                    Ok(RawElf::Dylib(self.load_dylib_impl(object)?))
                }
            }
            _ => Ok(RawElf::Exec(self.load_exec_impl(object)?)),
        }
    }

    #[cfg(not(feature = "object"))]
    pub(crate) fn load_rel(&mut self, _object: impl ElfReader) -> Result<RawElf<D>>
    where
        D: 'static,
    {
        Err(ParseEhdrError::RelocatableObjectsDisabled.into())
    }

    /// Loads a shared object (`ET_DYN`) into memory and returns a raw dylib image.
    ///
    /// The returned value is mapped but not yet relocated. Call `.relocator().relocate()`
    /// to resolve symbols and produce a ready-to-use loaded image.
    ///
    /// Any [`IntoElfReader`] input is accepted, including paths, byte slices,
    /// [`crate::input::ElfFile`], and [`crate::input::ElfBinary`].
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::Loader;
    ///
    /// let mut loader = Loader::new();
    /// let raw = loader.load_dylib("path/to/liba.so").unwrap();
    /// let lib = raw.relocator().relocate().unwrap();
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
            let file_type = ehdr.file_type();
            logging::error!(
                "[{}] Type mismatch: expected dylib, found {:?}",
                object.file_name(),
                file_type
            );
            return Err(ParseEhdrError::ExpectedDylib { found: file_type }.into());
        }

        let phdrs = self
            .buf
            .prepare_phdrs(&ehdr, &mut object)?
            .unwrap_or_default();
        let builder = self.inner.create_builder::<M, Tls>(ehdr, phdrs, object)?;
        let mut dylib = RawDylib::from_builder(builder, phdrs)?;
        (self.inner.post_load_dylib)(&mut dylib)?;

        logging::info!(
            "Loaded dylib: {} at [0x{:x}-0x{:x}]",
            dylib.name(),
            dylib.mapped_base(),
            dylib.mapped_base() + dylib.mapped_len()
        );

        Ok(dylib)
    }

    /// Loads an executable image into memory and returns a raw executable.
    ///
    /// Both static executables and dynamically-linked / PIE-style executables are supported.
    /// Dynamic executables can later be relocated with `.relocator().relocate()`.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::Loader;
    ///
    /// let mut loader = Loader::new();
    /// let exec = loader.load_exec("path/to/program").unwrap();
    /// println!("entry = 0x{:x}", exec.entry());
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
            let file_type = ehdr.file_type();
            logging::error!(
                "File type mismatch for {}: expected executable, found {:?}",
                object.file_name(),
                file_type
            );
            return Err(ParseEhdrError::ExpectedExecutable { found: file_type }.into());
        }

        let phdrs = self
            .buf
            .prepare_phdrs(&ehdr, &mut object)?
            .unwrap_or_default();
        let has_dynamic = phdrs
            .iter()
            .any(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC);

        let builder = self.inner.create_builder::<M, Tls>(ehdr, phdrs, object)?;
        let res = RawExec::from_builder(builder, phdrs, has_dynamic);

        if let Ok(ref exec) = res {
            logging::debug!(
                "Load executable: {} at [0x{:x}-0x{:x}] ({})",
                exec.name(),
                exec.mapped_base(),
                exec.mapped_base() + exec.mapped_len(),
                if has_dynamic { "dynamic" } else { "static" }
            );
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::{ElfHeader, ElfPhdr};
    use crate::{
        Result,
        arch::EM_ARCH,
        elf::{E_CLASS, EHDR_SIZE, ElfEhdr},
        input::ElfReader,
        loader::ElfBuf,
    };
    use alloc::vec::Vec;
    use core::mem::size_of;
    use elf::abi::{EI_CLASS, EI_VERSION, ELFMAGIC, ET_DYN, EV_CURRENT};

    struct TestReader {
        bytes: Vec<u8>,
    }

    impl TestReader {
        fn zeroed(size: usize) -> Self {
            Self {
                bytes: alloc::vec![0; size],
            }
        }
    }

    impl ElfReader for TestReader {
        fn file_name(&self) -> &str {
            "<test>"
        }

        fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
            buf.copy_from_slice(&self.bytes[offset..offset + buf.len()]);
            Ok(())
        }

        fn as_fd(&self) -> Option<isize> {
            None
        }
    }

    fn make_header(phentsize: usize, phnum: usize, shentsize: usize, shnum: usize) -> ElfHeader {
        let mut ehdr = unsafe { core::mem::zeroed::<ElfEhdr>() };
        ehdr.e_ident[0..4].copy_from_slice(&ELFMAGIC);
        ehdr.e_ident[EI_CLASS] = E_CLASS;
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_type = ET_DYN as _;
        ehdr.e_machine = EM_ARCH;
        ehdr.e_version = EV_CURRENT as _;
        ehdr.e_ehsize = EHDR_SIZE as _;
        ehdr.e_phoff = EHDR_SIZE as _;
        ehdr.e_phentsize = phentsize as _;
        ehdr.e_phnum = phnum as _;
        ehdr.e_shoff = (EHDR_SIZE + 128) as _;
        ehdr.e_shentsize = shentsize as _;
        ehdr.e_shnum = shnum as _;

        ElfHeader::from_raw(ehdr).expect("failed to parse crafted header")
    }

    #[test]
    fn prepare_phdrs_rejects_entry_size_mismatch() {
        let mut elf_buf = ElfBuf::new();
        let header = make_header(size_of::<ElfPhdr>() + 8, 1, 0, 0);
        let mut reader = TestReader::zeroed(512);

        let err = elf_buf
            .prepare_phdrs(&header, &mut reader)
            .expect_err("phdr entry size mismatch should fail");
        assert!(matches!(
            err,
            crate::Error::ParsePhdr(crate::ParsePhdrError::MalformedProgramHeaders)
        ));
    }
}
