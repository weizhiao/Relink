use super::{LoadHook, Loader};
use crate::{
    ParseEhdrError, ParsePhdrError, Result,
    elf::{ElfDyn, ElfFileType, ElfHeader, ElfPhdr, ElfPhdrs, ElfProgramType},
    image::{
        RawDylib, RawDynamic, RawDynamicParts, RawElf, RawExec, ScannedDynamic,
        ScannedDynamicLoadParts, ScannedElf, ScannedExec,
    },
    input::{ElfReader, IntoElfReader},
    logging,
    os::Mmap,
    relocation::RelocAddr,
    segment::{ELFRelro, ElfSegments, program::parse_segments},
    tls::TlsResolver,
};
use alloc::{string::String, vec::Vec};
use core::{
    ffi::{CStr, c_char, c_void},
    ptr::NonNull,
};

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook,
    Tls: TlsResolver,
{
    /// Reads the ELF header.
    ///
    /// The machine architecture check is controlled by the loader's
    /// [`Loader::with_cross_arch`](super::Loader::with_cross_arch) setting.
    pub fn read_ehdr(&mut self, object: &mut impl ElfReader) -> Result<ElfHeader> {
        self.buf.prepare_ehdr(object, !self.inner.allow_cross_arch)
    }

    /// Reads the program header table.
    pub fn read_phdr(
        &mut self,
        object: &mut impl ElfReader,
        ehdr: &ElfHeader,
    ) -> Result<Option<&[ElfPhdr]>> {
        self.buf.prepare_phdrs(ehdr, object)
    }

    fn read_expected_ehdr(
        &mut self,
        object: &mut impl ElfReader,
        expected: ExpectedElf,
    ) -> Result<ElfHeader> {
        let ehdr = self.read_ehdr(object)?;
        if expected.matches(&ehdr) {
            return Ok(ehdr);
        }

        let file_type = ehdr.file_type();
        logging::error!(
            "[{}] Type mismatch: expected {}, found {:?}",
            object.file_name(),
            expected.label(),
            file_type
        );
        Err(expected.error(file_type).into())
    }
}

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook,
    D: 'static,
    Tls: TlsResolver,
{
    /// Scans an executable or dynamic ELF image without mapping its segments.
    ///
    /// Images with `PT_DYNAMIC` are returned as [`ScannedElf::Dynamic`]. Executable
    /// images without `PT_DYNAMIC` are returned as [`ScannedElf::StaticExec`].
    pub fn scan<I>(&mut self, input: I) -> Result<ScannedElf>
    where
        I: IntoElfReader<'static>,
    {
        let mut object = input.into_reader()?;
        logging::debug!("Scanning ELF metadata: {}", object.file_name());

        let ehdr = self.read_expected_ehdr(&mut object, ExpectedElf::Executable)?;
        let phdrs = self
            .buf
            .prepare_phdrs(&ehdr, &mut object)?
            .unwrap_or_default();
        let has_dynamic = has_dynamic_phdr(phdrs);
        let builder = self.inner.create_scan_builder(ehdr, phdrs, object);

        if has_dynamic {
            return ScannedDynamic::from_builder(builder).map(ScannedElf::Dynamic);
        }

        ScannedExec::from_builder(builder).map(ScannedElf::StaticExec)
    }
}

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook,
    D: Default + 'static,
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
            ElfFileType::EXEC => Ok(RawElf::Exec(self.load_exec_from_ehdr(object, ehdr)?)),
            ElfFileType::DYN => {
                let phdrs = self.read_phdr(&mut object, &ehdr)?.unwrap_or_default();
                let has_dynamic = has_dynamic_phdr(phdrs);
                let is_pie = phdrs
                    .iter()
                    .any(|p| p.program_type() == ElfProgramType::INTERP)
                    || !has_dynamic;
                if is_pie {
                    Ok(RawElf::Exec(self.load_exec_from_ehdr(object, ehdr)?))
                } else {
                    let mut dynamic = self.load_dynamic_from_ehdr(object, ehdr)?;
                    self.inner.initialize_dynamic(&mut dynamic)?;
                    Ok(RawElf::Dylib(RawDylib::from_dynamic(dynamic)))
                }
            }
            other => Err(ParseEhdrError::ExpectedExecutable { found: other }.into()),
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
    /// To load ELF files targeting a different CPU architecture than the host, configure
    /// the loader with
    /// [`Loader::with_cross_arch(true)`](super::Loader::with_cross_arch) before calling
    /// this method.
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
        let mut object = input.into_reader()?;
        let ehdr = self.read_expected_ehdr(&mut object, ExpectedElf::Dylib)?;
        let mut dynamic = self.load_dynamic_from_ehdr(object, ehdr)?;
        self.inner.initialize_dynamic(&mut dynamic)?;
        let dylib = RawDylib::from_dynamic(dynamic);

        logging::info!(
            "Loaded dylib: {} at [0x{:x}-0x{:x}]",
            dylib.name(),
            dylib.mapped_base(),
            dylib.mapped_base() + dylib.mapped_len()
        );

        Ok(dylib)
    }

    /// Loads any dynamic ELF image into memory and returns a raw dynamic image.
    ///
    /// Unlike [`Loader::load_dylib`], this accepts both `ET_DYN` shared objects
    /// and `ET_EXEC` executables that carry a `PT_DYNAMIC` segment. The returned
    /// value is mapped but not yet relocated. Call `.relocator().relocate()` to
    /// resolve symbols and produce a ready-to-use loaded image.
    pub fn load_dynamic<'a, I>(&mut self, input: I) -> Result<RawDynamic<D>>
    where
        I: IntoElfReader<'a>,
    {
        let mut object = input.into_reader()?;
        logging::debug!("Loading dynamic image: {}", object.file_name());

        let ehdr = self.read_expected_ehdr(&mut object, ExpectedElf::Dynamic)?;
        let mut image = self.load_dynamic_from_ehdr(object, ehdr)?;
        self.inner.initialize_dynamic(&mut image)?;

        logging::info!(
            "Loaded dynamic image: {} at [0x{:x}-0x{:x}]",
            image.name(),
            image.mapped_base(),
            image.mapped_base() + image.mapped_len()
        );

        Ok(image)
    }

    fn load_dynamic_from_ehdr(
        &mut self,
        mut object: impl ElfReader,
        ehdr: ElfHeader,
    ) -> Result<RawDynamic<D>> {
        let phdrs = self
            .buf
            .prepare_phdrs(&ehdr, &mut object)?
            .unwrap_or_default();
        if !has_dynamic_phdr(phdrs) {
            return Err(ParsePhdrError::MissingDynamicSection.into());
        }

        let builder = self
            .inner
            .create_builder::<M, Tls>(ehdr, phdrs, object, D::default())?;
        RawDynamic::from_builder(builder, phdrs)
    }

    /// Maps a previously scanned dynamic image without rereading its ELF header
    /// or program headers.
    ///
    /// The scanned object's reader is reused for segment loading. User data is
    /// initialized through the loader's dynamic initializer, like ordinary dynamic loads.
    pub fn load_scanned_dynamic(&mut self, scanned: ScannedDynamic) -> Result<RawDynamic<D>> {
        let mut image = self.load_scanned_dynamic_raw_impl(scanned)?;
        self.inner.initialize_dynamic(&mut image)?;

        logging::info!(
            "Loaded scanned dynamic image: {} at [0x{:x}-0x{:x}]",
            image.name(),
            image.mapped_base(),
            image.mapped_base() + image.mapped_len()
        );

        Ok(image)
    }

    pub(crate) fn load_scanned_dynamic_raw_impl(
        &mut self,
        scanned: ScannedDynamic,
    ) -> Result<RawDynamic<D>> {
        let ScannedDynamicLoadParts {
            ehdr,
            phdrs,
            reader,
        } = scanned.into_load_parts();

        logging::debug!("Loading scanned dynamic image: {}", reader.file_name());

        let builder = self
            .inner
            .create_builder::<M, Tls>(ehdr, &phdrs, reader, D::default())?;
        RawDynamic::from_builder(builder, &phdrs)
    }

    /// Creates a raw dynamic image from an ELF object that is already mapped.
    ///
    /// This is intended for dynamic-linker startup, where the kernel has already
    /// mapped the main executable before transferring control to the interpreter.
    /// The returned object is not relocated yet and can be passed through the
    /// normal relocation pipeline.
    ///
    /// `load_bias` is the ELF load bias used to translate `p_vaddr` values into
    /// runtime addresses. For PIE/`ET_DYN` images this is the randomized base
    /// address; for fixed `ET_EXEC` images it is typically zero. `entry` must be
    /// the runtime entry address, such as `AT_ENTRY`.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that every `PT_LOAD` range described by `phdrs`
    /// is mapped at `load_bias + p_vaddr`, remains mapped for the returned
    /// object's lifetime, and is writable wherever relocation will write.
    pub unsafe fn load_mapped_dynamic(
        &mut self,
        name: impl Into<String>,
        load_bias: usize,
        phdrs: impl Into<Vec<ElfPhdr>>,
        entry: usize,
    ) -> Result<RawDynamic<D>> {
        let name = name.into();
        let phdrs = phdrs.into();
        let layout = parse_segments(&phdrs, true)?;
        let memory = load_bias.wrapping_add(layout.min_vaddr) as *mut c_void;
        let segments = ElfSegments::with_base(
            memory,
            layout.mapped_len,
            borrowed_munmap,
            load_bias,
            layout.min_vaddr,
        );
        let parts = borrowed_dynamic_parts::<M, D>(
            name,
            load_bias,
            entry,
            &phdrs,
            segments,
            self.inner.force_static_tls(),
            D::default(),
            self.inner.lifecycle_handlers(),
        )?;
        let mut image = RawDynamic::from_parts::<Tls>(parts)?;
        self.inner.initialize_dynamic(&mut image)?;

        logging::info!(
            "Borrowed dynamic image: {} at [0x{:x}-0x{:x}]",
            image.name(),
            image.mapped_base(),
            image.mapped_base() + image.mapped_len()
        );

        Ok(image)
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
        let mut object = input.into_reader()?;
        logging::info!("Loading executable: {}", object.file_name());

        let ehdr = self.read_expected_ehdr(&mut object, ExpectedElf::Executable)?;
        self.load_exec_from_ehdr(object, ehdr)
    }

    fn load_exec_from_ehdr(
        &mut self,
        mut object: impl ElfReader,
        ehdr: ElfHeader,
    ) -> Result<RawExec<D>> {
        let phdrs = self
            .buf
            .prepare_phdrs(&ehdr, &mut object)?
            .unwrap_or_default();
        let has_dynamic = has_dynamic_phdr(phdrs);

        let builder = self
            .inner
            .create_builder::<M, Tls>(ehdr, phdrs, object, D::default())?;
        let mut exec = RawExec::from_builder(builder, phdrs, has_dynamic)?;
        if let RawExec::Dynamic(dynamic) = &mut exec {
            self.inner.initialize_dynamic(dynamic)?;
        }

        logging::debug!(
            "Load executable: {} at [0x{:x}-0x{:x}] ({})",
            exec.name(),
            exec.mapped_base(),
            exec.mapped_base() + exec.mapped_len(),
            if has_dynamic { "dynamic" } else { "static" }
        );

        Ok(exec)
    }
}

#[inline]
fn has_dynamic_phdr(phdrs: &[ElfPhdr]) -> bool {
    phdrs
        .iter()
        .any(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
}

#[derive(Clone, Copy)]
enum ExpectedElf {
    Dylib,
    Dynamic,
    Executable,
}

impl ExpectedElf {
    #[inline]
    fn matches(self, ehdr: &ElfHeader) -> bool {
        match self {
            Self::Dylib => ehdr.is_dylib(),
            Self::Dynamic | Self::Executable => ehdr.is_executable(),
        }
    }

    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::Dylib => "dylib",
            Self::Dynamic => "dynamic image",
            Self::Executable => "executable",
        }
    }

    #[inline]
    const fn error(self, found: ElfFileType) -> ParseEhdrError {
        match self {
            Self::Dylib => ParseEhdrError::ExpectedDylib { found },
            Self::Dynamic | Self::Executable => ParseEhdrError::ExpectedExecutable { found },
        }
    }
}

fn borrowed_dynamic_parts<M, D>(
    name: String,
    load_bias: usize,
    entry: usize,
    phdrs: &[ElfPhdr],
    segments: ElfSegments,
    force_static_tls: bool,
    user_data: D,
    lifecycle_handlers: (super::DynLifecycleHandler, super::DynLifecycleHandler),
) -> Result<RawDynamicParts<D>>
where
    M: Mmap,
    D: 'static,
{
    let mut dynamic_ptr = None;
    let mut interp = None;
    let mut eh_frame_hdr = None;
    let mut tls_info = None;
    let mut relro = None;

    for phdr in phdrs {
        match phdr.program_type() {
            ElfProgramType::DYNAMIC => {
                dynamic_ptr = NonNull::new(load_bias.wrapping_add(phdr.p_vaddr()) as *mut ElfDyn);
            }
            ElfProgramType::INTERP => {
                let ptr = load_bias.wrapping_add(phdr.p_vaddr()) as *const c_char;
                interp = Some(
                    unsafe { CStr::from_ptr(ptr) }
                        .to_str()
                        .map_err(|_| ParsePhdrError::InvalidUtf8 { field: "PT_INTERP" })?,
                );
            }
            ElfProgramType::GNU_EH_FRAME => {
                eh_frame_hdr = NonNull::new(load_bias.wrapping_add(phdr.p_vaddr()) as *mut u8);
            }
            ElfProgramType::TLS => {
                let image = unsafe {
                    core::slice::from_raw_parts(
                        load_bias.wrapping_add(phdr.p_vaddr()) as *const u8,
                        phdr.p_filesz(),
                    )
                };
                tls_info = Some(crate::tls::TlsInfo::new(phdr, image));
            }
            ElfProgramType::GNU_RELRO => {
                relro = Some(ELFRelro::new::<M>(phdr, RelocAddr::new(load_bias)));
            }
            _ => {}
        }
    }

    let dynamic_ptr = dynamic_ptr.ok_or(ParsePhdrError::MissingDynamicSection)?;
    let (init_fn, fini_fn) = lifecycle_handlers;

    Ok(RawDynamicParts {
        name,
        entry: RelocAddr::new(entry),
        interp,
        phdrs: ElfPhdrs::Vec(Vec::from(phdrs)),
        dynamic_ptr,
        eh_frame_hdr,
        tls_info,
        force_static_tls,
        relro,
        segments,
        init_fn,
        fini_fn,
        user_data,
    })
}

unsafe fn borrowed_munmap(_memory: *mut c_void, _len: usize) -> Result<()> {
    Ok(())
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

        ElfHeader::from_raw(ehdr, true).expect("failed to parse crafted header")
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
