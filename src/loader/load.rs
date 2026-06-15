use super::{ImageBuilder, Loader, ScanBuilder};
use crate::{
    ParseEhdrError, ParsePhdrError, Result,
    elf::{ElfDyn, ElfFileType, ElfHeader, ElfLayout, ElfPhdr, ElfPhdrs, ElfProgramType, ElfShdr},
    image::{
        RawDylib, RawDynamic, RawDynamicParts, RawElf, RawExec, ScannedDynamic, ScannedElf,
        ScannedExec,
    },
    input::{ElfReader, IntoElfReader, PathBuf},
    logging,
    memory::{ImageMemory, RegionAccess, VmAddr},
    observer::{AfterDynamicLoadEvent, BeforeDynamicLoadEvent, LoadObserver},
    os::{Mmap, ProtFlags},
    relocation::{ObjectRelocationArch, RelocationArch},
    segment::{
        ElfSegments, MemoryProtection,
        program::{ProgramSegments, parse_segments},
    },
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};

impl<Obs, D, Tls, Arch, M> Loader<Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    Tls: TlsResolver,
    Arch: RelocationArch,
    M: Mmap,
{
    #[inline]
    pub(crate) fn notify_after_dynamic_load(
        &mut self,
        image: &mut RawDynamic<D, Arch, M::Region>,
    ) -> Result<()> {
        self.inner
            .observer
            .on_after_dynamic_load(AfterDynamicLoadEvent::new(image))
    }

    /// Reads the ELF header.
    ///
    /// The header's `e_machine` is required to equal `Arch::MACHINE`. To
    /// load an ELF whose target architecture differs from the host, switch
    /// the loader's target architecture with
    /// [`Loader::for_arch`](super::Loader::for_arch) before calling
    /// `load_*`; the gate will then accept ELFs targeting `NewArch::MACHINE`.
    pub fn read_ehdr(&mut self, object: &impl ElfReader) -> Result<ElfHeader<Arch::Layout>> {
        self.buf
            .prepare_ehdr::<Arch::Layout>(object, Some(<Arch as RelocationArch>::MACHINE))
    }

    /// Reads the program header table.
    pub fn read_phdrs<'a>(
        &'a mut self,
        object: &'a impl ElfReader,
        ehdr: &ElfHeader<Arch::Layout>,
    ) -> Result<Option<&'a [ElfPhdr<Arch::Layout>]>> {
        self.buf.prepare_phdrs(ehdr, object)
    }

    /// Reads the section header table.
    pub fn read_shdrs<'a>(
        &'a mut self,
        object: &'a impl ElfReader,
        ehdr: &ElfHeader<Arch::Layout>,
    ) -> Result<Option<&'a [ElfShdr<Arch::Layout>]>> {
        self.buf.prepare_shdrs(ehdr, object)
    }

    pub(crate) fn read_expected_ehdr(
        &mut self,
        object: &impl ElfReader,
        expected: ExpectedElf,
    ) -> Result<ElfHeader<Arch::Layout>> {
        let ehdr = self.read_ehdr(object)?;
        if expected.matches(&ehdr) {
            return Ok(ehdr);
        }

        let file_type = ehdr.file_type();
        logging::error!(
            "[{}] Type mismatch: expected {}, found {:?}",
            object.path(),
            expected.label(),
            file_type
        );
        Err(expected.error(file_type).into())
    }
}

impl<Obs, D, Tls, Arch, M> Loader<Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: 'static,
    Tls: TlsResolver,
    Arch: RelocationArch,
    M: Mmap,
{
    /// Scans an executable or dynamic ELF image without mapping its segments.
    ///
    /// Images with `PT_DYNAMIC` are returned as [`ScannedElf::Dynamic`]. Executable
    /// images without `PT_DYNAMIC` are returned as [`ScannedElf::StaticExec`].
    pub fn scan<I>(&mut self, input: I) -> Result<ScannedElf<Arch>>
    where
        I: IntoElfReader<'static>,
    {
        let object = input.into_reader()?;
        logging::debug!("Scanning ELF metadata: {}", object.path());

        let ehdr = self.read_expected_ehdr(&object, ExpectedElf::Executable)?;
        let phdrs = self.buf.prepare_phdrs(&ehdr, &object)?.unwrap_or_default();
        let has_dynamic = has_dynamic_phdr(phdrs);
        let phdrs = Box::from(phdrs);
        let path = PathBuf::from(object.path());
        let builder = ScanBuilder::new(path, ehdr, phdrs, Box::new(object));

        if has_dynamic {
            return ScannedDynamic::<Arch>::from_builder(builder).map(ScannedElf::Dynamic);
        }

        ScannedExec::<Arch>::from_builder(builder).map(ScannedElf::StaticExec)
    }
}

impl<Obs, D, Tls, Arch, M> Loader<Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: Default + 'static,
    Tls: TlsResolver,
    Arch: RelocationArch,
    M: Mmap,
{
    /// Loads an ELF input and chooses the appropriate raw image type automatically.
    ///
    /// This is the most flexible entry point when the caller does not already know
    /// whether the input is a shared object, executable, or relocatable object.
    /// `ET_DYN` inputs are classified by inspecting the program headers.
    pub fn load<'a, I>(&mut self, input: I) -> Result<RawElf<D, Arch, M::Region>>
    where
        D: 'static,
        Arch: ObjectRelocationArch,
        I: IntoElfReader<'a>,
    {
        let object = input.into_reader()?;
        let ehdr = self.read_ehdr(&object)?;

        match ehdr.file_type() {
            ElfFileType::REL => {
                #[cfg(feature = "object")]
                {
                    Ok(RawElf::Object(self.load_object_from_ehdr(object, ehdr)?))
                }
                #[cfg(not(feature = "object"))]
                {
                    let _ = object;
                    Err(ParseEhdrError::RelocatableObjectsDisabled.into())
                }
            }
            ElfFileType::EXEC => Ok(RawElf::Exec(self.load_exec_from_ehdr(&object, ehdr)?)),
            ElfFileType::DYN => {
                let is_pie = {
                    let phdrs = self.read_phdrs(&object, &ehdr)?.unwrap_or_default();
                    let has_dynamic = has_dynamic_phdr(phdrs);
                    phdrs
                        .iter()
                        .any(|p| p.program_type() == ElfProgramType::INTERP)
                        || !has_dynamic
                };
                if is_pie {
                    Ok(RawElf::Exec(self.load_exec_from_ehdr(&object, ehdr)?))
                } else {
                    let dynamic = self.load_dynamic_from_ehdr(&object, ehdr)?;
                    Ok(RawElf::Dylib(RawDylib::from_dynamic(dynamic)))
                }
            }
            other => Err(ParseEhdrError::ExpectedExecutable { found: other }.into()),
        }
    }

    /// Loads a shared object (`ET_DYN`) into memory and returns a raw dylib image.
    ///
    /// The returned value is mapped but not yet relocated. Call `.relocator().relocate()`
    /// to resolve symbols and produce a ready-to-use loaded image.
    ///
    /// Any [`IntoElfReader`] input is accepted, including paths, byte slices,
    /// [`crate::input::ElfFile`], and [`crate::input::ElfBinary`].
    ///
    /// To load ELF files targeting a different CPU architecture than the host,
    /// switch the loader's target architecture with
    /// [`Loader::for_arch::<NewArch>()`](super::Loader::for_arch) before
    /// calling this method. The `e_machine` gate then validates against
    /// `NewArch::MACHINE`, and the returned [`RawDylib`] carries the chosen
    /// `Arch`, so [`Relocator::relocate`] uses the matching relocation
    /// numbering and skips host-side runtime hooks (IFUNC, TLSDESC, lazy
    /// binding, init arrays).
    ///
    /// [`Relocator::relocate`]: crate::relocation::Relocator::relocate
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::Loader;
    ///
    /// let mut loader = Loader::new();
    /// let raw = loader.load_dylib("path/to/liba.so").unwrap();
    /// let lib = raw.relocator().relocate().unwrap();
    /// ```
    pub fn load_dylib<'a, I>(&mut self, input: I) -> Result<RawDylib<D, Arch, M::Region>>
    where
        I: IntoElfReader<'a>,
    {
        let object = input.into_reader()?;
        let ehdr = self.read_expected_ehdr(&object, ExpectedElf::Dylib)?;
        let dynamic = self.load_dynamic_from_ehdr(&object, ehdr)?;
        let dylib = RawDylib::from_dynamic(dynamic);

        Ok(dylib)
    }

    /// Loads any dynamic ELF image into memory and returns a raw dynamic image.
    ///
    /// Unlike [`Loader::load_dylib`], this accepts both `ET_DYN` shared objects
    /// and `ET_EXEC` executables that carry a `PT_DYNAMIC` segment. The returned
    /// value is mapped but not yet relocated. Call `.relocator().relocate()` to
    /// resolve symbols and produce a ready-to-use loaded image.
    pub fn load_dynamic<'a, I>(&mut self, input: I) -> Result<RawDynamic<D, Arch, M::Region>>
    where
        I: IntoElfReader<'a>,
    {
        let object = input.into_reader()?;
        logging::debug!("Loading dynamic image: {}", object.path());

        let ehdr = self.read_expected_ehdr(&object, ExpectedElf::Dynamic)?;
        let image = self.load_dynamic_from_ehdr(&object, ehdr)?;
        let base = image.base();

        logging::info!("Loaded dynamic image: {} at {}", image.name(), base);

        Ok(image)
    }

    fn load_dynamic_from_ehdr(
        &mut self,
        object: &impl ElfReader,
        ehdr: ElfHeader<Arch::Layout>,
    ) -> Result<RawDynamic<D, Arch, M::Region>> {
        let phdrs = self.buf.prepare_phdrs(&ehdr, object)?.unwrap_or_default();
        if !has_dynamic_phdr(phdrs) {
            return Err(ParsePhdrError::MissingDynamicSection.into());
        }

        let path = PathBuf::from(object.path());
        let mut user_data = D::default();
        self.inner
            .observer
            .on_before_dynamic_load(BeforeDynamicLoadEvent::new(
                path.as_path(),
                &ehdr,
                phdrs,
                &mut user_data,
            ))?;
        let page_size = self.inner.page_size()?.bytes();
        let segments = ProgramSegments::load(
            phdrs,
            ehdr.is_dylib(),
            self.inner.mapper(),
            object,
            page_size,
        )?;
        let force_static_tls = self.inner.force_static_tls();
        let builder: ImageBuilder<Tls, D, Arch, M::Region> =
            ImageBuilder::new(segments, path, ehdr, force_static_tls, page_size, user_data);
        let mut image = RawDynamic::from_builder(builder, phdrs)?;
        self.notify_after_dynamic_load(&mut image)?;
        Ok(image)
    }

    /// Maps a previously scanned dynamic image without rereading its ELF header
    /// or program headers.
    ///
    /// The scanned object's reader is reused for segment loading. User data is
    /// initialized through the loader's dynamic initializer, like ordinary dynamic loads.
    pub fn load_scanned_dynamic(
        &mut self,
        scanned: ScannedDynamic<Arch>,
    ) -> Result<RawDynamic<D, Arch, M::Region>> {
        let crate::image::ScannedDynamicLoadParts {
            ehdr,
            phdrs,
            reader,
        } = scanned.into_load_parts();

        logging::debug!("Loading scanned dynamic image: {}", reader.path());

        let path = PathBuf::from(reader.path());
        let mut user_data = D::default();
        self.inner
            .observer
            .on_before_dynamic_load(BeforeDynamicLoadEvent::new(
                path.as_path(),
                &ehdr,
                &phdrs,
                &mut user_data,
            ))?;
        let page_size = self.inner.page_size()?.bytes();
        let segments = ProgramSegments::load(
            &phdrs,
            ehdr.is_dylib(),
            self.inner.mapper(),
            &reader,
            page_size,
        )?;
        let force_static_tls = self.inner.force_static_tls();
        let builder: ImageBuilder<Tls, D, Arch, M::Region> =
            ImageBuilder::new(segments, path, ehdr, force_static_tls, page_size, user_data);
        let mut image = RawDynamic::from_builder(builder, &phdrs)?;
        self.notify_after_dynamic_load(&mut image)?;
        let base = image.base();

        logging::info!("Loaded scanned dynamic image: {} at {}", image.name(), base);

        Ok(image)
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
        path: impl Into<PathBuf>,
        load_bias: VmAddr,
        phdrs: impl Into<Vec<ElfPhdr<Arch::Layout>>>,
        entry: usize,
    ) -> Result<RawDynamic<D, Arch, M::Region>> {
        let path = path.into();
        let phdrs = phdrs.into();
        let page_size = self.inner.page_size()?.bytes();
        let layout = parse_segments(&phdrs, true, page_size)?;
        let mapped_addr = load_bias + layout.min_vaddr;
        let segments = ElfSegments::new(
            unsafe {
                self.inner
                    .mapper()
                    .alias_space(mapped_addr, layout.mapped_len)?
            },
            load_bias,
            layout.min_vaddr,
        );
        let parts = borrowed_dynamic_parts::<D, Arch, M::Region>(
            path,
            load_bias,
            entry,
            &phdrs,
            segments,
            self.inner.force_static_tls(),
            D::default(),
            page_size,
        )?;
        let mut image = RawDynamic::from_parts::<Tls>(parts)?;
        self.notify_after_dynamic_load(&mut image)?;
        let base = image.base();

        logging::info!("Borrowed dynamic image: {} at {}", image.name(), base);

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
    pub fn load_exec<'a, I>(&mut self, input: I) -> Result<RawExec<D, Arch, M::Region>>
    where
        I: IntoElfReader<'a>,
    {
        let object = input.into_reader()?;
        logging::info!("Loading executable: {}", object.path());

        let ehdr = self.read_expected_ehdr(&object, ExpectedElf::Executable)?;
        self.load_exec_from_ehdr(&object, ehdr)
    }

    fn load_exec_from_ehdr(
        &mut self,
        object: &impl ElfReader,
        ehdr: ElfHeader<Arch::Layout>,
    ) -> Result<RawExec<D, Arch, M::Region>> {
        let phdrs = self.buf.prepare_phdrs(&ehdr, object)?.unwrap_or_default();
        let has_dynamic = has_dynamic_phdr(phdrs);

        let path = PathBuf::from(object.path());
        let mut user_data = D::default();
        if has_dynamic {
            self.inner
                .observer
                .on_before_dynamic_load(BeforeDynamicLoadEvent::new(
                    path.as_path(),
                    &ehdr,
                    phdrs,
                    &mut user_data,
                ))?;
        }
        let page_size = self.inner.page_size()?.bytes();
        let segments = ProgramSegments::load(
            phdrs,
            ehdr.is_dylib(),
            self.inner.mapper(),
            object,
            page_size,
        )?;
        let force_static_tls = self.inner.force_static_tls();
        let builder: ImageBuilder<Tls, D, Arch, M::Region> =
            ImageBuilder::new(segments, path, ehdr, force_static_tls, page_size, user_data);
        let mut exec = RawExec::from_builder(builder, phdrs, has_dynamic)?;
        if let RawExec::Dynamic(dynamic) = &mut exec {
            self.notify_after_dynamic_load(dynamic)?;
        }
        let base = exec.base();

        logging::debug!(
            "Load executable: {} at {} ({})",
            exec.name(),
            base,
            if has_dynamic { "dynamic" } else { "static" }
        );

        Ok(exec)
    }
}

#[inline]
fn has_dynamic_phdr<L: crate::elf::ElfLayout>(phdrs: &[ElfPhdr<L>]) -> bool {
    phdrs
        .iter()
        .any(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
}

#[derive(Clone, Copy)]
pub(crate) enum ExpectedElf {
    Dylib,
    Dynamic,
    Executable,
    #[cfg(feature = "object")]
    Relocatable,
}

impl ExpectedElf {
    #[inline]
    fn matches<L: crate::elf::ElfLayout>(self, ehdr: &ElfHeader<L>) -> bool {
        match self {
            Self::Dylib => ehdr.is_dylib(),
            Self::Dynamic | Self::Executable => ehdr.is_executable(),
            #[cfg(feature = "object")]
            Self::Relocatable => ehdr.file_type() == ElfFileType::REL,
        }
    }

    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::Dylib => "dylib",
            Self::Dynamic => "dynamic image",
            Self::Executable => "executable",
            #[cfg(feature = "object")]
            Self::Relocatable => "relocatable object",
        }
    }

    #[inline]
    const fn error(self, found: ElfFileType) -> ParseEhdrError {
        match self {
            Self::Dylib => ParseEhdrError::ExpectedDylib { found },
            Self::Dynamic | Self::Executable => ParseEhdrError::ExpectedExecutable { found },
            #[cfg(feature = "object")]
            Self::Relocatable => ParseEhdrError::ExpectedRelocatable { found },
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn borrowed_dynamic_parts<D, Arch, R>(
    path: PathBuf,
    load_bias: VmAddr,
    entry: usize,
    phdrs: &[ElfPhdr<Arch::Layout>],
    segments: ElfSegments<R>,
    force_static_tls: bool,
    user_data: D,
    page_size: usize,
) -> Result<RawDynamicParts<D, Arch, R>>
where
    D: 'static,
    Arch: RelocationArch,
    R: RegionAccess,
{
    let mut dynamic = None;
    let mut dynamic_addr = None;
    let mut interp = None;
    let mut eh_frame_hdr = None;
    let mut tls_info = None;
    let mut relro = None;

    for phdr in phdrs {
        match phdr.program_type() {
            ElfProgramType::DYNAMIC => {
                dynamic_addr = Some(load_bias + phdr.p_vaddr());
                dynamic = Some(
                    segments
                        .read_view::<ElfDyn<Arch::Layout>>(phdr.p_vaddr(), phdr.p_filesz())
                        .ok_or_else(|| {
                            ParsePhdrError::malformed(
                                "PT_DYNAMIC is not directly readable from mapped segments",
                            )
                        })?,
                );
            }
            ElfProgramType::INTERP => {
                interp = Some(read_borrowed_interp(&segments, phdr)?);
            }
            ElfProgramType::GNU_EH_FRAME => {
                eh_frame_hdr = Some(
                    segments
                        .host_ptr_range(segments.base() + phdr.p_vaddr(), phdr.p_filesz())
                        .ok_or_else(|| {
                            ParsePhdrError::malformed(
                                "PT_GNU_EH_FRAME is not directly readable from mapped segments",
                            )
                        })?,
                );
            }
            ElfProgramType::TLS => {
                let image = segments
                    .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())
                    .ok_or(crate::ParsePhdrError::malformed(
                        "PT_TLS image is malformed",
                    ))?;
                tls_info = Some(crate::tls::TlsInfo::new(phdr, image.as_slice()));
            }
            ElfProgramType::GNU_RELRO => {
                relro = Some(MemoryProtection::new(
                    load_bias + phdr.p_vaddr(),
                    phdr.p_memsz(),
                    page_size,
                    ProtFlags::PROT_READ,
                ));
            }
            _ => {}
        }
    }

    let dynamic = dynamic.ok_or(ParsePhdrError::MissingDynamicSection)?;
    let dynamic_addr = dynamic_addr.ok_or(ParsePhdrError::MissingDynamicSection)?;
    Ok(RawDynamicParts {
        path,
        entry: VmAddr::new(entry),
        interp,
        phdrs: ElfPhdrs::Vec(Vec::from(phdrs)),
        dynamic,
        dynamic_addr,
        eh_frame_hdr,
        tls_info,
        force_static_tls,
        relro,
        segments,
        user_data,
    })
}

fn read_borrowed_interp<L, R>(segments: &ElfSegments<R>, phdr: &ElfPhdr<L>) -> Result<&'static str>
where
    L: ElfLayout,
    R: RegionAccess,
{
    let view = segments
        .read_view::<u8>(phdr.p_vaddr(), phdr.p_filesz())
        .ok_or_else(|| {
            ParsePhdrError::malformed("PT_INTERP is not directly readable from mapped segments")
        })?;
    let bytes = view.as_slice();
    let Some(nul) = bytes.iter().position(|byte| *byte == 0) else {
        return Err(ParsePhdrError::malformed("PT_INTERP is missing a NUL terminator").into());
    };
    if nul == 0 {
        return Err(ParsePhdrError::malformed("PT_INTERP is empty").into());
    }
    core::str::from_utf8(&bytes[..nul])
        .map_err(|_| ParsePhdrError::InvalidUtf8 { field: "PT_INTERP" }.into())
}

#[cfg(test)]
mod tests {
    use super::{ElfHeader, ElfPhdr};
    use crate::{
        Result,
        elf::{ElfEhdr, ElfLayout, NativeElfLayout},
        input::{ElfReader, Path},
        loader::ElfBuf,
        relocation::RelocationArch,
    };
    use alloc::vec::Vec;
    use core::mem::size_of;
    use elf::abi::{EI_CLASS, EI_VERSION, ELFMAGIC, ET_DYN, EV_CURRENT};

    struct TestReader {
        bytes: Vec<u8>,
    }

    struct UnalignedBorrowReader {
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
        fn path(&self) -> &Path {
            Path::new("<test>")
        }

        fn len(&self) -> usize {
            self.bytes.len()
        }

        fn read(&self, buf: &mut [u8], offset: usize) -> Result<()> {
            buf.copy_from_slice(&self.bytes[offset..offset + buf.len()]);
            Ok(())
        }

        fn as_fd(&self) -> Option<isize> {
            None
        }
    }

    impl UnalignedBorrowReader {
        fn zeroed(size: usize) -> Self {
            Self {
                bytes: alloc::vec![0; size + 1],
            }
        }
    }

    impl ElfReader for UnalignedBorrowReader {
        fn path(&self) -> &Path {
            Path::new("<test>")
        }

        fn len(&self) -> usize {
            self.bytes.len() - 1
        }

        fn read(&self, buf: &mut [u8], offset: usize) -> Result<()> {
            let offset = offset + 1;
            buf.copy_from_slice(&self.bytes[offset..offset + buf.len()]);
            Ok(())
        }

        fn borrow_bytes(&self, offset: usize, len: usize) -> Result<Option<&[u8]>> {
            let offset = offset + 1;
            Ok(Some(&self.bytes[offset..offset + len]))
        }

        fn as_fd(&self) -> Option<isize> {
            None
        }
    }

    fn make_header(phentsize: usize, phnum: usize, shentsize: usize, shnum: usize) -> ElfHeader {
        let mut ehdr = unsafe { core::mem::zeroed::<ElfEhdr>() };
        ehdr.e_ident[0..4].copy_from_slice(&ELFMAGIC);
        ehdr.e_ident[EI_CLASS] = <NativeElfLayout as ElfLayout>::E_CLASS;
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_type = ET_DYN as _;
        ehdr.e_machine = crate::arch::NativeArch::MACHINE.raw();
        ehdr.e_version = EV_CURRENT.into();
        ehdr.e_ehsize = <NativeElfLayout as ElfLayout>::EHDR_SIZE as _;
        ehdr.e_phoff = <NativeElfLayout as ElfLayout>::EHDR_SIZE as _;
        ehdr.e_phentsize = phentsize as _;
        ehdr.e_phnum = phnum as _;
        ehdr.e_shoff = (<NativeElfLayout as ElfLayout>::EHDR_SIZE + 128) as _;
        ehdr.e_shentsize = shentsize as _;
        ehdr.e_shnum = shnum as _;

        ElfHeader::from_raw(ehdr, Some(crate::arch::NativeArch::MACHINE))
            .expect("failed to parse crafted header")
    }

    #[test]
    fn prepare_phdrs_rejects_entry_size_mismatch() {
        let mut elf_buf = ElfBuf::new();
        let header = make_header(size_of::<ElfPhdr>() + 8, 1, 0, 0);
        let reader = TestReader::zeroed(512);

        let err = elf_buf
            .prepare_phdrs(&header, &reader)
            .expect_err("phdr entry size mismatch should fail");
        assert!(matches!(
            err,
            crate::Error::ParsePhdr(crate::ParsePhdrError::InvalidEntrySize { .. })
        ));
    }

    #[test]
    fn prepare_phdrs_rejects_table_past_object_len() {
        let mut elf_buf = ElfBuf::new();
        let header = make_header(size_of::<ElfPhdr>(), 2, 0, 0);
        let reader =
            TestReader::zeroed(<NativeElfLayout as ElfLayout>::EHDR_SIZE + size_of::<ElfPhdr>());

        let err = elf_buf
            .prepare_phdrs(&header, &reader)
            .expect_err("phdr table past object length should fail");
        assert!(matches!(
            err,
            crate::Error::Io(crate::IoError::ReadOutOfBounds(_))
        ));
    }

    #[test]
    fn prepare_phdrs_falls_back_when_borrow_is_unaligned() {
        let mut elf_buf = ElfBuf::new();
        let header = make_header(size_of::<ElfPhdr>(), 1, 0, 0);
        let reader = UnalignedBorrowReader::zeroed(
            <NativeElfLayout as ElfLayout>::EHDR_SIZE + size_of::<ElfPhdr>(),
        );

        let phdrs = elf_buf
            .prepare_phdrs(&header, &reader)
            .expect("unaligned borrow should fall back to aligned scratch")
            .expect("program headers should exist");
        assert_eq!(phdrs.len(), 1);
    }
}
