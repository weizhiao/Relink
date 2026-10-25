#[cfg(feature = "object")]
use crate::object::SectionGroups;
#[cfg(feature = "object")]
use crate::sync::Arc;
use crate::{
    ParseEhdrError, ParsePhdrError, Result,
    arch::NativeArch,
    elf::{ElfFileType, ElfHeader, ElfLayout, ElfPhdr, ElfProgramType, ElfShdr},
    image::{
        RawDylib, RawDynamic, RawElf, RawExec, ScannedDynamic, ScannedDynamicLoadParts, ScannedElf,
        ScannedExec, SearchPathPool,
    },
    input::{ElfReader, IntoElfReader, ModuleSourceId, PathBuf},
    logging,
    memory::{VmAddr, VmOffset},
    observer::{AfterDynamicLoadEvent, BeforeLoadEvent, LoadObserver},
    os::{DefaultMmap, Mmap},
    relocation::{ObjectArch, RelocationArch},
    runtime::Domain,
    segment::{
        ElfSegments,
        program::{load_segments, parse_segments},
    },
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};

use super::{ElfBuf, ExpectedElf, ImageBuilder, Loader, ScanBuilder, read_ehdr};

/// Per-run loader state.
///
/// A [`Loader`] owns reusable loading configuration. `LoaderRun` owns the
/// selected runtime domain and scratch buffer for one sequence of loads.
pub struct LoaderRun<
    'a,
    Obs = (),
    D: Send + Sync + 'static = (),
    Tls = (),
    Arch = NativeArch,
    M = DefaultMmap,
> where
    Obs: LoadObserver<D, Arch>,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    pub(crate) loader: &'a Loader<D, Arch, M>,
    pub(crate) domain: Domain<Arch, Tls>,
    pub(crate) observer: Obs,
    pub(super) buf: ElfBuf,
    pub(crate) search_paths: Option<&'a mut SearchPathPool>,
    #[cfg(feature = "object")]
    pub(crate) object_groups: Arc<SectionGroups>,
}

impl<'a, Obs, D, Tls, Arch, M> LoaderRun<'a, Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    /// Replaces the observer used by this loader run.
    #[inline]
    pub fn with_observer<NewObs>(self, observer: NewObs) -> LoaderRun<'a, NewObs, D, Tls, Arch, M>
    where
        NewObs: LoadObserver<D, Arch>,
    {
        LoaderRun {
            loader: self.loader,
            domain: self.domain,
            observer,
            buf: self.buf,
            search_paths: self.search_paths,
            #[cfg(feature = "object")]
            object_groups: self.object_groups,
        }
    }

    /// Uses `pool` to share canonical `DT_RPATH` and `DT_RUNPATH` directories
    /// with modules produced by other loader runs using the same pool.
    #[inline]
    pub fn with_search_path_pool(mut self, pool: &'a mut SearchPathPool) -> Self {
        self.search_paths = Some(pool);
        self
    }
}

impl<'run, Obs, D: Send + Sync + 'static, Tls, Arch, M> LoaderRun<'run, Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    /// Reads and validates the ELF header against the loader's target architecture.
    /// Use [`Loader::with_arch`] to select a different target.
    pub fn read_ehdr(&self, object: &(impl ElfReader + ?Sized)) -> Result<ElfHeader<Arch::Layout>> {
        read_ehdr::<Arch>(object)
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
        &self,
        object: &impl ElfReader,
        expected: ExpectedElf,
    ) -> Result<ElfHeader<Arch::Layout>> {
        let ehdr = self.read_ehdr(object)?;
        Self::validate_expected_ehdr(object, ehdr, expected)
    }

    fn validate_expected_ehdr(
        object: &impl ElfReader,
        ehdr: ElfHeader<Arch::Layout>,
        expected: ExpectedElf,
    ) -> Result<ElfHeader<Arch::Layout>> {
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

    /// Scans an executable or dynamic ELF image without mapping its segments.
    ///
    /// Images with `PT_DYNAMIC` are returned as [`ScannedElf::Dynamic`]. Executable
    /// images without `PT_DYNAMIC` are returned as [`ScannedElf::StaticExec`].
    pub fn scan<I>(&mut self, input: I) -> Result<ScannedElf<Arch>>
    where
        I: IntoElfReader,
        I::Reader: 'static,
    {
        let object = input.into_reader()?;
        let ehdr = self.read_ehdr(&object)?;
        self.scan_with_ehdr(Box::new(object), ehdr)
    }

    /// Reuses a header already validated for this architecture.
    pub(crate) fn scan_with_ehdr(
        &mut self,
        object: Box<dyn ElfReader>,
        ehdr: ElfHeader<Arch::Layout>,
    ) -> Result<ScannedElf<Arch>> {
        scan::<Arch>(
            object,
            &mut self.buf,
            self.search_paths.as_deref_mut(),
            ehdr,
        )
    }
}

impl<'run, Obs, D, Tls, Arch, M> LoaderRun<'run, Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: Default + Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    /// Loads an ELF image, detecting whether it is a shared object, executable, or object file.
    /// `ET_DYN` images are classified using their program headers.
    pub fn load<I>(&mut self, input: I) -> Result<RawElf<D, Arch, M::Region, Tls>>
    where
        Arch: ObjectArch,
        I: IntoElfReader,
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
                    let dynamic = self.load_dynamic_impl(&object, ehdr)?;
                    Ok(RawElf::Dylib(dynamic.into()))
                }
            }
            other => Err(ParseEhdrError::UnexpectedFileType {
                expected: &[ElfFileType::EXEC, ElfFileType::DYN],
                found: other,
            }
            .into()),
        }
    }

    /// Maps a shared object (`ET_DYN`) from a path, bytes, or another [`IntoElfReader`] input.
    /// Pass the raw image to [`crate::Relocator::run`] to relocate it.
    /// Select non-native targets with [`Loader::with_arch`] before creating this run.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::{Loader, Relocator};
    ///
    /// let config = Loader::new();
    /// use elf_loader::{AddressSpaceId, Domain};
    /// let domain = Domain::native(AddressSpaceId::PROCESS);
    /// let mut loader = config.run(domain);
    /// let raw = loader.load_dylib("path/to/liba.so").unwrap();
    /// let lib = Relocator::new().run(raw).relocate().unwrap();
    /// ```
    pub fn load_dylib<I>(&mut self, input: I) -> Result<RawDylib<D, Arch, M::Region, Tls>>
    where
        I: IntoElfReader,
    {
        let object = input.into_reader()?;
        let ehdr = self.read_expected_ehdr(&object, ExpectedElf::Dylib)?;
        let dynamic = self.load_dynamic_impl(&object, ehdr)?;
        let dylib = dynamic.into();

        Ok(dylib)
    }

    /// Maps an `ET_DYN` or `ET_EXEC` image containing a `PT_DYNAMIC` segment.
    /// Pass the raw image to [`crate::Relocator::run`] to relocate it.
    pub fn load_dynamic<I>(&mut self, input: I) -> Result<RawDynamic<D, Arch, M::Region, Tls>>
    where
        I: IntoElfReader,
    {
        let object = input.into_reader()?;
        let ehdr = self.read_ehdr(&object)?;
        self.load_dynamic_with_ehdr(object, ehdr)
    }

    /// Reuses a header already validated for this architecture.
    pub(crate) fn load_dynamic_with_ehdr(
        &mut self,
        object: impl ElfReader,
        ehdr: ElfHeader<Arch::Layout>,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        logging::debug!("Loading dynamic image: {}", object.path());

        let ehdr = Self::validate_expected_ehdr(&object, ehdr, ExpectedElf::Dynamic)?;
        self.load_dynamic_impl(&object, ehdr)
    }

    /// Builds the shared mapped-image state after headers have been read.
    /// Keep the observer before dynamic validation and segment allocation.
    fn prepare_image(
        loader: &Loader<D, Arch, M>,
        domain: Domain<Arch, Tls>,
        observer: &mut Obs,
        object: &impl ElfReader,
        ehdr: ElfHeader<Arch::Layout>,
        phdrs: &[ElfPhdr<Arch::Layout>],
        require_dynamic: bool,
    ) -> Result<(ImageBuilder<Tls, D, Arch, M::Region>, bool)> {
        let path = PathBuf::from(object.path());
        let mut user_data = D::default();
        let event = BeforeLoadEvent::new(path.as_path(), object, &ehdr, phdrs, &mut user_data);
        let has_dynamic = event.is_dynamic();
        observer.on_before_load(event)?;
        if require_dynamic && !has_dynamic {
            return Err(ParsePhdrError::MissingDynamicSection.into());
        }

        let page_size = loader.page_size()?.bytes();
        let segments = load_segments(phdrs, ehdr.is_dylib(), loader.mapper(), object, page_size)?;
        let entry = image_entry::<Arch>(segments.base(), &ehdr);
        let builder = ImageBuilder::new(
            segments,
            path,
            object.source_id(),
            Some(ehdr),
            entry,
            loader.force_static_tls(),
            page_size,
            user_data,
            domain,
        );
        Ok((builder, has_dynamic))
    }

    fn finish_dynamic_load(
        builder: ImageBuilder<Tls, D, Arch, M::Region>,
        phdrs: &[ElfPhdr<Arch::Layout>],
        observer: &mut Obs,
        search_paths: Option<&mut SearchPathPool>,
        operation: &str,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        let mut image = builder.build_dynamic(phdrs, search_paths)?;
        observer.on_after_dynamic_load(AfterDynamicLoadEvent::new(&mut image))?;
        logging::info!(
            "{}: {} ({})",
            operation,
            image.name().escape_ascii(),
            image.segments()
        );
        Ok(image)
    }

    fn load_dynamic_impl(
        &mut self,
        object: &impl ElfReader,
        ehdr: ElfHeader<Arch::Layout>,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        let phdrs = self.buf.prepare_phdrs(&ehdr, object)?.unwrap_or_default();
        let (builder, _) = Self::prepare_image(
            self.loader,
            self.domain.clone(),
            &mut self.observer,
            object,
            ehdr,
            phdrs,
            true,
        )?;
        Self::finish_dynamic_load(
            builder,
            phdrs,
            &mut self.observer,
            self.search_paths.as_deref_mut(),
            "Loaded dynamic image",
        )
    }

    /// Maps a scanned dynamic image using its saved metadata and reader.
    /// User data is initialized as for ordinary dynamic loads.
    pub fn load_scanned_dynamic(
        &mut self,
        scanned: ScannedDynamic<Arch>,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        let ScannedDynamicLoadParts {
            ehdr,
            phdrs,
            reader,
        } = scanned.into_load_parts();

        logging::debug!("Loading scanned dynamic image: {}", reader.path());

        let (builder, _) = Self::prepare_image(
            self.loader,
            self.domain.clone(),
            &mut self.observer,
            &reader,
            ehdr,
            &phdrs,
            false,
        )?;
        Self::finish_dynamic_load(
            builder,
            &phdrs,
            &mut self.observer,
            self.search_paths.as_deref_mut(),
            "Loaded scanned dynamic image",
        )
    }

    /// Wraps an already mapped dynamic image for relocation, such as a kernel-loaded executable.
    ///
    /// `load_bias` translates ELF virtual addresses to runtime addresses; it is
    /// usually zero for fixed `ET_EXEC` images. `entry` is the runtime entry address
    /// (such as `AT_ENTRY`).
    ///
    /// # Safety
    /// `phdrs` must describe a valid image. Every `PT_LOAD` range must be mapped at
    /// `load_bias + p_vaddr`, remain valid for the returned image's lifetime, and
    /// be writable wherever relocation will write.
    pub unsafe fn load_mapped_dynamic(
        &mut self,
        path: impl Into<PathBuf>,
        load_bias: VmAddr,
        phdrs: impl Into<Vec<ElfPhdr<Arch::Layout>>>,
        entry: usize,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        let path = path.into();
        let phdrs = phdrs.into();
        let page_size = self.loader.page_size()?.bytes();
        let layout = parse_segments(&phdrs, true, page_size)?;
        let min_vaddr = VmOffset::new(layout.offset);
        let mapped_addr = load_bias + min_vaddr;
        let segments = ElfSegments::new(
            unsafe { self.loader.mapper().alias_space(mapped_addr, layout.len)? },
            load_bias,
            min_vaddr,
        );
        let builder = ImageBuilder::<Tls, D, Arch, M::Region>::new(
            segments,
            path,
            ModuleSourceId::fresh(),
            None,
            VmAddr::new(entry),
            self.loader.force_static_tls(),
            page_size,
            D::default(),
            self.domain.clone(),
        );
        Self::finish_dynamic_load(
            builder,
            &phdrs,
            &mut self.observer,
            self.search_paths.as_deref_mut(),
            "Borrowed dynamic image",
        )
    }

    /// Loads an executable image into memory and returns a raw executable.
    ///
    /// Both static executables and dynamically-linked / PIE-style executables are supported.
    /// Dynamic executables can later be relocated with
    /// [`crate::Relocator::run`].
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::Loader;
    ///
    /// let config = Loader::new();
    /// use elf_loader::{AddressSpaceId, Domain};
    /// let domain = Domain::native(AddressSpaceId::PROCESS);
    /// let mut loader = config.run(domain);
    /// let exec = loader.load_exec("path/to/program").unwrap();
    /// println!("entry = 0x{:x}", exec.entry());
    /// ```
    pub fn load_exec<I>(&mut self, input: I) -> Result<RawExec<D, Arch, M::Region, Tls>>
    where
        I: IntoElfReader,
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
    ) -> Result<RawExec<D, Arch, M::Region, Tls>> {
        let phdrs = self.buf.prepare_phdrs(&ehdr, object)?.unwrap_or_default();
        let (builder, has_dynamic) = Self::prepare_image(
            self.loader,
            self.domain.clone(),
            &mut self.observer,
            object,
            ehdr,
            phdrs,
            false,
        )?;
        let mut exec = builder.build_exec(phdrs, has_dynamic, self.search_paths.as_deref_mut())?;
        if let RawExec::Dynamic(dynamic) = &mut exec {
            self.observer
                .on_after_dynamic_load(AfterDynamicLoadEvent::new(dynamic))?;
        }
        let base = exec.base();

        logging::debug!(
            "Load executable: {} at {} ({})",
            exec.name().escape_ascii(),
            base,
            if has_dynamic { "dynamic" } else { "static" }
        );

        Ok(exec)
    }
}

#[inline]
fn has_dynamic_phdr<L: ElfLayout>(phdrs: &[ElfPhdr<L>]) -> bool {
    phdrs
        .iter()
        .any(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
}

#[inline]
fn image_entry<Arch: RelocationArch>(base: VmAddr, ehdr: &ElfHeader<Arch::Layout>) -> VmAddr {
    if ehdr.is_dylib() {
        base + VmOffset::new(ehdr.e_entry())
    } else {
        VmAddr::new(ehdr.e_entry())
    }
}

fn scan<Arch: RelocationArch>(
    object: Box<dyn ElfReader>,
    buf: &mut ElfBuf,
    search_paths: Option<&mut SearchPathPool>,
    ehdr: ElfHeader<Arch::Layout>,
) -> Result<ScannedElf<Arch>> {
    logging::debug!("Scanning ELF metadata: {}", object.path());

    if !ExpectedElf::Executable.matches(&ehdr) {
        return Err(ExpectedElf::Executable.error(ehdr.file_type()).into());
    }
    let phdrs = buf.prepare_phdrs(&ehdr, &object)?.unwrap_or_default();
    let has_dynamic = has_dynamic_phdr(phdrs);
    let phdrs = Box::from(phdrs);
    let path = PathBuf::from(object.path());
    let builder = ScanBuilder {
        path,
        ehdr,
        phdrs,
        reader: object,
    };

    if has_dynamic {
        return ScannedDynamic::<Arch>::from_builder(builder, search_paths)
            .map(ScannedElf::Dynamic);
    }

    ScannedExec::<Arch>::from_builder(builder).map(ScannedElf::StaticExec)
}

impl<D: Send + Sync + 'static, Arch, M> Loader<D, Arch, M>
where
    (): LoadObserver<D, Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    /// Reads the ELF header without creating runtime state.
    #[inline]
    pub fn read_ehdr(&self, object: &(impl ElfReader + ?Sized)) -> Result<ElfHeader<Arch::Layout>> {
        read_ehdr::<Arch>(object)
    }

    /// Scans an executable or dynamic ELF image without mapping its segments.
    #[inline]
    pub fn scan<I>(&self, input: I) -> Result<ScannedElf<Arch>>
    where
        I: IntoElfReader,
        I::Reader: 'static,
    {
        let object = input.into_reader()?;
        let ehdr = self.read_ehdr(&object)?;
        scan::<Arch>(Box::new(object), &mut ElfBuf::new(), None, ehdr)
    }
}

#[cfg(test)]
mod tests {
    use super::{ElfHeader, ElfPhdr};
    use crate::{
        Error, IoError, ParsePhdrError, Result,
        arch::NativeArch,
        elf::{ElfEhdr, ElfLayout, NativeElfLayout},
        input::{ElfReader, ModuleSourceId, Path},
        loader::ElfBuf,
        relocation::RelocationArch,
    };
    use alloc::vec::Vec;
    use core::mem::size_of;
    use elf::abi::{EI_CLASS, EI_DATA, EI_VERSION, ELFMAGIC, ET_DYN, EV_CURRENT};

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

        fn source_id(&self) -> ModuleSourceId {
            ModuleSourceId::opaque(0, 1)
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

        fn source_id(&self) -> ModuleSourceId {
            ModuleSourceId::opaque(0, 2)
        }

        fn borrow_bytes(&self, offset: usize, len: usize) -> Result<Option<&[u8]>> {
            let offset = offset + 1;
            Ok(Some(&self.bytes[offset..offset + len]))
        }
    }

    fn make_header(phentsize: usize, phnum: usize, shentsize: usize, shnum: usize) -> ElfHeader {
        let mut ehdr = unsafe { core::mem::zeroed::<ElfEhdr>() };
        ehdr.e_ident[0..4].copy_from_slice(&ELFMAGIC);
        ehdr.e_ident[EI_CLASS] = <NativeElfLayout as ElfLayout>::CLASS.raw();
        ehdr.e_ident[EI_DATA] = <NativeElfLayout as ElfLayout>::DATA_ENCODING.raw();
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_type = ET_DYN as _;
        ehdr.e_machine = NativeArch::MACHINE.raw();
        ehdr.e_version = EV_CURRENT.into();
        ehdr.e_ehsize = <NativeElfLayout as ElfLayout>::EHDR_SIZE as _;
        ehdr.e_phoff = <NativeElfLayout as ElfLayout>::EHDR_SIZE as _;
        ehdr.e_phentsize = phentsize as _;
        ehdr.e_phnum = phnum as _;
        ehdr.e_shoff = (<NativeElfLayout as ElfLayout>::EHDR_SIZE + 128) as _;
        ehdr.e_shentsize = shentsize as _;
        ehdr.e_shnum = shnum as _;

        ElfHeader::from_raw(ehdr, NativeArch::TARGET).expect("failed to parse crafted header")
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
            Error::ParsePhdr(ParsePhdrError::InvalidEntrySize { .. })
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
        assert!(matches!(err, Error::Io(IoError::ReadOutOfBounds(_))));
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
