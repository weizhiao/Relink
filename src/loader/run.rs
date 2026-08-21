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
    runtime::{CodeExecutor, NativeCodeExecutor},
    segment::{
        ElfSegments,
        program::{ProgramSegments, parse_segments},
    },
    tls::TlsResolver,
};
use alloc::{boxed::Box, vec::Vec};

use super::{ElfBuf, ExpectedElf, ImageBuilder, Loader, ScanBuilder, read_ehdr};

/// Per-run loader state.
///
/// A [`Loader`] owns reusable loading configuration. `LoaderRun` owns the
/// scratch buffer used while reading ELF metadata for one sequence of loads.
pub struct LoaderRun<
    'a,
    Obs = (),
    D: Send + Sync + 'static = (),
    Tls = (),
    Arch = NativeArch,
    M = DefaultMmap,
    Exec = NativeCodeExecutor,
> where
    Obs: LoadObserver<D, Arch>,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    pub(crate) loader: &'a Loader<D, Tls, Arch, M, Exec>,
    pub(crate) observer: Obs,
    pub(super) buf: ElfBuf,
    pub(crate) search_paths: Option<&'a mut SearchPathPool>,
    #[cfg(feature = "object")]
    pub(crate) object_groups: Arc<SectionGroups>,
}

impl<'a, Obs, D: Send + Sync + 'static, Tls, Arch, M, Exec>
    LoaderRun<'a, Obs, D, Tls, Arch, M, Exec>
where
    Obs: LoadObserver<D, Arch>,
    D: Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    /// Replaces the observer used by this loader run.
    #[inline]
    pub fn with_observer<NewObs>(
        self,
        observer: NewObs,
    ) -> LoaderRun<'a, NewObs, D, Tls, Arch, M, Exec>
    where
        NewObs: LoadObserver<D, Arch>,
    {
        LoaderRun {
            loader: self.loader,
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

impl<'run, Obs, D: Send + Sync + 'static, Tls, Arch, M, Exec>
    LoaderRun<'run, Obs, D, Tls, Arch, M, Exec>
where
    Obs: LoadObserver<D, Arch>,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    /// Reads the ELF header.
    ///
    /// The header target is required to equal `Arch::TARGET`. To
    /// load an ELF whose target architecture differs from the host, switch
    /// the loader's target architecture with
    /// [`Loader::for_arch`](super::Loader::for_arch) before calling
    /// `load_*`; the gate will then accept ELFs targeting `NewArch::TARGET`.
    pub fn read_ehdr(&self, object: &impl ElfReader) -> Result<ElfHeader<Arch::Layout>> {
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

impl<'run, Obs, D: Send + Sync + 'static, Tls, Arch, M, Exec>
    LoaderRun<'run, Obs, D, Tls, Arch, M, Exec>
where
    Obs: LoadObserver<D, Arch>,
    D: Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
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
            return ScannedDynamic::<Arch>::from_builder(builder, self.search_paths.as_deref_mut())
                .map(ScannedElf::Dynamic);
        }

        ScannedExec::<Arch>::from_builder(builder).map(ScannedElf::StaticExec)
    }
}

impl<'run, Obs, D: Send + Sync + 'static, Tls, Arch, M, Exec>
    LoaderRun<'run, Obs, D, Tls, Arch, M, Exec>
where
    Obs: LoadObserver<D, Arch>,
    D: Default + Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    /// Loads an ELF input and chooses the appropriate raw image type automatically.
    ///
    /// This is the most flexible entry point when the caller does not already know
    /// whether the input is a shared object, executable, or relocatable object.
    /// `ET_DYN` inputs are classified by inspecting the program headers.
    pub fn load<'a, I>(&mut self, input: I) -> Result<RawElf<D, Arch, M::Region, Tls>>
    where
        D: Send + Sync + 'static,
        Arch: ObjectArch,
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
                    let dynamic = self.load_dynamic_impl(&object, ehdr)?;
                    Ok(RawElf::Dylib(RawDylib::from_dynamic(dynamic)))
                }
            }
            other => Err(ParseEhdrError::ExpectedExecutable { found: other }.into()),
        }
    }

    /// Loads a shared object (`ET_DYN`) into memory and returns a raw dylib image.
    ///
    /// The returned value is mapped but not yet relocated. Pass it to
    /// [`crate::Relocator::run`] to resolve symbols and produce a
    /// ready-to-use loaded image.
    ///
    /// Any [`IntoElfReader`] input is accepted, including paths, byte slices,
    /// [`crate::input::ElfFile`], and [`crate::input::ElfBinary`].
    ///
    /// To load ELF files targeting a different CPU architecture than the host,
    /// switch the loader's target architecture with
    /// [`Loader::for_arch::<NewArch>()`](super::Loader::for_arch) before
    /// calling this method. The `e_machine` gate then validates against
    /// `NewArch::MACHINE`, and the returned [`RawDylib`] carries the chosen
    /// `Arch`, so [`crate::Relocator::run`] uses the matching relocation
    /// numbering and skips host-side runtime hooks (IFUNC, TLSDESC, lazy
    /// binding, init arrays).
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::{Loader, Relocator};
    ///
    /// let mut loader = Loader::new();
    /// let raw = loader.load_dylib("path/to/liba.so").unwrap();
    /// let lib = Relocator::new().run(raw).relocate().unwrap();
    /// ```
    pub fn load_dylib<'a, I>(&mut self, input: I) -> Result<RawDylib<D, Arch, M::Region, Tls>>
    where
        I: IntoElfReader<'a>,
    {
        let object = input.into_reader()?;
        let ehdr = self.read_expected_ehdr(&object, ExpectedElf::Dylib)?;
        let dynamic = self.load_dynamic_impl(&object, ehdr)?;
        let dylib = RawDylib::from_dynamic(dynamic);

        Ok(dylib)
    }

    /// Loads any dynamic ELF image into memory and returns a raw dynamic image.
    ///
    /// Unlike [`Loader::load_dylib`], this accepts both `ET_DYN` shared objects
    /// and `ET_EXEC` executables that carry a `PT_DYNAMIC` segment. The returned
    /// value is mapped but not yet relocated. Pass it to
    /// [`crate::Relocator::run`] to resolve symbols and produce a
    /// ready-to-use loaded image.
    pub fn load_dynamic<'a, I>(&mut self, input: I) -> Result<RawDynamic<D, Arch, M::Region, Tls>>
    where
        I: IntoElfReader<'a>,
    {
        let object = input.into_reader()?;
        logging::debug!("Loading dynamic image: {}", object.path());

        let ehdr = self.read_expected_ehdr(&object, ExpectedElf::Dynamic)?;
        self.load_dynamic_impl(&object, ehdr)
    }

    fn load_dynamic_impl(
        &mut self,
        object: &impl ElfReader,
        ehdr: ElfHeader<Arch::Layout>,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        let executor = self.loader.executor();
        let phdrs = self.buf.prepare_phdrs(&ehdr, object)?.unwrap_or_default();
        let path = PathBuf::from(object.path());
        let mut user_data = D::default();
        let event = BeforeLoadEvent::new(path.as_path(), object, &ehdr, phdrs, &mut user_data);
        let has_dynamic = event.is_dynamic();
        self.observer.on_before_load(event)?;
        if !has_dynamic {
            return Err(ParsePhdrError::MissingDynamicSection.into());
        }

        let page_size = self.loader.page_size()?.bytes();
        let segments = ProgramSegments::load(
            phdrs,
            ehdr.is_dylib(),
            self.loader.mapper(),
            object,
            page_size,
        )?;
        let force_static_tls = self.loader.force_static_tls();
        let entry = image_entry::<Arch>(segments.base(), &ehdr);
        let builder: ImageBuilder<Tls, D, Arch, M::Region> = ImageBuilder::new(
            segments,
            path,
            object.source_id(),
            Some(ehdr),
            entry,
            force_static_tls,
            page_size,
            user_data,
            executor,
            self.loader.domain_id(),
            self.loader.tls_resolver(),
        );
        let mut image = builder.build_dynamic(phdrs, self.search_paths.as_deref_mut())?;
        self.observer
            .on_after_dynamic_load(AfterDynamicLoadEvent::new(&mut image))?;
        logging::info!(
            "Loaded dynamic image: {} ({})",
            image.name(),
            image.segments()
        );
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
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        let ScannedDynamicLoadParts {
            ehdr,
            phdrs,
            reader,
        } = scanned.into_load_parts();

        logging::debug!("Loading scanned dynamic image: {}", reader.path());

        let path = PathBuf::from(reader.path());
        let mut user_data = D::default();
        self.observer.on_before_load(BeforeLoadEvent::new(
            path.as_path(),
            &reader,
            &ehdr,
            &phdrs,
            &mut user_data,
        ))?;
        let page_size = self.loader.page_size()?.bytes();
        let segments = ProgramSegments::load(
            &phdrs,
            ehdr.is_dylib(),
            self.loader.mapper(),
            &reader,
            page_size,
        )?;
        let force_static_tls = self.loader.force_static_tls();
        let entry = image_entry::<Arch>(segments.base(), &ehdr);
        let builder: ImageBuilder<Tls, D, Arch, M::Region> = ImageBuilder::new(
            segments,
            path,
            reader.source_id(),
            Some(ehdr),
            entry,
            force_static_tls,
            page_size,
            user_data,
            self.loader.executor(),
            self.loader.domain_id(),
            self.loader.tls_resolver(),
        );
        let mut image = builder.build_dynamic(&phdrs, self.search_paths.as_deref_mut())?;
        self.observer
            .on_after_dynamic_load(AfterDynamicLoadEvent::new(&mut image))?;

        logging::info!(
            "Loaded scanned dynamic image: {} ({})",
            image.name(),
            image.segments()
        );

        Ok(image)
    }

    /// Creates a raw dynamic image from an ELF object that is already mapped.
    ///
    /// # Safety
    ///
    /// `load_bias` and `phdrs` must describe a live mapped image that remains
    /// valid for the returned module's lifetime.
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
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        let path = path.into();
        let phdrs = phdrs.into();
        let page_size = self.loader.page_size()?.bytes();
        let layout = parse_segments(&phdrs, true, page_size)?;
        let mapped_addr = load_bias + layout.min_vaddr;
        let segments = ElfSegments::new(
            unsafe {
                self.loader
                    .mapper()
                    .alias_space(mapped_addr, layout.mapped_len)?
            },
            load_bias,
            layout.min_vaddr,
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
            self.loader.executor(),
            self.loader.domain_id(),
            self.loader.tls_resolver(),
        );
        let mut image = builder.build_dynamic(&phdrs, self.search_paths.as_deref_mut())?;
        self.observer
            .on_after_dynamic_load(AfterDynamicLoadEvent::new(&mut image))?;

        logging::info!(
            "Borrowed dynamic image: {} ({})",
            image.name(),
            image.segments()
        );

        Ok(image)
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
    /// let mut loader = Loader::new();
    /// let exec = loader.load_exec("path/to/program").unwrap();
    /// println!("entry = 0x{:x}", exec.entry());
    /// ```
    pub fn load_exec<'a, I>(&mut self, input: I) -> Result<RawExec<D, Arch, M::Region, Tls>>
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
    ) -> Result<RawExec<D, Arch, M::Region, Tls>> {
        let executor = self.loader.executor();
        let phdrs = self.buf.prepare_phdrs(&ehdr, object)?.unwrap_or_default();

        let path = PathBuf::from(object.path());
        let mut user_data = D::default();
        let event = BeforeLoadEvent::new(path.as_path(), object, &ehdr, phdrs, &mut user_data);
        let has_dynamic = event.is_dynamic();
        self.observer.on_before_load(event)?;
        let page_size = self.loader.page_size()?.bytes();
        let segments = ProgramSegments::load(
            phdrs,
            ehdr.is_dylib(),
            self.loader.mapper(),
            object,
            page_size,
        )?;
        let force_static_tls = self.loader.force_static_tls();
        let entry = image_entry::<Arch>(segments.base(), &ehdr);
        let builder: ImageBuilder<Tls, D, Arch, M::Region> = ImageBuilder::new(
            segments,
            path,
            object.source_id(),
            Some(ehdr),
            entry,
            force_static_tls,
            page_size,
            user_data,
            executor,
            self.loader.domain_id(),
            self.loader.tls_resolver(),
        );
        let mut exec = builder.build_exec(phdrs, has_dynamic, self.search_paths.as_deref_mut())?;
        if let RawExec::Dynamic(dynamic) = &mut exec {
            self.observer
                .on_after_dynamic_load(AfterDynamicLoadEvent::new(dynamic))?;
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

impl<D: Send + Sync + 'static, Tls, Arch, M, Exec> Loader<D, Tls, Arch, M, Exec>
where
    (): LoadObserver<D, Arch>,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    /// Reads the ELF header with a fresh loader run.
    #[inline]
    pub fn read_ehdr(&self, object: &impl ElfReader) -> Result<ElfHeader<Arch::Layout>> {
        self.run().read_ehdr(object)
    }
}

impl<D: Send + Sync + 'static, Tls, Arch, M, Exec> Loader<D, Tls, Arch, M, Exec>
where
    (): LoadObserver<D, Arch>,
    D: Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    /// Scans an executable or dynamic ELF image without mapping its segments.
    #[inline]
    pub fn scan<I>(&self, input: I) -> Result<ScannedElf<Arch>>
    where
        I: IntoElfReader<'static>,
    {
        self.run().scan(input)
    }
}

impl<D: Send + Sync + 'static, Tls, Arch, M, Exec> Loader<D, Tls, Arch, M, Exec>
where
    (): LoadObserver<D, Arch>,
    D: Default + Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    /// Loads an ELF input and chooses the appropriate raw image type automatically.
    #[inline]
    pub fn load<'a, I>(&self, input: I) -> Result<RawElf<D, Arch, M::Region, Tls>>
    where
        Arch: ObjectArch,
        I: IntoElfReader<'a>,
    {
        self.run().load(input)
    }

    /// Loads a shared object (`ET_DYN`) into memory and returns a raw dylib image.
    #[inline]
    pub fn load_dylib<'a, I>(&self, input: I) -> Result<RawDylib<D, Arch, M::Region, Tls>>
    where
        I: IntoElfReader<'a>,
    {
        self.run().load_dylib(input)
    }

    /// Loads any dynamic ELF image into memory and returns a raw dynamic image.
    #[inline]
    pub fn load_dynamic<'a, I>(&self, input: I) -> Result<RawDynamic<D, Arch, M::Region, Tls>>
    where
        I: IntoElfReader<'a>,
    {
        self.run().load_dynamic(input)
    }

    /// Maps a previously scanned dynamic image without rereading metadata.
    #[inline]
    pub fn load_scanned_dynamic(
        &self,
        scanned: ScannedDynamic<Arch>,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        self.run().load_scanned_dynamic(scanned)
    }

    /// Creates a raw dynamic image from an ELF object that is already mapped.
    ///
    /// # Safety
    ///
    /// `load_bias` and `phdrs` must describe a valid mapped ELF image that
    /// remains accessible through the configured memory mapper for the
    /// lifetime of the returned image.
    #[inline]
    pub unsafe fn load_mapped_dynamic(
        &self,
        path: impl Into<PathBuf>,
        load_bias: VmAddr,
        phdrs: impl Into<Vec<ElfPhdr<Arch::Layout>>>,
        entry: usize,
    ) -> Result<RawDynamic<D, Arch, M::Region, Tls>> {
        unsafe {
            self.run()
                .load_mapped_dynamic(path, load_bias, phdrs, entry)
        }
    }

    /// Loads an executable image into memory and returns a raw executable.
    #[inline]
    pub fn load_exec<'a, I>(&self, input: I) -> Result<RawExec<D, Arch, M::Region, Tls>>
    where
        I: IntoElfReader<'a>,
    {
        self.run().load_exec(input)
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

        fn source_id(&self) -> ModuleSourceId {
            ModuleSourceId::opaque(0, 2)
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
