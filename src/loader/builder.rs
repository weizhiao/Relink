use super::{DynLifecycleHandler, LoadHook, LoadHookContext, LoaderInner, UserDataLoaderContext};
use crate::{
    Result,
    elf::{ElfDyn, ElfHeader, ElfPhdr, ElfPhdrs, ElfRelType, ElfShdr, ElfSymbol, SymbolTable},
    os::Mmap,
    relocation::StaticRelocation,
    segment::{
        ELFRelro, ElfSegments, SegmentBuilder,
        program::ProgramSegments,
        section::{PltGotSection, SectionSegments},
    },
    tls::{TlsInfo, TlsResolver},
};
use alloc::{borrow::ToOwned, boxed::Box, string::String, vec::Vec};
use core::{ffi::c_char, marker::PhantomData, ptr::NonNull};
use elf::abi::{
    PT_DYNAMIC, PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_INTERP, PT_LOAD, PT_PHDR, PT_TLS, SHN_UNDEF,
    SHT_INIT_ARRAY, SHT_REL, SHT_RELA, SHT_SYMTAB, STT_FILE,
};

/// Builder for creating relocated ELF objects
///
/// This structure is used internally during the loading process to collect
/// and organize the various components of a relocated ELF file before
/// building the final RelocatedCommonPart object.
pub(crate) struct ImageBuilder<'hook, H, M, Tls, D = ()>
where
    H: LoadHook,
    M: Mmap,
    Tls: TlsResolver,
{
    /// Hook function for processing program headers (always present)
    hook: &'hook mut H,

    /// Mapped program headers
    phdr_mmap: Option<&'static [ElfPhdr]>,

    /// Name of the ELF file
    pub(crate) name: String,

    /// ELF header
    pub(crate) ehdr: ElfHeader,

    /// GNU_RELRO segment information
    pub(crate) relro: Option<ELFRelro>,

    /// Pointer to the dynamic section
    pub(crate) dynamic_ptr: Option<NonNull<ElfDyn>>,

    /// TLS information
    pub(crate) tls_info: Option<TlsInfo>,

    /// Whether to use static TLS
    pub(crate) static_tls: bool,

    /// User-defined data
    pub(crate) user_data: D,

    /// Memory segments
    pub(crate) segments: ElfSegments,

    /// Initialization function handler
    pub(crate) init_fn: DynLifecycleHandler,

    /// Finalization function handler
    pub(crate) fini_fn: DynLifecycleHandler,

    /// Pointer to the interpreter path (PT_INTERP)
    pub(crate) interp: Option<NonNull<c_char>>,

    /// Pointer to the .eh_frame_hdr section (PT_GNU_EH_FRAME)
    pub(crate) eh_frame_hdr: Option<NonNull<u8>>,

    /// Phantom data to maintain Mmap type information
    _marker: PhantomData<(M, Tls)>,
}

impl<'hook, H, M, Tls, D> ImageBuilder<'hook, H, M, Tls, D>
where
    H: LoadHook,
    Tls: TlsResolver,
    M: Mmap,
{
    /// Create a new ImageBuilder
    ///
    /// # Arguments
    /// * `hook` - Hook function for processing program headers
    /// * `segments` - Memory segments of the ELF file
    /// * `name` - Name of the ELF file
    /// * `ehdr` - ELF header
    /// * `init_fn` - Initialization function handler
    /// * `fini_fn` - Finalization function handler
    ///
    /// # Returns
    /// A new DynamicBuilder instance
    pub(crate) fn new(
        hook: &'hook mut H,
        segments: ElfSegments,
        name: String,
        ehdr: ElfHeader,
        init_fn: DynLifecycleHandler,
        fini_fn: DynLifecycleHandler,
        static_tls: bool,
        user_data: D,
    ) -> Self {
        Self {
            hook,
            phdr_mmap: None,
            name,
            ehdr,
            relro: None,
            dynamic_ptr: None,
            tls_info: None,
            static_tls,
            segments,
            user_data,
            init_fn,
            fini_fn,
            interp: None,
            eh_frame_hdr: None,
            _marker: PhantomData,
        }
    }

    /// Parse a program header and extract relevant information
    ///
    /// This method processes a program header and extracts information
    /// needed for relocation, such as the dynamic section, GNU_RELRO
    /// segment, and interpreter path.
    ///
    /// # Arguments
    /// * `phdr` - The program header to parse
    ///
    /// # Returns
    /// * `Ok(())` - If parsing succeeds
    /// * `Err(Error)` - If parsing fails
    pub(crate) fn parse_phdr(&mut self, phdr: &ElfPhdr) -> Result<()> {
        let ctx = LoadHookContext::new(&self.name, phdr, &self.segments);
        self.hook.call(&ctx)?;

        // Process different program header types
        match phdr.p_type {
            // Parse the .dynamic section
            PT_DYNAMIC => {
                self.dynamic_ptr =
                    Some(NonNull::new(self.segments.get_mut_ptr(phdr.p_paddr as usize)).unwrap())
            }

            // Store GNU_RELRO segment information
            PT_GNU_RELRO => self.relro = Some(ELFRelro::new::<M>(phdr, self.segments.base())),

            // Store program header table mapping
            PT_PHDR => {
                self.phdr_mmap = Some(
                    self.segments
                        .get_slice::<ElfPhdr>(phdr.p_vaddr as usize, phdr.p_memsz as usize),
                );
            }

            // Store interpreter path
            PT_INTERP => {
                self.interp =
                    Some(NonNull::new(self.segments.get_mut_ptr(phdr.p_vaddr as usize)).unwrap());
            }

            PT_GNU_EH_FRAME => {
                self.eh_frame_hdr =
                    Some(NonNull::new(self.segments.get_mut_ptr(phdr.p_vaddr as usize)).unwrap());
            }

            // Store TLS segment information
            PT_TLS => {
                let tls_image = self
                    .segments
                    .get_slice::<u8>(phdr.p_vaddr as usize, phdr.p_filesz as usize);
                self.tls_info = Some(TlsInfo::new(phdr, tls_image));
            }

            // Ignore other program header types
            _ => {}
        };
        Ok(())
    }

    /// Parse all program headers and collect the builder state they describe.
    pub(crate) fn parse_phdrs(&mut self, phdrs: &[ElfPhdr]) -> Result<()> {
        for phdr in phdrs {
            self.parse_phdr(phdr)?;
        }
        Ok(())
    }

    /// Create program headers from the parsed data
    ///
    /// This method creates the appropriate program header representation
    /// based on whether they are mapped in memory or need to be stored
    /// in a vector.
    ///
    /// # Arguments
    /// * `phdrs` - Slice of program headers
    ///
    /// # Returns
    /// An ElfPhdrs enum containing either mapped or vector-based headers
    pub(crate) fn create_phdrs(&self, phdrs: &[ElfPhdr]) -> ElfPhdrs {
        let (phdr_start, phdr_end) = self.ehdr.phdr_range();

        // Get mapped program headers or create them from loaded segments
        self.phdr_mmap
            .or_else(|| {
                phdrs
                    .iter()
                    .filter(|phdr| phdr.p_type == PT_LOAD)
                    .find_map(|phdr| {
                        let cur_range =
                            phdr.p_offset as usize..(phdr.p_offset + phdr.p_filesz) as usize;
                        if cur_range.contains(&phdr_start) && cur_range.contains(&phdr_end) {
                            return Some(self.segments.get_slice::<ElfPhdr>(
                                phdr.p_vaddr as usize + phdr_start - cur_range.start,
                                self.ehdr.e_phnum() * size_of::<ElfPhdr>(),
                            ));
                        }
                        None
                    })
            })
            .map(ElfPhdrs::Mmap)
            .unwrap_or_else(|| ElfPhdrs::Vec(Vec::from(phdrs)))
    }
}

/// Builder for creating relocatable ELF objects
///
/// This structure is used internally during the loading process to collect
/// and organize the various components of a relocatable ELF file before
/// building the final ElfRelocatable object.
pub(crate) struct ObjectBuilder<Tls, D = ()> {
    /// Name of the ELF file
    pub(crate) name: String,

    /// Symbol table for the ELF file
    pub(crate) symtab: SymbolTable,

    /// Initialization function array
    pub(crate) init_array: Option<&'static [fn()]>,

    /// Initialization function handler
    pub(crate) init_fn: DynLifecycleHandler,

    /// Finalization function handler
    pub(crate) fini_fn: DynLifecycleHandler,

    /// Memory segments of the ELF file
    pub(crate) segments: ElfSegments,

    /// Static relocation information
    pub(crate) relocation: StaticRelocation,

    /// Memory protection function
    pub(crate) mprotect: Box<dyn Fn() -> Result<()>>,

    /// PLT/GOT section information
    pub(crate) pltgot: PltGotSection,

    /// TLS module ID
    pub(crate) tls_mod_id: Option<usize>,

    /// TLS thread pointer offset
    pub(crate) tls_tp_offset: Option<isize>,

    /// User-defined data
    pub(crate) user_data: D,

    /// TLS resolver
    _marker_tls: PhantomData<Tls>,
}

struct ObjectSectionData {
    symtab: SymbolTable,
    relocation: StaticRelocation,
    init_array: Option<&'static [fn()]>,
}

impl<T: TlsResolver, D> ObjectBuilder<T, D> {
    fn rebase_loaded_sections(shdrs: &mut [ElfShdr], pltgot: &mut PltGotSection, base: usize) {
        shdrs
            .iter_mut()
            .for_each(|shdr| shdr.sh_addr = (shdr.sh_addr as usize + base) as _);
        pltgot.rebase(base);
    }

    fn prepare_symbol_table(symtab_shdr: &ElfShdr, shdrs: &[ElfShdr], base: usize) -> SymbolTable {
        let symbols: &mut [ElfSymbol] = symtab_shdr.content_mut();
        for symbol in symbols {
            if symbol.st_type() == STT_FILE || symbol.st_shndx() == SHN_UNDEF as usize {
                continue;
            }
            let section_base = shdrs[symbol.st_shndx()].sh_addr as usize - base;
            symbol.set_value(section_base + symbol.st_value());
        }

        SymbolTable::from_shdrs(symtab_shdr, shdrs)
    }

    fn prepare_relocation_section(
        relocation_shdr: &ElfShdr,
        shdrs: &[ElfShdr],
        base: usize,
    ) -> &'static [ElfRelType] {
        let rels: &mut [ElfRelType] = relocation_shdr.content_mut();
        let section_base = shdrs[relocation_shdr.sh_info as usize].sh_addr as usize;
        for rel in rels {
            rel.set_offset(section_base + rel.r_offset() - base);
        }

        relocation_shdr.content()
    }

    fn prepare_init_array(init_array_shdr: &ElfShdr) -> &'static [fn()] {
        let array: &[usize] = init_array_shdr.content_mut();
        unsafe { core::mem::transmute(array) }
    }

    fn prepare_section_data(shdrs: &[ElfShdr], base: usize) -> ObjectSectionData {
        let mut symtab = None;
        let mut relocation = Vec::with_capacity(shdrs.len());
        let mut init_array = None;

        for shdr in shdrs {
            match shdr.sh_type {
                SHT_SYMTAB => symtab = Some(Self::prepare_symbol_table(shdr, shdrs, base)),
                SHT_RELA | SHT_REL => {
                    relocation.push(Self::prepare_relocation_section(shdr, shdrs, base))
                }
                SHT_INIT_ARRAY => init_array = Some(Self::prepare_init_array(shdr)),
                _ => {}
            }
        }

        ObjectSectionData {
            symtab: symtab.expect("object file missing symbol table"),
            relocation: StaticRelocation::new(relocation),
            init_array,
        }
    }

    /// Create a new RelocatableBuilder
    ///
    /// This method initializes a new RelocatableBuilder with the provided
    /// components and processes the section headers to prepare for relocation.
    ///
    /// # Arguments
    /// * `name` - The name of the ELF file
    /// * `shdrs` - Mutable reference to the section headers
    /// * `init_fn` - Initialization function handler
    /// * `fini_fn` - Finalization function handler
    /// * `segments` - Memory segments of the ELF file
    /// * `mprotect` - Memory protection function
    /// * `pltgot` - PLT/GOT section information
    /// * `user_data` - User-defined data
    ///
    /// # Returns
    /// A new RelocatableBuilder instance
    pub(crate) fn new(
        name: String,
        shdrs: &mut [ElfShdr],
        init_fn: DynLifecycleHandler,
        fini_fn: DynLifecycleHandler,
        segments: ElfSegments,
        mprotect: Box<dyn Fn() -> Result<()>>,
        mut pltgot: PltGotSection,
        user_data: D,
    ) -> Self {
        let base = segments.base();
        Self::rebase_loaded_sections(shdrs, &mut pltgot, base);
        let ObjectSectionData {
            symtab,
            relocation,
            init_array,
        } = Self::prepare_section_data(shdrs, base);

        Self {
            name,
            symtab,
            init_fn,
            fini_fn,
            segments,
            mprotect,
            relocation,
            pltgot,
            init_array,
            tls_mod_id: None,
            tls_tp_offset: None,
            user_data,
            _marker_tls: PhantomData,
        }
    }
}

impl<H, D> LoaderInner<H, D>
where
    H: LoadHook,
    D: 'static,
{
    fn lifecycle_handlers(&self) -> (DynLifecycleHandler, DynLifecycleHandler) {
        (self.init_fn.clone(), self.fini_fn.clone())
    }

    fn load_user_data(
        &self,
        name: &str,
        ehdr: &ElfHeader,
        phdrs: Option<&[ElfPhdr]>,
        shdrs: Option<&[ElfShdr]>,
    ) -> D {
        (self.user_data_loader)(&UserDataLoaderContext::new(name, ehdr, phdrs, shdrs))
    }

    pub(crate) fn create_builder<M, Tls>(
        &mut self,
        ehdr: ElfHeader,
        phdrs: &[ElfPhdr],
        mut object: impl crate::input::ElfReader,
    ) -> Result<ImageBuilder<'_, H, M, Tls, D>>
    where
        M: Mmap,
        Tls: TlsResolver,
    {
        let name = object.file_name().to_owned();
        let (init_fn, fini_fn) = self.lifecycle_handlers();
        let mut phdr_segments =
            ProgramSegments::new(phdrs, ehdr.is_dylib(), object.as_fd().is_some());
        let segments = phdr_segments.load_segments::<M>(&mut object)?;
        phdr_segments.mprotect::<M>()?;

        let user_data = self.load_user_data(&name, &ehdr, Some(phdrs), None);

        Ok(ImageBuilder::new(
            &mut self.hook,
            segments,
            name,
            ehdr,
            init_fn,
            fini_fn,
            self.force_static_tls,
            user_data,
        ))
    }

    pub(crate) fn create_object_builder<M, Tls>(
        &mut self,
        ehdr: ElfHeader,
        shdrs: &mut [ElfShdr],
        mut object: impl crate::input::ElfReader,
    ) -> Result<ObjectBuilder<Tls, D>>
    where
        M: Mmap,
        Tls: TlsResolver,
    {
        let name = object.file_name().to_owned();
        let (init_fn, fini_fn) = self.lifecycle_handlers();
        let mut shdr_segments = SectionSegments::new(shdrs, &mut object);
        let segments = shdr_segments.load_segments::<M>(&mut object)?;
        let pltgot = shdr_segments.take_pltgot();
        let mprotect = Box::new(move || {
            shdr_segments.mprotect::<M>()?;
            Ok(())
        });
        let user_data = self.load_user_data(&name, &ehdr, None, Some(shdrs));

        Ok(ObjectBuilder::new(
            name, shdrs, init_fn, fini_fn, segments, mprotect, pltgot, user_data,
        ))
    }
}
