use super::{
    ObjectBuilder, ObjectSections,
    layout::{SectionGroups, SectionSegments},
};
use crate::{
    LoaderRun, ParseShdrError, RelocationError, Result,
    elf::{ElfHeader, ElfLayout, ElfRelEntry, ElfRelType, ElfSectionType, ElfShdr},
    image::RawObject,
    input::{ElfReader, ElfReaderExt, IntoElfReader, PathBuf},
    loader::ExpectedElf,
    logging,
    observer::{AfterObjectLoadEvent, BeforeObjectLoadEvent, LoadObserver},
    os::Mmap,
    relocation::ObjectArch,
    sync::Arc,
    tls::TlsResolver,
};

impl<Obs, D, Tls, Arch, M> LoaderRun<'_, Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: ObjectArch,
    M: Mmap,
{
    /// Sets object section layout groups for this loader run.
    pub fn with_object_section_groups(mut self, groups: SectionGroups) -> Self {
        self.object_groups = Some(Arc::new(groups));
        self
    }
}

impl<'run, Obs, D, Tls, Arch, M> LoaderRun<'run, Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: Default + Send + Sync + 'static,
    Tls: TlsResolver<Arch>,
    Arch: ObjectArch,
    M: Mmap,
{
    /// Loads a relocatable object file into memory and prepares it for relocation.
    ///
    /// # Examples
    /// ```no_run
    /// use elf_loader::{Loader, input::ElfBinary};
    ///
    /// let config = Loader::new();
    /// use elf_loader::{AddressSpaceId, Domain};
    /// let domain = Domain::native(AddressSpaceId::PROCESS);
    /// let mut loader = config.run(domain);
    /// let bytes = &[]; // Relocatable ELF bytes
    /// let rel = loader.load_object(ElfBinary::new("liba.o", bytes)).unwrap();
    /// ```
    pub fn load_object<I>(&mut self, input: I) -> Result<RawObject<D, Arch, M::Region, Tls>>
    where
        I: IntoElfReader,
    {
        let object = input.into_reader()?;
        logging::debug!("Loading object: {}", object.path());

        let ehdr = self.read_expected_ehdr(&object, ExpectedElf::Relocatable)?;
        self.load_object_from_ehdr(object, ehdr)
    }

    pub(crate) fn load_object_from_ehdr(
        &mut self,
        object: impl ElfReader,
        ehdr: ElfHeader<Arch::Layout>,
    ) -> Result<RawObject<D, Arch, M::Region, Tls>> {
        let shdrs =
            read_object_shdrs(&ehdr, &object)?.ok_or(ParseShdrError::MissingSectionHeaders)?;
        validate_object_shdrs::<Arch>(&ehdr, &shdrs, &object)?;
        let shstrtab = read_section_name_table(&ehdr, &shdrs, &object)?;
        let mut sections = ObjectSections::new(shdrs, shstrtab);
        let mut user_data = D::default();
        let path = PathBuf::from(object.path());
        let source_id = object.source_id();
        let page_size = self.loader.mapper().page_size().bytes();
        let object_groups = Arc::clone(self.object_groups.get_or_insert_with(Default::default));
        let observer = &mut self.observer;
        let mapper = self.loader.mapper();
        observer.on_before_object_load(BeforeObjectLoadEvent::new(
            &ehdr,
            &mut sections,
            &object,
            &mut user_data,
        ))?;
        let (section_segments, segments, pltgot) = SectionSegments::<Arch>::load::<D, _, _>(
            &mut sections,
            &object,
            page_size,
            object_groups,
            observer,
            mapper,
        )?;
        let builder = ObjectBuilder::<Tls, D, Arch, M::Region>::new(
            path,
            source_id,
            sections,
            segments,
            section_segments,
            pltgot,
            user_data,
            self.domain.clone(),
        )?;
        let mut raw = builder.build_object();
        observer.on_after_object_load(AfterObjectLoadEvent::new(&mut raw))?;
        let base = raw.segments().base();

        logging::info!("Loaded object: {} at {}", raw.name().escape_ascii(), base);

        Ok(raw)
    }
}

fn read_object_shdrs<L: ElfLayout>(
    ehdr: &ElfHeader<L>,
    object: &impl ElfReader,
) -> Result<Option<alloc::vec::Vec<ElfShdr<L>>>> {
    let Some((start, _size)) = ehdr.checked_shdr_layout(object.len())? else {
        return Ok(None);
    };
    object.read_to_vec(start, ehdr.e_shnum()).map(Some)
}

fn read_section_name_table<L: ElfLayout>(
    ehdr: &ElfHeader<L>,
    shdrs: &[ElfShdr<L>],
    object: &impl ElfReader,
) -> Result<alloc::vec::Vec<u8>> {
    // validate_object_shdrs has already checked this index.
    let shstrtab = &shdrs[ehdr.e_shstrndx()];
    object.read_to_vec(shstrtab.sh_offset(), shstrtab.sh_size())
}

fn validate_object_shdrs<Arch>(
    ehdr: &ElfHeader<Arch::Layout>,
    shdrs: &[ElfShdr<Arch::Layout>],
    object: &impl ElfReader,
) -> Result<()>
where
    Arch: ObjectArch,
{
    let first = &shdrs[0];
    if first.section_type() != ElfSectionType::NULL || first.sh_size() != 0 {
        return Err(
            ParseShdrError::malformed("section 0 must be an empty SHT_NULL section").into(),
        );
    }

    let mut has_symtab = false;
    let shstrtab = shdrs
        .get(ehdr.e_shstrndx())
        .ok_or_else(|| ParseShdrError::malformed("e_shstrndx is out of range"))?;
    let shstrtab_size = shstrtab.sh_size();
    if shstrtab_size == 0 {
        return Err(ParseShdrError::malformed("section name string table is empty").into());
    }
    for shdr in shdrs {
        match shdr.section_type() {
            ElfSectionType::SYMTAB => has_symtab = true,
            ElfSectionType::REL | ElfSectionType::RELA => {
                validate_relocation_shdr::<Arch>(shdr, shdrs)?
            }
            _ => {}
        }

        if shdr.sh_name() as usize >= shstrtab_size {
            return Err(ParseShdrError::malformed(
                "section name offset exceeds section name string table",
            )
            .into());
        }
    }

    let object_len = object.len();
    for shdr in shdrs {
        if shdr.sh_size() == 0 || shdr.section_type() == ElfSectionType::NOBITS {
            continue;
        }
        let end = shdr
            .sh_offset()
            .checked_add(shdr.sh_size())
            .ok_or_else(|| ParseShdrError::malformed("section content range overflows"))?;
        if end > object_len {
            return Err(ParseShdrError::malformed("section content exceeds object length").into());
        }
    }

    let last = shstrtab
        .sh_offset()
        .checked_add(shstrtab_size - 1)
        .ok_or_else(|| ParseShdrError::malformed("section name string table range overflows"))?;
    let mut last_byte = [0];
    object.read(&mut last_byte, last)?;
    if last_byte[0] != 0 {
        return Err(
            ParseShdrError::malformed("section name string table must end with NUL").into(),
        );
    }

    if !has_symtab {
        return Err(RelocationError::MissingSymbolTable.into());
    }

    Ok(())
}

fn validate_relocation_shdr<Arch>(
    shdr: &ElfShdr<Arch::Layout>,
    shdrs: &[ElfShdr<Arch::Layout>],
) -> Result<()>
where
    Arch: ObjectArch,
{
    debug_assert!(matches!(
        shdr.section_type(),
        ElfSectionType::REL | ElfSectionType::RELA
    ));

    if shdr.section_type() != <ElfRelType<Arch> as ElfRelEntry<Arch::Layout>>::SECTION_TYPE {
        return Err(ParseShdrError::malformed(
            "relocation section type does not match target architecture",
        )
        .into());
    }

    shdrs
        .get(shdr.sh_info() as usize)
        .ok_or_else(|| ParseShdrError::malformed("relocation target section is out of range"))?;

    Ok(())
}
