use super::{ObjectBuilder, ObjectSections, layout::SectionSegments};
use crate::{
    ParseShdrError, RelocationError, Result,
    elf::{ElfHeader, ElfLayout, ElfRelEntry, ElfRelType, ElfSectionType, ElfShdr},
    image::RawObject,
    input::{ElfReader, ElfReaderExt, IntoElfReader, PathBuf},
    loader::{ExpectedElf, Loader},
    logging,
    observer::LoadObserver,
    os::Mmap,
    relocation::ObjectRelocationArch,
    tls::TlsResolver,
};

impl<Obs, D, Tls, Arch, M> Loader<Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: Default + 'static,
    Tls: TlsResolver<Arch>,
    Arch: ObjectRelocationArch,
    M: Mmap,
{
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
    pub fn load_object<'a, I>(&mut self, input: I) -> Result<RawObject<D, Arch, M::Region, Tls>>
    where
        I: IntoElfReader<'a>,
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
        self.notify_before_object_load(&ehdr, &mut sections, &object, &mut user_data)?;
        let path = PathBuf::from(object.path());
        let page_size = self.page_size()?.bytes();
        let (object_groups, observer, mapper) = self.object_load_context();
        let (section_segments, segments) = SectionSegments::<Arch>::load::<D, _, _>(
            &mut sections,
            &object,
            page_size,
            object_groups,
            observer,
            mapper,
        )?;
        let builder = ObjectBuilder::<Tls, D, Arch, M::Region>::new(
            path,
            sections,
            segments,
            section_segments,
            user_data,
            self.executor(),
        )?;
        let mut raw = builder.build_object();
        self.notify_after_object_load(&mut raw)?;
        let base = raw.base();

        logging::info!("Loaded object: {} at {}", raw.name(), base);

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
    let shstrtab = shdrs
        .get(ehdr.e_shstrndx())
        .ok_or_else(|| ParseShdrError::malformed("e_shstrndx is out of range"))?;
    object.read_to_vec(shstrtab.sh_offset(), shstrtab.sh_size())
}

fn validate_object_shdrs<Arch>(
    ehdr: &ElfHeader<Arch::Layout>,
    shdrs: &[ElfShdr<Arch::Layout>],
    object: &impl ElfReader,
) -> Result<()>
where
    Arch: ObjectRelocationArch,
{
    let first = shdrs.first().ok_or(ParseShdrError::MissingSectionHeaders)?;
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
    Arch: ObjectRelocationArch,
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

#[cfg(test)]
mod tests {
    use crate::elf::{ElfHeader, ElfShdr, ElfSymbol};
    use crate::{
        Loader, Result,
        elf::{ElfEhdr, ElfLayout, ElfSectionFlags, ElfSectionId, ElfSectionType, NativeElfLayout},
        input::{ElfBinary, ElfReader, Path},
        memory::RegionAccess,
        observer::{AfterObjectLoadEvent, BeforeObjectLoadEvent, LoadObserver},
        relocation::RelocationArch,
        tls::TlsResolver,
    };
    use alloc::vec::Vec;
    use core::mem::size_of;
    use elf::abi::{EI_CLASS, EI_DATA, EI_VERSION, ELFMAGIC, ET_REL, EV_CURRENT};

    struct TestReader {
        bytes: Vec<u8>,
    }

    #[derive(Default)]
    struct ObjectData {
        shstrtab: Option<ElfSectionId>,
    }

    #[derive(Default)]
    struct ObjectObserver {
        found_shstrtab: Option<ElfSectionId>,
        shstrtab_name_seen: bool,
        shstrtab_len: usize,
        borrowed_shstrtab: bool,
        renamed_shstrtab: bool,
        after_object_name_seen: bool,
        after_object_load_seen: bool,
    }

    impl LoadObserver<ObjectData> for ObjectObserver {
        fn on_before_object_load(
            &mut self,
            mut event: BeforeObjectLoadEvent<'_, ObjectData, NativeElfLayout>,
        ) -> Result<()> {
            let shstrtab = event.find_section(".shstrtab");
            event.user_data_mut().shstrtab = shstrtab;
            self.found_shstrtab = shstrtab;
            self.shstrtab_name_seen = shstrtab
                .map(|index| event.section_name(index))
                .is_some_and(|name| name.to_bytes() == b".shstrtab");
            self.borrowed_shstrtab = shstrtab
                .map(|index| {
                    event
                        .borrow_section_bytes(index)
                        .map(|bytes| bytes.is_some())
                })
                .transpose()?
                .unwrap_or(false);
            let mut scratch = Vec::new();
            self.shstrtab_len = shstrtab
                .map(|index| event.with_section_bytes(index, &mut scratch, |bytes| Ok(bytes.len())))
                .transpose()?
                .unwrap_or_default();
            if let Some(index) = shstrtab {
                let shdr = event.section_mut(index);
                shdr.set_sh_name(0);
            }
            self.renamed_shstrtab = shstrtab
                .map(|index| event.section_name(index))
                .is_some_and(|name| name.to_bytes().is_empty());
            Ok(())
        }

        fn on_after_object_load<R: RegionAccess, Tls: TlsResolver<crate::arch::NativeArch>>(
            &mut self,
            event: AfterObjectLoadEvent<'_, ObjectData, crate::arch::NativeArch, R, Tls>,
        ) -> Result<()> {
            self.after_object_name_seen = event.raw().name() == "metadata.o";
            self.after_object_load_seen = true;
            Ok(())
        }
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

    fn make_object_header(shentsize: usize, shnum: usize) -> ElfHeader {
        let ehdr = make_raw_object_header(shentsize, shnum);

        ElfHeader::from_raw(ehdr, Some(crate::arch::NativeArch::MACHINE))
            .expect("failed to parse crafted object header")
    }

    fn make_raw_object_header(shentsize: usize, shnum: usize) -> ElfEhdr {
        let mut ehdr = unsafe { core::mem::zeroed::<ElfEhdr>() };
        ehdr.e_ident[0..4].copy_from_slice(&ELFMAGIC);
        ehdr.e_ident[EI_CLASS] = <NativeElfLayout as ElfLayout>::E_CLASS;
        ehdr.e_ident[EI_DATA] = <NativeElfLayout as ElfLayout>::DATA_ENCODING.raw();
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_type = ET_REL as _;
        ehdr.e_machine = crate::arch::NativeArch::MACHINE.raw();
        ehdr.e_version = EV_CURRENT.into();
        ehdr.e_ehsize = <NativeElfLayout as ElfLayout>::EHDR_SIZE as _;
        ehdr.e_shoff = <NativeElfLayout as ElfLayout>::EHDR_SIZE as _;
        ehdr.e_shentsize = shentsize as _;
        ehdr.e_shnum = shnum as _;

        ehdr
    }

    fn write_value<T>(bytes: &mut [u8], offset: usize, value: &T) {
        let raw = unsafe {
            core::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>())
        };
        bytes[offset..offset + raw.len()].copy_from_slice(raw);
    }

    fn write_bytes(bytes: &mut [u8], offset: usize, value: &[u8]) {
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }

    fn make_two_section_object(shstrtab: &[u8], shstrtab_name: u32) -> Vec<u8> {
        let ehdr_size = <NativeElfLayout as ElfLayout>::EHDR_SIZE;
        let shdr_size = size_of::<ElfShdr>();
        let shstrtab_offset = ehdr_size + shdr_size * 2;
        let mut bytes = alloc::vec![0u8; shstrtab_offset + shstrtab.len()];

        let mut ehdr = make_raw_object_header(shdr_size, 2);
        ehdr.e_shstrndx = 1;
        write_value(&mut bytes, 0, &ehdr);

        let null_shdr: ElfShdr<NativeElfLayout> = ElfShdr::new(
            0,
            ElfSectionType::NULL,
            ElfSectionFlags::empty(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        let shstrtab_shdr: ElfShdr<NativeElfLayout> = ElfShdr::new(
            shstrtab_name,
            ElfSectionType::STRTAB,
            ElfSectionFlags::empty(),
            0,
            shstrtab_offset,
            shstrtab.len(),
            0,
            0,
            1,
            0,
        );
        write_value(&mut bytes, ehdr_size, &null_shdr);
        write_value(&mut bytes, ehdr_size + shdr_size, &shstrtab_shdr);
        write_bytes(&mut bytes, shstrtab_offset, shstrtab);

        bytes
    }

    fn make_metadata_object() -> Vec<u8> {
        const SYMTAB_NAME: u32 = 1;
        const STRTAB_NAME: u32 = 9;
        const SHSTRTAB_NAME: u32 = 17;

        let ehdr_size = <NativeElfLayout as ElfLayout>::EHDR_SIZE;
        let shdr_size = size_of::<ElfShdr>();
        let sym_size = size_of::<ElfSymbol>();
        let strtab = b"\0";
        let shstrtab = b"\0.symtab\0.strtab\0.shstrtab\0";
        let symtab_offset = ehdr_size + shdr_size * 4;
        let strtab_offset = symtab_offset + sym_size;
        let shstrtab_offset = strtab_offset + strtab.len();
        let mut bytes = alloc::vec![0u8; shstrtab_offset + shstrtab.len()];

        let mut ehdr = make_raw_object_header(shdr_size, 4);
        ehdr.e_shstrndx = 3;
        write_value(&mut bytes, 0, &ehdr);

        let null_shdr: ElfShdr<NativeElfLayout> = ElfShdr::new(
            0,
            ElfSectionType::NULL,
            ElfSectionFlags::empty(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        let symtab_shdr: ElfShdr<NativeElfLayout> = ElfShdr::new(
            SYMTAB_NAME,
            ElfSectionType::SYMTAB,
            ElfSectionFlags::empty(),
            0,
            symtab_offset,
            sym_size,
            2,
            1,
            size_of::<usize>(),
            sym_size,
        );
        let strtab_shdr: ElfShdr<NativeElfLayout> = ElfShdr::new(
            STRTAB_NAME,
            ElfSectionType::STRTAB,
            ElfSectionFlags::empty(),
            0,
            strtab_offset,
            strtab.len(),
            0,
            0,
            1,
            0,
        );
        let shstrtab_shdr: ElfShdr<NativeElfLayout> = ElfShdr::new(
            SHSTRTAB_NAME,
            ElfSectionType::STRTAB,
            ElfSectionFlags::empty(),
            0,
            shstrtab_offset,
            shstrtab.len(),
            0,
            0,
            1,
            0,
        );
        let null_sym: ElfSymbol<NativeElfLayout> = unsafe { core::mem::zeroed() };

        write_value(&mut bytes, ehdr_size, &null_shdr);
        write_value(&mut bytes, ehdr_size + shdr_size, &symtab_shdr);
        write_value(&mut bytes, ehdr_size + shdr_size * 2, &strtab_shdr);
        write_value(&mut bytes, ehdr_size + shdr_size * 3, &shstrtab_shdr);
        write_value(&mut bytes, symtab_offset, &null_sym);
        write_bytes(&mut bytes, strtab_offset, strtab);
        write_bytes(&mut bytes, shstrtab_offset, shstrtab);

        bytes
    }

    #[test]
    fn prepare_shdrs_rejects_entry_size_mismatch() {
        let header = make_object_header(size_of::<ElfShdr>() + 8, 1);
        let reader = TestReader::zeroed(512);

        let err = super::read_object_shdrs(&header, &reader)
            .expect_err("shdr entry size mismatch should fail");
        assert!(matches!(
            err,
            crate::Error::ParseShdr(crate::ParseShdrError::InvalidEntrySize { .. })
        ));
    }

    #[test]
    fn prepare_shdrs_rejects_table_past_object_len() {
        let header = make_object_header(size_of::<ElfShdr>(), 2);
        let reader =
            TestReader::zeroed(<NativeElfLayout as ElfLayout>::EHDR_SIZE + size_of::<ElfShdr>());

        let err = super::read_object_shdrs(&header, &reader)
            .expect_err("shdr table past object length should fail");
        assert!(matches!(
            err,
            crate::Error::Io(crate::IoError::ReadOutOfBounds(_))
        ));
    }

    #[test]
    fn load_object_rejects_section_content_past_object_len() {
        let ehdr_size = <NativeElfLayout as ElfLayout>::EHDR_SIZE;
        let shdr_size = size_of::<ElfShdr>();
        let shstrtab = b"\0.text\0.shstrtab\0";
        let shstrtab_offset = ehdr_size + shdr_size * 3;
        let mut bytes = alloc::vec![0u8; shstrtab_offset + shstrtab.len()];

        let mut ehdr = make_raw_object_header(shdr_size, 3);
        ehdr.e_shstrndx = 2;
        write_value(&mut bytes, 0, &ehdr);

        let null_shdr: ElfShdr<NativeElfLayout> = ElfShdr::new(
            0,
            ElfSectionType::NULL,
            ElfSectionFlags::empty(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        );
        let content_shdr: ElfShdr<NativeElfLayout> = ElfShdr::new(
            1,
            ElfSectionType::PROGBITS,
            ElfSectionFlags::empty(),
            0,
            bytes.len() - 4,
            8,
            0,
            0,
            1,
            0,
        );
        let shstrtab_shdr: ElfShdr<NativeElfLayout> = ElfShdr::new(
            7,
            ElfSectionType::STRTAB,
            ElfSectionFlags::empty(),
            0,
            shstrtab_offset,
            shstrtab.len(),
            0,
            0,
            1,
            0,
        );
        write_value(&mut bytes, ehdr_size, &null_shdr);
        write_value(&mut bytes, ehdr_size + shdr_size, &content_shdr);
        write_value(&mut bytes, ehdr_size + shdr_size * 2, &shstrtab_shdr);
        write_bytes(&mut bytes, shstrtab_offset, shstrtab);

        let mut loader = Loader::new();
        let result = loader.load_object(ElfBinary::owned("bad.o", bytes));
        assert!(matches!(
            result,
            Err(crate::Error::ParseShdr(
                crate::ParseShdrError::Malformed { .. }
            ))
        ));
    }

    #[test]
    fn load_object_rejects_section_name_table_without_nul() {
        let mut loader = Loader::new();
        let result = loader.load_object(ElfBinary::owned(
            "bad.o",
            make_two_section_object(b"\0.shstrtab", 1),
        ));
        assert!(matches!(
            result,
            Err(crate::Error::ParseShdr(
                crate::ParseShdrError::Malformed { .. }
            ))
        ));
    }

    #[test]
    fn load_object_rejects_section_name_offset_past_table() {
        let mut loader = Loader::new();
        let result =
            loader.load_object(ElfBinary::owned("bad.o", make_two_section_object(b"\0", 1)));
        assert!(matches!(
            result,
            Err(crate::Error::ParseShdr(
                crate::ParseShdrError::Malformed { .. }
            ))
        ));
    }

    #[test]
    fn load_object_notifies_object_load_observers() {
        let mut observer = ObjectObserver::default();
        let mut loader = Loader::new()
            .with_data::<ObjectData>()
            .with_observer(&mut observer);

        let _ = loader.load_object(ElfBinary::owned("metadata.o", make_metadata_object()));
        drop(loader);

        assert_eq!(observer.found_shstrtab, Some(ElfSectionId::new(3)));
        assert!(observer.shstrtab_name_seen);
        assert_eq!(
            observer.shstrtab_len,
            b"\0.symtab\0.strtab\0.shstrtab\0".len()
        );
        assert!(observer.borrowed_shstrtab);
        assert!(observer.renamed_shstrtab);
        assert!(observer.after_object_name_seen);
        assert!(observer.after_object_load_seen);
    }
}
