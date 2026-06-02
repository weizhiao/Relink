use crate::{
    ParseShdrError, Result,
    elf::{ElfHeader, ElfLayout, ElfSectionType, ElfSections, ElfShdr},
    image::RawObject,
    input::{ElfReader, ElfReaderExt, IntoElfReader},
    loader::{ExpectedElf, Loader},
    logging,
    observer::{LoadObserver, ObjectMetadataEvent},
    os::{Mmap, VmOffset},
    relocation::ObjectRelocationArch,
    tls::TlsResolver,
};

impl<Obs, D, Tls, Arch, M> Loader<Obs, D, Tls, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: Default + 'static,
    Tls: TlsResolver,
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
    pub fn load_object<'a, I>(&mut self, input: I) -> Result<RawObject<D, Arch, M::Region>>
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
    ) -> Result<RawObject<D, Arch, M::Region>> {
        let shdrs = self
            .buf
            .prepare_shdrs_mut(&ehdr, &object)?
            .ok_or(ParseShdrError::MissingSectionHeaders)?;
        validate_object_shdrs(&ehdr, shdrs, &object)?;
        let shstrtab = read_section_name_table(&ehdr, shdrs, &object)?;
        let mut sections = ElfSections::new(shdrs, shstrtab);
        let mut user_data = D::default();
        self.inner
            .observer
            .on_object_metadata(ObjectMetadataEvent::new(
                &ehdr,
                &mut sections,
                &object,
                &mut user_data,
            ))?;
        let builder = self
            .inner
            .create_object_builder::<Tls>(sections, object, user_data)?;
        let raw = RawObject::from_builder(builder);

        logging::info!(
            "Loaded object: {} at [{}-{}]",
            raw.name(),
            raw.mapped_base(),
            raw.mapped_base() + VmOffset::new(raw.mapped_len())
        );

        Ok(raw)
    }
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

fn validate_object_shdrs<L: ElfLayout>(
    ehdr: &ElfHeader<L>,
    shdrs: &[ElfShdr<L>],
    object: &impl ElfReader,
) -> Result<()> {
    let first = shdrs.first().ok_or(ParseShdrError::MissingSectionHeaders)?;
    if first.section_type() != ElfSectionType::NULL || first.sh_size() != 0 {
        return Err(
            ParseShdrError::malformed("section 0 must be an empty SHT_NULL section").into(),
        );
    }

    let shstrtab = shdrs
        .get(ehdr.e_shstrndx())
        .ok_or_else(|| ParseShdrError::malformed("e_shstrndx is out of range"))?;
    let shstrtab_size = shstrtab.sh_size();
    if shstrtab_size == 0 {
        return Err(ParseShdrError::malformed("section name string table is empty").into());
    }
    for shdr in shdrs.iter() {
        if shdr.sh_name() as usize >= shstrtab_size {
            return Err(ParseShdrError::malformed(
                "section name offset exceeds section name string table",
            )
            .into());
        }
    }

    let object_len = object.len();
    for shdr in shdrs.iter() {
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        Loader, Result,
        elf::{ElfEhdr, ElfLayout, ElfSectionFlags, ElfSectionId, ElfSectionType, NativeElfLayout},
        input::{ElfBinary, ElfReader, Path},
        observer::{LoadObserver, ObjectMetadataEvent},
        relocation::RelocationArch,
    };
    use crate::{
        elf::{ElfHeader, ElfShdr},
        loader::ElfBuf,
    };
    use alloc::vec::Vec;
    use core::mem::size_of;
    use elf::abi::{EI_CLASS, EI_VERSION, ELFMAGIC, ET_REL, EV_CURRENT};

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
    }

    impl LoadObserver<ObjectData> for ObjectObserver {
        fn on_object_metadata(
            &mut self,
            mut event: ObjectMetadataEvent<'_, '_, ObjectData, NativeElfLayout>,
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
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_type = ET_REL as _;
        ehdr.e_machine = crate::arch::NativeArch::MACHINE.raw();
        ehdr.e_version = EV_CURRENT as _;
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

    #[test]
    fn prepare_shdrs_rejects_entry_size_mismatch() {
        let mut elf_buf = ElfBuf::new();
        let header = make_object_header(size_of::<ElfShdr>() + 8, 1);
        let mut reader = TestReader::zeroed(512);

        let err = elf_buf
            .prepare_shdrs_mut(&header, &mut reader)
            .expect_err("shdr entry size mismatch should fail");
        assert!(matches!(
            err,
            crate::Error::ParseShdr(crate::ParseShdrError::InvalidEntrySize { .. })
        ));
    }

    #[test]
    fn prepare_shdrs_rejects_table_past_object_len() {
        let mut elf_buf = ElfBuf::new();
        let header = make_object_header(size_of::<ElfShdr>(), 2);
        let mut reader =
            TestReader::zeroed(<NativeElfLayout as ElfLayout>::EHDR_SIZE + size_of::<ElfShdr>());

        let err = elf_buf
            .prepare_shdrs_mut(&header, &mut reader)
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
    fn load_object_notifies_object_metadata_observer() {
        let mut observer = ObjectObserver::default();
        let mut loader = Loader::new()
            .with_data::<ObjectData>()
            .with_observer(&mut observer);

        let result = loader.load_object(ElfBinary::owned(
            "metadata.o",
            make_two_section_object(b"\0.shstrtab\0", 1),
        ));
        assert!(result.is_err());
        drop(loader);

        assert_eq!(observer.found_shstrtab, Some(ElfSectionId::new(1)));
        assert!(observer.shstrtab_name_seen);
        assert_eq!(observer.shstrtab_len, b"\0.shstrtab\0".len());
        assert!(observer.borrowed_shstrtab);
        assert!(observer.renamed_shstrtab);
    }
}
