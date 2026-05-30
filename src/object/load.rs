use crate::{
    ParseEhdrError, Result,
    elf::{ElfLayout, ElfSectionType, ElfShdr},
    image::{RawElf, RawObject},
    input::{ElfReader, IntoElfReader},
    loader::Loader,
    logging,
    observer::LoadObserver,
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
    pub(crate) fn load_rel(
        &mut self,
        object: impl ElfReader,
    ) -> Result<RawElf<D, Arch, M::Region>> {
        Ok(RawElf::Object(self.load_object_impl(object)?))
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
    pub fn load_object<'a, I>(&mut self, input: I) -> Result<RawObject<D, Arch, M::Region>>
    where
        I: IntoElfReader<'a>,
    {
        self.load_object_impl(input.into_reader()?)
    }

    pub(crate) fn load_object_impl(
        &mut self,
        mut object: impl ElfReader,
    ) -> Result<RawObject<D, Arch, M::Region>> {
        logging::debug!("Loading object: {}", object.path());

        let ehdr = self
            .buf
            .prepare_ehdr::<Arch::Layout>(&mut object, Some(Arch::MACHINE))?;
        let shdrs = self
            .buf
            .prepare_shdrs_mut(&ehdr, &mut object)?
            .ok_or(ParseEhdrError::MissingSectionHeaders)?;
        validate_object_shdrs(shdrs, object.len())?;
        let builder = self.inner.create_object_builder::<Tls>(shdrs, object)?;
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

fn validate_object_shdrs<L: ElfLayout>(shdrs: &[ElfShdr<L>], object_len: usize) -> Result<()> {
    let first = shdrs.first().ok_or(ParseEhdrError::MissingSectionHeaders)?;
    if first.section_type() != ElfSectionType::NULL || first.sh_size() != 0 {
        return Err(ParseEhdrError::malformed_section_headers(
            "section 0 must be an empty SHT_NULL section",
        )
        .into());
    }

    for shdr in shdrs.iter() {
        if shdr.sh_size() == 0 || shdr.section_type() == ElfSectionType::NOBITS {
            continue;
        }
        let end = shdr
            .sh_offset()
            .checked_add(shdr.sh_size())
            .ok_or_else(|| {
                ParseEhdrError::malformed_section_headers("section content range overflows")
            })?;
        if end > object_len {
            return Err(ParseEhdrError::malformed_section_headers(
                "section content exceeds object length",
            )
            .into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        Loader, Result,
        elf::{ElfEhdr, ElfLayout, ElfSectionFlags, ElfSectionType, NativeElfLayout},
        input::{ElfBinary, ElfReader, Path},
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

        fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
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
            crate::Error::ParseEhdr(crate::ParseEhdrError::MissingSectionHeaders)
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
            crate::Error::ParseEhdr(crate::ParseEhdrError::MalformedSectionHeaders { .. })
        ));
    }

    #[test]
    fn load_object_rejects_section_content_past_object_len() {
        let ehdr_size = <NativeElfLayout as ElfLayout>::EHDR_SIZE;
        let shdr_size = size_of::<ElfShdr>();
        let mut bytes = alloc::vec![0u8; ehdr_size + shdr_size * 2];

        let ehdr = make_raw_object_header(shdr_size, 2);
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
            0,
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
        write_value(&mut bytes, ehdr_size, &null_shdr);
        write_value(&mut bytes, ehdr_size + shdr_size, &content_shdr);

        let mut loader = Loader::new();
        let result = loader.load_object(ElfBinary::owned("bad.o", bytes));
        assert!(matches!(
            result,
            Err(crate::Error::ParseEhdr(
                crate::ParseEhdrError::MalformedSectionHeaders { .. }
            ))
        ));
    }
}
