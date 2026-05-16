use crate::{
    ParseEhdrError, Result,
    image::{RawElf, RawObject},
    input::{ElfReader, IntoElfReader},
    loader::{LoadHook, Loader},
    logging,
    os::Mmap,
    relocation::RelocationArch,
    tls::TlsResolver,
};

impl<M, H, D, Tls, Arch> Loader<M, H, D, Tls, Arch>
where
    M: Mmap,
    H: LoadHook<Arch::Layout>,
    D: Default + 'static,
    Tls: TlsResolver,
    Arch: RelocationArch,
{
    pub(crate) fn load_rel(&mut self, object: impl ElfReader) -> Result<RawElf<D, Arch>> {
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
    pub fn load_object<'a, I>(&mut self, input: I) -> Result<RawObject<D, Arch>>
    where
        I: IntoElfReader<'a>,
    {
        self.load_object_impl(input.into_reader()?)
    }

    pub(crate) fn load_object_impl(
        &mut self,
        mut object: impl ElfReader,
    ) -> Result<RawObject<D, Arch>> {
        logging::debug!("Loading object: {}", object.path());

        let ehdr = self
            .buf
            .prepare_ehdr::<Arch::Layout>(&mut object, Some(Arch::MACHINE))?;
        let shdrs = self
            .buf
            .prepare_shdrs_mut(&ehdr, &mut object)?
            .ok_or(ParseEhdrError::MissingSectionHeaders)?;
        let builder = self.inner.create_object_builder::<M, Tls>(shdrs, object)?;
        let raw = RawObject::from_builder(builder);

        logging::info!(
            "Loaded object: {} at [0x{:x}-0x{:x}]",
            raw.name(),
            raw.mapped_base(),
            raw.mapped_base() + raw.mapped_len()
        );

        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Result,
        elf::{ElfEhdr, ElfLayout, NativeElfLayout},
        input::{ElfReader, Path},
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

        fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
            buf.copy_from_slice(&self.bytes[offset..offset + buf.len()]);
            Ok(())
        }

        fn as_fd(&self) -> Option<isize> {
            None
        }
    }

    fn make_object_header(shentsize: usize, shnum: usize) -> ElfHeader {
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

        ElfHeader::from_raw(ehdr, Some(crate::arch::NativeArch::MACHINE))
            .expect("failed to parse crafted object header")
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
}
