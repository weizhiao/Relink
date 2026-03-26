use crate::{
    ParseEhdrError, Result,
    elf::{ElfHeader, ElfShdr},
    image::{RawElf, RawObject},
    input::{ElfReader, IntoElfReader},
    loader::{ElfBuf, LoadHook, Loader},
    logging,
    os::Mmap,
    tls::TlsResolver,
};

impl ElfBuf {
    pub(crate) fn prepare_shdrs_mut(
        &mut self,
        ehdr: &ElfHeader,
        object: &mut impl ElfReader,
    ) -> Result<Option<&mut [ElfShdr]>> {
        let Some((start, size)) = ehdr.checked_shdr_layout()? else {
            return Ok(None);
        };
        let count = ehdr.e_shnum();

        self.buf
            .set_len(size)
            .ok_or(ParseEhdrError::MissingSectionHeaders)?;
        object.read(self.buf.as_bytes_mut(), start)?;

        let shdrs = self
            .buf
            .as_slice_mut::<ElfShdr>()
            .ok_or(ParseEhdrError::MissingSectionHeaders)?;
        if shdrs.len() != count {
            return Err(ParseEhdrError::MissingSectionHeaders.into());
        }

        Ok(Some(shdrs))
    }
}

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook,
    D: Default + 'static,
    Tls: TlsResolver,
{
    pub(crate) fn load_rel(&mut self, object: impl ElfReader) -> Result<RawElf<D>> {
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
    pub fn load_object<'a, I>(&mut self, input: I) -> Result<RawObject<D>>
    where
        I: IntoElfReader<'a>,
    {
        self.load_object_impl(input.into_reader()?)
    }

    pub(crate) fn load_object_impl(&mut self, mut object: impl ElfReader) -> Result<RawObject<D>> {
        logging::debug!("Loading object: {}", object.file_name());

        let ehdr = self.read_ehdr(&mut object)?;
        let shdrs = self
            .buf
            .prepare_shdrs_mut(&ehdr, &mut object)?
            .ok_or(ParseEhdrError::MissingSectionHeaders)?;
        let builder = self
            .inner
            .create_object_builder::<M, Tls>(ehdr, shdrs, object)?;
        let raw = RawObject::from_builder(builder);

        logging::info!(
            "Loaded object: {} at [0x{:x}-0x{:x}]",
            raw.name(),
            raw.base(),
            raw.base() + raw.core.inner.segments.len()
        );

        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::{ElfBuf, ElfHeader, ElfShdr};
    use crate::{
        Result,
        arch::EM_ARCH,
        elf::{E_CLASS, EHDR_SIZE, ElfEhdr},
        input::ElfReader,
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

    fn make_object_header(shentsize: usize, shnum: usize) -> ElfHeader {
        let mut ehdr = unsafe { core::mem::zeroed::<ElfEhdr>() };
        ehdr.e_ident[0..4].copy_from_slice(&ELFMAGIC);
        ehdr.e_ident[EI_CLASS] = E_CLASS;
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_type = ET_REL as _;
        ehdr.e_machine = EM_ARCH;
        ehdr.e_version = EV_CURRENT as _;
        ehdr.e_ehsize = EHDR_SIZE as _;
        ehdr.e_shoff = EHDR_SIZE as _;
        ehdr.e_shentsize = shentsize as _;
        ehdr.e_shnum = shnum as _;

        ElfHeader::from_raw(ehdr).expect("failed to parse crafted object header")
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
