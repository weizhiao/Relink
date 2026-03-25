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
        let Some(size) = self.read_table(object, ehdr.shdr_range())? else {
            return Ok(None);
        };
        unsafe {
            Ok(Some(core::slice::from_raw_parts_mut(
                self.buf.as_mut_ptr().cast::<ElfShdr>(),
                size / size_of::<ElfShdr>(),
            )))
        }
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
