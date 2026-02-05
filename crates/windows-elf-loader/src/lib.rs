use elf_loader::{
    Error, Loader,
    image::RawDylib as ElfDylib,
    input::{ElfBinary, ElfFile},
};

/// elf loader
pub struct WinElfLoader {
    loader: Loader,
}

impl WinElfLoader {
    pub fn new() -> Self {
        let loader = Loader::new().with_default_tls_resolver();
        Self { loader }
    }

    pub fn load_dylib(
        &mut self,
        name: &str,
        bytes: impl AsRef<[u8]>,
    ) -> Result<ElfDylib<()>, Error> {
        let object = ElfBinary::new(name, bytes.as_ref());
        self.loader.load_dylib(object)
    }

    pub fn load_file(&mut self, name: &str) -> Result<ElfDylib<()>, Error> {
        let object = ElfFile::from_path(name)?;
        self.loader.load_dylib(object)
    }
}
