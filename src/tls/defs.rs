use crate::elf::ElfPhdr;
use elf::abi::PT_TLS;

/// Information about a TLS segment from ELF headers.
#[derive(Clone, Copy, Default)]
pub struct TlsInfo {
    /// Virtual address of the TLS template in the ELF file.
    pub vaddr: usize,
    /// Size of the initialized TLS data.
    pub filesz: usize,
    /// Total size of the TLS block in memory.
    pub memsz: usize,
    /// Alignment requirement of the TLS block.
    pub align: usize,
    /// The initial TLS data (template).
    pub image: &'static [u8],
}

impl core::fmt::Debug for TlsInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsInfo")
            .field("vaddr", &format_args!("0x{:x}", self.vaddr))
            .field("filesz", &self.filesz)
            .field("memsz", &self.memsz)
            .field("align", &self.align)
            .field("image_len", &self.image.len())
            .finish()
    }
}

impl TlsInfo {
    /// Creates a new `TlsInfo` from an ELF program header.
    pub fn new(phdr: &ElfPhdr, image: &'static [u8]) -> Self {
        assert_eq!(phdr.p_type, PT_TLS);
        Self {
            vaddr: phdr.p_vaddr as usize,
            filesz: phdr.p_filesz as usize,
            memsz: phdr.p_memsz as usize,
            align: phdr.p_align as usize,
            image,
        }
    }
}

/// The TLS Index structure passed to `__tls_get_addr`.
/// This matches the C ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsIndex {
    pub ti_module: usize,
    pub ti_offset: usize,
}

/// Dynamic TLSDESC resolver argument.
///
/// This structure is used as the second word of a TLSDESC descriptor
/// when dynamic resolution is required. It contains a pointer to the
/// `tls_get_addr` function and the actual `TlsIndex` data.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct TlsDescDynamicArg {
    pub tls_get_addr: usize,
    pub ti: TlsIndex,
}
