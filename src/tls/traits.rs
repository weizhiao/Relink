use crate::elf::ElfPhdr;
use elf::abi::PT_TLS;

/// Information about a TLS segment from ELF headers.
#[derive(Debug, Clone, Copy, Default)]
pub struct TlsInfo {
    /// Virtual address of the TLS template in the ELF file.
    pub vaddr: usize,
    /// Size of the initialized TLS data.
    pub filesz: usize,
    /// Total size of the TLS block in memory.
    pub memsz: usize,
    /// Alignment requirement of the TLS block.
    pub align: usize,
}

impl TlsInfo {
    /// Creates a new `TlsInfo` from an ELF program header.
    pub fn new(phdr: &ElfPhdr) -> Self {
        assert_eq!(phdr.p_type, PT_TLS);
        Self {
            vaddr: phdr.p_vaddr as usize,
            filesz: phdr.p_filesz as usize,
            memsz: phdr.p_memsz as usize,
            align: phdr.p_align as usize,
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

/// A trait for resolving TLS (Thread Local Storage) information.
///
/// Implement this trait to provide custom TLS module IDs and thread pointer offsets.
/// This is essential for supporting TLS in environments with custom thread management.
pub trait TlsResolver {
    /// Returns the module ID for the given ELF object.
    ///
    /// # Arguments
    /// * `name` - The name of the ELF object.
    /// * `tls_info` - TLS metadata for the ELF object.
    /// * `tls_image` - The initial TLS data (template).
    fn register(tls_info: &TlsInfo, tls_image: &'static [u8]) -> Option<usize>;

    /// Returns the offset from the thread pointer for a given symbol.
    ///
    /// # Arguments
    /// * `mod_id` - The module ID of the ELF object containing the symbol.
    fn tp_offset(mod_id: usize) -> Option<isize>;

    /// Called when the module is unloaded.
    /// Implementations should release any resources associated with this module.
    fn unregister(mod_id: usize);

    /// Returns the address of a thread-local variable.
    extern "C" fn tls_get_addr(ti: *const TlsIndex) -> *mut u8;
}
