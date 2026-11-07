//! Translate Relink TLS requests to the module registered by glibc.
use super::{
    error::metadata,
    native::{self, NativeLibrary},
};
use crate::{
    Result,
    arch::NativeArch,
    relocation::RelocationArch,
    sync::Arc,
    tls::{TlsContext, TlsIndex, TlsModuleId, TlsProvider},
};
use core::{ffi::c_void, ptr::NonNull};

type TlsGetAddr = unsafe extern "C" fn(*const TlsIndex) -> *mut u8;

pub(super) struct HostTls {
    library: Arc<NativeLibrary>,
    mod_id: TlsModuleId,
    get_addr: TlsGetAddr,
}

impl HostTls {
    pub(super) fn new(library: Arc<NativeLibrary>) -> Result<Self> {
        let mut id = 0usize;
        let status = unsafe {
            libc::dlinfo(
                library.handle(),
                libc::RTLD_DI_TLS_MODID,
                (&mut id as *mut usize).cast(),
            )
        };
        if status != 0 {
            return Err(native::last_error("dlinfo(RTLD_DI_TLS_MODID)"));
        }
        if id == 0 {
            return Err(metadata("PT_TLS has no native module ID"));
        }
        let address = library.lookup(c"__tls_get_addr", None)?;
        if address.is_null() {
            return Err(metadata("null __tls_get_addr entry"));
        }
        // SAFETY: the native ABI defines this entry with the TlsGetAddr signature.
        let get_addr = unsafe { core::mem::transmute::<*mut c_void, TlsGetAddr>(address) };
        Ok(Self {
            library,
            mod_id: TlsModuleId::new(id),
            get_addr,
        })
    }
}

// SAFETY: the retained handle pins glibc's registration. glibc supplies each
// thread's block; we translate IDs and the architecture's DTV bias at the boundary.
unsafe impl TlsProvider for HostTls {
    unsafe fn get_or_init(&self, _context: &TlsContext) -> Result<NonNull<u8>> {
        let index = TlsIndex {
            ti_module: self.mod_id,
            ti_offset: 0usize.wrapping_sub(NativeArch::TLS_DTV_OFFSET),
        };
        NonNull::new(unsafe { (self.get_addr)(&index) }).ok_or_else(|| {
            crate::TlsError::InvalidModuleId {
                mod_id: self.mod_id,
            }
            .into()
        })
    }

    unsafe fn get(&self, _context: &TlsContext) -> Option<NonNull<u8>> {
        let mut data: *mut u8 = core::ptr::null_mut();
        let status = unsafe {
            libc::dlinfo(
                self.library.handle(),
                libc::RTLD_DI_TLS_DATA,
                (&mut data as *mut *mut u8).cast(),
            )
        };
        (status == 0).then(|| NonNull::new(data)).flatten()
    }
}
