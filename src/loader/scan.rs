use super::{LoadHook, Loader};
use crate::{
    ParseDynamicError, ParseEhdrError, ParsePhdrError, Result,
    elf::{ElfDyn, ElfFileType, ElfPhdr, ElfProgramType},
    image::{ScannedDylib, ScannedDynamicInfo},
    input::{ElfReader, IntoElfReader},
    logging,
    os::Mmap,
    tls::TlsResolver,
};
use alloc::{borrow::ToOwned, boxed::Box, string::String, vec, vec::Vec};
use core::{mem::size_of, num::NonZeroUsize};
use elf::abi::{DF_1_NOW, DF_BIND_NOW, DF_STATIC_TLS, DT_STRSZ};

struct OwnedDynamicScan {
    dynamic: ScannedDynamicInfo,
    needed_libs: Box<[String]>,
    rpath: Option<Box<str>>,
    runpath: Option<Box<str>>,
}

fn read_bytes(object: &mut impl ElfReader, offset: usize, len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; len];
    object.read(&mut bytes, offset)?;
    Ok(bytes)
}

fn read_typed<T>(object: &mut impl ElfReader, offset: usize, count: usize) -> Result<Vec<T>> {
    let byte_len = count
        .checked_mul(size_of::<T>())
        .ok_or(ParseDynamicError::AddressOverflow)?;
    let mut values = Vec::<T>::with_capacity(count);
    unsafe {
        values.set_len(count);
    }
    let bytes =
        unsafe { core::slice::from_raw_parts_mut(values.as_mut_ptr().cast::<u8>(), byte_len) };
    object.read(bytes, offset)?;
    Ok(values)
}

fn read_terminated_str(bytes: &[u8], offset: usize, field: &'static str) -> Result<Box<str>> {
    let value = bytes
        .get(offset..)
        .ok_or(ParseDynamicError::AddressOverflow)?;
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    let s =
        core::str::from_utf8(&value[..end]).map_err(|_| ParsePhdrError::InvalidUtf8 { field })?;
    Ok(s.into())
}

fn read_interp(object: &mut impl ElfReader, phdrs: &[ElfPhdr]) -> Result<Option<Box<str>>> {
    let Some(interp) = phdrs
        .iter()
        .find(|phdr| phdr.program_type() == ElfProgramType::INTERP)
    else {
        return Ok(None);
    };

    let bytes = read_bytes(object, interp.p_offset(), interp.p_filesz())?;
    Ok(Some(read_terminated_str(&bytes, 0, "PT_INTERP")?))
}

fn vaddr_to_file_offset(vaddr: usize, phdrs: &[ElfPhdr]) -> Result<usize> {
    for phdr in phdrs
        .iter()
        .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
    {
        let seg_start = phdr.p_vaddr();
        let seg_end = seg_start
            .checked_add(phdr.p_filesz())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        if seg_start <= vaddr && vaddr < seg_end {
            return phdr
                .p_offset()
                .checked_add(vaddr - seg_start)
                .ok_or(ParseDynamicError::AddressOverflow.into());
        }
    }

    Err(ParsePhdrError::MalformedProgramHeaders.into())
}

fn strtab_limit(vaddr: usize, phdrs: &[ElfPhdr]) -> Result<usize> {
    for phdr in phdrs
        .iter()
        .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
    {
        let seg_start = phdr.p_vaddr();
        let seg_end = seg_start
            .checked_add(phdr.p_filesz())
            .ok_or(ParseDynamicError::AddressOverflow)?;
        if seg_start <= vaddr && vaddr < seg_end {
            return Ok(seg_end - vaddr);
        }
    }

    Err(ParsePhdrError::MalformedProgramHeaders.into())
}

fn scan_dynamic(object: &mut impl ElfReader, phdrs: &[ElfPhdr]) -> Result<OwnedDynamicScan> {
    let dynamic_phdr = phdrs
        .iter()
        .find(|phdr| phdr.program_type() == ElfProgramType::DYNAMIC)
        .ok_or(ParsePhdrError::MissingDynamicSection)?;
    if dynamic_phdr.p_filesz() % size_of::<ElfDyn>() != 0 {
        return Err(ParsePhdrError::MalformedProgramHeaders.into());
    }

    let dyns = read_typed::<ElfDyn>(
        object,
        dynamic_phdr.p_offset(),
        dynamic_phdr.p_filesz() / size_of::<ElfDyn>(),
    )?;

    let mut strtab_vaddr = None;
    let mut strtab_size = None;
    let mut needed_offsets = Vec::<NonZeroUsize>::new();
    let mut rpath_off = None;
    let mut runpath_off = None;
    let mut flags = 0;
    let mut flags_1 = 0;

    for dynamic in &dyns {
        let tag = dynamic.tag().raw();
        let value = dynamic.value();
        match tag {
            elf::abi::DT_STRTAB => strtab_vaddr = NonZeroUsize::new(value),
            DT_STRSZ => strtab_size = NonZeroUsize::new(value),
            elf::abi::DT_NEEDED => {
                if let Some(value) = NonZeroUsize::new(value) {
                    needed_offsets.push(value);
                }
            }
            elf::abi::DT_RPATH => rpath_off = NonZeroUsize::new(value),
            elf::abi::DT_RUNPATH => runpath_off = NonZeroUsize::new(value),
            elf::abi::DT_FLAGS => flags = value,
            elf::abi::DT_FLAGS_1 => flags_1 = value,
            elf::abi::DT_NULL => break,
            _ => {}
        }
    }

    let strtab_vaddr = strtab_vaddr.ok_or(ParseDynamicError::AddressOverflow)?;
    let strtab_file_off = vaddr_to_file_offset(strtab_vaddr.get(), phdrs)?;
    let strtab_size = match strtab_size {
        Some(size) => size.get(),
        None => strtab_limit(strtab_vaddr.get(), phdrs)?,
    };
    let strtab = read_bytes(object, strtab_file_off, strtab_size)?;

    let needed_libs = needed_offsets
        .into_iter()
        .map(|offset| read_terminated_str(&strtab, offset.get(), "DT_NEEDED").map(String::from))
        .collect::<Result<Vec<_>>>()?
        .into_boxed_slice();
    let rpath = rpath_off
        .map(|offset| read_terminated_str(&strtab, offset.get(), "DT_RPATH"))
        .transpose()?;
    let runpath = runpath_off
        .map(|offset| read_terminated_str(&strtab, offset.get(), "DT_RUNPATH"))
        .transpose()?;

    Ok(OwnedDynamicScan {
        dynamic: ScannedDynamicInfo::new(
            flags & DF_BIND_NOW as usize != 0 || flags_1 & DF_1_NOW as usize != 0,
            flags & DF_STATIC_TLS as usize != 0,
        ),
        needed_libs,
        rpath,
        runpath,
    })
}

impl<M, H, D, Tls> Loader<M, H, D, Tls>
where
    M: Mmap,
    H: LoadHook,
    D: 'static,
    Tls: TlsResolver,
{
    /// Scans a shared object and returns metadata without mapping its segments.
    pub fn scan_dylib<'a, I>(&mut self, input: I) -> Result<ScannedDylib<D>>
    where
        I: IntoElfReader<'a>,
    {
        self.scan_dylib_impl(input.into_reader()?)
    }

    pub(crate) fn scan_dylib_impl(
        &mut self,
        mut object: impl ElfReader,
    ) -> Result<ScannedDylib<D>> {
        logging::debug!("Scanning dylib metadata: {}", object.file_name());

        let ehdr = self.read_ehdr(&mut object)?;
        if ehdr.file_type() != ElfFileType::DYN {
            let file_type = ehdr.file_type();
            return Err(ParseEhdrError::ExpectedDylib { found: file_type }.into());
        }

        let phdrs = self
            .read_phdr(&mut object, &ehdr)?
            .unwrap_or_default()
            .to_vec();
        let name = object.file_name().to_owned();
        let interp = read_interp(&mut object, &phdrs)?;
        let dynamic = scan_dynamic(&mut object, &phdrs)?;
        let user_data = self.inner.load_user_data(
            &name,
            &ehdr,
            Some(phdrs.as_slice()),
            None,
            Some(&mut object),
        );

        Ok(ScannedDylib::from_parts(
            name,
            ehdr,
            phdrs.into_boxed_slice(),
            interp,
            dynamic.rpath,
            dynamic.runpath,
            dynamic.needed_libs,
            dynamic.dynamic,
            user_data,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::Loader;
    use crate::{
        Result,
        arch::EM_ARCH,
        elf::{E_CLASS, EHDR_SIZE, ElfDyn, ElfEhdr, ElfPhdr, ElfProgramFlags, ElfProgramType},
        input::ElfReader,
        loader::ElfBuf,
    };
    use alloc::{vec, vec::Vec};
    use core::mem::size_of;
    use elf::abi::{
        DF_BIND_NOW, DT_FLAGS, DT_NEEDED, DT_NULL, DT_STRSZ, DT_STRTAB, EI_CLASS, EI_VERSION,
        ELFMAGIC, ET_DYN, EV_CURRENT,
    };

    struct TestReader {
        name: &'static str,
        bytes: Vec<u8>,
    }

    impl ElfReader for TestReader {
        fn file_name(&self) -> &str {
            self.name
        }

        fn read(&mut self, buf: &mut [u8], offset: usize) -> Result<()> {
            buf.copy_from_slice(&self.bytes[offset..offset + buf.len()]);
            Ok(())
        }

        fn as_fd(&self) -> Option<isize> {
            None
        }
    }

    fn write_bytes(bytes: &mut [u8], offset: usize, src: &[u8]) {
        bytes[offset..offset + src.len()].copy_from_slice(src);
    }

    fn as_bytes<T>(values: &[T]) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                values.as_ptr().cast::<u8>(),
                core::mem::size_of_val(values),
            )
        }
    }

    fn make_header(phnum: usize) -> ElfEhdr {
        let mut ehdr = unsafe { core::mem::zeroed::<ElfEhdr>() };
        ehdr.e_ident[0..4].copy_from_slice(&ELFMAGIC);
        ehdr.e_ident[EI_CLASS] = E_CLASS;
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_type = ET_DYN as _;
        ehdr.e_machine = EM_ARCH;
        ehdr.e_version = EV_CURRENT as _;
        ehdr.e_ehsize = EHDR_SIZE as _;
        ehdr.e_phoff = EHDR_SIZE as _;
        ehdr.e_phentsize = size_of::<ElfPhdr>() as _;
        ehdr.e_phnum = phnum as _;
        ehdr
    }

    #[test]
    fn scan_dylib_reads_dynamic_metadata_without_mapping() {
        let phoff = EHDR_SIZE;
        let load_off = 0x100;
        let dynamic_off = 0x180;
        let strtab_off = 0x220;
        let base_vaddr = 0x1000;
        let dynamic_vaddr = base_vaddr + (dynamic_off - load_off);
        let strtab_vaddr = base_vaddr + (strtab_off - load_off);

        let strings = b"\0libdep.so\0$ORIGIN/lib\0";
        let dyns = [
            ElfDyn::new(crate::elf::ElfDynamicTag::new(DT_STRTAB), strtab_vaddr),
            ElfDyn::new(crate::elf::ElfDynamicTag::new(DT_STRSZ), strings.len()),
            ElfDyn::new(crate::elf::ElfDynamicTag::new(DT_NEEDED), 1),
            ElfDyn::new(crate::elf::ElfDynamicTag::new(elf::abi::DT_RUNPATH), 11),
            ElfDyn::new(
                crate::elf::ElfDynamicTag::new(DT_FLAGS),
                DF_BIND_NOW as usize,
            ),
            ElfDyn::new(crate::elf::ElfDynamicTag::new(DT_NULL), 0),
        ];
        let phdrs = [
            ElfPhdr::new(
                ElfProgramType::LOAD,
                ElfProgramFlags::READ,
                load_off,
                base_vaddr,
                base_vaddr,
                0x200,
                0x200,
                0x1000,
            ),
            ElfPhdr::new(
                ElfProgramType::DYNAMIC,
                ElfProgramFlags::READ,
                dynamic_off,
                dynamic_vaddr,
                dynamic_vaddr,
                size_of::<[ElfDyn; 6]>(),
                size_of::<[ElfDyn; 6]>(),
                size_of::<usize>(),
            ),
        ];

        let mut bytes = vec![0; 0x400];
        let ehdr = make_header(phdrs.len());
        write_bytes(&mut bytes, 0, unsafe {
            core::slice::from_raw_parts(
                (&ehdr as *const ElfEhdr).cast::<u8>(),
                size_of::<ElfEhdr>(),
            )
        });
        write_bytes(&mut bytes, phoff, as_bytes(&phdrs));
        write_bytes(&mut bytes, dynamic_off, as_bytes(&dyns));
        write_bytes(&mut bytes, strtab_off, strings);

        let mut loader = Loader::new();
        let scanned = loader
            .scan_dylib_impl(TestReader {
                name: "libscan.so",
                bytes,
            })
            .expect("scan should succeed");

        assert_eq!(scanned.name(), "libscan.so");
        assert_eq!(scanned.needed_libs(), ["libdep.so"]);
        assert_eq!(scanned.runpath(), Some("$ORIGIN/lib"));
        assert!(scanned.dynamic().bind_now());
        assert!(!scanned.dynamic().static_tls());
        assert_eq!(scanned.phdrs().len(), 2);

        let _ = ElfBuf::new();
    }
}
