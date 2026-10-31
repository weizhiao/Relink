//! Construct a synthetic module from a native library and its ELF export metadata.
use super::{error::metadata, native::NativeLibrary, tls::HostTls};
use crate::{
    ByteRepr, Domain, Loader, Result,
    arch::NativeArch,
    elf::{
        ElfDyn, ElfDynamicTag, ElfGnuHeader, ElfPhdr, ElfProgramType, ElfSymbol, ElfSymbolType,
        abi, parse_dynamic_entries,
        version::{VerDef, VerDefAux},
    },
    image::{ModuleHandle, SyntheticModule, SyntheticSymbol},
    input::{ElfFile, ElfReader, ElfReaderExt, Path},
    sync::Arc,
    tls::{DefaultTlsResolver, TlsInfo},
};
use alloc::{collections::BTreeMap, ffi::CString, string::String, vec::Vec};
use core::{ffi::CStr, mem::size_of};

struct ExportVersion {
    name: CString,
    is_default: bool,
}

/// Opens a native library and imports its exports into `domain` under `name`.
///
/// Uses `RTLD_NOW | RTLD_LOCAL`; the returned module retains the native handle.
/// glibc manages initialization, finalization, and TLS storage. Imported addresses
/// refer to the current process and must be interpreted accordingly by `domain`.
/// Static TLS offsets are not imported, so initial-exec relocations against these
/// TLS exports are unsupported. Symbol versions are retained without the `version`
/// feature; exact version lookup requires that feature.
///
/// Paths are used without SONAME searching. Relative paths, including bare
/// filenames, are relative to the current directory. Export metadata is read
/// through program headers; section headers are optional.
///
/// # Safety
/// Loading, resolving IFUNCs, and unloading can execute arbitrary native code.
/// That code must be safe to execute for the lifetime of the returned module.
/// The file must be a valid ELF image; metadata is trusted without structural
/// validation. It must describe the image returned by `dlopen`, including when glibc
/// reuses an existing mapping. Do not replace or modify the file, or change the
/// working directory, while this call is in progress.
pub unsafe fn open(
    domain: &Domain<NativeArch, DefaultTlsResolver>,
    path: impl AsRef<Path>,
    name: impl Into<String>,
) -> Result<ModuleHandle> {
    let path = path.as_ref();
    let file = ElfFile::from_path(path)?;
    let header = Loader::new().read_ehdr(&file)?;
    let headers = file.read_to_vec::<ElfPhdr>(header.e_phoff(), header.e_phnum())?;
    let reader = FileView {
        file: &file,
        headers: &headers,
    };
    let entries = reader.read_dynamic_entries()?;
    let dynamic = parse_dynamic_entries(entries.iter().map(|entry| (entry.tag(), entry.value())));
    let string_size = dynamic
        .strtab_size
        .ok_or_else(|| metadata("missing DT_STRSZ"))?
        .get();
    let strings = reader.read_array::<u8>(dynamic.strtab_off, string_size)?;
    let symbol_count = reader.symbol_count(dynamic.elf_hash_off, dynamic.gnu_hash_off)?;
    let symbols = reader.read_array::<ElfSymbol>(dynamic.symtab_off, symbol_count)?;
    let version_ids = dynamic
        .version_ids_off
        .map(|address| reader.read_array::<u16>(address.get(), symbol_count))
        .transpose()?;
    let definitions = reader.read_version_definitions(
        dynamic.verdef_off.map(|address| address.get()),
        dynamic_value(&entries, ElfDynamicTag::VERDEFNUM),
        &strings,
    )?;

    let library = Arc::new(unsafe { NativeLibrary::open(path) }?);
    let mut module = SyntheticModule::empty(domain, name).with_data(library.clone());
    if let Some(header) = headers
        .iter()
        .find(|header| header.program_type() == ElfProgramType::TLS)
    {
        let provider = HostTls::new(library.clone())?;
        // SAFETY: the metadata describes the retained native image; the provider
        // delegates storage to glibc and never frees or republishes its bytes.
        let registration = unsafe {
            domain
                .tls_resolver()
                .register_provider(TlsInfo::new(header), None, provider)
        }?;
        module = module.with_tls(registration)?;
    }
    for (index, symbol) in symbols.into_iter().enumerate().skip(1) {
        if !is_export(&symbol) {
            continue;
        }
        let version_id = version_ids.as_ref().map(|ids| ids[index]);
        let version = export_version(version_id, &definitions)?;
        let name = read_string(&strings, symbol.st_name())?;
        module.insert(import_symbol(symbol, name, version, &library)?);
    }
    Ok(module.into())
}

fn import_symbol(
    symbol: ElfSymbol,
    name: CString,
    version: Option<ExportVersion>,
    library: &NativeLibrary,
) -> Result<SyntheticSymbol> {
    let mut export = if symbol.symbol_type() == ElfSymbolType::TLS {
        SyntheticSymbol::tls(name.as_c_str(), symbol.st_value(), symbol.st_size())
    } else {
        let address = library.lookup(
            &name,
            version.as_ref().map(|version| version.name.as_c_str()),
        )?;
        if symbol.symbol_type() == ElfSymbolType::OBJECT {
            SyntheticSymbol::object(name.as_c_str(), address.cast(), symbol.st_size())
        } else {
            SyntheticSymbol::function(name.as_c_str(), address.cast()).with_size(symbol.st_size())
        }
    }
    .with_other(symbol.st_other())
    .with_bind(symbol.bind());
    if let Some(version) = version {
        export = export.with_version(version.name.to_bytes(), version.is_default);
    }
    Ok(export)
}

/// Reads ELF virtual addresses by locating their file-backed PT_LOAD ranges.
struct FileView<'a, R> {
    file: &'a R,
    headers: &'a [ElfPhdr],
}

impl<R: ElfReader> FileView<'_, R> {
    fn read_dynamic_entries(&self) -> Result<Vec<ElfDyn>> {
        let header = self
            .headers
            .iter()
            .find(|header| header.program_type() == ElfProgramType::DYNAMIC)
            .ok_or_else(|| metadata("missing PT_DYNAMIC"))?;
        let count = header.p_filesz() / size_of::<ElfDyn>();
        let mut entries = self.file.read_to_vec::<ElfDyn>(header.p_offset(), count)?;
        if let Some(end) = entries
            .iter()
            .position(|entry| entry.tag() == ElfDynamicTag::NULL)
        {
            entries.truncate(end);
        }
        Ok(entries)
    }

    fn symbol_count(&self, sysv_hash: Option<usize>, gnu_hash: Option<usize>) -> Result<usize> {
        if let Some(address) = sysv_hash {
            let header = self.read_array::<u32>(address, 2)?;
            // SysV has one chain entry per dynamic symbol, including the null symbol.
            Ok(header[1] as usize)
        } else if let Some(address) = gnu_hash {
            self.gnu_symbol_count(address)
        } else {
            Err(metadata("missing dynamic symbol hash table"))
        }
    }

    fn gnu_symbol_count(&self, address: usize) -> Result<usize> {
        let header = self.read_record::<ElfGnuHeader>(address)?;
        let bloom_address = address + size_of::<ElfGnuHeader>();
        let bloom_size = header.nbloom as usize * size_of::<usize>();
        let buckets_address = bloom_address + bloom_size;
        let buckets = self.read_array::<u32>(buckets_address, header.nbucket as usize)?;
        let symbol_offset = header.symbias as usize;
        // Chains follow symbol order; walking the final bucket gives the table's end.
        let mut symbol_index = buckets.into_iter().max().unwrap_or(0) as usize;
        if symbol_index == 0 {
            return Ok(symbol_offset);
        }
        let buckets_size = header.nbucket as usize * size_of::<u32>();
        let chains_address = buckets_address + buckets_size;
        loop {
            let chain_offset = (symbol_index - symbol_offset) * size_of::<u32>();
            let chain_address = chains_address + chain_offset;
            let hash = self.read_record::<u32>(chain_address)?;
            symbol_index += 1;
            if hash & 1 != 0 {
                return Ok(symbol_index);
            }
        }
    }

    fn read_version_definitions(
        &self,
        address: Option<usize>,
        count: Option<usize>,
        strings: &[u8],
    ) -> Result<BTreeMap<usize, CString>> {
        let mut definitions = BTreeMap::new();
        let Some(mut address) = address else {
            return Ok(definitions);
        };
        let count = count.ok_or_else(|| metadata("missing DT_VERDEFNUM"))?;
        for _ in 0..count {
            let definition = self.read_record::<VerDef>(address)?;
            let aux_address = address + definition.vd_aux as usize;
            let aux = self.read_record::<VerDefAux>(aux_address)?;
            if definition.vd_flags & abi::VER_FLG_BASE == 0 {
                definitions.insert(
                    definition.index(),
                    read_string(strings, aux.vda_name as usize)?,
                );
            }
            address += definition.vd_next as usize;
        }
        Ok(definitions)
    }

    fn file_offset(&self, address: usize) -> Result<usize> {
        let header = self
            .headers
            .iter()
            .find(|header| {
                let start = header.p_vaddr().get();
                header.program_type() == ElfProgramType::LOAD
                    && (start..start + header.p_filesz()).contains(&address)
            })
            .ok_or_else(|| metadata("metadata outside file-backed PT_LOAD ranges"))?;
        Ok(header.p_offset() + (address - header.p_vaddr().get()))
    }

    fn read_array<T: ByteRepr>(&self, address: usize, count: usize) -> Result<Vec<T>> {
        let offset = self.file_offset(address)?;
        self.file.read_to_vec(offset, count)
    }

    fn read_record<T: ByteRepr + Copy>(&self, address: usize) -> Result<T> {
        Ok(self.read_array::<T>(address, 1)?[0])
    }
}

fn dynamic_value(entries: &[ElfDyn], tag: ElfDynamicTag) -> Option<usize> {
    entries
        .iter()
        .find(|entry| entry.tag() == tag)
        .map(ElfDyn::value)
}

fn export_version(
    id: Option<u16>,
    definitions: &BTreeMap<usize, CString>,
) -> Result<Option<ExportVersion>> {
    let Some(id) = id else {
        return Ok(None);
    };
    let index = id & abi::VER_NDX_VERSION;
    if index <= abi::VER_NDX_GLOBAL {
        return Ok(None);
    }
    let name = definitions
        .get(&(index as usize))
        .ok_or_else(|| metadata("missing export version definition"))?
        .clone();
    Ok(Some(ExportVersion {
        name,
        is_default: id & abi::VER_NDX_HIDDEN == 0,
    }))
}

fn read_string(strings: &[u8], offset: usize) -> Result<CString> {
    CStr::from_bytes_until_nul(&strings[offset..])
        .map(CString::from)
        .map_err(metadata)
}

fn is_export(symbol: &ElfSymbol) -> bool {
    symbol.is_exported()
        && matches!(
            symbol.symbol_type(),
            ElfSymbolType::FUNC
                | ElfSymbolType::GNU_IFUNC
                | ElfSymbolType::OBJECT
                | ElfSymbolType::TLS
        )
}
