//! Read-only snapshots of huge pages backing the benchmark's libpython instance.
use super::python::{Installation, Symbols};
use object::{Object, ObjectSegment, ObjectSymbol};
use std::{ffi::c_char, ops::Range};

pub fn report(backend: &str, library: &(impl Symbols + ?Sized), installation: &Installation) {
    match snapshot(library, installation) {
        Ok(pages) => eprintln!(
            "python_pages\t{backend}\tphase=after_bench\tfile_pmd_kib={}\tanon_huge_kib={}\tshmem_pmd_kib={}\tpartial_vmas={}",
            pages.file_pmd, pages.anon_huge, pages.shmem_pmd, pages.partial_vmas
        ),
        Err(error) => eprintln!("python_pages\t{backend}\tunavailable={error}"),
    }
}

#[derive(Default)]
struct Pages {
    file_pmd: usize,
    anon_huge: usize,
    shmem_pmd: usize,
    partial_vmas: usize,
}

fn snapshot(
    library: &(impl Symbols + ?Sized),
    installation: &Installation,
) -> Result<Pages, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(&installation.library)?;
    let elf = object::File::parse(bytes.as_slice())?;
    let symbol = elf
        .dynamic_symbols()
        .find(|symbol| symbol.is_definition() && symbol.name() == Ok("Py_GetVersion"))
        .ok_or("Py_GetVersion is missing from the dynamic symbol table")?;
    // SAFETY: Py_GetVersion has this documented CPython C ABI signature; the
    // loaded library is still alive. Only its address is used here.
    let version: unsafe extern "C" fn() -> *const c_char =
        unsafe { library.symbol(c"Py_GetVersion") };
    let base = (version as usize)
        .checked_sub(usize::try_from(symbol.address())?)
        .ok_or("invalid libpython load address")?;
    // SAFETY: sysconf has no memory or ownership preconditions.
    let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    if !page_size.is_power_of_two() {
        return Err("invalid system page size".into());
    }
    let mut image = usize::MAX..0;
    for segment in elf.segments() {
        let start = base
            .checked_add(usize::try_from(segment.address())?)
            .ok_or("libpython segment address overflow")?;
        let end = start
            .checked_add(usize::try_from(segment.size())?)
            .and_then(|end| end.checked_add(page_size - 1))
            .ok_or("libpython segment end overflow")?;
        image.start = image.start.min(start & !(page_size - 1));
        image.end = image.end.max(end & !(page_size - 1));
    }
    if image.is_empty() {
        return Err("libpython has no load segments".into());
    }

    let smaps = std::fs::read_to_string("/proc/self/smaps")?;
    let mut pages = Pages::default();
    let mut in_image = false;
    let mut matched = false;
    for line in smaps.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else { continue };
        if let Some(mapping) = mapping_range(key) {
            in_image = mapping.start >= image.start && mapping.end <= image.end;
            matched |= in_image;
            if !in_image && mapping.start < image.end && image.start < mapping.end {
                // smaps reports counters per VMA. A merged VMA extending beyond
                // the image cannot be attributed precisely, so do not sum it.
                pages.partial_vmas += 1;
            }
        } else if in_image {
            let counter = match key {
                "FilePmdMapped:" => &mut pages.file_pmd,
                "AnonHugePages:" => &mut pages.anon_huge,
                "ShmemPmdMapped:" => &mut pages.shmem_pmd,
                _ => continue,
            };
            *counter += fields
                .next()
                .ok_or("missing smaps counter")?
                .parse::<usize>()?;
        }
    }
    if !matched {
        return Err("libpython mappings are missing from smaps".into());
    }
    Ok(pages)
}

fn mapping_range(field: &str) -> Option<Range<usize>> {
    let (start, end) = field.split_once('-')?;
    Some(usize::from_str_radix(start, 16).ok()?..usize::from_str_radix(end, 16).ok()?)
}
