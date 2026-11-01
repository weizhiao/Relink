//! Read-only snapshots of the workload library's mappings, including BSS.
use object::{Object, ObjectSegment, ObjectSymbol};
use std::{ops::Range, path::Path};

type Snapshot = Result<Pages, Box<dyn std::error::Error>>;

pub fn report(label: &str, before: Snapshot, after: Snapshot) {
    eprintln!("{label} mappings (MiB; partial VMAs are excluded from counts):");
    eprintln!(
        "  {:<10} {:>10} {:>10} {:>10} {:>10} {:>13}",
        "Snapshot", "File", "Anonymous", "Shmem", "RSS", "Partial VMAs"
    );
    for (phase, snapshot) in [("Before", before), ("After", after)] {
        match snapshot {
            Ok(pages) => eprintln!(
                "  {phase:<10} {:>10.1} {:>10.1} {:>10.1} {:>10.1} {:>13}",
                pages.file_pmd as f64 / 1024.0,
                pages.anon_huge as f64 / 1024.0,
                pages.shmem_pmd as f64 / 1024.0,
                pages.rss as f64 / 1024.0,
                pages.partial_vmas,
            ),
            Err(error) => eprintln!("  {phase:<10} unavailable: {error}"),
        }
    }
}

#[derive(Default)]
pub struct Pages {
    file_pmd: usize,
    anon_huge: usize,
    shmem_pmd: usize,
    partial_vmas: usize,
    rss: usize,
}

pub fn snapshot(library: &Path, anchor_name: &str, anchor: usize) -> Snapshot {
    let bytes = std::fs::read(library)?;
    let elf = object::File::parse(bytes.as_slice())?;
    let symbol = elf
        .dynamic_symbols()
        .find(|symbol| symbol.is_definition() && symbol.name() == Ok(anchor_name))
        .ok_or("anchor is missing from the dynamic symbol table")?;
    let base = anchor
        .checked_sub(usize::try_from(symbol.address())?)
        .ok_or("invalid library load address")?;
    // SAFETY: sysconf has no memory or ownership preconditions.
    let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    if !page_size.is_power_of_two() {
        return Err("invalid system page size".into());
    }
    let mut image_start = usize::MAX;
    let mut image_end = 0;
    for segment in elf.segments() {
        let start = base
            .checked_add(usize::try_from(segment.address())?)
            .ok_or("library segment address overflow")?;
        let end = start
            .checked_add(usize::try_from(segment.size())?)
            .and_then(|end| end.checked_add(page_size - 1))
            .ok_or("library segment end overflow")?;
        image_start = image_start.min(start & !(page_size - 1));
        image_end = image_end.max(end & !(page_size - 1));
    }
    let image = image_start..image_end;
    if image.is_empty() {
        return Err("library has no load segments".into());
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
                "Rss:" => &mut pages.rss,
                _ => continue,
            };
            *counter += fields
                .next()
                .ok_or("missing smaps counter")?
                .parse::<usize>()?;
        }
    }
    if !matched {
        return Err("library mappings are missing from smaps".into());
    }
    Ok(pages)
}

fn mapping_range(field: &str) -> Option<Range<usize>> {
    let (start, end) = field.split_once('-')?;
    Some(usize::from_str_radix(start, 16).ok()?..usize::from_str_radix(end, 16).ok()?)
}
