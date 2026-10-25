use super::{
    ObjectSections, ObjectSymbolTable,
    layout::{ObjectSegments, PltGotSection, SectionSegments},
    section_entries,
};
use crate::{
    RelocationError, Result,
    arch::NativeArch,
    elf::{ElfSectionType, ElfShdr, Lifecycle},
    input::{ModulePath, ModuleSourceId, PathBuf},
    memory::{HostRegion, ImageMemory, RegionAccess, VmAddr},
    relocation::ObjectArch,
    runtime::Domain,
    tls::TlsResolver,
};

/// Builder for creating relocatable ELF objects.
pub(crate) struct ObjectBuilder<
    Tls: TlsResolver<Arch>,
    D = (),
    Arch: ObjectArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) path: ModulePath,
    pub(crate) source_id: ModuleSourceId,
    pub(crate) sections: ObjectSections<Arch::Layout>,
    pub(crate) symtab: ObjectSymbolTable<Arch::Layout>,
    pub(crate) init: Lifecycle,
    pub(crate) fini: Lifecycle,
    pub(crate) segments: ObjectSegments<R>,
    pub(crate) section_segments: SectionSegments<Arch>,
    pub(crate) pltgot: PltGotSection,
    pub(crate) user_data: D,
    pub(crate) domain: Domain<Arch, Tls>,
}

struct ObjectSectionData<Arch: ObjectArch> {
    symtab: ObjectSymbolTable<Arch::Layout>,
    init: Lifecycle,
    fini: Lifecycle,
}

impl<T, D: Send + Sync + 'static, Arch, R> ObjectBuilder<T, D, Arch, R>
where
    T: TlsResolver<Arch>,
    Arch: ObjectArch,
    R: RegionAccess,
{
    fn prepare_lifecycle_array<Memory>(
        lifecycle_array_shdr: &ElfShdr<Arch::Layout>,
        memory: &Memory,
    ) -> Result<Lifecycle>
    where
        Memory: ImageMemory + ?Sized,
    {
        let array: &[usize] = section_entries(memory, lifecycle_array_shdr)?;
        Ok(Lifecycle::new(None, array.iter().copied().map(VmAddr::new)))
    }

    fn prepare_section_data<Memory>(
        shdrs: &[ElfShdr<Arch::Layout>],
        memory: &Memory,
    ) -> Result<ObjectSectionData<Arch>>
    where
        Memory: ImageMemory + ?Sized,
    {
        let mut symtab = None;
        let mut init = Lifecycle::default();
        let mut fini = Lifecycle::default();

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => {
                    symtab = Some(ObjectSymbolTable::from_shdrs(shdr, shdrs, memory)?)
                }
                ElfSectionType::INIT_ARRAY => init = Self::prepare_lifecycle_array(shdr, memory)?,
                ElfSectionType::FINI_ARRAY => fini = Self::prepare_lifecycle_array(shdr, memory)?,
                _ => {}
            }
        }

        Ok(ObjectSectionData {
            symtab: symtab.ok_or(RelocationError::MissingSymbolTable)?,
            init,
            fini,
        })
    }

    pub(crate) fn new(
        path: PathBuf,
        source_id: ModuleSourceId,
        sections: ObjectSections<Arch::Layout>,
        segments: ObjectSegments<R>,
        section_segments: SectionSegments<Arch>,
        pltgot: PltGotSection,
        user_data: D,
        domain: Domain<Arch, T>,
    ) -> Result<Self> {
        let path = ModulePath::try_from(path).map_err(|_| crate::IoError::NullByteInPath)?;
        let shdrs = sections.headers();
        let ObjectSectionData { symtab, init, fini } = {
            let memory = segments.view();
            Self::prepare_section_data(shdrs, &memory)?
        };

        Ok(Self {
            path,
            source_id,
            sections,
            symtab,
            segments,
            section_segments,
            pltgot,
            init,
            fini,
            user_data,
            domain,
        })
    }
}
