use super::{
    ObjectSections, ObjectSymbolTable,
    layout::{ObjectSegments, SectionSegments},
    section_entries,
};
use crate::{
    RelocationError, Result,
    arch::NativeArch,
    elf::{ElfSectionType, ElfShdr, Lifecycle},
    input::{ModuleSourceId, PathBuf},
    memory::{HostRegion, ImageMemory, RegionAccess, VmAddr},
    relocation::ObjectArch,
    runtime::{CodeExecutor, DomainId},
    sync::Arc,
    tls::TlsResolver,
};
use alloc::boxed::Box;

/// Builder for creating relocatable ELF objects.
pub(crate) struct ObjectBuilder<
    Tls,
    D = (),
    Arch: ObjectArch = NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) path: PathBuf,
    pub(crate) source_id: ModuleSourceId,
    pub(crate) sections: ObjectSections<Arch::Layout>,
    pub(crate) symtab: ObjectSymbolTable<Arch::Layout>,
    pub(crate) init: Lifecycle,
    pub(crate) fini: Lifecycle,
    pub(crate) segments: ObjectSegments<R>,
    pub(crate) section_segments: SectionSegments<Arch>,
    pub(crate) user_data: D,
    pub(crate) executor: Arc<dyn CodeExecutor<Arch>>,
    pub(crate) domain: DomainId,
    pub(crate) tls_resolver: Tls,
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
        let array = array.iter().copied().map(VmAddr::new).collect::<Box<[_]>>();
        Ok(Lifecycle::new(None, Some(array)))
    }

    fn prepare_section_data<Memory>(
        shdrs: &[ElfShdr<Arch::Layout>],
        memory: &Memory,
    ) -> Result<ObjectSectionData<Arch>>
    where
        Memory: ImageMemory + ?Sized,
    {
        let mut symtab = None;
        let mut init = Lifecycle::new(None, None);
        let mut fini = Lifecycle::new(None, None);

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
        user_data: D,
        executor: Arc<dyn CodeExecutor<Arch>>,
        domain: DomainId,
        tls_resolver: T,
    ) -> Result<Self> {
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
            init,
            fini,
            user_data,
            executor,
            domain,
            tls_resolver,
        })
    }
}
