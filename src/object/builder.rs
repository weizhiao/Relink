use super::{
    CustomHash, ObjectSections,
    layout::{ObjectSegmentView, ObjectSegments, PltGotSection, SectionLifetime, SectionSegments},
    section_entries,
};
use crate::{
    RelocationError, Result,
    elf::{ElfSectionId, ElfSectionType, ElfShdr, Lifecycle, SymbolTable},
    input::PathBuf,
    loader::LoaderInner,
    memory::{HostRegion, RegionAccess, VmAddr},
    observer::LoadObserver,
    relocation::ObjectRelocationArch,
    tls::{TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

/// Builder for creating relocatable ELF objects.
pub(crate) struct ObjectBuilder<
    Tls,
    D = (),
    Arch: ObjectRelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) path: PathBuf,
    pub(crate) shdrs: Vec<ElfShdr<Arch::Layout>>,
    pub(crate) symtab: SymbolTable<Arch::Layout, CustomHash>,
    pub(crate) post_init_symtab: Option<SymbolTable<Arch::Layout, CustomHash>>,
    pub(crate) init: Lifecycle,
    pub(crate) segments: ObjectSegments<R>,
    pub(crate) mprotect: Box<dyn for<'segments> Fn(&ObjectSegmentView<'segments, R>) -> Result<()>>,
    pub(crate) pltgot: PltGotSection,
    pub(crate) tls_mod_id: Option<TlsModuleId>,
    pub(crate) tls_tp_offset: Option<TlsTpOffset>,
    pub(crate) user_data: D,
    _marker_tls: PhantomData<Tls>,
    _marker_arch: PhantomData<Arch>,
}

struct ObjectSectionData<Arch: ObjectRelocationArch> {
    symtab: SymbolTable<Arch::Layout, CustomHash>,
    init: Lifecycle,
}

impl<T, D, Arch, R> ObjectBuilder<T, D, Arch, R>
where
    T: TlsResolver,
    Arch: ObjectRelocationArch,
    R: RegionAccess,
{
    fn prepare_init_array<Memory>(
        init_array_shdr: &ElfShdr<Arch::Layout>,
        memory: &Memory,
    ) -> Result<Lifecycle>
    where
        Memory: crate::memory::ImageMemory + ?Sized,
    {
        let array: &[usize] = section_entries(memory, init_array_shdr)?;
        let array = array.iter().copied().map(VmAddr::new).collect::<Box<[_]>>();
        Ok(Lifecycle::new(None, Some(array)))
    }

    fn prepare_section_data<Memory>(
        shdrs: &[ElfShdr<Arch::Layout>],
        memory: &Memory,
    ) -> Result<ObjectSectionData<Arch>>
    where
        Memory: crate::memory::ImageMemory + ?Sized,
    {
        let mut symtab = None;
        let mut init = Lifecycle::new(None, None);

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => {
                    symtab = Some(SymbolTable::from_shdrs(shdr, shdrs, memory)?)
                }
                ElfSectionType::INIT_ARRAY => init = Self::prepare_init_array(shdr, memory)?,
                _ => {}
            }
        }

        Ok(ObjectSectionData {
            symtab: symtab.ok_or(RelocationError::MissingSymbolTable)?,
            init,
        })
    }

    fn post_init_symtab(
        shdrs: &[ElfShdr<Arch::Layout>],
        shdr_segments: &SectionSegments<Arch>,
    ) -> Option<SymbolTable<Arch::Layout, CustomHash>> {
        for (index, shdr) in shdrs.iter().enumerate() {
            if shdr.section_type() != ElfSectionType::SYMTAB {
                continue;
            }

            let symtab_id = ElfSectionId::new(index);
            let strtab_id = ElfSectionId::new(shdr.sh_link() as usize);
            if shdr_segments.section_lifetime(symtab_id) == Some(SectionLifetime::Init)
                || shdr_segments.section_lifetime(strtab_id) == Some(SectionLifetime::Init)
            {
                return Some(SymbolTable::empty_object());
            }
        }

        None
    }

    pub(crate) fn new(
        path: PathBuf,
        mut sections: ObjectSections<Arch::Layout>,
        segments: ObjectSegments<R>,
        mut shdr_segments: SectionSegments<Arch>,
        user_data: D,
    ) -> Result<Self> {
        let shdrs = sections.headers_mut();
        let post_init_symtab = Self::post_init_symtab(shdrs, &shdr_segments);
        let pltgot = shdr_segments.take_pltgot();
        let ObjectSectionData { symtab, init } = {
            let memory = segments.view();
            Self::prepare_section_data(shdrs, &memory)?
        };
        let mprotect =
            Box::new(move |segments: &ObjectSegmentView<'_, R>| shdr_segments.mprotect(segments));
        let shdrs = sections.into_headers();

        Ok(Self {
            path,
            shdrs,
            symtab,
            post_init_symtab,
            segments,
            mprotect,
            pltgot,
            init,
            tls_mod_id: None,
            tls_tp_offset: None,
            user_data,
            _marker_tls: PhantomData,
            _marker_arch: PhantomData,
        })
    }
}

impl<Obs, D, Arch, M> LoaderInner<Obs, D, Arch, M>
where
    Obs: LoadObserver<D, Arch>,
    D: Default + 'static,
    Arch: crate::relocation::ObjectRelocationArch,
    M: crate::os::Mmap,
{
    pub(crate) fn create_object_builder<Tls>(
        &mut self,
        mut sections: ObjectSections<Arch::Layout>,
        object: impl crate::input::ElfReader,
        user_data: D,
    ) -> Result<ObjectBuilder<Tls, D, Arch, M::Region>>
    where
        Tls: TlsResolver,
    {
        let path = PathBuf::from(object.path());
        let page_size = self.page_size()?.bytes();
        let mut shdr_segments = SectionSegments::<Arch>::new::<D, _>(
            &mut sections,
            &object,
            page_size,
            &mut self.observer,
        )?;
        let mapper = self.mapper();
        let segments = shdr_segments.load_segments(mapper, &object)?;
        shdr_segments.rebase_loaded_sections(sections.headers_mut(), &segments);

        ObjectBuilder::new(path, sections, segments, shdr_segments, user_data)
    }
}
