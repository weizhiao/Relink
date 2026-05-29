use super::{
    CustomHash, ObjectRelocation,
    layout::{PltGotSection, SectionSegments},
};
use crate::{
    RelocationError, Result,
    elf::{
        ElfRelEntry, ElfRelType, ElfSectionType, ElfShdr, ElfSymbol, ElfSymbolType, Lifecycle,
        SymbolTable,
    },
    input::PathBuf,
    loader::LoaderInner,
    observer::LoadObserver,
    os::{HostRegion, RegionAccess, VmAddr, VmOffset},
    relocation::RelocationArch,
    segment::{ElfSegments, SegmentBuilder},
    tls::{TlsModuleId, TlsResolver, TlsTpOffset},
};
use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

/// Builder for creating relocatable ELF objects.
pub(crate) struct ObjectBuilder<
    Tls,
    D = (),
    Arch: RelocationArch = crate::arch::NativeArch,
    R: RegionAccess = HostRegion,
> {
    pub(crate) path: PathBuf,
    pub(crate) symtab: SymbolTable<Arch::Layout, CustomHash>,
    pub(crate) init: Lifecycle,
    pub(crate) segments: ElfSegments<R>,
    pub(crate) relocation: ObjectRelocation<Arch>,
    pub(crate) mprotect: Box<dyn Fn(&ElfSegments<R>) -> Result<()>>,
    pub(crate) pltgot: PltGotSection,
    pub(crate) tls_mod_id: Option<TlsModuleId>,
    pub(crate) tls_tp_offset: Option<TlsTpOffset>,
    pub(crate) user_data: D,
    _marker_tls: PhantomData<Tls>,
    _marker_arch: PhantomData<Arch>,
}

struct ObjectSectionData<Arch: RelocationArch> {
    symtab: SymbolTable<Arch::Layout, CustomHash>,
    relocation: ObjectRelocation<Arch>,
    init: Lifecycle,
}

impl<T, D, Arch, R> ObjectBuilder<T, D, Arch, R>
where
    T: TlsResolver,
    Arch: RelocationArch,
    R: RegionAccess,
{
    #[inline]
    pub(crate) fn validate_shdrs(shdrs: &[ElfShdr<Arch::Layout>]) -> Result<()> {
        let mut has_symtab = false;

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => has_symtab = true,
                ElfSectionType::REL | ElfSectionType::RELA => Self::validate_relocation_shdr(shdr)?,
                _ => {}
            }
        }

        if !has_symtab {
            return Err(RelocationError::MissingSymbolTable.into());
        }

        Ok(())
    }

    #[inline]
    fn validate_relocation_shdr(shdr: &ElfShdr<Arch::Layout>) -> Result<()> {
        debug_assert!(matches!(
            shdr.section_type(),
            ElfSectionType::REL | ElfSectionType::RELA
        ));

        debug_assert_eq!(
            shdr.section_type(),
            <ElfRelType<Arch> as ElfRelEntry<Arch::Layout>>::SECTION_TYPE
        );

        let expected = core::mem::size_of::<ElfRelType<Arch>>();
        let found = shdr.sh_entsize();
        debug_assert_eq!(found, expected);

        Ok(())
    }

    fn rebase_loaded_sections(
        shdrs: &mut [ElfShdr<Arch::Layout>],
        pltgot: &mut PltGotSection,
        base: VmAddr,
    ) {
        shdrs.iter_mut().for_each(|shdr| {
            shdr.set_sh_addr((base + VmOffset::new(shdr.sh_addr())).get());
        });
        pltgot.rebase(base);
    }

    fn prepare_symbol_table(
        symtab_shdr: &ElfShdr<Arch::Layout>,
        shdrs: &[ElfShdr<Arch::Layout>],
        base: VmAddr,
    ) -> SymbolTable<Arch::Layout, CustomHash> {
        let symbols: &mut [ElfSymbol<Arch::Layout>] = symtab_shdr.content_mut();
        for symbol in symbols {
            let section_index = symbol.st_shndx();
            if symbol.symbol_type() == ElfSymbolType::FILE || section_index.is_undef() {
                continue;
            }
            let section_base = shdrs[section_index.index()]
                .sh_addr()
                .wrapping_sub(base.get());
            symbol.set_value(section_base.wrapping_add(symbol.st_value()));
        }

        SymbolTable::from_shdrs(symtab_shdr, shdrs)
    }

    fn prepare_relocation_section(
        relocation_shdr: &ElfShdr<Arch::Layout>,
        shdrs: &[ElfShdr<Arch::Layout>],
        base: VmAddr,
    ) -> &'static [ElfRelType<Arch>] {
        let rels: &mut [ElfRelType<Arch>] = relocation_shdr.content_mut();
        let section_base = VmAddr::new(shdrs[relocation_shdr.sh_info() as usize].sh_addr());
        for rel in rels {
            rel.set_offset((section_base + rel.r_offset()).wrapping_offset_from(base));
        }

        relocation_shdr.content()
    }

    fn prepare_init_array(init_array_shdr: &ElfShdr<Arch::Layout>) -> Lifecycle {
        let array: &[usize] = init_array_shdr.content_mut();
        let array = array.iter().copied().map(VmAddr::new).collect::<Box<[_]>>();
        Lifecycle::new(None, Some(array))
    }

    fn prepare_section_data(
        shdrs: &[ElfShdr<Arch::Layout>],
        base: VmAddr,
    ) -> Result<ObjectSectionData<Arch>> {
        let mut symtab = None;
        let mut relocation = Vec::with_capacity(shdrs.len());
        let mut init = Lifecycle::new(None, None);

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => {
                    symtab = Some(Self::prepare_symbol_table(shdr, shdrs, base))
                }
                ElfSectionType::RELA | ElfSectionType::REL => {
                    relocation.push(Self::prepare_relocation_section(shdr, shdrs, base))
                }
                ElfSectionType::INIT_ARRAY => init = Self::prepare_init_array(shdr),
                _ => {}
            }
        }

        Ok(ObjectSectionData {
            symtab: symtab.ok_or(RelocationError::MissingSymbolTable)?,
            relocation: ObjectRelocation::new(relocation),
            init,
        })
    }

    pub(crate) fn new(
        path: PathBuf,
        shdrs: &mut [ElfShdr<Arch::Layout>],
        segments: ElfSegments<R>,
        mprotect: Box<dyn Fn(&ElfSegments<R>) -> Result<()>>,
        mut pltgot: PltGotSection,
        user_data: D,
    ) -> Result<Self> {
        Self::validate_shdrs(shdrs)?;
        let base = segments.base();
        Self::rebase_loaded_sections(shdrs, &mut pltgot, base);
        let ObjectSectionData {
            symtab,
            relocation,
            init,
        } = Self::prepare_section_data(shdrs, base)?;

        Ok(Self {
            path,
            symtab,
            segments,
            mprotect,
            relocation,
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
    Obs: LoadObserver<Arch>,
    D: Default + 'static,
    Arch: crate::relocation::RelocationArch,
    M: crate::os::Mmap,
{
    pub(crate) fn create_object_builder<Tls>(
        &mut self,
        shdrs: &mut [ElfShdr<Arch::Layout>],
        mut object: impl crate::input::ElfReader,
    ) -> Result<ObjectBuilder<Tls, D, Arch, M::Region>>
    where
        Tls: TlsResolver,
    {
        let path = PathBuf::from(object.path());
        let mapper = self.mapper();
        let mut shdr_segments =
            SectionSegments::<Arch>::new(shdrs, &mut object, self.page_size()?.bytes())?;
        let segments = shdr_segments.load_segments(mapper, &mut object)?;
        let pltgot = shdr_segments.take_pltgot();
        let mprotect =
            Box::new(move |segments: &ElfSegments<M::Region>| shdr_segments.mprotect(segments));
        let user_data = D::default();

        ObjectBuilder::new(path, shdrs, segments, mprotect, pltgot, user_data)
    }
}
