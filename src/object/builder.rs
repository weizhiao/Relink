use super::{
    ObjectRelocation,
    layout::{PltGotSection, SectionSegments},
};
use crate::{
    RelocationError, Result,
    elf::{
        ELF_REL_SECTION_TYPE, ElfHeader, ElfRelType, ElfSectionType, ElfShdr, ElfSymbol,
        ElfSymbolType, SymbolTable,
    },
    loader::{DynLifecycleHandler, LoadHook, LoaderInner},
    os::Mmap,
    relocation::RelocAddr,
    segment::{ElfSegments, SegmentBuilder},
    tls::TlsResolver,
};
use alloc::{borrow::ToOwned, boxed::Box, string::String, vec::Vec};
use core::marker::PhantomData;
use elf::abi::SHN_UNDEF;

/// Builder for creating relocatable ELF objects.
pub(crate) struct ObjectBuilder<Tls, D = ()> {
    pub(crate) name: String,
    pub(crate) symtab: SymbolTable,
    pub(crate) init_array: Option<&'static [fn()]>,
    pub(crate) init_fn: DynLifecycleHandler,
    pub(crate) fini_fn: DynLifecycleHandler,
    pub(crate) segments: ElfSegments,
    pub(crate) relocation: ObjectRelocation,
    pub(crate) mprotect: Box<dyn Fn() -> Result<()>>,
    pub(crate) pltgot: PltGotSection,
    pub(crate) tls_mod_id: Option<usize>,
    pub(crate) tls_tp_offset: Option<isize>,
    pub(crate) user_data: D,
    _marker_tls: PhantomData<Tls>,
}

struct ObjectSectionData {
    symtab: SymbolTable,
    relocation: ObjectRelocation,
    init_array: Option<&'static [fn()]>,
}

impl<T: TlsResolver, D> ObjectBuilder<T, D> {
    #[inline]
    pub(crate) fn validate_shdrs(shdrs: &[ElfShdr]) -> Result<()> {
        let mut has_symtab = false;

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => has_symtab = true,
                ElfSectionType::REL | ElfSectionType::RELA => Self::validate_relocation_shdr(shdr)?,
                _ => {}
            }
        }

        if !has_symtab {
            return Err(RelocationError::MissingObjectSymbolTable.into());
        }

        Ok(())
    }

    #[inline]
    fn validate_relocation_shdr(shdr: &ElfShdr) -> Result<()> {
        debug_assert!(matches!(
            shdr.section_type(),
            ElfSectionType::REL | ElfSectionType::RELA
        ));

        debug_assert_eq!(shdr.section_type(), ELF_REL_SECTION_TYPE);

        let expected = core::mem::size_of::<ElfRelType>();
        let found = shdr.sh_entsize();
        debug_assert_eq!(found, expected);

        Ok(())
    }

    fn rebase_loaded_sections(shdrs: &mut [ElfShdr], pltgot: &mut PltGotSection, base: RelocAddr) {
        shdrs.iter_mut().for_each(|shdr| {
            shdr.set_sh_addr(base.offset(shdr.sh_addr()).into_inner());
        });
        pltgot.rebase(base);
    }

    fn prepare_symbol_table(
        symtab_shdr: &ElfShdr,
        shdrs: &[ElfShdr],
        base: RelocAddr,
    ) -> SymbolTable {
        let symbols: &mut [ElfSymbol] = symtab_shdr.content_mut();
        for symbol in symbols {
            if symbol.symbol_type() == ElfSymbolType::FILE
                || symbol.st_shndx() == SHN_UNDEF as usize
            {
                continue;
            }
            let section_base =
                RelocAddr::new(shdrs[symbol.st_shndx()].sh_addr()).relative_to(base.into_inner());
            symbol.set_value(section_base.offset(symbol.st_value()).into_inner());
        }

        SymbolTable::from_shdrs(symtab_shdr, shdrs)
    }

    fn prepare_relocation_section(
        relocation_shdr: &ElfShdr,
        shdrs: &[ElfShdr],
        base: RelocAddr,
    ) -> &'static [ElfRelType] {
        let rels: &mut [ElfRelType] = relocation_shdr.content_mut();
        let section_base = RelocAddr::new(shdrs[relocation_shdr.sh_info() as usize].sh_addr());
        for rel in rels {
            rel.set_offset(
                section_base
                    .offset(rel.r_offset())
                    .relative_to(base.into_inner())
                    .into_inner(),
            );
        }

        relocation_shdr.content()
    }

    fn prepare_init_array(init_array_shdr: &ElfShdr) -> &'static [fn()] {
        let array: &[usize] = init_array_shdr.content_mut();
        unsafe { core::mem::transmute(array) }
    }

    fn prepare_section_data(shdrs: &[ElfShdr], base: RelocAddr) -> Result<ObjectSectionData> {
        let mut symtab = None;
        let mut relocation = Vec::with_capacity(shdrs.len());
        let mut init_array = None;

        for shdr in shdrs {
            match shdr.section_type() {
                ElfSectionType::SYMTAB => {
                    symtab = Some(Self::prepare_symbol_table(shdr, shdrs, base))
                }
                ElfSectionType::RELA | ElfSectionType::REL => {
                    relocation.push(Self::prepare_relocation_section(shdr, shdrs, base))
                }
                ElfSectionType::INIT_ARRAY => init_array = Some(Self::prepare_init_array(shdr)),
                _ => {}
            }
        }

        Ok(ObjectSectionData {
            symtab: symtab.ok_or(RelocationError::MissingObjectSymbolTable)?,
            relocation: ObjectRelocation::new(relocation),
            init_array,
        })
    }

    pub(crate) fn new(
        name: String,
        shdrs: &mut [ElfShdr],
        init_fn: DynLifecycleHandler,
        fini_fn: DynLifecycleHandler,
        segments: ElfSegments,
        mprotect: Box<dyn Fn() -> Result<()>>,
        mut pltgot: PltGotSection,
        user_data: D,
    ) -> Result<Self> {
        Self::validate_shdrs(shdrs)?;
        let base = segments.base_addr();
        Self::rebase_loaded_sections(shdrs, &mut pltgot, base);
        let ObjectSectionData {
            symtab,
            relocation,
            init_array,
        } = Self::prepare_section_data(shdrs, base)?;

        Ok(Self {
            name,
            symtab,
            init_fn,
            fini_fn,
            segments,
            mprotect,
            relocation,
            pltgot,
            init_array,
            tls_mod_id: None,
            tls_tp_offset: None,
            user_data,
            _marker_tls: PhantomData,
        })
    }
}

impl<H, D> LoaderInner<H, D>
where
    H: LoadHook,
    D: 'static,
{
    pub(crate) fn create_object_builder<M, Tls>(
        &mut self,
        ehdr: ElfHeader,
        shdrs: &mut [ElfShdr],
        mut object: impl crate::input::ElfReader,
    ) -> Result<ObjectBuilder<Tls, D>>
    where
        M: Mmap,
        Tls: TlsResolver,
    {
        let name = object.file_name().to_owned();
        let (init_fn, fini_fn) = self.lifecycle_handlers();
        let mut shdr_segments = SectionSegments::new(shdrs, &mut object)?;
        let segments = shdr_segments.load_segments::<M>(&mut object)?;
        let pltgot = shdr_segments.take_pltgot();
        let mprotect = Box::new(move || {
            shdr_segments.mprotect::<M>()?;
            Ok(())
        });
        let user_data = self.load_user_data(&name, &ehdr, None, Some(shdrs), None);

        ObjectBuilder::new(
            name, shdrs, init_fn, fini_fn, segments, mprotect, pltgot, user_data,
        )
    }
}
