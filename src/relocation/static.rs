use crate::{
    Result,
    arch::StaticRelocator,
    elf::ElfRelType,
    image::{LoadedCore, RawObject},
    relocation::{RelocHelper, RelocationHandler, SymbolLookup},
    segment::section::PltGotSection,
};
use alloc::{boxed::Box, vec::Vec};

pub(crate) struct StaticRelocation {
    relocation: Box<[&'static [ElfRelType]]>,
}

impl StaticRelocation {
    pub(crate) fn new(relocation: Vec<&'static [ElfRelType]>) -> Self {
        Self {
            relocation: relocation.into_boxed_slice(),
        }
    }
}

impl<D: 'static> RawObject<D> {
    pub(crate) fn relocate_impl<PreS, PostS, PreH, PostH>(
        mut self,
        scope: &[LoadedCore<D>],
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
    ) -> Result<LoadedCore<D>>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized,
    {
        let mut helper = RelocHelper::new(
            &self.core,
            scope.to_vec(),
            pre_find,
            post_find,
            pre_handler,
            post_handler,
        );
        for reloc in self.relocation.relocation.iter() {
            for rel in *reloc {
                if !helper.handle_pre(rel)? {
                    continue;
                }
                StaticRelocator::relocate(&mut helper, rel, &mut self.pltgot)?;
                if !helper.handle_post(rel)? {
                    continue;
                }
            }
        }
        (self.mprotect)()?;
        (self.init)(None, self.init_array);
        Ok(unsafe { LoadedCore::from_core(self.core) })
    }
}

pub(crate) trait StaticReloc {
    fn relocate<D, PreS, PostS, PreH, PostH>(
        helper: &mut RelocHelper<'_, D, PreS, PostS, PreH, PostH>,
        rel: &ElfRelType,
        pltgot: &mut PltGotSection,
    ) -> Result<()>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler + ?Sized,
        PostH: RelocationHandler + ?Sized;

    fn needs_got(_rel_type: u32) -> bool {
        false
    }

    fn needs_plt(_rel_type: u32) -> bool {
        false
    }
}
