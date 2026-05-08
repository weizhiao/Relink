use crate::{
    Result,
    elf::ElfRelType,
    image::{LoadedCore, RawObject},
    loader::LifecycleContext,
    logging,
    relocation::{RelocHelper, RelocationArch, RelocationHandler, SymbolLookup},
    sync::Arc,
};

use alloc::{boxed::Box, vec::Vec};

pub(crate) struct ObjectRelocation<Arch: RelocationArch = crate::arch::NativeArch> {
    sections: Box<[&'static [ElfRelType<Arch>]]>,
}

impl<Arch: RelocationArch> ObjectRelocation<Arch> {
    pub(crate) fn new(sections: Vec<&'static [ElfRelType<Arch>]>) -> Self {
        Self {
            sections: sections.into_boxed_slice(),
        }
    }
}

impl<D: 'static, Arch> RawObject<D, Arch>
where
    Arch: RelocationArch,
{
    pub(crate) fn relocate_impl<PreS, PostS, PreH, PostH>(
        mut self,
        scope: Arc<[LoadedCore<D, Arch>]>,
        pre_find: &PreS,
        post_find: &PostS,
        pre_handler: &PreH,
        post_handler: &PostH,
    ) -> Result<crate::image::LoadedCore<D, Arch>>
    where
        PreS: SymbolLookup + ?Sized,
        PostS: SymbolLookup + ?Sized,
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
    {
        logging::debug!("Relocating object: {}", self.core.name());

        let mut helper = RelocHelper::new(
            &self.core,
            scope.clone(),
            pre_find,
            post_find,
            pre_handler,
            post_handler,
            self.core.tls_get_addr(),
        );
        for reloc in self.relocation.sections.iter() {
            for rel in *reloc {
                if !helper.handle_pre(rel)?.is_unhandled() {
                    continue;
                }
                Arch::relocate_object(&mut helper, rel, &mut self.pltgot)?;
                helper.handle_post(rel)?;
            }
        }

        let RelocHelper { tls_desc_args, .. } = helper;

        unsafe {
            self.core.set_tls_desc_args(tls_desc_args);
        }

        (self.mprotect)()?;

        logging::trace!("[{}] Executing init functions", self.core.name());
        self.init
            .call(&LifecycleContext::new(None, self.init_array));

        logging::info!("Relocation completed for {}", self.core.name());

        Ok(unsafe { crate::image::LoadedCore::from_core_deps(self.core, scope) })
    }
}
