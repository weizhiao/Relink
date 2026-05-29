use crate::{
    Result,
    elf::ElfRelType,
    image::{ModuleScope, RawObject},
    logging,
    observer::default_lifecycle_executor,
    observer::{LifecycleEvent, LifecyclePhase, RelocationObserver},
    os::RegionAccess,
    relocation::{RelocHelper, RelocationArch, RelocationHandler},
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

impl<D: 'static, Arch, R> RawObject<D, Arch, R>
where
    Arch: RelocationArch,
    R: RegionAccess,
{
    pub(crate) fn relocate_impl<PreH, PostH, Obs>(
        mut self,
        scope: ModuleScope<Arch>,
        pre_handler: &PreH,
        post_handler: &PostH,
        observer: &mut Obs,
    ) -> Result<crate::image::LoadedCore<D, Arch, R, crate::object::CustomHash>>
    where
        PreH: RelocationHandler<Arch> + ?Sized,
        PostH: RelocationHandler<Arch> + ?Sized,
        Obs: RelocationObserver<Arch> + ?Sized,
    {
        logging::debug!("Relocating object: {}", self.core.name());

        let mut helper = RelocHelper::new(
            &self.core,
            scope,
            pre_handler,
            post_handler,
            observer,
            self.core.tls_get_addr(),
        );
        for reloc in self.relocation.sections.iter() {
            for rel in *reloc {
                if !helper.handle_pre(rel)?.is_unhandled() {
                    continue;
                }
                match Arch::relocate_object(&mut helper, rel, &mut self.pltgot) {
                    Ok(()) => continue,
                    Err(err) => {
                        if helper.handle_post(rel)?.is_unhandled() {
                            return Err(err);
                        }
                    }
                }
            }
        }

        let RelocHelper {
            scope,
            tls_desc_args,
            ..
        } = helper;
        self.core.set_tls_desc_args(tls_desc_args);

        (self.mprotect)(self.core.segments())?;

        logging::trace!("[{}] Executing init functions", self.core.name());
        let mut event = LifecycleEvent::with_executor(
            LifecyclePhase::Init,
            self.core.name(),
            &self.init,
            self.core.segments(),
            default_lifecycle_executor(),
        );
        observer.on_lifecycle(&mut event)?;
        event.run();

        logging::info!("Relocation completed for {}", self.core.name());

        Ok(crate::image::LoadedCore::from_relocated_core_deps(
            self.core, scope,
        ))
    }
}
