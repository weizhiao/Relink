#[cfg(feature = "object")]
use crate::object::SectionGroups;
#[cfg(feature = "object")]
use crate::sync::Arc;
use crate::{
    arch::NativeArch,
    observer::LoadObserver,
    os::{DefaultMmap, Mmap},
    relocation::RelocationArch,
    runtime::{CodeExecutor, NativeCodeExecutor},
    tls::TlsResolver,
};

use super::{ElfBuf, Loader};

/// Per-run loader state.
///
/// A [`Loader`] owns reusable loading configuration. `LoaderRun` owns the
/// scratch buffer used while reading ELF metadata for one sequence of loads.
pub struct LoaderRun<
    'a,
    Obs = (),
    D: 'static = (),
    Tls = (),
    Arch = NativeArch,
    M = DefaultMmap,
    Exec = NativeCodeExecutor,
> where
    Obs: LoadObserver<D, Arch>,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
{
    pub(crate) loader: &'a Loader<D, Tls, Arch, M, Exec>,
    pub(super) observer: Obs,
    pub(super) buf: ElfBuf,
    #[cfg(feature = "object")]
    pub(super) object_groups: Arc<SectionGroups>,
}

impl<'a, Obs, D, Tls, Arch, M, Exec> LoaderRun<'a, Obs, D, Tls, Arch, M, Exec>
where
    Obs: LoadObserver<D, Arch>,
    D: 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    /// Replaces the observer used by this loader run.
    #[inline]
    pub fn with_observer<NewObs>(
        self,
        observer: NewObs,
    ) -> LoaderRun<'a, NewObs, D, Tls, Arch, M, Exec>
    where
        NewObs: LoadObserver<D, Arch>,
    {
        LoaderRun {
            loader: self.loader,
            observer,
            buf: self.buf,
            #[cfg(feature = "object")]
            object_groups: self.object_groups,
        }
    }
}

#[cfg(feature = "object")]
impl<Obs, D, Tls, Arch, M, Exec> LoaderRun<'_, Obs, D, Tls, Arch, M, Exec>
where
    Obs: LoadObserver<D, Arch>,
    D: 'static,
    Tls: TlsResolver<Arch>,
    Arch: RelocationArch,
    M: Mmap,
    Exec: CodeExecutor<Arch> + Clone,
{
    pub(crate) fn object_load_context(&mut self) -> (Arc<SectionGroups>, &mut Obs, &M) {
        (
            Arc::clone(&self.object_groups),
            &mut self.observer,
            self.loader.mapper(),
        )
    }

    /// Sets object section layout groups for this loader run.
    pub fn with_object_section_groups(mut self, groups: SectionGroups) -> Self {
        self.object_groups = Arc::new(groups);
        self
    }
}
