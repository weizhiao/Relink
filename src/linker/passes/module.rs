use super::{LinkPassPlan, PassScopeMode, Section, SectionDataAccess};
use crate::{
    image::{ModuleCapability, ScannedDynamic, ScannedSectionId},
    linker::{Materialization, layout::ModuleLayout, plan::ModuleId},
    relocation::RelocationArch,
};
use core::marker::PhantomData;

/// A module handle that has been checked against one pass scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Module<'plan, S> {
    id: ModuleId,
    scope: PhantomData<fn(&'plan ()) -> S>,
}

impl<'plan, S> Module<'plan, S> {
    #[inline]
    pub(super) const fn new(id: ModuleId) -> Self {
        Self {
            id,
            scope: PhantomData,
        }
    }
}

impl<'scope, S> Module<'scope, S>
where
    S: PassScopeMode,
{
    /// Returns this module's canonical key through `plan`.
    #[inline]
    pub fn key<'borrow, K, Arch>(
        self,
        plan: &'borrow LinkPassPlan<'scope, K, S, Arch>,
    ) -> &'borrow K
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan
            .module_key(self.id)
            .expect("checked module handle should have a key")
    }

    /// Returns this module's scanned image through `plan`.
    #[inline]
    pub fn scanned<'borrow, K, Arch>(
        self,
        plan: &'borrow LinkPassPlan<'scope, K, S, Arch>,
    ) -> &'borrow ScannedDynamic<Arch::Layout>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan
            .get(self.id)
            .expect("checked module handle should resolve to a planned module")
            .module()
    }

    /// Returns this module's scanned image mutably through `plan`.
    #[inline]
    pub fn scanned_mut<'borrow, K, Arch>(
        self,
        plan: &'borrow mut LinkPassPlan<'scope, K, S, Arch>,
    ) -> &'borrow mut ScannedDynamic<Arch::Layout>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan
            .get_mut(self.id)
            .expect("checked module handle should resolve to a planned module")
            .module_mut()
    }

    /// Iterates over visible direct dependency modules recorded for this module.
    #[inline]
    pub fn direct_deps<'borrow, K, Arch>(
        self,
        plan: &'borrow LinkPassPlan<'scope, K, S, Arch>,
    ) -> impl Iterator<Item = Self> + 'borrow
    where
        K: Clone + Ord,
        Arch: RelocationArch,
        'scope: 'borrow,
    {
        plan.plan
            .get(self.id)
            .expect("checked module handle should resolve to a planned module")
            .direct_deps()
            .iter()
            .copied()
            .filter_map(move |id| plan.checked_module(id))
    }

    /// Returns this module's planning capability.
    #[inline]
    pub fn capability<K, Arch>(self, plan: &LinkPassPlan<'scope, K, S, Arch>) -> ModuleCapability
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan
            .module_capability(self.id)
            .expect("checked module handle should have a capability")
    }

    /// Returns this module's configured materialization mode.
    #[inline]
    pub fn materialization<K, Arch>(
        self,
        plan: &LinkPassPlan<'scope, K, S, Arch>,
    ) -> Option<Materialization>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.materialization(self.id)
    }

    /// Selects this module's materialization mode through `plan`.
    #[inline]
    pub fn set_materialization<K, Arch>(
        self,
        plan: &mut LinkPassPlan<'scope, K, S, Arch>,
        mode: Materialization,
    ) -> Option<Materialization>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.set_materialization(self.id, mode)
    }
}

impl<'scope, S> Module<'scope, S>
where
    S: SectionDataAccess,
{
    /// Returns this module's planned layout through `plan`.
    #[inline]
    pub fn layout<'borrow, K, Arch>(
        self,
        plan: &'borrow LinkPassPlan<'scope, K, S, Arch>,
    ) -> &'borrow ModuleLayout
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.module_layout(self.id)
    }

    /// Returns one checked section handle for a scanned section in this module.
    #[inline]
    pub fn section<K, Arch>(
        self,
        plan: &LinkPassPlan<'scope, K, S, Arch>,
        id: impl Into<ScannedSectionId>,
    ) -> Option<Section<'scope, S>>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        let section = plan.plan.module_section_id(self.id, id)?;
        plan.checked_section(section)
    }
}
