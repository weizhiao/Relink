use super::{LinkPassPlan, ReorderAccess, SectionDataAccess};
use crate::{
    AlignedBytes, LinkerError, Result,
    aligned_bytes::ByteRepr,
    linker::{
        layout::{ArenaId, SectionId, SectionMetadata, SectionPlacement},
        plan::ModuleId,
    },
    relocation::RelocationArch,
};
use core::marker::PhantomData;

/// A section handle that has been checked against one pass scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Section<'plan, S> {
    id: SectionId,
    scope: PhantomData<fn(&'plan ()) -> S>,
}

impl<'plan, S> Section<'plan, S> {
    #[inline]
    pub(super) const fn new(id: SectionId) -> Self {
        Self {
            id,
            scope: PhantomData,
        }
    }

    /// Returns the underlying stable section id.
    #[inline]
    pub const fn id(self) -> SectionId {
        self.id
    }
}

impl<'scope, S> Section<'scope, S>
where
    S: SectionDataAccess,
{
    /// Returns this section's owner module through `plan`.
    #[inline]
    pub fn owner<K, Arch>(self, plan: &LinkPassPlan<'scope, K, S, Arch>) -> ModuleId
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan
            .section_owner(self.id)
            .expect("checked section handle should have an owner")
    }

    /// Returns this section's metadata through `plan`.
    #[inline]
    pub fn metadata<'borrow, K, Arch>(
        self,
        plan: &'borrow LinkPassPlan<'scope, K, S, Arch>,
    ) -> &'borrow SectionMetadata
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.section_metadata(self.id)
    }

    #[inline]
    fn aligned_data<'borrow, K, Arch>(
        self,
        plan: &'borrow mut LinkPassPlan<'scope, K, S, Arch>,
    ) -> Result<&'borrow AlignedBytes>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.section_data(self.id)
    }

    #[inline]
    fn aligned_data_mut<'borrow, K, Arch>(
        self,
        plan: &'borrow mut LinkPassPlan<'scope, K, S, Arch>,
    ) -> Result<&'borrow mut AlignedBytes>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.section_data_mut(self.id)
    }

    /// Returns this section's data bytes through `plan`, materializing them on demand.
    #[inline]
    pub fn data<'borrow, K, Arch>(
        self,
        plan: &'borrow mut LinkPassPlan<'scope, K, S, Arch>,
    ) -> Result<&'borrow [u8]>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        Ok(self.aligned_data(plan)?.as_bytes())
    }

    /// Returns this section's mutable data bytes through `plan`, materializing them on demand.
    #[inline]
    pub fn data_mut<'borrow, K, Arch>(
        self,
        plan: &'borrow mut LinkPassPlan<'scope, K, S, Arch>,
    ) -> Result<&'borrow mut [u8]>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        Ok(self.aligned_data_mut(plan)?.as_bytes_mut())
    }

    /// Returns this section's data as typed entries through `plan`.
    #[inline]
    pub fn entries<'borrow, T, K, Arch>(
        self,
        plan: &'borrow mut LinkPassPlan<'scope, K, S, Arch>,
    ) -> Result<&'borrow [T]>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
        T: ByteRepr,
    {
        self.aligned_data(plan)?
            .try_cast_slice::<T>()
            .ok_or_else(|| {
                LinkerError::section_data("section data bytes do not match requested entry type")
                    .into()
            })
    }

    /// Returns this section's mutable data as typed entries through `plan`.
    #[inline]
    pub fn entries_mut<'borrow, T, K, Arch>(
        self,
        plan: &'borrow mut LinkPassPlan<'scope, K, S, Arch>,
    ) -> Result<&'borrow mut [T]>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
        T: ByteRepr,
    {
        self.aligned_data_mut(plan)?
            .try_cast_slice_mut::<T>()
            .ok_or_else(|| {
                LinkerError::section_data("section data bytes do not match requested entry type")
                    .into()
            })
    }

    /// Sets this section data's logical byte length through `plan`.
    #[inline]
    pub fn set_data_len<K, Arch>(
        self,
        plan: &mut LinkPassPlan<'scope, K, S, Arch>,
        byte_len: usize,
    ) -> Result<()>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        let data = self.aligned_data_mut(plan)?;
        data.set_len(byte_len)
            .ok_or_else(|| LinkerError::section_data("section data length overflow"))?;
        Ok(())
    }
}

impl<'scope, S> Section<'scope, S>
where
    S: ReorderAccess,
{
    /// Returns this section's arena placement through `plan`.
    #[inline]
    pub fn placement<K, Arch>(
        self,
        plan: &LinkPassPlan<'scope, K, S, Arch>,
    ) -> Option<SectionPlacement>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.placement(self.id)
    }

    /// Assigns this section to an arena through `plan`.
    #[inline]
    pub fn assign<K, Arch>(
        self,
        plan: &mut LinkPassPlan<'scope, K, S, Arch>,
        arena: ArenaId,
        offset: usize,
    ) -> bool
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.memory_layout_mut().assign(self.id, arena, offset)
    }

    /// Assigns this section to the next aligned arena offset through `plan`.
    #[inline]
    pub fn assign_next<K, Arch>(
        self,
        plan: &mut LinkPassPlan<'scope, K, S, Arch>,
        arena: ArenaId,
    ) -> bool
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.memory_layout_mut().assign_next(self.id, arena)
    }

    /// Clears this section's arena assignment through `plan`.
    #[inline]
    pub fn clear_placement<K, Arch>(
        self,
        plan: &mut LinkPassPlan<'scope, K, S, Arch>,
    ) -> Option<SectionPlacement>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.memory_layout_mut().clear_section(self.id)
    }
}
