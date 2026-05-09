use super::{Arena, LinkPassPlan, Module, ReorderAccess, SectionDataAccess};
use crate::{
    LinkerError, Result,
    aligned_bytes::ByteRepr,
    linker::layout::{SectionId, SectionMetadata, SectionPlacement},
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
    pub(in crate::linker) const fn id(self) -> SectionId {
        self.id
    }
}

impl<'scope, S> Section<'scope, S>
where
    S: SectionDataAccess,
{
    /// Returns this section's owner module through `plan`.
    #[inline]
    pub fn owner<K, Arch>(self, plan: &LinkPassPlan<'scope, K, S, Arch>) -> Module<'scope, S>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        let owner = plan
            .plan
            .section_owner(self.id)
            .expect("checked section handle should have an owner");
        Module::new(owner)
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

    /// Returns the section referenced by this section's `sh_link`, when present.
    #[inline]
    pub fn linked_section<K, Arch>(self, plan: &LinkPassPlan<'scope, K, S, Arch>) -> Option<Self>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan
            .section_metadata(self.id)
            .linked_section()
            .map(Self::new)
    }

    /// Returns the section referenced by this section's `sh_info`, when present.
    #[inline]
    pub fn info_section<K, Arch>(self, plan: &LinkPassPlan<'scope, K, S, Arch>) -> Option<Self>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan
            .section_metadata(self.id)
            .info_section()
            .map(Self::new)
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
        Ok(plan.plan.section_data(self.id)?.as_bytes())
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
        Ok(plan.plan.section_data_mut(self.id)?.as_bytes_mut())
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
        plan.plan
            .section_data(self.id)?
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
        plan.plan
            .section_data_mut(self.id)?
            .try_cast_slice_mut::<T>()
            .ok_or_else(|| {
                LinkerError::section_data("section data bytes do not match requested entry type")
                    .into()
            })
    }
}

impl<'scope, S> Section<'scope, S>
where
    S: ReorderAccess,
{
    /// Resizes this section's data and layout metadata through `plan`.
    ///
    /// Existing arena placement is cleared. Allocated sections are forced into
    /// section-region materialization so the resized section is packed from its
    /// updated metadata.
    #[inline]
    pub fn resize<K, Arch>(
        self,
        plan: &mut LinkPassPlan<'scope, K, S, Arch>,
        byte_len: usize,
    ) -> Result<()>
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan.resize_section(self.id, byte_len)
    }

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
        arena: Arena<'scope>,
        offset: usize,
    ) -> bool
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan
            .memory_layout_mut()
            .assign(self.id, arena.id(), offset)
    }

    /// Assigns this section to the next aligned arena offset through `plan`.
    #[inline]
    pub fn assign_next<K, Arch>(
        self,
        plan: &mut LinkPassPlan<'scope, K, S, Arch>,
        arena: Arena<'scope>,
    ) -> bool
    where
        K: Clone + Ord,
        Arch: RelocationArch,
    {
        plan.plan
            .memory_layout_mut()
            .assign_next(self.id, arena.id())
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
