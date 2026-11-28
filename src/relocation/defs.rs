/// Result of a relocation hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleResult {
    /// The handler did not process this relocation.
    Unhandled,
    /// The handler processed this relocation.
    Handled,
}

impl HandleResult {
    /// Returns whether the handler left the relocation for the next stage.
    #[inline]
    pub const fn is_unhandled(self) -> bool {
        matches!(self, Self::Unhandled)
    }
}
