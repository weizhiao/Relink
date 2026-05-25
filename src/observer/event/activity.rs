/// Runtime linker state change notification.
///
/// These states intentionally mirror the shape of the classic `r_debug.r_state`
/// values without requiring Relink to own an `r_debug` or `link_map` instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkActivity {
    /// The loaded module set is being extended.
    Add,
    /// The loaded module set is being reduced.
    Delete,
    /// The loaded module set is stable.
    Consistent,
}
