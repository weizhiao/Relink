use crate::{
    fixture::fixtures,
    support::{CALL_FIRST, FIRST, call, load_lazy, load_provider, slot, symbol},
};

#[test]
fn retains_scope() {
    let provider = load_provider();
    let loaded = load_lazy(&provider);
    let bytes = &fixtures().consumer;

    assert_eq!(loaded.scope().len(), 1);
    assert_eq!(loaded.scope()[0].name(), provider.name());
    assert_ne!(slot(&loaded, bytes, FIRST), symbol(&provider, FIRST));
    assert_eq!(call(&loaded, CALL_FIRST), 1);
    assert_eq!(slot(&loaded, bytes, FIRST), symbol(&provider, FIRST));
}
