use crate::{
    fixture::fixtures,
    support::{
        CALL_FIRST, CALL_SECOND, FIRST, SECOND, call, load_eager, load_lazy, load_provider, slot,
        symbol,
    },
};

#[test]
fn resolves_slots_independently() {
    let provider = load_provider();
    let loaded = load_lazy(&provider);
    let bytes = &fixtures().consumer;
    let first = symbol(&provider, FIRST);
    let second = symbol(&provider, SECOND);
    let second_before = slot(&loaded, bytes, SECOND);

    assert_ne!(slot(&loaded, bytes, FIRST), first);
    assert_ne!(second_before, second);

    assert_eq!(call(&loaded, CALL_FIRST), 1);
    assert_eq!(slot(&loaded, bytes, FIRST), first);
    assert_eq!(slot(&loaded, bytes, SECOND), second_before);

    assert_eq!(call(&loaded, CALL_SECOND), 2);
    assert_eq!(slot(&loaded, bytes, FIRST), first);
    assert_eq!(slot(&loaded, bytes, SECOND), second);
}

#[test]
fn bind_now_is_eager() {
    let provider = load_provider();
    let loaded = load_eager(&provider);
    let bytes = &fixtures().now;

    assert_eq!(slot(&loaded, bytes, FIRST), symbol(&provider, FIRST));
    assert_eq!(slot(&loaded, bytes, SECOND), symbol(&provider, SECOND));
}
