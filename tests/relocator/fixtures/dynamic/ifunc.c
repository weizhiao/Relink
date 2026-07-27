int ifunc_implementation(void) {
    return 73;
}

static void *resolve_selected(void) {
    return ifunc_implementation;
}

__attribute__((ifunc("resolve_selected"), visibility("hidden")))
int selected(void);

int call_selected(void) {
    return selected();
}
