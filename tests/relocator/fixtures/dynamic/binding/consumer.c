extern int external_fn(int value);
extern int external_value;

int *external_pointer = &external_value;

int call_external(int value) {
    return external_fn(value);
}
