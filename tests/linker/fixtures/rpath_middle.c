extern int rpath_leaf(void);

int rpath_middle(void) {
    return rpath_leaf() + 1;
}
