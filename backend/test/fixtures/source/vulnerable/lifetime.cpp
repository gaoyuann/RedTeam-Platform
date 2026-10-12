int expired_value() {
    int *value = new int(42);
    delete value;
    return *value;
}
