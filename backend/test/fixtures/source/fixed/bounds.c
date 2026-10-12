#include <stddef.h>
#include <string.h>
int copy_input(char *buffer, size_t capacity, const char *input) {
    if (!buffer || !input) return -1;
    size_t length = strlen(input);
    if (length >= capacity) return -1;
    memcpy(buffer, input, length + 1);
    return 0;
}
