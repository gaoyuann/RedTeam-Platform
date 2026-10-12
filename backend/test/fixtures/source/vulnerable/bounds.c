#include <string.h>
int overflow(void) {
    char buffer[4];
    strcpy(buffer, "long-input");
    return buffer[0];
}
