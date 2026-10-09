#include <cstdint>
#include <cstring>
struct Info {
    uint16_t version, type;
    unsigned char birthday[8];
    uint32_t agent, pid, userId;
    unsigned char hid[8];
    uint32_t isMother, deviceType;
};
static unsigned char records[2][256];
static int writes = 0, count = 2, closeError = 0, enumError = 0, pid = 100;
extern "C" {
void TestReset() { std::memset(records, 0, sizeof records); writes = 0; count = 2; closeError = 0; enumError = 0; pid = 100; }
int TestWrites() { return writes; }
void TestSet(int field, int value) {
    if (field == 0) count = value;
    if (field == 1) closeError = value;
    if (field == 2) enumError = value;
    if (field == 3) pid = value;
    if (field == 4) std::memset(records[0], value, 256);
}
unsigned int Dongle_Enum(Info *out, int *n) {
    if (enumError) return enumError;
    if (out) for (int i = 0; i < count; ++i) {
        out[i] = {};
        out[i].version = 0x100;
        out[i].pid = pid;
        std::memset(out[i].hid, i + 1, 8);
    }
    *n = count;
    return 0;
}
unsigned int Dongle_Open(void **handle, int index) {
    if (index < 0 || index >= count) return 9;
    *handle = reinterpret_cast<void *>(static_cast<intptr_t>(index + 1));
    return 0;
}
unsigned int Dongle_ResetState(void *) { return 0; }
unsigned int Dongle_Close(void *) { return closeError; }
unsigned int Dongle_ReadData(void *h, int offset, unsigned char *out, int size) {
    if (offset != 3840 || size != 256) return 9;
    std::memcpy(out, records[reinterpret_cast<intptr_t>(h) - 1], 256);
    return 0;
}
unsigned int Dongle_WriteData(void *h, int offset, unsigned char *data, int size) {
    if (offset != 3840 || size != 256) return 9;
    std::memcpy(records[reinterpret_cast<intptr_t>(h) - 1], data, 256);
    ++writes;
    return 0;
}
}
