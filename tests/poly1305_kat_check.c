#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    static const uint8_t key[32] = {0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
                                    0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
                                    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
                                    0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};
    static const uint8_t msg[] = "Cryptographic Forum Research Group";
    static const uint8_t expect[16] = {0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
                                       0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9};

    uint8_t tag[16];
    speer_poly1305(tag, msg, sizeof(msg) - 1, key);
    if (memcmp(tag, expect, 16) != 0) {
        fprintf(stderr, "got: ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", tag[i]);
        fprintf(stderr, "\nexpect: ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", expect[i]);
        fprintf(stderr, "\n");
        return 1;
    }
    puts("poly1305_kat: ok");
    return 0;
}
