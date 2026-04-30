#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "ecdsa_p256.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    uint8_t pub[64] = {0};
    uint8_t hash[32] = {1};
    uint8_t r[32] = {2};
    uint8_t s[32] = {3};
    if (speer_ecdsa_p256_verify(pub, hash, sizeof(hash), r, sizeof(r), s, sizeof(s)) == 0)
        FAIL("verify accepted off-curve pubkey\n");

    uint8_t pub2[64];
    memset(pub2, 0xaa, sizeof(pub2));
    uint8_t r0[32] = {0};
    if (speer_ecdsa_p256_verify(pub2, hash, sizeof(hash), r0, sizeof(r0), s, sizeof(s)) == 0)
        FAIL("verify accepted r=0\n");

    puts("ecdsa_p256: ok");
    return 0;
}
