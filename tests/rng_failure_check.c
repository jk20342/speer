#include "speer.h"
#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    uint8_t buf[64];
    memset(buf, 0xcc, sizeof(buf));
    if (speer_random_bytes_or_fail(buf, sizeof(buf)) != 0) FAIL("rng_or_fail failed\n");
    int all_zero = 1, all_cc = 1;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) all_zero = 0;
        if (buf[i] != 0xcc) all_cc = 0;
    }
    if (all_zero || all_cc) FAIL("rng_or_fail did not produce randomness\n");

    if (speer_random_bytes_or_fail(buf, 0) != 0) FAIL("rng_or_fail rejected size 0\n");

    puts("rng_failure: ok");
    return 0;
}
