#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "quic_pkt.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    uint64_t out = speer_quic_decode_pn(100, 4, 8);
    if (out != 4) FAIL("decode_pn wrong: got %llu\n", (unsigned long long)out);

    out = speer_quic_decode_pn(255, 0, 8);
    if (out != 256) FAIL("decode_pn wrap: got %llu\n", (unsigned long long)out);

    puts("quic_pkt_robustness: ok");
    return 0;
}
