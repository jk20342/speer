#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    speer_chacha_ctx_t ctx;
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    speer_chacha_init(&ctx, key, nonce);

    if (speer_chacha_block_counter_at_max(&ctx)) FAIL("counter at max at start\n");

    uint8_t out[64];
    for (int i = 0; i < 4; i++) speer_chacha_block(&ctx, out);
    if (speer_chacha_block_counter_at_max(&ctx)) FAIL("at_max prematurely\n");

    puts("chacha_counter: ok");
    return 0;
}
