#include "speer_internal.h"

#include <stdio.h>

int main(void) {
    uint8_t key[32] = {3}, nonce[12] = {0};
    uint8_t msg[32] = {0}, ct[32], pt[32], block[64], mac[16], mac2[16];
    for (int i = 0; i < 32; i++) msg[i] = (uint8_t)i;

    speer_chacha_ctx_t c;
    speer_chacha_init(&c, key, nonce);
    speer_chacha_block(&c, block);
    speer_chacha_crypt(&c, ct, msg, 32);
    speer_poly1305(mac, ct, 32, block);

    speer_chacha_init(&c, key, nonce);
    speer_chacha_block(&c, block);
    speer_poly1305(mac2, ct, 32, block);
    speer_chacha_crypt(&c, pt, ct, 32);

    int ok = memcmp(mac, mac2, 16) == 0 && memcmp(msg, pt, 32) == 0;
    printf("aead primitive: %s\n", ok ? "ok" : "fail");
    return ok ? 0 : 1;
}
