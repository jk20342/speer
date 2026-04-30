#include "speer_internal.h"
#include <stdio.h>

int main(void) {
    uint8_t a_seed[32] = {1}, b_seed[32] = {2};
    uint8_t a_pub[32], a_priv[32], b_pub[32], b_priv[32];
    uint8_t ab[32], ba[32];
    speer_generate_keypair(a_pub, a_priv, a_seed);
    speer_generate_keypair(b_pub, b_priv, b_seed);
    speer_x25519(ab, a_priv, b_pub);
    speer_x25519(ba, b_priv, a_pub);
    int ok = memcmp(ab, ba, 32) == 0;
    printf("x25519 symmetry: %s\n", ok ? "ok" : "fail");
    return ok ? 0 : 1;
}
