#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "tls13_handshake.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    speer_tls13_t h;
    uint8_t cert_priv[32] = {1};
    uint8_t cert_pub[32] = {2};
    uint8_t libp2p_priv[32] = {3};
    uint8_t libp2p_pub[32] = {4};
    if (speer_tls13_init_handshake(&h, SPEER_TLS_ROLE_CLIENT, cert_priv, cert_pub,
                                   SPEER_LIBP2P_KEY_ED25519, libp2p_pub, sizeof(libp2p_pub),
                                   libp2p_priv, sizeof(libp2p_priv), "test/1.0", NULL) != 0)
        FAIL("init\n");

    if (speer_tls13_handshake_start(&h) != SPEER_TLS_NEED_OUT) FAIL("start\n");

    uint8_t fake_cv[64] = {0};
    int rc = speer_tls13_handshake_consume(&h, 0x0f, fake_cv, sizeof(fake_cv));
    if (rc != SPEER_TLS_ERR) FAIL("consume out-of-order CV must error, got %d\n", rc);

    puts("tls13_auth: ok");
    return 0;
}
