#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "tls13_handshake.h"
#include "tls_msg.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static void ready(speer_tls13_t *h, speer_tls_role_t role) {
    ZERO(h, sizeof(*h));
    h->role = role;
    h->state = TLS_ST_DONE;
    h->cipher_suite = TLS_CS_AES_128_GCM_SHA256;
    speer_tls13_init(&h->ks, h->cipher_suite, NULL, 0);
    for (size_t i = 0; i < h->ks.suite.hash->digest_size; i++) {
        h->ks.client_application_traffic[i] = (uint8_t)(0x10 + i);
        h->ks.server_application_traffic[i] = (uint8_t)(0x80 + i);
    }
}

int main(void) {
    speer_tls13_t h;
    uint8_t before[SPEER_TLS13_MAX_HASH];
    uint8_t after[SPEER_TLS13_MAX_HASH];
    size_t n;

    ready(&h, SPEER_TLS_ROLE_CLIENT);
    speer_tls13_export_traffic_secret(&h, 0, 1, before, &n);
    if (speer_tls13_send_key_update(&h, 1) != SPEER_TLS_NEED_OUT) FAIL("send ku\n");
    if (h.out_len != 5 || h.out_buf[0] != TLS_HS_KEY_UPDATE || h.out_buf[4] != 1) FAIL("ku msg\n");
    speer_tls13_export_traffic_secret(&h, 0, 1, after, NULL);
    if (memcmp(before, after, n) == 0) FAIL("client traffic unchanged\n");
    if (h.client_record_seq != 0) FAIL("client seq\n");

    ready(&h, SPEER_TLS_ROLE_CLIENT);
    uint8_t req[] = {1};
    speer_tls13_export_traffic_secret(&h, 1, 1, before, &n);
    if (speer_tls13_handshake_consume(&h, TLS_HS_KEY_UPDATE, req, sizeof(req)) !=
        SPEER_TLS_NEED_OUT)
        FAIL("consume ku request\n");
    if (h.out_len != 5 || h.out_buf[0] != TLS_HS_KEY_UPDATE || h.out_buf[4] != 0)
        FAIL("ku response\n");
    speer_tls13_export_traffic_secret(&h, 1, 1, after, NULL);
    if (memcmp(before, after, n) == 0) FAIL("server traffic unchanged\n");
    if (h.server_record_seq != 0) FAIL("server seq\n");

    ready(&h, SPEER_TLS_ROLE_CLIENT);
    uint8_t bad[] = {2};
    if (speer_tls13_handshake_consume(&h, TLS_HS_KEY_UPDATE, bad, sizeof(bad)) != SPEER_TLS_ERR)
        FAIL("bad ku accepted\n");

    puts("tls13_key_update: ok");
    return 0;
}
