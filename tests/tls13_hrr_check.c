#include "speer_internal.h"

#include <stdio.h>

#include "tls13_handshake.h"
#include "tls_msg.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    static const uint8_t hrr_random[32] = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
                                           0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                           0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
                                           0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    speer_tls13_t h;
    uint8_t cert_priv[32] = {1};
    uint8_t cert_pub[32] = {2};
    uint8_t libp2p_priv[32] = {3};
    uint8_t libp2p_pub[32] = {4};
    if (speer_tls13_init_handshake(&h, SPEER_TLS_ROLE_CLIENT, cert_priv, cert_pub,
                                   SPEER_LIBP2P_KEY_ED25519, libp2p_pub, sizeof(libp2p_pub),
                                   libp2p_priv, sizeof(libp2p_priv), NULL, NULL) != 0)
        FAIL("init\n");
    if (speer_tls13_handshake_start(&h) != SPEER_TLS_NEED_OUT) FAIL("start\n");

    uint8_t msg[128];
    speer_tls_writer_t w;
    speer_tls_writer_init(&w, msg, sizeof(msg));
    if (speer_tls_w_u16(&w, 0x0303) != 0) FAIL("legacy\n");
    if (speer_tls_w_bytes(&w, hrr_random, sizeof(hrr_random)) != 0) FAIL("random\n");
    if (speer_tls_w_u8(&w, 0) != 0) FAIL("sid\n");
    if (speer_tls_w_u16(&w, TLS_CS_AES_128_GCM_SHA256) != 0) FAIL("suite\n");
    if (speer_tls_w_u8(&w, 0) != 0) FAIL("comp\n");
    size_t exts = speer_tls_w_save(&w);
    if (speer_tls_w_u16(&w, 0) != 0) FAIL("exts\n");
    if (speer_tls_w_u16(&w, TLS_EXT_SUPPORTED_VERSIONS) != 0) FAIL("sv type\n");
    uint8_t sv[] = {0x03, 0x04};
    if (speer_tls_w_vec_u16(&w, sv, sizeof(sv)) != 0) FAIL("sv\n");
    if (speer_tls_w_u16(&w, TLS_EXT_KEY_SHARE) != 0) FAIL("ks type\n");
    uint8_t group[] = {0x00, 0x1d};
    if (speer_tls_w_vec_u16(&w, group, sizeof(group)) != 0) FAIL("ks\n");
    if (speer_tls_w_finish_vec_u16(&w, exts) != 0) FAIL("finish\n");

    if (speer_tls13_handshake_consume(&h, TLS_HS_SERVER_HELLO, msg, w.pos) != SPEER_TLS_NEED_OUT)
        FAIL("consume hrr\n");
    if (!h.hrr_seen || h.out_len == 0 || h.out_buf[0] != TLS_HS_CLIENT_HELLO) FAIL("hrr state\n");

    puts("tls13_hrr: ok");
    return 0;
}
