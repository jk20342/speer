#include "speer_internal.h"

#include <stdio.h>
#include <string.h>

#include "ed25519.h"
#include "tls13_handshake.h"
#include "tls_msg.h"
#include "x509_libp2p.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static int feed_one(speer_tls13_t *h, const uint8_t *msg, size_t msg_len, size_t *used) {
    speer_tls_reader_t r;
    speer_tls_reader_init(&r, msg, msg_len);
    uint8_t type;
    uint32_t body_len;
    if (speer_tls_r_u8(&r, &type) != 0) return SPEER_TLS_ERR;
    if (speer_tls_r_u24(&r, &body_len) != 0) return SPEER_TLS_ERR;
    if (4 + body_len > msg_len) return SPEER_TLS_ERR;
    int rc = speer_tls13_handshake_consume(h, type, msg + 4, body_len);
    *used = 4 + body_len;
    return rc;
}

static void make_keys(uint8_t cert_pub[32], uint8_t cert_priv[32], uint8_t lib_pub[32],
                      uint8_t lib_priv[32], uint8_t seed_base) {
    uint8_t seed[32] = {0};
    seed[0] = seed_base;
    speer_ed25519_keypair(cert_pub, cert_priv, seed);
    seed[0] = (uint8_t)(seed_base + 1);
    speer_ed25519_keypair(lib_pub, lib_priv, seed);
}

int main(void) {
    uint8_t c_cert_pub[32], c_cert_priv[32], c_lib_pub[32], c_lib_priv[32];
    uint8_t s_cert_pub[32], s_cert_priv[32], s_lib_pub[32], s_lib_priv[32];
    make_keys(c_cert_pub, c_cert_priv, c_lib_pub, c_lib_priv, 1);
    make_keys(s_cert_pub, s_cert_priv, s_lib_pub, s_lib_priv, 9);
    uint8_t cert[2500];
    size_t cert_len;
    speer_x509_libp2p_t parsed;
    if (speer_x509_libp2p_make_self_signed(cert, sizeof(cert), &cert_len, s_cert_priv, s_cert_pub,
                                           SPEER_LIBP2P_KEY_ED25519, s_lib_pub, 32, s_lib_priv,
                                           32) != 0)
        FAIL("cert make\n");
    if (speer_x509_libp2p_parse(&parsed, cert, cert_len) != 0) FAIL("cert parse\n");
    if (speer_x509_libp2p_verify(&parsed) != 0) FAIL("cert verify\n");

    speer_tls13_t client, server;
    if (speer_tls13_init_handshake(&client, SPEER_TLS_ROLE_CLIENT, c_cert_priv, c_cert_pub,
                                   SPEER_LIBP2P_KEY_ED25519, c_lib_pub, sizeof(c_lib_pub),
                                   c_lib_priv, sizeof(c_lib_priv), NULL, NULL) != 0)
        FAIL("client init\n");
    if (speer_tls13_init_handshake(&server, SPEER_TLS_ROLE_SERVER, s_cert_priv, s_cert_pub,
                                   SPEER_LIBP2P_KEY_ED25519, s_lib_pub, sizeof(s_lib_pub),
                                   s_lib_priv, sizeof(s_lib_priv), NULL, NULL) != 0)
        FAIL("server init\n");

    if (speer_tls13_handshake_start(&server) != SPEER_TLS_OK) FAIL("server start\n");
    if (speer_tls13_handshake_start(&client) != SPEER_TLS_NEED_OUT) FAIL("client start\n");
    size_t used;
    int rc = feed_one(&server, client.out_buf, client.out_len, &used);
    if (rc != SPEER_TLS_NEED_OUT) {
        FAIL("server consume ch rc=%d state=%d alert=%u out=%zu\n", rc, server.state,
             server.alert_description, server.out_len);
    }

    size_t off = 0;
    while (off < server.out_len) {
        rc = feed_one(&client, server.out_buf + off, server.out_len - off, &used);
        uint8_t msg_type = server.out_buf[off];
        off += used;
        if (off < server.out_len && rc != SPEER_TLS_OK)
            FAIL("client mid flight type=%u rc=%d state=%d alert=%u\n", msg_type, rc,
                 client.state, client.alert_description);
        if (off == server.out_len && rc != SPEER_TLS_NEED_OUT)
            FAIL("client final flight type=%u rc=%d state=%d alert=%u\n", msg_type, rc,
                 client.state, client.alert_description);
    }
    if (!speer_tls13_is_done(&client)) FAIL("client not done\n");

    if (feed_one(&server, client.out_buf, client.out_len, &used) != SPEER_TLS_DONE)
        FAIL("server consume cfin\n");
    if (!speer_tls13_is_done(&server)) FAIL("server not done\n");
    if (!client.peer_libp2p_verified) FAIL("peer auth\n");
    if (memcmp(client.peer_libp2p_pub, s_lib_pub, 32) != 0) FAIL("client peer id\n");

    puts("tls13_full_handshake: ok");
    return 0;
}
