#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "ed25519.h"
#include "tls13_handshake.h"
#include "tls_msg.h"

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

static int handshake(speer_tls13_t *client, speer_tls13_t *server) {
    if (speer_tls13_handshake_start(server) != SPEER_TLS_OK) FAIL("server start\n");
    if (speer_tls13_handshake_start(client) != SPEER_TLS_NEED_OUT) FAIL("client start\n");
    size_t used;
    if (feed_one(server, client->out_buf, client->out_len, &used) != SPEER_TLS_NEED_OUT)
        FAIL("server ch\n");
    size_t off = 0;
    while (off < server->out_len) {
        int rc = feed_one(client, server->out_buf + off, server->out_len - off, &used);
        off += used;
        if (off < server->out_len && rc != SPEER_TLS_OK) FAIL("client flight\n");
        if (off == server->out_len && rc != SPEER_TLS_NEED_OUT) FAIL("client done flight\n");
    }
    if (feed_one(server, client->out_buf, client->out_len, &used) != SPEER_TLS_DONE)
        FAIL("server cfin\n");
    return 0;
}

int main(void) {
    uint8_t c_cert_pub[32], c_cert_priv[32], c_lib_pub[32], c_lib_priv[32];
    uint8_t s_cert_pub[32], s_cert_priv[32], s_lib_pub[32], s_lib_priv[32];
    make_keys(c_cert_pub, c_cert_priv, c_lib_pub, c_lib_priv, 1);
    make_keys(s_cert_pub, s_cert_priv, s_lib_pub, s_lib_priv, 9);

    speer_tls13_t client, server;
    if (speer_tls13_init_handshake(&client, SPEER_TLS_ROLE_CLIENT, c_cert_priv, c_cert_pub,
                                   SPEER_LIBP2P_KEY_ED25519, c_lib_pub, 32, c_lib_priv, 32, NULL,
                                   NULL) != 0)
        FAIL("client init\n");
    if (speer_tls13_init_handshake(&server, SPEER_TLS_ROLE_SERVER, s_cert_priv, s_cert_pub,
                                   SPEER_LIBP2P_KEY_ED25519, s_lib_pub, 32, s_lib_priv, 32, NULL,
                                   NULL) != 0)
        FAIL("server init\n");
    if (handshake(&client, &server) != 0) return 1;

    speer_tls13_record_dir_t csend, srecv;
    speer_tls13_record_dir_init(&csend, &client.ks.suite, &client.client_app_keys);
    speer_tls13_record_dir_init(&srecv, &server.ks.suite, &server.client_app_keys);

    uint8_t rec[256], plain[256], inner;
    size_t rec_len, plain_len;
    const uint8_t msg[] = "hello over tls record";
    if (speer_tls13_record_seal(&csend, TLS_CT_APPLICATION_DATA, msg, sizeof(msg), rec, sizeof(rec),
                                &rec_len) != 0)
        FAIL("seal\n");
    if (speer_tls13_record_open(&srecv, rec, rec_len, plain, sizeof(plain), &plain_len, &inner) !=
        0)
        FAIL("open\n");
    if (inner != TLS_CT_APPLICATION_DATA || plain_len != sizeof(msg) ||
        memcmp(plain, msg, sizeof(msg)) != 0)
        FAIL("plaintext\n");

    rec[rec_len - 1] ^= 1;
    if (speer_tls13_record_open(&srecv, rec, rec_len, plain, sizeof(plain), &plain_len, &inner) ==
        0)
        FAIL("tamper accepted\n");

    puts("tls13_record_handshake: ok");
    return 0;
}
