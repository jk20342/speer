#include "speer_internal.h"

#include <stdio.h>

#include "ed25519.h"
#include "tls13_handshake.h"
#include "tls_msg.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static void make_keys(uint8_t cert_pub[32], uint8_t cert_priv[32], uint8_t lib_pub[32],
                      uint8_t lib_priv[32]) {
    uint8_t seed[32] = {1};
    speer_ed25519_keypair(cert_pub, cert_priv, seed);
    seed[0] = 2;
    speer_ed25519_keypair(lib_pub, lib_priv, seed);
}

static int init_client(speer_tls13_t *h) {
    uint8_t cert_pub[32], cert_priv[32], lib_pub[32], lib_priv[32];
    make_keys(cert_pub, cert_priv, lib_pub, lib_priv);
    return speer_tls13_init_handshake(h, SPEER_TLS_ROLE_CLIENT, cert_priv, cert_pub,
                                      SPEER_LIBP2P_KEY_ED25519, lib_pub, 32, lib_priv, 32, NULL,
                                      NULL);
}

static int init_server(speer_tls13_t *h) {
    uint8_t cert_pub[32], cert_priv[32], lib_pub[32], lib_priv[32];
    make_keys(cert_pub, cert_priv, lib_pub, lib_priv);
    return speer_tls13_init_handshake(h, SPEER_TLS_ROLE_SERVER, cert_priv, cert_pub,
                                      SPEER_LIBP2P_KEY_ED25519, lib_pub, 32, lib_priv, 32, NULL,
                                      NULL);
}

static int client_hello_missing_keyshare(uint8_t *out, size_t cap, size_t *out_len) {
    speer_tls_writer_t w;
    speer_tls_writer_init(&w, out, cap);
    if (speer_tls_w_u16(&w, 0x0303) != 0) return -1;
    uint8_t random[32] = {1};
    if (speer_tls_w_bytes(&w, random, sizeof(random)) != 0) return -1;
    if (speer_tls_w_u8(&w, 0) != 0) return -1;
    uint8_t suite[] = {0x13, 0x01};
    if (speer_tls_w_vec_u16(&w, suite, sizeof(suite)) != 0) return -1;
    uint8_t comp[] = {0};
    if (speer_tls_w_vec_u8(&w, comp, sizeof(comp)) != 0) return -1;
    size_t exts = speer_tls_w_save(&w);
    if (speer_tls_w_u16(&w, 0) != 0) return -1;
    if (speer_tls_w_u16(&w, TLS_EXT_SUPPORTED_VERSIONS) != 0) return -1;
    uint8_t sv[] = {2, 3, 4};
    if (speer_tls_w_vec_u16(&w, sv, sizeof(sv)) != 0) return -1;
    if (speer_tls_w_u16(&w, TLS_EXT_SUPPORTED_GROUPS) != 0) return -1;
    uint8_t groups[] = {0, 2, 0, 0x1d};
    if (speer_tls_w_vec_u16(&w, groups, sizeof(groups)) != 0) return -1;
    if (speer_tls_w_u16(&w, TLS_EXT_SIGNATURE_ALGORITHMS) != 0) return -1;
    uint8_t sigs[] = {0, 2, 0x08, 0x07};
    if (speer_tls_w_vec_u16(&w, sigs, sizeof(sigs)) != 0) return -1;
    if (speer_tls_w_finish_vec_u16(&w, exts) != 0) return -1;
    *out_len = w.pos;
    return 0;
}

int main(void) {
    speer_tls13_t h;
    if (init_server(&h) != 0) FAIL("server init\n");
    if (speer_tls13_handshake_start(&h) != SPEER_TLS_OK) FAIL("server start\n");
    uint8_t ch[256];
    size_t ch_len;
    if (client_hello_missing_keyshare(ch, sizeof(ch), &ch_len) != 0) FAIL("ch build\n");
    if (speer_tls13_handshake_consume(&h, TLS_HS_CLIENT_HELLO, ch, ch_len) != SPEER_TLS_NEED_OUT)
        FAIL("hrr not produced\n");
    if (speer_tls13_handshake_consume(&h, TLS_HS_CLIENT_HELLO, ch, ch_len) != SPEER_TLS_ERR)
        FAIL("second hrr accepted\n");

    if (init_client(&h) != 0) FAIL("client init\n");
    if (speer_tls13_handshake_start(&h) != SPEER_TLS_NEED_OUT) FAIL("client start\n");
    uint8_t bad_ku[] = {2};
    h.state = TLS_ST_DONE;
    if (speer_tls13_handshake_consume(&h, TLS_HS_KEY_UPDATE, bad_ku, sizeof(bad_ku)) !=
        SPEER_TLS_ERR)
        FAIL("bad keyupdate\n");

    if (init_client(&h) != 0) FAIL("client init2\n");
    if (speer_tls13_handshake_start(&h) != SPEER_TLS_NEED_OUT) FAIL("client start2\n");
    uint8_t dup_ext_sh[] = {0x03, 0x03, 0,    0,    0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0, 0,
                            0,    0,    0,    0,    0, 0, 0, 0,    0, 0, 0, 0, 0,    0, 0, 0, 0,
                            0,    0,    0x13, 0x01, 0, 0, 8, 0x2b, 0, 2, 3, 4, 0x2b, 0, 2, 3, 4};
    if (speer_tls13_handshake_consume(&h, TLS_HS_SERVER_HELLO, dup_ext_sh, sizeof(dup_ext_sh)) !=
        SPEER_TLS_ERR)
        FAIL("duplicate ext\n");

    puts("tls13_negative_vectors: ok");
    return 0;
}
