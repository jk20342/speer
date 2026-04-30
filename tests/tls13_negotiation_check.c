#include "speer_internal.h"

#include <stdio.h>

#include "tls13_handshake.h"
#include "tls_msg.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static int has_u16(const uint8_t *p, size_t n, uint16_t v) {
    for (size_t i = 0; i + 1 < n; i += 2) {
        if ((((uint16_t)p[i] << 8) | p[i + 1]) == v) return 1;
    }
    return 0;
}

int main(void) {
    speer_tls13_t h;
    uint8_t cert_priv[32] = {1};
    uint8_t cert_pub[32] = {2};
    uint8_t libp2p_priv[32] = {3};
    uint8_t libp2p_pub[32] = {4};
    if (speer_tls13_init_handshake(&h, SPEER_TLS_ROLE_CLIENT, cert_priv, cert_pub,
                                   SPEER_LIBP2P_KEY_ED25519, libp2p_pub, sizeof(libp2p_pub),
                                   libp2p_priv, sizeof(libp2p_priv), "test/1.0", "example.test") != 0)
        FAIL("init\n");
    if (speer_tls13_handshake_start(&h) != SPEER_TLS_NEED_OUT) FAIL("start\n");

    speer_tls_reader_t r;
    speer_tls_reader_init(&r, h.out_buf, h.out_len);
    uint8_t ty;
    uint32_t body_len;
    if (speer_tls_r_u8(&r, &ty) != 0 || ty != TLS_HS_CLIENT_HELLO) FAIL("type\n");
    if (speer_tls_r_u24(&r, &body_len) != 0) FAIL("len\n");
    const uint8_t *body;
    if (speer_tls_r_bytes(&r, &body, body_len) != 0) FAIL("body\n");

    speer_tls_reader_t cr;
    speer_tls_reader_init(&cr, body, body_len);
    uint16_t legacy;
    const uint8_t *skip;
    size_t n;
    if (speer_tls_r_u16(&cr, &legacy) != 0 || legacy != 0x0303) FAIL("legacy\n");
    if (speer_tls_r_bytes(&cr, &skip, 32) != 0) FAIL("random\n");
    if (speer_tls_r_vec_u8(&cr, &skip, &n) != 0) FAIL("sid\n");
    if (speer_tls_r_vec_u16(&cr, &skip, &n) != 0) FAIL("suites\n");
    if (!has_u16(skip, n, TLS_CS_AES_128_GCM_SHA256) ||
        !has_u16(skip, n, TLS_CS_AES_256_GCM_SHA384) ||
        !has_u16(skip, n, TLS_CS_CHACHA20_POLY1305_SHA256))
        FAIL("missing suite\n");
    if (speer_tls_r_vec_u8(&cr, &skip, &n) != 0) FAIL("compression\n");
    const uint8_t *exts;
    size_t exts_len;
    if (speer_tls_r_vec_u16(&cr, &exts, &exts_len) != 0) FAIL("exts\n");

    int saw_sigalgs = 0;
    speer_tls_reader_t er;
    speer_tls_reader_init(&er, exts, exts_len);
    while (er.pos < er.len) {
        uint16_t ext;
        const uint8_t *ed;
        size_t el;
        if (speer_tls_r_u16(&er, &ext) != 0) FAIL("ext type\n");
        if (speer_tls_r_vec_u16(&er, &ed, &el) != 0) FAIL("ext body\n");
        if (ext == TLS_EXT_SIGNATURE_ALGORITHMS) {
            speer_tls_reader_t sr;
            speer_tls_reader_init(&sr, ed, el);
            const uint8_t *list;
            size_t list_len;
            if (speer_tls_r_vec_u16(&sr, &list, &list_len) != 0) FAIL("sig list\n");
            if (!has_u16(list, list_len, TLS_SIGSCHEME_ED25519) ||
                !has_u16(list, list_len, TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256))
                FAIL("missing sigalg\n");
            saw_sigalgs = 1;
        }
    }
    if (!saw_sigalgs) FAIL("no sigalgs\n");

    puts("tls13_negotiation: ok");
    return 0;
}
