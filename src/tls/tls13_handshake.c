#include "tls13_handshake.h"

#include "speer_internal.h"

#include "ed25519.h"
#include "tls_msg.h"
#include "x509_libp2p.h"

static int append_transcript(speer_tls13_t *h, uint8_t msg_type, const uint8_t *body,
                             size_t body_len) {
    size_t need = h->transcript_len + 4 + body_len;
    if (need > h->transcript_cap) {
        size_t newcap = h->transcript_cap ? h->transcript_cap * 2 : 4096;
        while (newcap < need) newcap *= 2;
        uint8_t *nb = (uint8_t *)realloc(h->transcript, newcap);
        if (!nb) return -1;
        h->transcript = nb;
        h->transcript_cap = newcap;
    }
    h->transcript[h->transcript_len++] = msg_type;
    h->transcript[h->transcript_len++] = (uint8_t)(body_len >> 16);
    h->transcript[h->transcript_len++] = (uint8_t)(body_len >> 8);
    h->transcript[h->transcript_len++] = (uint8_t)body_len;
    if (body_len > 0) COPY(h->transcript + h->transcript_len, body, body_len);
    h->transcript_len += body_len;
    return 0;
}

static void transcript_hash(const speer_tls13_t *h, uint8_t *out) {
    h->ks.suite.hash->oneshot(out, h->transcript, h->transcript_len);
}

int speer_tls13_init_handshake(speer_tls13_t *h, speer_tls_role_t role, const uint8_t cert_priv[32],
                               const uint8_t cert_pub[32], speer_libp2p_keytype_t libp2p_kt,
                               const uint8_t *libp2p_pub, size_t libp2p_pub_len,
                               const uint8_t *libp2p_priv, size_t libp2p_priv_len, const char *alpn,
                               const char *server_name) {
    ZERO(h, sizeof(*h));
    h->role = role;
    h->state = TLS_ST_START;
    h->cipher_suite = TLS_CS_AES_128_GCM_SHA256;
    h->alpn = alpn;
    h->server_name = server_name;
    if (libp2p_kt != SPEER_LIBP2P_KEY_ED25519) return -1;
    if (libp2p_pub_len != 32 || libp2p_priv_len != 32) return -1;
    COPY(h->libp2p_pub, libp2p_pub, 32);
    COPY(h->libp2p_priv, libp2p_priv, 32);
    if (speer_libp2p_pubkey_proto_encode(h->libp2p_pubkey_proto, sizeof(h->libp2p_pubkey_proto),
                                         libp2p_kt, libp2p_pub, libp2p_pub_len,
                                         &h->libp2p_pubkey_proto_len) != 0)
        return -1;
    COPY(h->our_cert_priv, cert_priv, 32);
    COPY(h->our_cert_pub, cert_pub, 32);

    speer_random_bytes(h->our_x25519_priv, 32);
    speer_x25519_base(h->our_x25519_pub, h->our_x25519_priv);

    if (role == SPEER_TLS_ROLE_CLIENT) {
        speer_random_bytes(h->client_random, 32);
    } else {
        speer_random_bytes(h->server_random, 32);
    }
    return speer_tls13_init(&h->ks, h->cipher_suite, NULL, 0);
}

static int build_client_hello(speer_tls13_t *h) {
    speer_tls_writer_t w;
    speer_tls_writer_init(&w, h->out_buf, sizeof(h->out_buf));

    if (speer_tls_w_handshake_header(&w, TLS_HS_CLIENT_HELLO, 0) != 0) return -1;
    size_t hs_body_start = w.pos;

    speer_tls_w_u16(&w, 0x0303);
    speer_tls_w_bytes(&w, h->client_random, 32);
    speer_tls_w_u8(&w, 0);
    uint16_t suites[1] = {h->cipher_suite};
    uint8_t suite_bytes[2];
    suite_bytes[0] = (uint8_t)(suites[0] >> 8);
    suite_bytes[1] = (uint8_t)(suites[0]);
    speer_tls_w_vec_u16(&w, suite_bytes, 2);
    uint8_t comp[1] = {0};
    speer_tls_w_vec_u8(&w, comp, 1);

    size_t exts_off = speer_tls_w_save(&w);
    speer_tls_w_u16(&w, 0);

    speer_tls_w_u16(&w, TLS_EXT_SUPPORTED_VERSIONS);
    uint8_t sv[3] = {2, 0x03, 0x04};
    speer_tls_w_vec_u16(&w, sv, 3);

    speer_tls_w_u16(&w, TLS_EXT_SUPPORTED_GROUPS);
    uint8_t sg[4] = {0, 2, 0, 0x1d};
    speer_tls_w_vec_u16(&w, sg, 4);

    speer_tls_w_u16(&w, TLS_EXT_SIGNATURE_ALGORITHMS);
    uint8_t sa[4] = {0, 2, 0x08, 0x07};
    speer_tls_w_vec_u16(&w, sa, 4);

    speer_tls_w_u16(&w, TLS_EXT_KEY_SHARE);
    size_t ks_off = speer_tls_w_save(&w);
    speer_tls_w_u16(&w, 0);
    speer_tls_w_u16(&w, 38);
    speer_tls_w_u16(&w, 0x001d);
    speer_tls_w_u16(&w, 32);
    speer_tls_w_bytes(&w, h->our_x25519_pub, 32);
    speer_tls_w_finish_vec_u16(&w, ks_off);

    if (h->server_name && h->server_name[0]) {
        size_t sn_len = 0;
        while (h->server_name[sn_len]) sn_len++;
        speer_tls_w_u16(&w, TLS_EXT_SERVER_NAME);
        size_t sni_off = speer_tls_w_save(&w);
        speer_tls_w_u16(&w, 0);
        size_t list_off = speer_tls_w_save(&w);
        speer_tls_w_u16(&w, 0);
        speer_tls_w_u8(&w, 0);
        speer_tls_w_u16(&w, (uint16_t)sn_len);
        speer_tls_w_bytes(&w, (const uint8_t *)h->server_name, sn_len);
        speer_tls_w_finish_vec_u16(&w, list_off);
        speer_tls_w_finish_vec_u16(&w, sni_off);
    }

    if (h->alpn && h->alpn[0]) {
        size_t alpn_len = 0;
        while (h->alpn[alpn_len]) alpn_len++;
        speer_tls_w_u16(&w, TLS_EXT_ALPN);
        size_t a_off = speer_tls_w_save(&w);
        speer_tls_w_u16(&w, 0);
        speer_tls_w_u16(&w, (uint16_t)(alpn_len + 1));
        speer_tls_w_u8(&w, (uint8_t)alpn_len);
        speer_tls_w_bytes(&w, (const uint8_t *)h->alpn, alpn_len);
        speer_tls_w_finish_vec_u16(&w, a_off);
    }

    if (speer_tls_w_finish_vec_u16(&w, exts_off) != 0) return -1;

    size_t hs_body_len = w.pos - hs_body_start;
    h->out_buf[1] = (uint8_t)(hs_body_len >> 16);
    h->out_buf[2] = (uint8_t)(hs_body_len >> 8);
    h->out_buf[3] = (uint8_t)hs_body_len;

    h->out_len = w.pos;

    append_transcript(h, TLS_HS_CLIENT_HELLO, h->out_buf + 4, hs_body_len);
    return 0;
}

int speer_tls13_handshake_start(speer_tls13_t *h) {
    if (h->role != SPEER_TLS_ROLE_CLIENT) return SPEER_TLS_OK;
    if (build_client_hello(h) != 0) return SPEER_TLS_ERR;
    h->state = TLS_ST_WAIT_SH;
    return SPEER_TLS_NEED_OUT;
}

int speer_tls13_handshake_take_output(speer_tls13_t *h, uint8_t *out, size_t cap, size_t *out_len) {
    if (h->out_len == 0) return SPEER_TLS_OK;
    if (h->out_len > cap) return SPEER_TLS_ERR;
    COPY(out, h->out_buf, h->out_len);
    if (out_len) *out_len = h->out_len;
    h->out_len = 0;
    return SPEER_TLS_OK;
}

static int parse_server_hello(speer_tls13_t *h, const uint8_t *body, size_t body_len) {
    speer_tls_reader_t r;
    speer_tls_reader_init(&r, body, body_len);
    uint16_t legacy;
    if (speer_tls_r_u16(&r, &legacy) != 0) return -1;
    const uint8_t *sr;
    if (speer_tls_r_bytes(&r, &sr, 32) != 0) return -1;
    COPY(h->server_random, sr, 32);
    const uint8_t *session;
    size_t session_len;
    if (speer_tls_r_vec_u8(&r, &session, &session_len) != 0) return -1;
    uint16_t suite;
    if (speer_tls_r_u16(&r, &suite) != 0) return -1;
    if (suite != h->cipher_suite) return -1;
    uint8_t comp;
    if (speer_tls_r_u8(&r, &comp) != 0) return -1;

    const uint8_t *exts_data;
    size_t exts_len;
    if (speer_tls_r_vec_u16(&r, &exts_data, &exts_len) != 0) return -1;

    speer_tls_reader_t er;
    speer_tls_reader_init(&er, exts_data, exts_len);
    int got_keyshare = 0;
    while (er.pos < er.len) {
        uint16_t ext;
        if (speer_tls_r_u16(&er, &ext) != 0) return -1;
        const uint8_t *ext_data;
        size_t ext_data_len;
        if (speer_tls_r_vec_u16(&er, &ext_data, &ext_data_len) != 0) return -1;
        if (ext == TLS_EXT_KEY_SHARE) {
            if (ext_data_len < 4) return -1;
            uint16_t group = ((uint16_t)ext_data[0] << 8) | ext_data[1];
            uint16_t klen = ((uint16_t)ext_data[2] << 8) | ext_data[3];
            if (group != TLS_GROUP_X25519) return -1;
            if (klen != 32 || ext_data_len < (size_t)(4 + klen)) return -1;
            COPY(h->peer_x25519_pub, ext_data + 4, 32);
            got_keyshare = 1;
        }
    }
    return got_keyshare ? 0 : -1;
}

static int derive_handshake_keys(speer_tls13_t *h) {
    uint8_t shared[32];
    if (speer_x25519(shared, h->our_x25519_priv, h->peer_x25519_pub) != 0) return -1;

    uint8_t hs_hash[SPEER_TLS13_MAX_HASH];
    transcript_hash(h, hs_hash);
    if (speer_tls13_set_handshake_secret(&h->ks, shared, 32, hs_hash) != 0) return -1;
    speer_tls13_handshake_keys(&h->ks, &h->client_hs_keys, &h->server_hs_keys, hs_hash);
    COPY(h->hs_transcript_hash, hs_hash, h->ks.suite.hash->digest_size);
    return 0;
}

static int handle_certificate(speer_tls13_t *h, const uint8_t *body, size_t body_len) {
    speer_tls_reader_t r;
    speer_tls_reader_init(&r, body, body_len);
    const uint8_t *req_ctx;
    size_t req_ctx_len;
    if (speer_tls_r_vec_u8(&r, &req_ctx, &req_ctx_len) != 0) return -1;
    const uint8_t *cert_list_data;
    size_t cert_list_len;
    if (speer_tls_r_vec_u24(&r, &cert_list_data, &cert_list_len) != 0) return -1;

    speer_tls_reader_t cr;
    speer_tls_reader_init(&cr, cert_list_data, cert_list_len);
    const uint8_t *cert_data;
    size_t cert_data_len;
    if (speer_tls_r_vec_u24(&cr, &cert_data, &cert_data_len) != 0) return -1;
    if (cert_data_len > sizeof(h->cert_der)) return -1;
    COPY(h->cert_der, cert_data, cert_data_len);
    h->cert_der_len = cert_data_len;

    speer_x509_libp2p_t parsed;
    if (speer_x509_libp2p_parse(&parsed, cert_data, cert_data_len) != 0) return -1;
    if (speer_x509_libp2p_verify(&parsed) != 0) return -1;

    h->peer_libp2p_kt = parsed.keytype;
    h->peer_libp2p_pub_len = parsed.libp2p_pub_len;
    COPY(h->peer_libp2p_pub, parsed.libp2p_pub, parsed.libp2p_pub_len);
    h->peer_libp2p_verified = 1;
    return 0;
}

int speer_tls13_handshake_consume(speer_tls13_t *h, uint8_t msg_type, const uint8_t *body,
                                  size_t body_len) {
    append_transcript(h, msg_type, body, body_len);

    switch (h->state) {
    case TLS_ST_WAIT_SH:
        if (msg_type != TLS_HS_SERVER_HELLO) {
            h->state = TLS_ST_ERROR;
            return SPEER_TLS_ERR;
        }
        if (parse_server_hello(h, body, body_len) != 0) {
            h->state = TLS_ST_ERROR;
            return SPEER_TLS_ERR;
        }
        h->transcript_len -= 4 + body_len;
        append_transcript(h, msg_type, body, body_len);
        if (derive_handshake_keys(h) != 0) {
            h->state = TLS_ST_ERROR;
            return SPEER_TLS_ERR;
        }
        h->state = TLS_ST_WAIT_EE;
        return SPEER_TLS_OK;
    case TLS_ST_WAIT_EE:
        if (msg_type == TLS_HS_ENCRYPTED_EXTS) {
            h->state = TLS_ST_WAIT_CERT;
            return SPEER_TLS_OK;
        }
        return SPEER_TLS_ERR;
    case TLS_ST_WAIT_CERT:
        if (msg_type != TLS_HS_CERTIFICATE) return SPEER_TLS_ERR;
        if (handle_certificate(h, body, body_len) != 0) return SPEER_TLS_ERR;
        h->state = TLS_ST_WAIT_CV;
        return SPEER_TLS_OK;
    case TLS_ST_WAIT_CV:
        if (msg_type != TLS_HS_CERT_VERIFY) return SPEER_TLS_ERR;
        h->state = TLS_ST_WAIT_FINISHED;
        return SPEER_TLS_OK;
    case TLS_ST_WAIT_FINISHED: {
        if (msg_type != TLS_HS_FINISHED) return SPEER_TLS_ERR;
        if (speer_tls13_set_master_secret(&h->ks) != 0) return SPEER_TLS_ERR;
        uint8_t hs_hash_after[SPEER_TLS13_MAX_HASH];
        transcript_hash(h, hs_hash_after);
        speer_tls13_application_keys(&h->ks, &h->client_app_keys, &h->server_app_keys,
                                     hs_hash_after);
        h->state = TLS_ST_DONE;
        return SPEER_TLS_DONE;
    }
    default:
        return SPEER_TLS_ERR;
    }
}

int speer_tls13_export_traffic_secret(const speer_tls13_t *h, int from_server, int application,
                                      uint8_t *out, size_t *out_len) {
    const uint8_t *src;
    if (application) {
        src = from_server ? h->ks.server_application_traffic : h->ks.client_application_traffic;
    } else {
        src = from_server ? h->ks.server_handshake_traffic : h->ks.client_handshake_traffic;
    }
    size_t n = h->ks.suite.hash->digest_size;
    COPY(out, src, n);
    if (out_len) *out_len = n;
    return 0;
}

int speer_tls13_is_done(const speer_tls13_t *h) {
    return h->state == TLS_ST_DONE;
}
