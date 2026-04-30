#include "tls13_handshake.h"

#include "speer_internal.h"

#include "asn1.h"
#include "ct_helpers.h"
#include "ed25519.h"
#include "sig_dispatch.h"
#include "tls_msg.h"
#include "x509_libp2p.h"
#include "x509_webpki.h"

static const char CV_LABEL_SERVER[] = "TLS 1.3, server CertificateVerify";
static const char CV_LABEL_CLIENT[] = "TLS 1.3, client CertificateVerify";

static int append_transcript(speer_tls13_t *h, uint8_t msg_type, const uint8_t *body,
                             size_t body_len) {
    if (body_len > 0xffffff) return -1;
    if (h->transcript_len > SIZE_MAX - 4 - body_len) return -1;
    size_t need = h->transcript_len + 4 + body_len;
    if (need > h->transcript_cap) {
        size_t newcap = h->transcript_cap ? h->transcript_cap * 2 : 4096;
        if (newcap < need) newcap = need + 256;
        if (newcap > (size_t)1 << 20) newcap = (size_t)1 << 20;
        if (newcap < need) return -1;
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

    if (speer_random_bytes_or_fail(h->our_x25519_priv, 32) != 0) return -1;
    speer_x25519_base(h->our_x25519_pub, h->our_x25519_priv);

    if (role == SPEER_TLS_ROLE_CLIENT) {
        if (speer_random_bytes_or_fail(h->client_random, 32) != 0) return -1;
    } else {
        if (speer_random_bytes_or_fail(h->server_random, 32) != 0) return -1;
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

    if (append_transcript(h, TLS_HS_CLIENT_HELLO, h->out_buf + 4, hs_body_len) != 0) return -1;
    return 0;
}

int speer_tls13_handshake_start(speer_tls13_t *h) {
    if (h->role == SPEER_TLS_ROLE_CLIENT) {
        if (build_client_hello(h) != 0) {
            h->state = TLS_ST_ERROR;
            return SPEER_TLS_ERR;
        }
        h->state = TLS_ST_WAIT_SH;
        return SPEER_TLS_NEED_OUT;
    }
    h->state = TLS_ST_WAIT_CH;
    return SPEER_TLS_OK;
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
    if (legacy != 0x0303) return -1;
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
    if (comp != 0) return -1;

    const uint8_t *exts_data;
    size_t exts_len;
    if (speer_tls_r_vec_u16(&r, &exts_data, &exts_len) != 0) return -1;
    if (r.pos != body_len) return -1;

    speer_tls_reader_t er;
    speer_tls_reader_init(&er, exts_data, exts_len);
    int got_keyshare = 0;
    int got_supported_versions = 0;
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
            if (klen != 32 || ext_data_len != (size_t)(4 + klen)) return -1;
            COPY(h->peer_x25519_pub, ext_data + 4, 32);
            got_keyshare = 1;
        } else if (ext == TLS_EXT_SUPPORTED_VERSIONS) {
            if (ext_data_len != 2) return -1;
            uint16_t selected = ((uint16_t)ext_data[0] << 8) | ext_data[1];
            if (selected != 0x0304) return -1;
            got_supported_versions = 1;
        }
    }
    if (er.pos != er.len) return -1;
    if (!got_keyshare || !got_supported_versions) return -1;
    return 0;
}

static int parse_encrypted_extensions(speer_tls13_t *h, const uint8_t *body, size_t body_len) {
    speer_tls_reader_t r;
    speer_tls_reader_init(&r, body, body_len);
    const uint8_t *exts_data;
    size_t exts_len;
    if (speer_tls_r_vec_u16(&r, &exts_data, &exts_len) != 0) return -1;
    if (r.pos != body_len) return -1;

    speer_tls_reader_t er;
    speer_tls_reader_init(&er, exts_data, exts_len);
    while (er.pos < er.len) {
        uint16_t ext;
        if (speer_tls_r_u16(&er, &ext) != 0) return -1;
        const uint8_t *ext_data;
        size_t ext_data_len;
        if (speer_tls_r_vec_u16(&er, &ext_data, &ext_data_len) != 0) return -1;
        switch (ext) {
        case TLS_EXT_ALPN: {
            speer_tls_reader_t ar;
            speer_tls_reader_init(&ar, ext_data, ext_data_len);
            const uint8_t *list;
            size_t list_len;
            if (speer_tls_r_vec_u16(&ar, &list, &list_len) != 0) return -1;
            speer_tls_reader_t lr;
            speer_tls_reader_init(&lr, list, list_len);
            const uint8_t *name;
            size_t name_len;
            if (speer_tls_r_vec_u8(&lr, &name, &name_len) != 0) return -1;
            if (lr.pos != lr.len) return -1;
            if (name_len >= sizeof(h->negotiated_alpn)) return -1;
            COPY(h->negotiated_alpn, name, name_len);
            h->negotiated_alpn[name_len] = 0;
            break;
        }
        case TLS_EXT_SERVER_NAME:
            break;
        case TLS_EXT_SUPPORTED_GROUPS:
            break;
        default:
            break;
        }
    }
    if (er.pos != er.len) return -1;
    return 0;
}

static int derive_handshake_keys(speer_tls13_t *h) {
    uint8_t shared[32];
    if (speer_x25519(shared, h->our_x25519_priv, h->peer_x25519_pub) != 0) return -1;

    int all_zero = 1;
    for (int i = 0; i < 32; i++)
        if (shared[i] != 0) {
            all_zero = 0;
            break;
        }
    if (all_zero) {
        WIPE(shared, sizeof(shared));
        return -1;
    }

    uint8_t hs_hash[SPEER_TLS13_MAX_HASH];
    transcript_hash(h, hs_hash);
    if (speer_tls13_set_handshake_secret(&h->ks, shared, 32, hs_hash) != 0) {
        WIPE(shared, sizeof(shared));
        return -1;
    }
    speer_tls13_handshake_keys(&h->ks, &h->client_hs_keys, &h->server_hs_keys);
    COPY(h->hs_transcript_hash, hs_hash, h->ks.suite.hash->digest_size);
    WIPE(shared, sizeof(shared));
    return 0;
}

static int extract_spki_pubkey(const uint8_t *spki, size_t spki_len, uint16_t *out_alg_id,
                               const uint8_t **out_pub, size_t *out_pub_len) {
    speer_asn1_t spki_seq;
    if (speer_asn1_parse(spki, spki_len, &spki_seq) != 0) return -1;
    if (spki_seq.tag != ASN1_SEQUENCE) return -1;
    const uint8_t *sc;
    const uint8_t *se;
    if (speer_asn1_seq_iter_init(&spki_seq, &sc, &se) != 0) return -1;
    speer_asn1_t alg;
    if (speer_asn1_seq_next(&sc, se, &alg) != 0) return -1;
    if (alg.tag != ASN1_SEQUENCE) return -1;
    const uint8_t *ac;
    const uint8_t *ae;
    if (speer_asn1_seq_iter_init(&alg, &ac, &ae) != 0) return -1;
    speer_asn1_t alg_oid;
    if (speer_asn1_seq_next(&ac, ae, &alg_oid) != 0) return -1;
    if (alg_oid.tag != ASN1_OID) return -1;

    speer_asn1_t bs;
    if (speer_asn1_seq_next(&sc, se, &bs) != 0) return -1;
    if (bs.tag != ASN1_BIT_STRING || bs.value_len < 1) return -1;
    if (bs.value[0] != 0) return -1;
    const uint8_t *pub = bs.value + 1;
    size_t pub_len = bs.value_len - 1;

    static const uint8_t OID_ED25519[] = {0x2b, 0x65, 0x70};
    static const uint8_t OID_EC_PUBKEY[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
    static const uint8_t OID_RSA[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};

    if (alg_oid.value_len == sizeof(OID_ED25519) &&
        memcmp(alg_oid.value, OID_ED25519, sizeof(OID_ED25519)) == 0) {
        if (pub_len != 32) return -1;
        *out_alg_id = TLS_SIGSCHEME_ED25519;
    } else if (alg_oid.value_len == sizeof(OID_EC_PUBKEY) &&
               memcmp(alg_oid.value, OID_EC_PUBKEY, sizeof(OID_EC_PUBKEY)) == 0) {
        *out_alg_id = TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256;
    } else if (alg_oid.value_len == sizeof(OID_RSA) &&
               memcmp(alg_oid.value, OID_RSA, sizeof(OID_RSA)) == 0) {
        *out_alg_id = TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256;
    } else {
        return -1;
    }
    *out_pub = pub;
    *out_pub_len = pub_len;
    return 0;
}

static const uint8_t SIG_OID_RSA_SHA256[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
static const uint8_t SIG_OID_RSA_SHA384[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c};
static const uint8_t SIG_OID_RSA_SHA512[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d};
static const uint8_t SIG_OID_RSA_PSS[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a};
static const uint8_t SIG_OID_ECDSA_SHA256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
static const uint8_t SIG_OID_ECDSA_SHA384[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03};
static const uint8_t SIG_OID_ED25519_ALG[] = {0x2b, 0x65, 0x70};

static int sig_oid_to_tls_id(const uint8_t *oid, size_t l, uint16_t *out) {
    if (l == sizeof(SIG_OID_ED25519_ALG) && memcmp(oid, SIG_OID_ED25519_ALG, l) == 0) {
        *out = TLS_SIGSCHEME_ED25519;
        return 0;
    }
    if (l == sizeof(SIG_OID_ECDSA_SHA256) && memcmp(oid, SIG_OID_ECDSA_SHA256, l) == 0) {
        *out = TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256;
        return 0;
    }
    if (l == sizeof(SIG_OID_ECDSA_SHA384) && memcmp(oid, SIG_OID_ECDSA_SHA384, l) == 0) {
        *out = TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384;
        return 0;
    }
    if (l == sizeof(SIG_OID_RSA_SHA256) && memcmp(oid, SIG_OID_RSA_SHA256, l) == 0) {
        *out = TLS_SIGSCHEME_RSA_PKCS1_SHA256;
        return 0;
    }
    if (l == sizeof(SIG_OID_RSA_SHA384) && memcmp(oid, SIG_OID_RSA_SHA384, l) == 0) {
        *out = TLS_SIGSCHEME_RSA_PKCS1_SHA384;
        return 0;
    }
    if (l == sizeof(SIG_OID_RSA_SHA512) && memcmp(oid, SIG_OID_RSA_SHA512, l) == 0) {
        *out = TLS_SIGSCHEME_RSA_PKCS1_SHA512;
        return 0;
    }
    if (l == sizeof(SIG_OID_RSA_PSS) && memcmp(oid, SIG_OID_RSA_PSS, l) == 0) {
        *out = TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256;
        return 0;
    }
    return -1;
}

static int verify_outer_cert_signature(const uint8_t *cert_der, size_t cert_der_len) {
    speer_x509_t x;
    if (speer_x509_parse(&x, cert_der, cert_der_len) != 0) return -1;
    if (!x.tbs || !x.sig || !x.sig_alg_oid || !x.spki_pubkey) return -1;
    uint16_t sig_id;
    if (sig_oid_to_tls_id(x.sig_alg_oid, x.sig_alg_oid_len, &sig_id) != 0) return -1;
    return speer_sig_verify(sig_id, x.spki_pubkey, x.spki_pubkey_len, x.tbs, x.tbs_len, x.sig,
                            x.sig_len);
}

static int handle_certificate(speer_tls13_t *h, const uint8_t *body, size_t body_len) {
    speer_tls_reader_t r;
    speer_tls_reader_init(&r, body, body_len);
    const uint8_t *req_ctx;
    size_t req_ctx_len;
    if (speer_tls_r_vec_u8(&r, &req_ctx, &req_ctx_len) != 0) return -1;
    if (h->role == SPEER_TLS_ROLE_CLIENT && req_ctx_len != 0) return -1;
    const uint8_t *cert_list_data;
    size_t cert_list_len;
    if (speer_tls_r_vec_u24(&r, &cert_list_data, &cert_list_len) != 0) return -1;
    if (r.pos != body_len) return -1;
    if (cert_list_len == 0) return -1;

    speer_tls_reader_t cr;
    speer_tls_reader_init(&cr, cert_list_data, cert_list_len);

    int leaf_processed = 0;
    while (cr.pos < cr.len) {
        const uint8_t *cert_data;
        size_t cert_data_len;
        if (speer_tls_r_vec_u24(&cr, &cert_data, &cert_data_len) != 0) return -1;
        if (cert_data_len == 0) return -1;
        const uint8_t *cert_exts;
        size_t cert_exts_len;
        if (speer_tls_r_vec_u16(&cr, &cert_exts, &cert_exts_len) != 0) return -1;

        if (!leaf_processed) {
            if (cert_data_len > sizeof(h->cert_der)) return -1;
            COPY(h->cert_der, cert_data, cert_data_len);
            h->cert_der_len = cert_data_len;

            speer_x509_libp2p_t parsed;
            if (speer_x509_libp2p_parse(&parsed, cert_data, cert_data_len) != 0) return -1;
            if (speer_x509_libp2p_verify(&parsed) != 0) return -1;

            if (verify_outer_cert_signature(cert_data, cert_data_len) != 0) return -1;

            uint16_t spki_alg_id;
            const uint8_t *spki_pub;
            size_t spki_pub_len;
            if (extract_spki_pubkey(parsed.cert_pubkey_spki, parsed.cert_pubkey_spki_len,
                                    &spki_alg_id, &spki_pub, &spki_pub_len) != 0)
                return -1;
            if (spki_pub_len > sizeof(h->peer_spki_pubkey)) return -1;
            COPY(h->peer_spki_pubkey, spki_pub, spki_pub_len);
            h->peer_spki_pubkey_len = spki_pub_len;
            h->peer_spki_alg_tls_id = spki_alg_id;

            h->peer_libp2p_kt = parsed.keytype;
            h->peer_libp2p_pub_len = parsed.libp2p_pub_len;
            COPY(h->peer_libp2p_pub, parsed.libp2p_pub, parsed.libp2p_pub_len);
            h->peer_libp2p_verified = 1;
            h->peer_cert_outer_verified = 1;

            leaf_processed = 1;
        }
    }
    if (cr.pos != cr.len) return -1;
    if (!leaf_processed) return -1;
    return 0;
}

static int parse_client_hello(speer_tls13_t *h, const uint8_t *body, size_t body_len) {
    speer_tls_reader_t r;
    speer_tls_reader_init(&r, body, body_len);
    uint16_t legacy;
    if (speer_tls_r_u16(&r, &legacy) != 0) return -1;
    if (legacy != 0x0303) return -1;
    const uint8_t *cr;
    if (speer_tls_r_bytes(&r, &cr, 32) != 0) return -1;
    COPY(h->client_random, cr, 32);
    const uint8_t *session;
    size_t session_len;
    if (speer_tls_r_vec_u8(&r, &session, &session_len) != 0) return -1;

    const uint8_t *suites_data;
    size_t suites_len;
    if (speer_tls_r_vec_u16(&r, &suites_data, &suites_len) != 0) return -1;
    if (suites_len < 2 || (suites_len & 1) != 0) return -1;
    int found_suite = 0;
    uint16_t selected_suite = 0;
    for (size_t i = 0; i + 1 < suites_len; i += 2) {
        uint16_t s = ((uint16_t)suites_data[i] << 8) | suites_data[i + 1];
        if (s == TLS_CS_AES_128_GCM_SHA256 || s == TLS_CS_AES_256_GCM_SHA384 ||
            s == TLS_CS_CHACHA20_POLY1305_SHA256) {
            if (!found_suite) {
                selected_suite = s;
                found_suite = 1;
            }
        }
    }
    if (!found_suite) return -1;

    const uint8_t *comp;
    size_t comp_len;
    if (speer_tls_r_vec_u8(&r, &comp, &comp_len) != 0) return -1;
    if (comp_len != 1 || comp[0] != 0) return -1;

    const uint8_t *exts_data;
    size_t exts_len;
    if (speer_tls_r_vec_u16(&r, &exts_data, &exts_len) != 0) return -1;
    if (r.pos != body_len) return -1;

    int got_supported_versions = 0;
    int got_keyshare = 0;
    speer_tls_reader_t er;
    speer_tls_reader_init(&er, exts_data, exts_len);
    while (er.pos < er.len) {
        uint16_t ext;
        if (speer_tls_r_u16(&er, &ext) != 0) return -1;
        const uint8_t *ext_data;
        size_t ext_data_len;
        if (speer_tls_r_vec_u16(&er, &ext_data, &ext_data_len) != 0) return -1;
        if (ext == TLS_EXT_SUPPORTED_VERSIONS) {
            if (ext_data_len < 1) return -1;
            uint8_t list_len = ext_data[0];
            if (list_len < 2 || (list_len & 1) != 0 || (size_t)list_len + 1 > ext_data_len)
                return -1;
            for (size_t i = 1; i + 1 < (size_t)list_len + 1; i += 2) {
                uint16_t v = ((uint16_t)ext_data[i] << 8) | ext_data[i + 1];
                if (v == 0x0304) got_supported_versions = 1;
            }
        } else if (ext == TLS_EXT_KEY_SHARE) {
            if (ext_data_len < 2) return -1;
            uint16_t shares_len = ((uint16_t)ext_data[0] << 8) | ext_data[1];
            if ((size_t)shares_len + 2 > ext_data_len) return -1;
            size_t off = 2;
            while (off + 4 <= (size_t)shares_len + 2) {
                uint16_t group = ((uint16_t)ext_data[off] << 8) | ext_data[off + 1];
                uint16_t klen = ((uint16_t)ext_data[off + 2] << 8) | ext_data[off + 3];
                if (off + 4 + klen > ext_data_len) return -1;
                if (group == TLS_GROUP_X25519 && klen == 32) {
                    COPY(h->peer_x25519_pub, ext_data + off + 4, 32);
                    got_keyshare = 1;
                    break;
                }
                off += 4 + klen;
            }
        }
    }
    if (er.pos != er.len) return -1;
    if (!got_supported_versions || !got_keyshare) return -1;

    h->cipher_suite = selected_suite;
    return speer_tls13_init(&h->ks, h->cipher_suite, NULL, 0);
}

static int build_server_hello(speer_tls13_t *h) {
    speer_tls_writer_t w;
    speer_tls_writer_init(&w, h->out_buf, sizeof(h->out_buf));
    if (speer_tls_w_handshake_header(&w, TLS_HS_SERVER_HELLO, 0) != 0) return -1;
    size_t hs_body_start = w.pos;

    speer_tls_w_u16(&w, 0x0303);
    speer_tls_w_bytes(&w, h->server_random, 32);
    speer_tls_w_u8(&w, 0);
    speer_tls_w_u16(&w, h->cipher_suite);
    speer_tls_w_u8(&w, 0);

    size_t exts_off = speer_tls_w_save(&w);
    speer_tls_w_u16(&w, 0);

    speer_tls_w_u16(&w, TLS_EXT_SUPPORTED_VERSIONS);
    uint8_t sv[2] = {0x03, 0x04};
    speer_tls_w_vec_u16(&w, sv, 2);

    speer_tls_w_u16(&w, TLS_EXT_KEY_SHARE);
    size_t ks_off = speer_tls_w_save(&w);
    speer_tls_w_u16(&w, 0);
    speer_tls_w_u16(&w, TLS_GROUP_X25519);
    speer_tls_w_u16(&w, 32);
    speer_tls_w_bytes(&w, h->our_x25519_pub, 32);
    speer_tls_w_finish_vec_u16(&w, ks_off);

    if (speer_tls_w_finish_vec_u16(&w, exts_off) != 0) return -1;

    size_t hs_body_len = w.pos - hs_body_start;
    h->out_buf[1] = (uint8_t)(hs_body_len >> 16);
    h->out_buf[2] = (uint8_t)(hs_body_len >> 8);
    h->out_buf[3] = (uint8_t)hs_body_len;
    h->out_len = w.pos;

    if (append_transcript(h, TLS_HS_SERVER_HELLO, h->out_buf + 4, hs_body_len) != 0) return -1;
    return 0;
}

static int append_handshake_msg(speer_tls13_t *h, uint8_t msg_type, const uint8_t *body,
                                size_t body_len) {
    if (h->out_len + 4 + body_len > sizeof(h->out_buf)) return -1;
    h->out_buf[h->out_len++] = msg_type;
    h->out_buf[h->out_len++] = (uint8_t)(body_len >> 16);
    h->out_buf[h->out_len++] = (uint8_t)(body_len >> 8);
    h->out_buf[h->out_len++] = (uint8_t)body_len;
    if (body_len > 0) COPY(h->out_buf + h->out_len, body, body_len);
    h->out_len += body_len;
    return append_transcript(h, msg_type, body, body_len);
}

static int build_server_flight(speer_tls13_t *h) {
    if (build_server_hello(h) != 0) return -1;
    if (derive_handshake_keys(h) != 0) return -1;

    uint8_t ee_body[8];
    ee_body[0] = 0;
    ee_body[1] = 0;
    if (append_handshake_msg(h, TLS_HS_ENCRYPTED_EXTS, ee_body, 2) != 0) return -1;

    uint8_t cert_der[2500];
    size_t cert_der_len;
    if (speer_x509_libp2p_make_self_signed(cert_der, sizeof(cert_der), &cert_der_len,
                                           h->our_cert_priv, h->our_cert_pub,
                                           SPEER_LIBP2P_KEY_ED25519, h->libp2p_pub, 32,
                                           h->libp2p_priv, 32) != 0)
        return -1;
    if (cert_der_len > sizeof(h->cert_der)) return -1;
    COPY(h->cert_der, cert_der, cert_der_len);
    h->cert_der_len = cert_der_len;

    uint8_t cert_msg[3000];
    size_t cm_len = 0;
    cert_msg[cm_len++] = 0;
    size_t list_len_pos = cm_len;
    cm_len += 3;
    size_t list_start = cm_len;

    cert_msg[cm_len++] = (uint8_t)(cert_der_len >> 16);
    cert_msg[cm_len++] = (uint8_t)(cert_der_len >> 8);
    cert_msg[cm_len++] = (uint8_t)cert_der_len;
    if (cm_len + cert_der_len + 2 > sizeof(cert_msg)) return -1;
    COPY(cert_msg + cm_len, cert_der, cert_der_len);
    cm_len += cert_der_len;
    cert_msg[cm_len++] = 0;
    cert_msg[cm_len++] = 0;

    size_t list_body_len = cm_len - list_start;
    cert_msg[list_len_pos] = (uint8_t)(list_body_len >> 16);
    cert_msg[list_len_pos + 1] = (uint8_t)(list_body_len >> 8);
    cert_msg[list_len_pos + 2] = (uint8_t)list_body_len;

    if (append_handshake_msg(h, TLS_HS_CERTIFICATE, cert_msg, cm_len) != 0) return -1;

    transcript_hash(h, h->transcript_hash_after_cert);

    size_t hash_len = h->ks.suite.hash->digest_size;
    uint8_t signed_content[64 + 64 + 1 + SPEER_TLS13_MAX_HASH];
    size_t label_len = 0;
    while (CV_LABEL_SERVER[label_len]) label_len++;
    if (64 + label_len + 1 + hash_len > sizeof(signed_content)) return -1;
    memset(signed_content, 0x20, 64);
    memcpy(signed_content + 64, CV_LABEL_SERVER, label_len);
    signed_content[64 + label_len] = 0;
    memcpy(signed_content + 64 + label_len + 1, h->transcript_hash_after_cert, hash_len);
    size_t sc_len = 64 + label_len + 1 + hash_len;

    uint8_t cv_sig[64];
    speer_ed25519_sign(cv_sig, signed_content, sc_len, h->our_cert_pub, h->our_cert_priv);

    uint8_t cv_msg[80];
    size_t cv_len = 0;
    cv_msg[cv_len++] = (uint8_t)(TLS_SIGSCHEME_ED25519 >> 8);
    cv_msg[cv_len++] = (uint8_t)(TLS_SIGSCHEME_ED25519 & 0xff);
    cv_msg[cv_len++] = 0;
    cv_msg[cv_len++] = 64;
    COPY(cv_msg + cv_len, cv_sig, 64);
    cv_len += 64;
    if (append_handshake_msg(h, TLS_HS_CERT_VERIFY, cv_msg, cv_len) != 0) return -1;

    transcript_hash(h, h->transcript_hash_after_cv);

    uint8_t fin_mac[SPEER_TLS13_MAX_HASH];
    if (speer_tls13_finished_mac(&h->ks, 1, h->ks.server_handshake_traffic,
                                 h->transcript_hash_after_cv, fin_mac) != 0)
        return -1;
    if (append_handshake_msg(h, TLS_HS_FINISHED, fin_mac, hash_len) != 0) return -1;

    transcript_hash(h, h->transcript_hash_after_sfin);
    if (speer_tls13_set_master_secret(&h->ks) != 0) return -1;
    speer_tls13_application_keys(&h->ks, &h->client_app_keys, &h->server_app_keys,
                                 h->transcript_hash_after_sfin);
    return 0;
}

static int verify_certificate_verify(speer_tls13_t *h, const uint8_t *body, size_t body_len) {
    speer_tls_reader_t r;
    speer_tls_reader_init(&r, body, body_len);
    uint16_t sigalg;
    if (speer_tls_r_u16(&r, &sigalg) != 0) return -1;
    const uint8_t *sig;
    size_t sig_len;
    if (speer_tls_r_vec_u16(&r, &sig, &sig_len) != 0) return -1;
    if (r.pos != body_len) return -1;

    if (sigalg != TLS_SIGSCHEME_ED25519 && sigalg != TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256 &&
        sigalg != TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256 &&
        sigalg != TLS_SIGSCHEME_RSA_PSS_RSAE_SHA384 && sigalg != TLS_SIGSCHEME_RSA_PSS_RSAE_SHA512)
        return -1;

    if (!h->peer_cert_outer_verified) return -1;
    if (h->peer_spki_pubkey_len == 0) return -1;

    const char *label = (h->role == SPEER_TLS_ROLE_CLIENT) ? CV_LABEL_SERVER : CV_LABEL_CLIENT;
    size_t label_len = 0;
    while (label[label_len]) label_len++;
    size_t hash_len = h->ks.suite.hash->digest_size;

    uint8_t signed_content[64 + 64 + 1 + SPEER_TLS13_MAX_HASH];
    if (label_len > 64) return -1;
    if (64 + label_len + 1 + hash_len > sizeof(signed_content)) return -1;
    memset(signed_content, 0x20, 64);
    memcpy(signed_content + 64, label, label_len);
    signed_content[64 + label_len] = 0;
    memcpy(signed_content + 64 + label_len + 1, h->transcript_hash_after_cert, hash_len);
    size_t sc_len = 64 + label_len + 1 + hash_len;

    return speer_sig_verify(sigalg, h->peer_spki_pubkey, h->peer_spki_pubkey_len, signed_content,
                            sc_len, sig, sig_len);
}

static int verify_finished(speer_tls13_t *h, const uint8_t *body, size_t body_len, int from_server,
                           const uint8_t *transcript_hash_at_send) {
    size_t hash_len = h->ks.suite.hash->digest_size;
    if (body_len != hash_len) return -1;
    const uint8_t *base = from_server ? h->ks.server_handshake_traffic
                                      : h->ks.client_handshake_traffic;
    uint8_t expected[SPEER_TLS13_MAX_HASH];
    if (speer_tls13_finished_mac(&h->ks, from_server, base, transcript_hash_at_send, expected) != 0)
        return -1;
    if (!speer_ct_memeq(expected, body, hash_len)) {
        WIPE(expected, sizeof(expected));
        return -1;
    }
    WIPE(expected, sizeof(expected));
    return 0;
}

static int do_fail(speer_tls13_t *h) {
    h->state = TLS_ST_ERROR;
    return SPEER_TLS_ERR;
}

int speer_tls13_handshake_consume(speer_tls13_t *h, uint8_t msg_type, const uint8_t *body,
                                  size_t body_len) {
    if (h->state == TLS_ST_ERROR || h->state == TLS_ST_DONE) return SPEER_TLS_ERR;
    if (body_len > 0xffffff) return do_fail(h);

    switch (h->state) {
    case TLS_ST_WAIT_CH: {
        if (h->role != SPEER_TLS_ROLE_SERVER) return do_fail(h);
        if (msg_type != TLS_HS_CLIENT_HELLO) return do_fail(h);
        if (parse_client_hello(h, body, body_len) != 0) return do_fail(h);
        if (append_transcript(h, msg_type, body, body_len) != 0) return do_fail(h);
        if (build_server_flight(h) != 0) return do_fail(h);
        h->state = TLS_ST_WAIT_CFIN;
        return SPEER_TLS_NEED_OUT;
    }
    case TLS_ST_WAIT_CFIN: {
        if (h->role != SPEER_TLS_ROLE_SERVER) return do_fail(h);
        if (msg_type != TLS_HS_FINISHED) return do_fail(h);
        if (verify_finished(h, body, body_len, 0, h->transcript_hash_after_sfin) != 0)
            return do_fail(h);
        if (append_transcript(h, msg_type, body, body_len) != 0) return do_fail(h);
        h->state = TLS_ST_DONE;
        return SPEER_TLS_DONE;
    }
    case TLS_ST_WAIT_SH: {
        if (msg_type != TLS_HS_SERVER_HELLO) return do_fail(h);
        if (parse_server_hello(h, body, body_len) != 0) return do_fail(h);
        if (append_transcript(h, msg_type, body, body_len) != 0) return do_fail(h);
        if (derive_handshake_keys(h) != 0) return do_fail(h);
        h->state = TLS_ST_WAIT_EE;
        return SPEER_TLS_OK;
    }
    case TLS_ST_WAIT_EE: {
        if (msg_type != TLS_HS_ENCRYPTED_EXTS) return do_fail(h);
        if (parse_encrypted_extensions(h, body, body_len) != 0) return do_fail(h);
        if (append_transcript(h, msg_type, body, body_len) != 0) return do_fail(h);
        h->state = TLS_ST_WAIT_CERT_OR_REQ;
        return SPEER_TLS_OK;
    }
    case TLS_ST_WAIT_CERT_OR_REQ: {
        if (msg_type == TLS_HS_CERT_REQUEST) {
            if (append_transcript(h, msg_type, body, body_len) != 0) return do_fail(h);
            h->cert_request_seen = 1;
            h->state = TLS_ST_WAIT_CERT;
            return SPEER_TLS_OK;
        }
        if (msg_type != TLS_HS_CERTIFICATE) return do_fail(h);
        if (handle_certificate(h, body, body_len) != 0) return do_fail(h);
        if (append_transcript(h, msg_type, body, body_len) != 0) return do_fail(h);
        transcript_hash(h, h->transcript_hash_after_cert);
        h->state = TLS_ST_WAIT_CV;
        return SPEER_TLS_OK;
    }
    case TLS_ST_WAIT_CERT: {
        if (msg_type != TLS_HS_CERTIFICATE) return do_fail(h);
        if (handle_certificate(h, body, body_len) != 0) return do_fail(h);
        if (append_transcript(h, msg_type, body, body_len) != 0) return do_fail(h);
        transcript_hash(h, h->transcript_hash_after_cert);
        h->state = TLS_ST_WAIT_CV;
        return SPEER_TLS_OK;
    }
    case TLS_ST_WAIT_CV: {
        if (msg_type != TLS_HS_CERT_VERIFY) return do_fail(h);
        if (verify_certificate_verify(h, body, body_len) != 0) return do_fail(h);
        if (append_transcript(h, msg_type, body, body_len) != 0) return do_fail(h);
        transcript_hash(h, h->transcript_hash_after_cv);
        h->state = TLS_ST_WAIT_FINISHED;
        return SPEER_TLS_OK;
    }
    case TLS_ST_WAIT_FINISHED: {
        if (msg_type != TLS_HS_FINISHED) return do_fail(h);
        int from_server = (h->role == SPEER_TLS_ROLE_CLIENT);
        if (verify_finished(h, body, body_len, from_server, h->transcript_hash_after_cv) != 0)
            return do_fail(h);
        if (append_transcript(h, msg_type, body, body_len) != 0) return do_fail(h);
        transcript_hash(h, h->transcript_hash_after_sfin);
        if (speer_tls13_set_master_secret(&h->ks) != 0) return do_fail(h);
        speer_tls13_application_keys(&h->ks, &h->client_app_keys, &h->server_app_keys,
                                     h->transcript_hash_after_sfin);
        h->server_finished_received = 1;
        if (h->role == SPEER_TLS_ROLE_CLIENT) {
            size_t hash_len = h->ks.suite.hash->digest_size;
            uint8_t finished_mac[SPEER_TLS13_MAX_HASH];
            if (speer_tls13_finished_mac(&h->ks, 0, h->ks.client_handshake_traffic,
                                         h->transcript_hash_after_sfin, finished_mac) != 0)
                return do_fail(h);
            speer_tls_writer_t w;
            speer_tls_writer_init(&w, h->out_buf, sizeof(h->out_buf));
            if (speer_tls_w_handshake_header(&w, TLS_HS_FINISHED, hash_len) != 0) return do_fail(h);
            if (speer_tls_w_bytes(&w, finished_mac, hash_len) != 0) return do_fail(h);
            h->out_len = w.pos;
            if (append_transcript(h, TLS_HS_FINISHED, finished_mac, hash_len) != 0)
                return do_fail(h);
            h->client_finished_sent = 1;
            h->state = TLS_ST_DONE;
            return SPEER_TLS_NEED_OUT;
        }
        h->state = TLS_ST_DONE;
        return SPEER_TLS_DONE;
    }
    default:
        return do_fail(h);
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
