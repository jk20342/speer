#include "x509_libp2p.h"

#include "speer_internal.h"

#include "asn1.h"
#include "ed25519.h"
#include "peer_id.h"
#include "sig_dispatch.h"

static int find_libp2p_ext(const speer_asn1_t *tbs, const uint8_t **ext_value, size_t *ext_len) {
    const uint8_t *c;
    const uint8_t *e;
    if (speer_asn1_seq_iter_init(tbs, &c, &e) != 0) return -1;

    speer_asn1_t node;
    if (speer_asn1_seq_next(&c, e, &node) != 0) return -1;
    if (node.tag == 0xa0) {
        if (speer_asn1_seq_next(&c, e, &node) != 0) return -1;
    }
    if (speer_asn1_seq_next(&c, e, &node) != 0) return -1;
    if (speer_asn1_seq_next(&c, e, &node) != 0) return -1;
    if (speer_asn1_seq_next(&c, e, &node) != 0) return -1;
    if (speer_asn1_seq_next(&c, e, &node) != 0) return -1;
    if (speer_asn1_seq_next(&c, e, &node) != 0) return -1;

    while (c < e) {
        if (speer_asn1_seq_next(&c, e, &node) != 0) return -1;
        if (node.tag == 0xa3) {
            speer_asn1_t exts_seq;
            if (speer_asn1_parse(node.value, node.value_len, &exts_seq) != 0) return -1;
            const uint8_t *ec;
            const uint8_t *ee;
            if (speer_asn1_seq_iter_init(&exts_seq, &ec, &ee) != 0) return -1;
            while (ec < ee) {
                speer_asn1_t ext;
                if (speer_asn1_seq_next(&ec, ee, &ext) != 0) return -1;
                const uint8_t *xc;
                const uint8_t *xe;
                if (speer_asn1_seq_iter_init(&ext, &xc, &xe) != 0) continue;
                speer_asn1_t oid;
                if (speer_asn1_seq_next(&xc, xe, &oid) != 0) continue;
                if (!speer_asn1_oid_eq(&oid, (const uint8_t *)LIBP2P_TLS_EXT_OID_BYTES,
                                       LIBP2P_TLS_EXT_OID_LEN))
                    continue;

                speer_asn1_t maybe;
                if (speer_asn1_seq_next(&xc, xe, &maybe) != 0) continue;
                if (maybe.tag == ASN1_BOOLEAN) {
                    if (speer_asn1_seq_next(&xc, xe, &maybe) != 0) continue;
                }
                if (maybe.tag != ASN1_OCTET_STRING) continue;
                *ext_value = maybe.value;
                *ext_len = maybe.value_len;
                return 0;
            }
            return -1;
        }
    }
    return -1;
}

static int parse_signed_libp2p_key(const uint8_t *in, size_t in_len, speer_x509_libp2p_t *out) {
    speer_asn1_t seq;
    if (speer_asn1_parse(in, in_len, &seq) != 0) return -1;
    if (seq.tag != ASN1_SEQUENCE) return -1;
    const uint8_t *c;
    const uint8_t *e;
    if (speer_asn1_seq_iter_init(&seq, &c, &e) != 0) return -1;

    speer_asn1_t pkey, sig;
    if (speer_asn1_seq_next(&c, e, &pkey) != 0) return -1;
    if (speer_asn1_seq_next(&c, e, &sig) != 0) return -1;
    if (pkey.tag != ASN1_OCTET_STRING || sig.tag != ASN1_OCTET_STRING) return -1;

    if (speer_libp2p_pubkey_proto_decode(pkey.value, pkey.value_len, &out->keytype,
                                         (const uint8_t **)&pkey.value, &pkey.value_len) != 0)
        return -1;
    if (pkey.value_len > sizeof(out->libp2p_pub)) return -1;
    COPY(out->libp2p_pub, pkey.value, pkey.value_len);
    out->libp2p_pub_len = pkey.value_len;

    if (sig.value_len > sizeof(out->libp2p_signature)) return -1;
    COPY(out->libp2p_signature, sig.value, sig.value_len);
    out->libp2p_signature_len = sig.value_len;
    return 0;
}

int speer_x509_libp2p_parse(speer_x509_libp2p_t *out, const uint8_t *der, size_t der_len) {
    ZERO(out, sizeof(*out));
    speer_asn1_t cert;
    if (speer_asn1_parse(der, der_len, &cert) != 0) return -1;
    if (cert.tag != ASN1_SEQUENCE) return -1;

    const uint8_t *cc;
    const uint8_t *ce;
    if (speer_asn1_seq_iter_init(&cert, &cc, &ce) != 0) return -1;

    speer_asn1_t tbs;
    if (speer_asn1_seq_next(&cc, ce, &tbs) != 0) return -1;
    if (tbs.tag != ASN1_SEQUENCE) return -1;

    const uint8_t *tc;
    const uint8_t *te;
    if (speer_asn1_seq_iter_init(&tbs, &tc, &te) != 0) return -1;

    speer_asn1_t node;
    if (speer_asn1_seq_next(&tc, te, &node) != 0) return -1;
    if (node.tag == 0xa0) {
        if (speer_asn1_seq_next(&tc, te, &node) != 0) return -1;
    }
    if (speer_asn1_seq_next(&tc, te, &node) != 0) return -1;
    if (speer_asn1_seq_next(&tc, te, &node) != 0) return -1;
    if (speer_asn1_seq_next(&tc, te, &node) != 0) return -1;
    if (speer_asn1_seq_next(&tc, te, &node) != 0) return -1;

    speer_asn1_t spki;
    if (speer_asn1_seq_next(&tc, te, &spki) != 0) return -1;
    if (spki.tag != ASN1_SEQUENCE) return -1;
    if (spki.tlv_total_len > sizeof(out->cert_pubkey_spki)) return -1;
    COPY(out->cert_pubkey_spki, spki.tlv_start, spki.tlv_total_len);
    out->cert_pubkey_spki_len = spki.tlv_total_len;

    speer_asn1_t sig_alg, sig_value;
    if (speer_asn1_seq_next(&cc, ce, &sig_alg) != 0) return -1;
    if (speer_asn1_seq_next(&cc, ce, &sig_value) != 0) return -1;
    if (sig_value.tag != ASN1_BIT_STRING) return -1;
    if (sig_value.value_len < 1) return -1;
    if (sig_value.value_len - 1 > sizeof(out->cert_signature)) return -1;
    COPY(out->cert_signature, sig_value.value + 1, sig_value.value_len - 1);
    out->cert_signature_len = sig_value.value_len - 1;

    const uint8_t *ext_value;
    size_t ext_len;
    if (find_libp2p_ext(&tbs, &ext_value, &ext_len) != 0) return -1;
    if (parse_signed_libp2p_key(ext_value, ext_len, out) != 0) return -1;
    return 0;
}

int speer_x509_libp2p_verify(const speer_x509_libp2p_t *p) {
    uint8_t msg[1024];
    size_t prefix_len = 0;
    while (LIBP2P_TLS_SIG_PREFIX[prefix_len]) prefix_len++;
    if (prefix_len + p->cert_pubkey_spki_len > sizeof(msg)) return -1;
    COPY(msg, LIBP2P_TLS_SIG_PREFIX, prefix_len);
    COPY(msg + prefix_len, p->cert_pubkey_spki, p->cert_pubkey_spki_len);

    if (p->keytype != SPEER_LIBP2P_KEY_ED25519) return -1;
    if (p->libp2p_pub_len != 32) return -1;
    if (p->libp2p_signature_len != 64) return -1;
    return speer_ed25519_verify(p->libp2p_signature, msg, prefix_len + p->cert_pubkey_spki_len,
                                p->libp2p_pub);
}

static size_t put_len(uint8_t *out, size_t len) {
    if (len < 128) {
        out[0] = (uint8_t)len;
        return 1;
    }
    if (len < 256) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)len;
    return 3;
}

static size_t emit_tlv(uint8_t *out, uint8_t tag, const uint8_t *val, size_t val_len) {
    out[0] = tag;
    size_t n = put_len(out + 1, val_len);
    if (val_len > 0) COPY(out + 1 + n, val, val_len);
    return 1 + n + val_len;
}

static const uint8_t ED25519_ALG_ID[] = {0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70};

int speer_x509_libp2p_make_self_signed(uint8_t *out, size_t cap, size_t *out_len,
                                       const uint8_t cert_priv_key[32],
                                       const uint8_t cert_pub_key[32],
                                       speer_libp2p_keytype_t libp2p_kt, const uint8_t *libp2p_pub,
                                       size_t libp2p_pub_len, const uint8_t *libp2p_priv,
                                       size_t libp2p_priv_len) {
    if (libp2p_kt != SPEER_LIBP2P_KEY_ED25519) return -1;
    if (libp2p_pub_len != 32 || libp2p_priv_len != 32) return -1;
    if (!out || !out_len || !cert_priv_key || !cert_pub_key) return -1;

    uint8_t spki[64];
    size_t spki_len = 0;
    spki[spki_len++] = 0x30;
    spki[spki_len++] = 42;
    COPY(spki + spki_len, ED25519_ALG_ID, sizeof(ED25519_ALG_ID));
    spki_len += sizeof(ED25519_ALG_ID);
    spki[spki_len++] = 0x03;
    spki[spki_len++] = 33;
    spki[spki_len++] = 0x00;
    COPY(spki + spki_len, cert_pub_key, 32);
    spki_len += 32;

    size_t prefix_len = 0;
    while (LIBP2P_TLS_SIG_PREFIX[prefix_len]) prefix_len++;
    uint8_t signed_msg[256];
    if (prefix_len + spki_len > sizeof(signed_msg)) return -1;
    COPY(signed_msg, LIBP2P_TLS_SIG_PREFIX, prefix_len);
    COPY(signed_msg + prefix_len, spki, spki_len);
    uint8_t libp2p_sig[64];
    speer_ed25519_sign(libp2p_sig, signed_msg, prefix_len + spki_len, libp2p_pub, libp2p_priv);

    uint8_t pubkey_proto[256];
    size_t pubkey_proto_len;
    if (speer_libp2p_pubkey_proto_encode(pubkey_proto, sizeof(pubkey_proto), libp2p_kt, libp2p_pub,
                                         libp2p_pub_len, &pubkey_proto_len) != 0)
        return -1;

    uint8_t ext_seq[600];
    size_t ext_seq_len = 0;
    if (pubkey_proto_len > 250 || ext_seq_len + 2 + pubkey_proto_len > sizeof(ext_seq)) return -1;
    ext_seq_len += emit_tlv(ext_seq + ext_seq_len, ASN1_OCTET_STRING, pubkey_proto,
                            pubkey_proto_len);
    ext_seq_len += emit_tlv(ext_seq + ext_seq_len, ASN1_OCTET_STRING, libp2p_sig, 64);

    uint8_t ext_seq_wrapped[700];
    size_t ext_seq_wrapped_len = emit_tlv(ext_seq_wrapped, ASN1_SEQUENCE, ext_seq, ext_seq_len);

    uint8_t libp2p_ext[800];
    size_t libp2p_ext_len = 0;
    libp2p_ext[libp2p_ext_len++] = 0x30;
    size_t ext_inner_len_pos = libp2p_ext_len;
    libp2p_ext_len += 3;
    size_t ext_inner_start = libp2p_ext_len;

    libp2p_ext[libp2p_ext_len++] = 0x06;
    libp2p_ext[libp2p_ext_len++] = LIBP2P_TLS_EXT_OID_LEN;
    COPY(libp2p_ext + libp2p_ext_len, LIBP2P_TLS_EXT_OID_BYTES, LIBP2P_TLS_EXT_OID_LEN);
    libp2p_ext_len += LIBP2P_TLS_EXT_OID_LEN;
    libp2p_ext_len += emit_tlv(libp2p_ext + libp2p_ext_len, ASN1_OCTET_STRING, ext_seq_wrapped,
                               ext_seq_wrapped_len);

    size_t ext_inner_len = libp2p_ext_len - ext_inner_start;
    libp2p_ext[ext_inner_len_pos] = 0x82;
    libp2p_ext[ext_inner_len_pos + 1] = (uint8_t)(ext_inner_len >> 8);
    libp2p_ext[ext_inner_len_pos + 2] = (uint8_t)ext_inner_len;

    uint8_t exts_seq[1024];
    size_t exts_seq_len = emit_tlv(exts_seq, ASN1_SEQUENCE, libp2p_ext, libp2p_ext_len);
    uint8_t exts_a3[1100];
    size_t exts_a3_len = emit_tlv(exts_a3, 0xa3, exts_seq, exts_seq_len);

    uint8_t tbs_body[2048];
    size_t tbs_body_len = 0;
    static const uint8_t version_v3[] = {0xa0, 0x03, 0x02, 0x01, 0x02};
    if (tbs_body_len + sizeof(version_v3) > sizeof(tbs_body)) return -1;
    COPY(tbs_body + tbs_body_len, version_v3, sizeof(version_v3));
    tbs_body_len += sizeof(version_v3);

    static const uint8_t serial[] = {0x02, 0x01, 0x01};
    if (tbs_body_len + sizeof(serial) > sizeof(tbs_body)) return -1;
    COPY(tbs_body + tbs_body_len, serial, sizeof(serial));
    tbs_body_len += sizeof(serial);

    if (tbs_body_len + sizeof(ED25519_ALG_ID) > sizeof(tbs_body)) return -1;
    COPY(tbs_body + tbs_body_len, ED25519_ALG_ID, sizeof(ED25519_ALG_ID));
    tbs_body_len += sizeof(ED25519_ALG_ID);

    static const uint8_t empty_seq[] = {0x30, 0x00};
    if (tbs_body_len + sizeof(empty_seq) > sizeof(tbs_body)) return -1;
    COPY(tbs_body + tbs_body_len, empty_seq, sizeof(empty_seq));
    tbs_body_len += sizeof(empty_seq);

    static const uint8_t validity[] = {0x30, 0x1e, 0x17, 0x0d, '2', '6', '0',  '1',  '0', '1', '0',
                                       '0',  '0',  '0',  '0',  '0', 'Z', 0x17, 0x0d, '4', '9', '0',
                                       '1',  '0',  '1',  '0',  '0', '0', '0',  '0',  '0', 'Z'};
    if (tbs_body_len + sizeof(validity) > sizeof(tbs_body)) return -1;
    COPY(tbs_body + tbs_body_len, validity, sizeof(validity));
    tbs_body_len += sizeof(validity);

    if (tbs_body_len + sizeof(empty_seq) > sizeof(tbs_body)) return -1;
    COPY(tbs_body + tbs_body_len, empty_seq, sizeof(empty_seq));
    tbs_body_len += sizeof(empty_seq);

    if (tbs_body_len + spki_len > sizeof(tbs_body)) return -1;
    COPY(tbs_body + tbs_body_len, spki, spki_len);
    tbs_body_len += spki_len;

    if (tbs_body_len + exts_a3_len > sizeof(tbs_body)) return -1;
    COPY(tbs_body + tbs_body_len, exts_a3, exts_a3_len);
    tbs_body_len += exts_a3_len;

    uint8_t tbs[2200];
    size_t tbs_len = emit_tlv(tbs, ASN1_SEQUENCE, tbs_body, tbs_body_len);

    uint8_t cert_sig[64];
    speer_ed25519_sign(cert_sig, tbs, tbs_len, cert_pub_key, cert_priv_key);

    uint8_t cert_body[2400];
    size_t cert_body_len = 0;
    if (cert_body_len + tbs_len > sizeof(cert_body)) return -1;
    COPY(cert_body + cert_body_len, tbs, tbs_len);
    cert_body_len += tbs_len;
    if (cert_body_len + sizeof(ED25519_ALG_ID) > sizeof(cert_body)) return -1;
    COPY(cert_body + cert_body_len, ED25519_ALG_ID, sizeof(ED25519_ALG_ID));
    cert_body_len += sizeof(ED25519_ALG_ID);

    uint8_t sig_bs[67];
    sig_bs[0] = 0x03;
    sig_bs[1] = 65;
    sig_bs[2] = 0x00;
    COPY(sig_bs + 3, cert_sig, 64);
    if (cert_body_len + sizeof(sig_bs) > sizeof(cert_body)) return -1;
    COPY(cert_body + cert_body_len, sig_bs, sizeof(sig_bs));
    cert_body_len += sizeof(sig_bs);

    uint8_t cert[2500];
    size_t cert_len = emit_tlv(cert, ASN1_SEQUENCE, cert_body, cert_body_len);
    if (cert_len > cap) return -1;
    COPY(out, cert, cert_len);
    *out_len = cert_len;
    return 0;
}
