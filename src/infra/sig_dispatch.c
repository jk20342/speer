#include "sig_dispatch.h"

#include "speer_internal.h"

#include "ecdsa_p256.h"
#include "ed25519.h"
#include "hash_iface.h"
#include "rsa.h"

static int parse_ecdsa_der(const uint8_t *sig, size_t sig_len, const uint8_t **r_out, size_t *r_len,
                           const uint8_t **s_out, size_t *s_len) {
    if (sig_len < 8) return -1;
    if (sig[0] != 0x30) return -1;
    size_t pos = 1;
    size_t total_len;
    if (sig[pos] & 0x80) {
        size_t n = sig[pos] & 0x7f;
        if (n != 1 || pos + 1 + n > sig_len) return -1;
        total_len = sig[pos + 1];
        pos += 2;
    } else {
        total_len = sig[pos];
        pos += 1;
    }
    if (pos + total_len > sig_len) return -1;

    if (sig[pos] != 0x02) return -1;
    size_t r_l = sig[pos + 1];
    if (pos + 2 + r_l > sig_len) return -1;
    const uint8_t *rp = sig + pos + 2;
    while (r_l > 0 && *rp == 0) {
        rp++;
        r_l--;
    }

    pos += 2 + sig[pos + 1];
    if (sig[pos] != 0x02) return -1;
    size_t s_l = sig[pos + 1];
    if (pos + 2 + s_l > sig_len) return -1;
    const uint8_t *sp = sig + pos + 2;
    while (s_l > 0 && *sp == 0) {
        sp++;
        s_l--;
    }

    *r_out = rp;
    *r_len = r_l;
    *s_out = sp;
    *s_len = s_l;
    return 0;
}

int speer_sig_verify(uint16_t alg_id, const uint8_t *pubkey, size_t pubkey_len, const uint8_t *msg,
                     size_t msg_len, const uint8_t *sig, size_t sig_len) {
    switch (alg_id) {
    case TLS_SIGSCHEME_ED25519: {
        if (pubkey_len != 32 || sig_len != 64) return -1;
        return speer_ed25519_verify(sig, msg, msg_len, pubkey);
    }
    case TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256: {
        if (pubkey_len < 64) return -1;
        const uint8_t *pk = pubkey;
        if (pubkey_len == 65 && pubkey[0] == 0x04) pk = pubkey + 1;
        uint8_t h[32];
        speer_sha256(h, msg, msg_len);
        const uint8_t *r;
        size_t rl;
        const uint8_t *s;
        size_t sl;
        if (parse_ecdsa_der(sig, sig_len, &r, &rl, &s, &sl) != 0) return -1;
        return speer_ecdsa_p256_verify(pk, h, 32, r, rl, s, sl);
    }
    case TLS_SIGSCHEME_RSA_PKCS1_SHA256:
    case TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256: {
        uint8_t h[32];
        speer_sha256(h, msg, msg_len);
        return speer_sig_verify_prehashed(alg_id, pubkey, pubkey_len, h, 32, sig, sig_len);
    }
    case TLS_SIGSCHEME_RSA_PKCS1_SHA384:
    case TLS_SIGSCHEME_RSA_PSS_RSAE_SHA384: {
        uint8_t h[48];
        speer_sha384(h, msg, msg_len);
        return speer_sig_verify_prehashed(alg_id, pubkey, pubkey_len, h, 48, sig, sig_len);
    }
    case TLS_SIGSCHEME_RSA_PKCS1_SHA512:
    case TLS_SIGSCHEME_RSA_PSS_RSAE_SHA512: {
        uint8_t h[64];
        speer_sha512(h, msg, msg_len);
        return speer_sig_verify_prehashed(alg_id, pubkey, pubkey_len, h, 64, sig, sig_len);
    }
    default:
        return -1;
    }
}

static int parse_rsa_pubkey(const uint8_t *spki, size_t spki_len, const uint8_t **n, size_t *n_len,
                            const uint8_t **e, size_t *e_len) {
    if (spki_len < 4 || spki[0] != 0x30) return -1;
    size_t pos = 1;
    size_t seq_len;
    if (pos >= spki_len) return -1;
    if (spki[pos] & 0x80) {
        size_t k = spki[pos] & 0x7f;
        if (k == 0 || k > 4) return -1;
        if (k > spki_len - pos - 1) return -1;
        seq_len = 0;
        for (size_t i = 0; i < k; i++) seq_len = (seq_len << 8) | spki[pos + 1 + i];
        pos += 1 + k;
    } else {
        seq_len = spki[pos];
        pos += 1;
    }
    if (seq_len > spki_len - pos) return -1;

    if (pos >= spki_len || spki[pos] != 0x02) return -1;
    pos++;
    if (pos >= spki_len) return -1;
    size_t nl;
    if (spki[pos] & 0x80) {
        size_t k = spki[pos] & 0x7f;
        if (k == 0 || k > 4) return -1;
        if (k > spki_len - pos - 1) return -1;
        nl = 0;
        for (size_t i = 0; i < k; i++) nl = (nl << 8) | spki[pos + 1 + i];
        pos += 1 + k;
    } else {
        nl = spki[pos];
        pos++;
    }
    if (nl > spki_len - pos) return -1;
    *n = spki + pos;
    *n_len = nl;
    pos += nl;

    if (pos >= spki_len || spki[pos] != 0x02) return -1;
    pos++;
    if (pos >= spki_len) return -1;
    size_t el;
    if (spki[pos] & 0x80) {
        size_t k = spki[pos] & 0x7f;
        if (k == 0 || k > 4) return -1;
        if (k > spki_len - pos - 1) return -1;
        el = 0;
        for (size_t i = 0; i < k; i++) el = (el << 8) | spki[pos + 1 + i];
        pos += 1 + k;
    } else {
        el = spki[pos];
        pos++;
    }
    if (el > spki_len - pos) return -1;
    *e = spki + pos;
    *e_len = el;
    return 0;
}

int speer_sig_verify_prehashed(uint16_t alg_id, const uint8_t *pubkey, size_t pubkey_len,
                               const uint8_t *msg_hash, size_t msg_hash_len, const uint8_t *sig,
                               size_t sig_len) {
    const speer_hash_iface_t *h = NULL;
    switch (alg_id) {
    case TLS_SIGSCHEME_RSA_PKCS1_SHA256:
    case TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256:
        h = &speer_hash_sha256;
        break;
    case TLS_SIGSCHEME_RSA_PKCS1_SHA384:
    case TLS_SIGSCHEME_RSA_PSS_RSAE_SHA384:
        h = &speer_hash_sha384;
        break;
    case TLS_SIGSCHEME_RSA_PKCS1_SHA512:
    case TLS_SIGSCHEME_RSA_PSS_RSAE_SHA512:
        h = &speer_hash_sha512;
        break;
    case TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256: {
        const uint8_t *pk = pubkey;
        if (pubkey_len == 65 && pubkey[0] == 0x04) pk = pubkey + 1;
        const uint8_t *r;
        size_t rl;
        const uint8_t *s;
        size_t sl;
        if (parse_ecdsa_der(sig, sig_len, &r, &rl, &s, &sl) != 0) return -1;
        return speer_ecdsa_p256_verify(pk, msg_hash, msg_hash_len, r, rl, s, sl);
    }
    case TLS_SIGSCHEME_ED25519:
        return -1;
    default:
        return -1;
    }
    const uint8_t *n;
    size_t n_len;
    const uint8_t *e;
    size_t e_len;
    if (parse_rsa_pubkey(pubkey, pubkey_len, &n, &n_len, &e, &e_len) != 0) return -1;
    int is_pss = (alg_id == TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256 ||
                  alg_id == TLS_SIGSCHEME_RSA_PSS_RSAE_SHA384 ||
                  alg_id == TLS_SIGSCHEME_RSA_PSS_RSAE_SHA512);
    if (is_pss) {
        return speer_rsa_pss_verify(n, n_len, e, e_len, h, msg_hash, msg_hash_len, sig, sig_len,
                                    h->digest_size);
    } else {
        return speer_rsa_pkcs1_v15_verify(n, n_len, e, e_len, h, msg_hash, msg_hash_len, sig,
                                          sig_len);
    }
}
