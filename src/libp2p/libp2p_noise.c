#include "libp2p_noise.h"

#include "speer_internal.h"

#include <string.h>

#include "aead_iface.h"
#include "ed25519.h"
#include "hash_iface.h"
#include "protobuf.h"
#include "rsa.h"

int speer_libp2p_noise_init(speer_libp2p_noise_t *n, const uint8_t static_pub[32],
                            const uint8_t static_priv[32], speer_libp2p_keytype_t kt,
                            const uint8_t *libp2p_pub, size_t libp2p_pub_len,
                            const uint8_t *libp2p_priv, size_t libp2p_priv_len) {
    ZERO(n, sizeof(*n));
    COPY(n->local_static_pub, static_pub, 32);
    COPY(n->local_static_priv, static_priv, 32);
    n->local_keytype = kt;
    if (libp2p_pub) {
        if (libp2p_pub_len > sizeof(n->local_libp2p_pub)) return -1;
        COPY(n->local_libp2p_pub, libp2p_pub, libp2p_pub_len);
        n->local_libp2p_pub_len = libp2p_pub_len;
    }
    if (libp2p_priv) {
        if (libp2p_priv_len > sizeof(n->local_libp2p_priv)) return -1;
        COPY(n->local_libp2p_priv, libp2p_priv, libp2p_priv_len);
        n->local_libp2p_priv_len = libp2p_priv_len;
    }
    return speer_noise_xx_init(&n->hs, static_pub, static_priv);
}

int speer_libp2p_noise_payload_make(uint8_t *out, size_t cap, size_t *out_len,
                                    speer_libp2p_keytype_t kt, const uint8_t *libp2p_pub,
                                    size_t libp2p_pub_len, const uint8_t *sig, size_t sig_len) {
    uint8_t pubkey_proto[256];
    size_t pubkey_proto_len = 0;
    if (speer_libp2p_pubkey_proto_encode(pubkey_proto, sizeof(pubkey_proto), kt, libp2p_pub,
                                         libp2p_pub_len, &pubkey_proto_len) != 0)
        return -1;

    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_bytes_field(&w, 1, pubkey_proto, pubkey_proto_len) != 0) return -1;
    if (speer_pb_write_bytes_field(&w, 2, sig, sig_len) != 0) return -1;
    if (out_len) *out_len = w.pos;
    return 0;
}

int speer_libp2p_noise_payload_parse(const uint8_t *in, size_t in_len, speer_libp2p_keytype_t *kt,
                                     const uint8_t **libp2p_pub, size_t *libp2p_pub_len,
                                     const uint8_t **sig, size_t *sig_len) {
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, in, in_len);
    int got_id = 0;
    int got_sig = 0;
    if (sig) *sig = NULL;
    if (sig_len) *sig_len = 0;
    while (r.pos < r.len) {
        uint32_t f, wire;
        if (speer_pb_read_tag(&r, &f, &wire) != 0) return -1;
        if (f == 1 && wire == PB_WIRE_LEN) {
            const uint8_t *d;
            size_t l;
            if (speer_pb_read_bytes(&r, &d, &l) != 0) return -1;
            if (speer_libp2p_pubkey_proto_decode(d, l, kt, libp2p_pub, libp2p_pub_len) != 0)
                return -1;
            got_id = 1;
        } else if (f == 2 && wire == PB_WIRE_LEN) {
            if (speer_pb_read_bytes(&r, sig, sig_len) != 0) return -1;
            if (!sig_len || *sig_len == 0) return -1;
            got_sig = 1;
        } else {
            if (speer_pb_skip(&r, wire) != 0) return -1;
        }
    }
    if (!got_id || !got_sig) return -1;
    return 0;
}

int speer_libp2p_noise_sign_static(uint8_t *sig_out, size_t sig_cap, size_t *sig_len,
                                   speer_libp2p_keytype_t kt, const uint8_t *libp2p_priv,
                                   size_t libp2p_priv_len, const uint8_t static_pub[32]) {
    if (kt != SPEER_LIBP2P_KEY_ED25519) return -1;
    if (sig_cap < 64) return -1;
    if (libp2p_priv_len != 32) return -1;

    uint8_t msg[256];
    size_t prefix_len = strlen(LIBP2P_NOISE_PAYLOAD_PREFIX);
    COPY(msg, LIBP2P_NOISE_PAYLOAD_PREFIX, prefix_len);
    COPY(msg + prefix_len, static_pub, 32);

    uint8_t pk[32];
    speer_ed25519_keypair(pk, (uint8_t *)libp2p_priv, libp2p_priv);
    speer_ed25519_sign(sig_out, msg, prefix_len + 32, pk, libp2p_priv);
    if (sig_len) *sig_len = 64;
    return 0;
}

static size_t der_read_len(const uint8_t *buf, size_t buf_len, size_t *pos) {
    if (*pos >= buf_len) return (size_t)-1;
    uint8_t b = buf[(*pos)++];
    if ((b & 0x80) == 0) return b;
    size_t k = b & 0x7f;
    if (k == 0 || k > 4) return (size_t)-1;
    if (*pos + k > buf_len) return (size_t)-1;
    size_t out = 0;
    for (size_t i = 0; i < k; i++) out = (out << 8) | buf[(*pos)++];
    return out;
}

static int spki_rsa_extract_n_e(const uint8_t *spki, size_t spki_len, const uint8_t **n_out,
                                size_t *n_len_out, const uint8_t **e_out, size_t *e_len_out) {
    if (spki_len < 2 || spki[0] != 0x30) return -1;
    size_t pos = 1;
    size_t outer = der_read_len(spki, spki_len, &pos);
    if (outer == (size_t)-1) return -1;
    if (outer != spki_len - pos) return -1;

    if (pos >= spki_len || spki[pos] != 0x30) return -1;
    pos++;
    size_t alg_len = der_read_len(spki, spki_len, &pos);
    if (alg_len == (size_t)-1) return -1;
    if (alg_len > spki_len - pos) return -1;
    pos += alg_len;

    if (pos >= spki_len || spki[pos] != 0x03) return -1;
    pos++;
    size_t bs_len = der_read_len(spki, spki_len, &pos);
    if (bs_len == (size_t)-1 || bs_len < 1 || bs_len > spki_len - pos) return -1;
    if (spki[pos] != 0x00) return -1;
    pos++;
    bs_len--;

    if (bs_len < 2 || spki[pos] != 0x30) return -1;
    size_t inner_start = pos;
    pos++;
    size_t inner_len = der_read_len(spki, spki_len, &pos);
    if (inner_len == (size_t)-1) return -1;
    if (inner_len > spki_len - pos) return -1;
    if ((pos - inner_start) + inner_len != bs_len) return -1;

    if (spki[pos] != 0x02) return -1;
    pos++;
    size_t nl = der_read_len(spki, spki_len, &pos);
    if (nl == (size_t)-1 || nl == 0 || nl > spki_len - pos) return -1;
    *n_out = spki + pos;
    *n_len_out = nl;
    pos += nl;

    if (pos >= spki_len || spki[pos] != 0x02) return -1;
    pos++;
    size_t el = der_read_len(spki, spki_len, &pos);
    if (el == (size_t)-1 || el == 0 || el > spki_len - pos) return -1;
    *e_out = spki + pos;
    *e_len_out = el;
    return 0;
}

int speer_libp2p_noise_verify_static(speer_libp2p_keytype_t kt, const uint8_t *libp2p_pub,
                                     size_t libp2p_pub_len, const uint8_t static_pub[32],
                                     const uint8_t *sig, size_t sig_len) {
    uint8_t msg[256];
    size_t prefix_len = strlen(LIBP2P_NOISE_PAYLOAD_PREFIX);
    if (prefix_len + 32 > sizeof(msg)) return -1;
    COPY(msg, LIBP2P_NOISE_PAYLOAD_PREFIX, prefix_len);
    COPY(msg + prefix_len, static_pub, 32);

    if (kt == SPEER_LIBP2P_KEY_ED25519) {
        if (libp2p_pub_len != 32) return -1;
        if (sig_len != 64) return -1;
        return speer_ed25519_verify(sig, msg, prefix_len + 32, libp2p_pub);
    }
    if (kt == SPEER_LIBP2P_KEY_RSA) {
        /* Reject obviously bogus shapes early. RSA-2048 sigs are 256 bytes;
         * we accept up to RSA-8192 = 1024 bytes. SPKIs smaller than ~200
         * bytes can't carry a real RSA-2048 modulus. */
        if (libp2p_pub_len < 200 || libp2p_pub_len > SPEER_LIBP2P_PUBKEY_MAX) return -1;
        if (sig_len < 256 || sig_len > 1024) return -1;
        const uint8_t *n;
        size_t n_len;
        const uint8_t *e;
        size_t e_len;
        if (spki_rsa_extract_n_e(libp2p_pub, libp2p_pub_len, &n, &n_len, &e, &e_len) != 0)
            return -1;
        /* Strip a possible leading 0x00 sign byte from the DER INTEGER n. */
        if (n_len > 1 && n[0] == 0x00) {
            n++;
            n_len--;
        }
        /* Reject anything smaller than RSA-2048 (256 bytes of modulus). */
        if (n_len < 256) return -1;
        /* go-libp2p / rust-libp2p sign with RSA-PKCS#1-v1.5 over SHA-256. */
        uint8_t h[32];
        speer_sha256(h, msg, prefix_len + 32);
        return speer_rsa_pkcs1_v15_verify(n, n_len, e, e_len, &speer_hash_sha256, h, sizeof(h), sig,
                                          sig_len);
    }
    /* secp256k1 / ECDSA-P256 not implemented yet. */
    return -1;
}

int speer_libp2p_noise_seal(speer_libp2p_noise_t *n, const uint8_t *plaintext, size_t pt_len,
                            uint8_t *out_ct, size_t *out_ct_len) {
    uint8_t nonce[12] = {0};
    STORE64_LE(nonce + 4, n->send_nonce);
    uint8_t tag[16];
    if (speer_aead_chacha20_poly1305.seal(n->send_key, nonce, NULL, 0, plaintext, pt_len, out_ct,
                                          tag) != 0)
        return -1;
    COPY(out_ct + pt_len, tag, 16);
    if (out_ct_len) *out_ct_len = pt_len + 16;
    n->send_nonce++;
    return 0;
}

int speer_libp2p_noise_open(speer_libp2p_noise_t *n, const uint8_t *ct, size_t ct_len,
                            uint8_t *out_pt, size_t *out_pt_len) {
    if (ct_len < 16) return -1;
    uint8_t nonce[12] = {0};
    STORE64_LE(nonce + 4, n->recv_nonce);
    if (speer_aead_chacha20_poly1305.open(n->recv_key, nonce, NULL, 0, ct, ct_len - 16,
                                          ct + ct_len - 16, out_pt) != 0)
        return -1;
    if (out_pt_len) *out_pt_len = ct_len - 16;
    n->recv_nonce++;
    return 0;
}
