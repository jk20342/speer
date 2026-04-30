#include "libp2p_noise.h"

#include "speer_internal.h"

#include <string.h>

#include "aead_iface.h"
#include "ed25519.h"
#include "protobuf.h"

int speer_libp2p_noise_init(speer_libp2p_noise_t *n, const uint8_t static_pub[32],
                            const uint8_t static_priv[32], speer_libp2p_keytype_t kt,
                            const uint8_t *libp2p_pub, size_t libp2p_pub_len,
                            const uint8_t *libp2p_priv, size_t libp2p_priv_len) {
    ZERO(n, sizeof(*n));
    COPY(n->local_static_pub, static_pub, 32);
    COPY(n->local_static_priv, static_priv, 32);
    n->local_keytype = kt;
    if (libp2p_pub && libp2p_pub_len <= sizeof(n->local_libp2p_pub)) {
        COPY(n->local_libp2p_pub, libp2p_pub, libp2p_pub_len);
        n->local_libp2p_pub_len = libp2p_pub_len;
    }
    if (libp2p_priv && libp2p_priv_len <= sizeof(n->local_libp2p_priv)) {
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
        } else {
            if (speer_pb_skip(&r, wire) != 0) return -1;
        }
    }
    return got_id ? 0 : -1;
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

int speer_libp2p_noise_verify_static(speer_libp2p_keytype_t kt, const uint8_t *libp2p_pub,
                                     size_t libp2p_pub_len, const uint8_t static_pub[32],
                                     const uint8_t *sig, size_t sig_len) {
    if (kt != SPEER_LIBP2P_KEY_ED25519) return -1;
    if (libp2p_pub_len != 32) return -1;
    if (sig_len != 64) return -1;

    uint8_t msg[256];
    size_t prefix_len = strlen(LIBP2P_NOISE_PAYLOAD_PREFIX);
    COPY(msg, LIBP2P_NOISE_PAYLOAD_PREFIX, prefix_len);
    COPY(msg + prefix_len, static_pub, 32);
    return speer_ed25519_verify(sig, msg, prefix_len + 32, libp2p_pub);
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
