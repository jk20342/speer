#ifndef SPEER_LIBP2P_NOISE_H
#define SPEER_LIBP2P_NOISE_H

#include "speer_internal.h"

#include <stddef.h>
#include <stdint.h>

#include "peer_id.h"

#define LIBP2P_NOISE_PROTOCOL       "/noise"
#define LIBP2P_NOISE_PAYLOAD_PREFIX "noise-libp2p-static-key:"

typedef struct {
    speer_handshake_t hs;
    uint8_t local_static_pub[32];
    uint8_t local_static_priv[32];
    uint8_t local_libp2p_pub[64];
    size_t local_libp2p_pub_len;
    uint8_t local_libp2p_priv[64];
    size_t local_libp2p_priv_len;
    speer_libp2p_keytype_t local_keytype;

    uint8_t remote_static_pub[32];
    uint8_t remote_libp2p_pub[64];
    size_t remote_libp2p_pub_len;
    speer_libp2p_keytype_t remote_keytype;

    uint8_t send_key[32];
    uint8_t recv_key[32];
    uint64_t send_nonce;
    uint64_t recv_nonce;
} speer_libp2p_noise_t;

int speer_libp2p_noise_init(speer_libp2p_noise_t *n, const uint8_t static_pub[32],
                            const uint8_t static_priv[32], speer_libp2p_keytype_t libp2p_keytype,
                            const uint8_t *libp2p_pub, size_t libp2p_pub_len,
                            const uint8_t *libp2p_priv, size_t libp2p_priv_len);

int speer_libp2p_noise_payload_make(uint8_t *out, size_t cap, size_t *out_len,
                                    speer_libp2p_keytype_t kt, const uint8_t *libp2p_pub,
                                    size_t libp2p_pub_len, const uint8_t *sig, size_t sig_len);

int speer_libp2p_noise_payload_parse(const uint8_t *in, size_t in_len, speer_libp2p_keytype_t *kt,
                                     const uint8_t **libp2p_pub, size_t *libp2p_pub_len,
                                     const uint8_t **sig, size_t *sig_len);

int speer_libp2p_noise_sign_static(uint8_t *sig_out, size_t sig_cap, size_t *sig_len,
                                   speer_libp2p_keytype_t kt, const uint8_t *libp2p_priv,
                                   size_t libp2p_priv_len, const uint8_t static_pub[32]);

int speer_libp2p_noise_verify_static(speer_libp2p_keytype_t kt, const uint8_t *libp2p_pub,
                                     size_t libp2p_pub_len, const uint8_t static_pub[32],
                                     const uint8_t *sig, size_t sig_len);

int speer_libp2p_noise_seal(speer_libp2p_noise_t *n, const uint8_t *plaintext, size_t pt_len,
                            uint8_t *out_ct, size_t *out_ct_len);
int speer_libp2p_noise_open(speer_libp2p_noise_t *n, const uint8_t *ct, size_t ct_len,
                            uint8_t *out_pt, size_t *out_pt_len);

#endif
