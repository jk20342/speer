#ifndef SPEER_PEER_ID_H
#define SPEER_PEER_ID_H

#include <stddef.h>
#include <stdint.h>

#define SPEER_PEERID_MAX_BYTES 64

typedef enum {
    SPEER_LIBP2P_KEY_RSA = 0,
    SPEER_LIBP2P_KEY_ED25519 = 1,
    SPEER_LIBP2P_KEY_SECP256K1 = 2,
    SPEER_LIBP2P_KEY_ECDSA = 3,
} speer_libp2p_keytype_t;

int speer_libp2p_pubkey_proto_encode(uint8_t *out, size_t cap, speer_libp2p_keytype_t kt,
                                     const uint8_t *key, size_t key_len, size_t *out_len);
int speer_libp2p_pubkey_proto_decode(const uint8_t *in, size_t in_len, speer_libp2p_keytype_t *kt,
                                     const uint8_t **key, size_t *key_len);

int speer_peer_id_from_pubkey_bytes(uint8_t *out, size_t out_cap, const uint8_t *pubkey_proto,
                                    size_t pubkey_proto_len, size_t *out_len);
int speer_peer_id_to_b58(char *out, size_t out_cap, const uint8_t *peer_id, size_t peer_id_len);

#endif
