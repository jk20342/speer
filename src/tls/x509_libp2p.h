#ifndef SPEER_X509_LIBP2P_H
#define SPEER_X509_LIBP2P_H

#include <stddef.h>
#include <stdint.h>

#include "peer_id.h"

#define LIBP2P_TLS_EXT_OID_BYTES "\x2b\x06\x01\x04\x01\x83\xa2\x5a\x01\x01"
#define LIBP2P_TLS_EXT_OID_LEN   10

#define LIBP2P_TLS_SIG_PREFIX    "libp2p-tls-handshake:"

typedef struct {
    speer_libp2p_keytype_t keytype;
    uint8_t libp2p_pub[64];
    size_t libp2p_pub_len;
    uint8_t libp2p_signature[256];
    size_t libp2p_signature_len;
    uint8_t cert_pubkey_spki[256];
    size_t cert_pubkey_spki_len;
    uint16_t cert_sig_alg;
    uint8_t cert_signature[512];
    size_t cert_signature_len;
} speer_x509_libp2p_t;

int speer_x509_libp2p_parse(speer_x509_libp2p_t *out, const uint8_t *der, size_t der_len);

int speer_x509_libp2p_verify(const speer_x509_libp2p_t *parsed);

int speer_x509_libp2p_make_self_signed(uint8_t *out, size_t cap, size_t *out_len,
                                       const uint8_t cert_priv_key[32],
                                       const uint8_t cert_pub_key[32],
                                       speer_libp2p_keytype_t libp2p_kt, const uint8_t *libp2p_pub,
                                       size_t libp2p_pub_len, const uint8_t *libp2p_priv,
                                       size_t libp2p_priv_len);

#endif
