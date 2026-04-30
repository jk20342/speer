#ifndef SPEER_TLS13_KEYSCHED_H
#define SPEER_TLS13_KEYSCHED_H

#include <stddef.h>
#include <stdint.h>

#include "aead_iface.h"
#include "hash_iface.h"

#define SPEER_TLS13_MAX_HASH 64

typedef struct {
    const speer_hash_iface_t *hash;
    const speer_aead_iface_t *aead;
    size_t key_len;
    size_t iv_len;
    size_t hp_len;
} speer_tls13_suite_t;

typedef struct {
    uint8_t key[32];
    uint8_t iv[12];
    uint8_t hp[32];
} speer_tls13_keys_t;

typedef struct {
    speer_tls13_suite_t suite;
    uint8_t early_secret[SPEER_TLS13_MAX_HASH];
    uint8_t handshake_secret[SPEER_TLS13_MAX_HASH];
    uint8_t master_secret[SPEER_TLS13_MAX_HASH];
    uint8_t client_handshake_traffic[SPEER_TLS13_MAX_HASH];
    uint8_t server_handshake_traffic[SPEER_TLS13_MAX_HASH];
    uint8_t client_application_traffic[SPEER_TLS13_MAX_HASH];
    uint8_t server_application_traffic[SPEER_TLS13_MAX_HASH];
} speer_tls13_keysched_t;

int speer_tls13_suite_init(speer_tls13_suite_t *s, uint16_t cipher_suite);

int speer_tls13_derive_secret(uint8_t *out, const speer_tls13_suite_t *s, const uint8_t *secret,
                              size_t secret_len, const char *label, const uint8_t *transcript_hash,
                              size_t transcript_len);

int speer_tls13_init(speer_tls13_keysched_t *ks, uint16_t cipher_suite, const uint8_t *psk,
                     size_t psk_len);

int speer_tls13_set_handshake_secret(speer_tls13_keysched_t *ks, const uint8_t *dhe_shared,
                                     size_t dhe_len, const uint8_t *hs_transcript_hash);

int speer_tls13_set_master_secret(speer_tls13_keysched_t *ks);

int speer_tls13_handshake_keys(const speer_tls13_keysched_t *ks, speer_tls13_keys_t *client_keys,
                               speer_tls13_keys_t *server_keys, const uint8_t *hs_transcript_hash);

int speer_tls13_application_keys(const speer_tls13_keysched_t *ks, speer_tls13_keys_t *client_keys,
                                 speer_tls13_keys_t *server_keys,
                                 const uint8_t *server_finished_hash);

int speer_tls13_finished_mac(const speer_tls13_keysched_t *ks, int from_server,
                             const uint8_t *base_secret, const uint8_t *transcript_hash,
                             uint8_t *out_mac);

#endif
