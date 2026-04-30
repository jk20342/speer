#include "speer_internal.h"
#include "tls13_keysched.h"
#include "tls_msg.h"

int speer_tls13_suite_init(speer_tls13_suite_t* s, uint16_t cipher_suite) {
    ZERO(s, sizeof(*s));
    switch (cipher_suite) {
        case TLS_CS_AES_128_GCM_SHA256:
            s->hash = &speer_hash_sha256;
            s->aead = &speer_aead_aes128_gcm;
            s->key_len = 16; s->iv_len = 12; s->hp_len = 16;
            return 0;
        case TLS_CS_AES_256_GCM_SHA384:
            s->hash = &speer_hash_sha384;
            s->aead = &speer_aead_aes256_gcm;
            s->key_len = 32; s->iv_len = 12; s->hp_len = 32;
            return 0;
        case TLS_CS_CHACHA20_POLY1305_SHA256:
            s->hash = &speer_hash_sha256;
            s->aead = &speer_aead_chacha20_poly1305;
            s->key_len = 32; s->iv_len = 12; s->hp_len = 32;
            return 0;
    }
    return -1;
}

int speer_tls13_derive_secret(uint8_t* out, const speer_tls13_suite_t* s,
                                const uint8_t* secret, size_t secret_len,
                                const char* label,
                                const uint8_t* transcript_hash, size_t transcript_len) {
    (void)secret_len;
    speer_hkdf_expand_label(s->hash, out, s->hash->digest_size,
                              secret, s->hash->digest_size,
                              label, transcript_hash, transcript_len);
    return 0;
}

static void zero_extract(const speer_tls13_suite_t* s,
                          const uint8_t* salt, size_t salt_len,
                          const uint8_t* ikm, size_t ikm_len,
                          uint8_t* out_prk) {
    static const uint8_t zero[SPEER_TLS13_MAX_HASH] = {0};
    if (!ikm) { ikm = zero; ikm_len = s->hash->digest_size; }
    if (!salt) { salt = zero; salt_len = s->hash->digest_size; }
    speer_hkdf2_extract(s->hash, out_prk, salt, salt_len, ikm, ikm_len);
}

int speer_tls13_init(speer_tls13_keysched_t* ks, uint16_t cipher_suite,
                      const uint8_t* psk, size_t psk_len) {
    ZERO(ks, sizeof(*ks));
    if (speer_tls13_suite_init(&ks->suite, cipher_suite) != 0) return -1;
    zero_extract(&ks->suite, NULL, 0, psk, psk_len, ks->early_secret);
    return 0;
}

static void derived_secret(const speer_tls13_suite_t* s, const uint8_t* secret, uint8_t* out) {
    uint8_t empty_hash[SPEER_HASH_MAX_DIGEST];
    s->hash->oneshot(empty_hash, NULL, 0);
    speer_hkdf_expand_label(s->hash, out, s->hash->digest_size,
                              secret, s->hash->digest_size,
                              "derived", empty_hash, s->hash->digest_size);
}

int speer_tls13_set_handshake_secret(speer_tls13_keysched_t* ks,
                                       const uint8_t* dhe_shared, size_t dhe_len,
                                       const uint8_t* hs_transcript_hash) {
    uint8_t derived[SPEER_TLS13_MAX_HASH];
    derived_secret(&ks->suite, ks->early_secret, derived);
    speer_hkdf2_extract(ks->suite.hash, ks->handshake_secret,
                         derived, ks->suite.hash->digest_size,
                         dhe_shared, dhe_len);

    speer_hkdf_expand_label(ks->suite.hash,
                              ks->client_handshake_traffic, ks->suite.hash->digest_size,
                              ks->handshake_secret, ks->suite.hash->digest_size,
                              "c hs traffic",
                              hs_transcript_hash, ks->suite.hash->digest_size);
    speer_hkdf_expand_label(ks->suite.hash,
                              ks->server_handshake_traffic, ks->suite.hash->digest_size,
                              ks->handshake_secret, ks->suite.hash->digest_size,
                              "s hs traffic",
                              hs_transcript_hash, ks->suite.hash->digest_size);
    return 0;
}

int speer_tls13_set_master_secret(speer_tls13_keysched_t* ks) {
    uint8_t derived[SPEER_TLS13_MAX_HASH];
    derived_secret(&ks->suite, ks->handshake_secret, derived);
    zero_extract(&ks->suite,
                  derived, ks->suite.hash->digest_size,
                  NULL, 0,
                  ks->master_secret);
    return 0;
}

static void derive_keys(const speer_tls13_suite_t* s,
                         const uint8_t* traffic_secret,
                         speer_tls13_keys_t* k) {
    speer_hkdf_expand_label(s->hash, k->key, s->key_len,
                              traffic_secret, s->hash->digest_size,
                              "key", NULL, 0);
    speer_hkdf_expand_label(s->hash, k->iv, s->iv_len,
                              traffic_secret, s->hash->digest_size,
                              "iv", NULL, 0);
    speer_hkdf_expand_label(s->hash, k->hp, s->hp_len,
                              traffic_secret, s->hash->digest_size,
                              "quic hp", NULL, 0);
}

int speer_tls13_handshake_keys(const speer_tls13_keysched_t* ks,
                                 speer_tls13_keys_t* client_keys,
                                 speer_tls13_keys_t* server_keys,
                                 const uint8_t* hs_transcript_hash) {
    (void)hs_transcript_hash;
    derive_keys(&ks->suite, ks->client_handshake_traffic, client_keys);
    derive_keys(&ks->suite, ks->server_handshake_traffic, server_keys);
    return 0;
}

int speer_tls13_application_keys(const speer_tls13_keysched_t* ks,
                                   speer_tls13_keys_t* client_keys,
                                   speer_tls13_keys_t* server_keys,
                                   const uint8_t* server_finished_hash) {
    speer_tls13_keysched_t* ksw = (speer_tls13_keysched_t*)ks;
    speer_hkdf_expand_label(ks->suite.hash,
                              ksw->client_application_traffic, ks->suite.hash->digest_size,
                              ks->master_secret, ks->suite.hash->digest_size,
                              "c ap traffic",
                              server_finished_hash, ks->suite.hash->digest_size);
    speer_hkdf_expand_label(ks->suite.hash,
                              ksw->server_application_traffic, ks->suite.hash->digest_size,
                              ks->master_secret, ks->suite.hash->digest_size,
                              "s ap traffic",
                              server_finished_hash, ks->suite.hash->digest_size);
    derive_keys(&ks->suite, ks->client_application_traffic, client_keys);
    derive_keys(&ks->suite, ks->server_application_traffic, server_keys);
    return 0;
}

int speer_tls13_finished_mac(const speer_tls13_keysched_t* ks,
                               int from_server,
                               const uint8_t* base_secret,
                               const uint8_t* transcript_hash,
                               uint8_t* out_mac) {
    (void)from_server;
    uint8_t finished_key[SPEER_TLS13_MAX_HASH];
    speer_hkdf_expand_label(ks->suite.hash,
                              finished_key, ks->suite.hash->digest_size,
                              base_secret, ks->suite.hash->digest_size,
                              "finished", NULL, 0);
    speer_hmac(ks->suite.hash, out_mac,
                finished_key, ks->suite.hash->digest_size,
                transcript_hash, ks->suite.hash->digest_size);
    return 0;
}
