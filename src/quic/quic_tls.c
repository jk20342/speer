#include "speer_internal.h"
#include "quic_tls.h"
#include "quic_frame.h"
#include "hash_iface.h"
#include "header_protect.h"

int speer_quic_tls_set_keys_from_secret(speer_quic_keys_t* k,
                                          const speer_tls13_suite_t* suite,
                                          const uint8_t* traffic_secret) {
    ZERO(k, sizeof(*k));
    k->aead = suite->aead;
    k->key_len = suite->key_len;

    speer_hkdf_expand_label(suite->hash, k->key, suite->key_len,
                              traffic_secret, suite->hash->digest_size,
                              "quic key", NULL, 0);
    speer_hkdf_expand_label(suite->hash, k->iv, suite->iv_len,
                              traffic_secret, suite->hash->digest_size,
                              "quic iv", NULL, 0);
    uint8_t hp_key[32];
    speer_hkdf_expand_label(suite->hash, hp_key, suite->hp_len,
                              traffic_secret, suite->hash->digest_size,
                              "quic hp", NULL, 0);

    speer_hp_alg_t alg;
    if (suite->aead == &speer_aead_aes128_gcm) alg = SPEER_HP_AES_128;
    else if (suite->aead == &speer_aead_aes256_gcm) alg = SPEER_HP_AES_256;
    else alg = SPEER_HP_CHACHA;
    return speer_hp_init(&k->hp, alg, hp_key);
}

int speer_quic_tls_make_crypto_frames(uint8_t* out, size_t cap, size_t* out_len,
                                        uint64_t* offset_inout,
                                        const uint8_t* tls_msg, size_t tls_msg_len) {
    speer_qf_writer_t w;
    speer_qf_writer_init(&w, out, cap);
    if (speer_qf_encode_crypto(&w, *offset_inout, tls_msg, tls_msg_len) != 0) return -1;
    *offset_inout += tls_msg_len;
    if (out_len) *out_len = w.pos;
    return 0;
}

int speer_quic_tls_consume_crypto_frame(uint64_t frame_offset,
                                          const uint8_t* data, size_t data_len,
                                          uint8_t* reassembly_buf,
                                          size_t* reassembly_len,
                                          size_t reassembly_cap) {
    if (frame_offset != *reassembly_len) return -1;
    if (frame_offset + data_len > reassembly_cap) return -1;
    if (data_len > 0) COPY(reassembly_buf + frame_offset, data, data_len);
    *reassembly_len = (size_t)(frame_offset + data_len);
    return 0;
}
