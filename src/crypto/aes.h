#ifndef SPEER_AES_H
#define SPEER_AES_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t round_keys[60];
    int nr;
    int use_aesni;
} speer_aes_key_t;

void speer_aes_set_encrypt_key(speer_aes_key_t *k, const uint8_t *key, size_t key_bits);
void speer_aes_encrypt(const speer_aes_key_t *k, const uint8_t in[16], uint8_t out[16]);
void speer_aes_ctr(const speer_aes_key_t *k, const uint8_t nonce[16], uint8_t *out,
                   const uint8_t *in, size_t len);

void speer_aes_set_encrypt_key_sw(speer_aes_key_t *k, const uint8_t *key, size_t key_bits);
void speer_aes_encrypt_sw(const speer_aes_key_t *k, const uint8_t in[16], uint8_t out[16]);
void speer_aes_ctr_sw(const speer_aes_key_t *k, const uint8_t nonce[16], uint8_t *out,
                      const uint8_t *in, size_t len);

#if (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86))
#define SPEER_AESNI_AVAILABLE 1
void speer_aes_set_encrypt_key_aesni(speer_aes_key_t *k, const uint8_t *key, size_t key_bits);
void speer_aes_encrypt_aesni(const speer_aes_key_t *k, const uint8_t in[16], uint8_t out[16]);
void speer_aes_ctr_aesni(const speer_aes_key_t *k, const uint8_t nonce[16], uint8_t *out,
                         const uint8_t *in, size_t len);
#endif

#endif
