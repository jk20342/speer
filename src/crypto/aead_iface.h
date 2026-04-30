#ifndef SPEER_AEAD_IFACE_H
#define SPEER_AEAD_IFACE_H

#include <stddef.h>
#include <stdint.h>

#define SPEER_AEAD_MAX_KEY   32
#define SPEER_AEAD_MAX_NONCE 12
#define SPEER_AEAD_TAG_LEN   16

typedef struct speer_aead_iface_s {
    const char *name;
    size_t key_len;
    size_t nonce_len;
    size_t tag_len;
    int (*seal)(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_len,
                const uint8_t *plaintext, size_t pt_len, uint8_t *out_ciphertext, uint8_t *out_tag);
    int (*open)(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_len,
                const uint8_t *ciphertext, size_t ct_len, const uint8_t *tag,
                uint8_t *out_plaintext);
} speer_aead_iface_t;

extern const speer_aead_iface_t speer_aead_chacha20_poly1305;
extern const speer_aead_iface_t speer_aead_aes128_gcm;
extern const speer_aead_iface_t speer_aead_aes256_gcm;

#endif
