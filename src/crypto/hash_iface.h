#ifndef SPEER_HASH_IFACE_H
#define SPEER_HASH_IFACE_H

#include <stdint.h>
#include <stddef.h>

#define SPEER_HASH_MAX_DIGEST 64
#define SPEER_HASH_MAX_BLOCK 128
#define SPEER_HASH_MAX_CTX 256

typedef struct {
    const char* name;
    size_t digest_size;
    size_t block_size;
    void (*init)(void* ctx);
    void (*update)(void* ctx, const uint8_t* data, size_t len);
    void (*final)(void* ctx, uint8_t* out);
    void (*oneshot)(uint8_t* out, const uint8_t* data, size_t len);
} speer_hash_iface_t;

extern const speer_hash_iface_t speer_hash_sha256;
extern const speer_hash_iface_t speer_hash_sha384;
extern const speer_hash_iface_t speer_hash_sha512;

void speer_hmac(const speer_hash_iface_t* h,
                uint8_t* out,
                const uint8_t* key, size_t key_len,
                const uint8_t* data, size_t data_len);

void speer_hkdf2(const speer_hash_iface_t* h,
                 uint8_t* okm, size_t okm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* info, size_t info_len);

void speer_hkdf2_extract(const speer_hash_iface_t* h,
                         uint8_t* prk,
                         const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm, size_t ikm_len);

void speer_hkdf2_expand(const speer_hash_iface_t* h,
                        uint8_t* okm, size_t okm_len,
                        const uint8_t* prk, size_t prk_len,
                        const uint8_t* info, size_t info_len);

void speer_hkdf_expand_label(const speer_hash_iface_t* h,
                             uint8_t* out, size_t out_len,
                             const uint8_t* secret, size_t secret_len,
                             const char* label,
                             const uint8_t* context, size_t context_len);

#endif
