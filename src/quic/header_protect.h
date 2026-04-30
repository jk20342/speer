#ifndef SPEER_HEADER_PROTECT_H
#define SPEER_HEADER_PROTECT_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    SPEER_HP_AES_128 = 1,
    SPEER_HP_AES_256 = 2,
    SPEER_HP_CHACHA = 3,
} speer_hp_alg_t;

typedef struct {
    speer_hp_alg_t alg;
    uint8_t key[32];
    size_t key_len;
} speer_hp_ctx_t;

int speer_hp_init(speer_hp_ctx_t *ctx, speer_hp_alg_t alg, const uint8_t *hp_key);
int speer_hp_mask(const speer_hp_ctx_t *ctx, const uint8_t sample[16], uint8_t mask[5]);
int speer_hp_protect(const speer_hp_ctx_t *ctx, uint8_t *pkt, size_t pkt_len, size_t pn_offset,
                     size_t pn_length);
int speer_hp_unprotect(const speer_hp_ctx_t *ctx, uint8_t *pkt, size_t pkt_len, size_t pn_offset,
                       size_t *out_pn_length);

#endif
