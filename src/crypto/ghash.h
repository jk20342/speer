#ifndef SPEER_GHASH_H
#define SPEER_GHASH_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int use_clmul;
    uint8_t h[16];
    uint8_t htables[16][16];
} speer_ghash_state_t;

void speer_ghash_init(speer_ghash_state_t *s, const uint8_t h[16]);
void speer_ghash_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data, size_t len);

void speer_ghash_soft_init(speer_ghash_state_t *s, const uint8_t h[16]);
void speer_ghash_soft_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data,
                             size_t len);

#if (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86))
#define SPEER_GHASH_CLMUL_AVAILABLE 1
void speer_ghash_clmul_init(speer_ghash_state_t *s, const uint8_t h[16]);
void speer_ghash_clmul_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data,
                              size_t len);
#endif

#endif
