#ifndef SPEER_CT_HELPERS_H
#define SPEER_CT_HELPERS_H

#include <stddef.h>
#include <stdint.h>

static inline uint32_t speer_ct_eq_u8(uint8_t a, uint8_t b) {
    return (uint32_t)((((uint32_t)a ^ (uint32_t)b) - 1) >> 31) & 1u;
}

static inline uint32_t speer_ct_eq_u32(uint32_t a, uint32_t b) {
    uint64_t d = (uint64_t)a ^ (uint64_t)b;
    return (uint32_t)((d - 1) >> 63) & 1u;
}

static inline uint32_t speer_ct_lt_u32(uint32_t a, uint32_t b) {
    return (uint32_t)(((uint64_t)a - (uint64_t)b) >> 63) & 1u;
}

static inline uint32_t speer_ct_select_u32(uint32_t mask, uint32_t a, uint32_t b) {
    return b ^ ((0u - (mask & 1u)) & (a ^ b));
}

static inline uint8_t speer_ct_select_u8(uint32_t mask, uint8_t a, uint8_t b) {
    return (uint8_t)(b ^ ((0u - (mask & 1u)) & (a ^ b)));
}

static inline int speer_ct_memeq(const void *a, const void *b, size_t n) {
    if (n == 0) return 1;
    const uint8_t *ap = (const uint8_t *)a;
    const uint8_t *bp = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= ap[i] ^ bp[i];
    return ((diff - 1) >> 8) & 1;
}

static inline void speer_ct_cmov(uint8_t *dst, const uint8_t *src, size_t n, uint32_t cond) {
    uint8_t mask = (uint8_t)(0u - (cond & 1u));
    for (size_t i = 0; i < n; i++) { dst[i] ^= mask & (dst[i] ^ src[i]); }
}

#endif
