#include "speer_internal.h"

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))

#include <immintrin.h>

#define SPEER_POLY1305_AVX2_TARGET __attribute__((target("avx2")))

static SPEER_POLY1305_AVX2_TARGET uint64_t poly1305_hsum4_u64(__m256i v) {
    __m128i lo = _mm256_castsi256_si128(v);
    __m128i hi = _mm256_extracti128_si256(v, 1);
    lo = _mm_add_epi64(lo, hi);
    lo = _mm_add_epi64(lo, _mm_unpackhi_epi64(lo, lo));
    return (uint64_t)_mm_cvtsi128_si64(lo);
}

SPEER_POLY1305_AVX2_TARGET
void speer_poly1305_blocks_avx2(uint32_t h[5], const uint32_t r[5], const uint8_t *m, size_t len,
                                uint32_t padbit) {
    const uint32_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];

    while (len >= 16) {
        uint64_t t0 = LOAD32_LE(m + 0);
        uint64_t t1 = LOAD32_LE(m + 4);
        uint64_t t2 = LOAD32_LE(m + 8);
        uint64_t t3 = LOAD32_LE(m + 12);

        h0 += (uint32_t)(t0) & 0x3ffffff;
        h1 += (uint32_t)((((t1) << 32) | (t0)) >> 26) & 0x3ffffff;
        h2 += (uint32_t)((((t2) << 32) | (t1)) >> 20) & 0x3ffffff;
        h3 += (uint32_t)((((t3) << 32) | (t2)) >> 14) & 0x3ffffff;
        h4 += (uint32_t)(((t3) >> 8) | ((uint64_t)padbit << 24));

        __m256i H0 = _mm256_set_epi64x((int64_t)(uint64_t)h3, (int64_t)(uint64_t)h2,
                                       (int64_t)(uint64_t)h1, (int64_t)(uint64_t)h0);
        __m256i R0 = _mm256_set_epi64x((int64_t)(uint64_t)s2, (int64_t)(uint64_t)s3,
                                       (int64_t)(uint64_t)s4, (int64_t)(uint64_t)r0);
        uint64_t d0 = poly1305_hsum4_u64(_mm256_mul_epu32(H0, R0)) + (uint64_t)h4 * (uint64_t)s1;

        __m256i H_hi = _mm256_set_epi64x((int64_t)(uint64_t)h3, (int64_t)(uint64_t)h2,
                                         (int64_t)(uint64_t)h1, (int64_t)(uint64_t)h0);
        __m256i R1 = _mm256_set_epi64x((int64_t)(uint64_t)s3, (int64_t)(uint64_t)s4,
                                       (int64_t)(uint64_t)r0, (int64_t)(uint64_t)r1);
        uint64_t d1 = poly1305_hsum4_u64(_mm256_mul_epu32(H_hi, R1)) + (uint64_t)h4 * (uint64_t)s2;

        __m256i R2 = _mm256_set_epi64x((int64_t)(uint64_t)s4, (int64_t)(uint64_t)r0,
                                       (int64_t)(uint64_t)r1, (int64_t)(uint64_t)r2);
        uint64_t d2 = poly1305_hsum4_u64(_mm256_mul_epu32(H_hi, R2)) + (uint64_t)h4 * (uint64_t)s3;

        __m256i R3 = _mm256_set_epi64x((int64_t)(uint64_t)r0, (int64_t)(uint64_t)r1,
                                       (int64_t)(uint64_t)r2, (int64_t)(uint64_t)r3);
        uint64_t d3 = poly1305_hsum4_u64(_mm256_mul_epu32(H_hi, R3)) + (uint64_t)h4 * (uint64_t)s4;

        __m256i R4 = _mm256_set_epi64x((int64_t)(uint64_t)r1, (int64_t)(uint64_t)r2,
                                       (int64_t)(uint64_t)r3, (int64_t)(uint64_t)r4);
        uint64_t d4 = poly1305_hsum4_u64(_mm256_mul_epu32(H_hi, R4)) + (uint64_t)h4 * (uint64_t)r0;

        uint32_t c = (uint32_t)(d0 >> 26);
        h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c;
        c = (uint32_t)(d1 >> 26);
        h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c;
        c = (uint32_t)(d2 >> 26);
        h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c;
        c = (uint32_t)(d3 >> 26);
        h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c;
        c = (uint32_t)(d4 >> 26);
        h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5;
        c = (h0 >> 26);
        h0 &= 0x3ffffff;
        h1 += c;

        m += 16;
        len -= 16;
    }

    h[0] = h0;
    h[1] = h1;
    h[2] = h2;
    h[3] = h3;
    h[4] = h4;
}

#endif
