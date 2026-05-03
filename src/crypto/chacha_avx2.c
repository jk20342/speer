#include "speer_internal.h"

#if (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)) && \
    (defined(__GNUC__) || defined(__clang__))

#define SPEER_CHACHA_AVX2_AVAILABLE 1

#include <immintrin.h>

#define SPEER_AVX2_TARGET __attribute__((target("avx2")))

static SPEER_AVX2_TARGET INLINE __m256i rotl32_avx2(__m256i v, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(v, n), _mm256_srli_epi32(v, 32 - n));
}

#define ROT16(v) _mm256_shuffle_epi8(v, rot16_mask)
#define ROT8(v)  _mm256_shuffle_epi8(v, rot8_mask)
#define ROT12(v) rotl32_avx2(v, 12)
#define ROT7(v)  rotl32_avx2(v, 7)

#define QR8(a, b, c, d)             \
    do {                            \
        a = _mm256_add_epi32(a, b); \
        d = _mm256_xor_si256(d, a); \
        d = ROT16(d);               \
        c = _mm256_add_epi32(c, d); \
        b = _mm256_xor_si256(b, c); \
        b = ROT12(b);               \
        a = _mm256_add_epi32(a, b); \
        d = _mm256_xor_si256(d, a); \
        d = ROT8(d);                \
        c = _mm256_add_epi32(c, d); \
        b = _mm256_xor_si256(b, c); \
        b = ROT7(b);                \
    } while (0)

SPEER_AVX2_TARGET
/*
 * avx2 schedules eight consecutive chacha20 blocks and xor's with input plaintext
 * used when runtime cpu reports avx2; falls back elsewhere in dispatcher
 */
void speer_chacha20_avx2_8blocks(const uint32_t state[16], const uint8_t *in, uint8_t *out) {
    const __m256i rot16_mask = _mm256_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
                                               13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3,
                                               2);
    const __m256i rot8_mask = _mm256_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
                                              14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

    __m256i s0 = _mm256_set1_epi32((int)state[0]);
    __m256i s1 = _mm256_set1_epi32((int)state[1]);
    __m256i s2 = _mm256_set1_epi32((int)state[2]);
    __m256i s3 = _mm256_set1_epi32((int)state[3]);
    __m256i s4 = _mm256_set1_epi32((int)state[4]);
    __m256i s5 = _mm256_set1_epi32((int)state[5]);
    __m256i s6 = _mm256_set1_epi32((int)state[6]);
    __m256i s7 = _mm256_set1_epi32((int)state[7]);
    __m256i s8 = _mm256_set1_epi32((int)state[8]);
    __m256i s9 = _mm256_set1_epi32((int)state[9]);
    __m256i s10 = _mm256_set1_epi32((int)state[10]);
    __m256i s11 = _mm256_set1_epi32((int)state[11]);
    __m256i s12 = _mm256_add_epi32(_mm256_set1_epi32((int)state[12]),
                                   _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
    __m256i s13 = _mm256_set1_epi32((int)state[13]);
    __m256i s14 = _mm256_set1_epi32((int)state[14]);
    __m256i s15 = _mm256_set1_epi32((int)state[15]);

    __m256i x0 = s0, x1 = s1, x2 = s2, x3 = s3;
    __m256i x4 = s4, x5 = s5, x6 = s6, x7 = s7;
    __m256i x8 = s8, x9 = s9, x10 = s10, x11 = s11;
    __m256i x12 = s12, x13 = s13, x14 = s14, x15 = s15;

    for (int i = 0; i < 10; i++) {
        QR8(x0, x4, x8, x12);
        QR8(x1, x5, x9, x13);
        QR8(x2, x6, x10, x14);
        QR8(x3, x7, x11, x15);
        QR8(x0, x5, x10, x15);
        QR8(x1, x6, x11, x12);
        QR8(x2, x7, x8, x13);
        QR8(x3, x4, x9, x14);
    }

    x0 = _mm256_add_epi32(x0, s0);
    x1 = _mm256_add_epi32(x1, s1);
    x2 = _mm256_add_epi32(x2, s2);
    x3 = _mm256_add_epi32(x3, s3);
    x4 = _mm256_add_epi32(x4, s4);
    x5 = _mm256_add_epi32(x5, s5);
    x6 = _mm256_add_epi32(x6, s6);
    x7 = _mm256_add_epi32(x7, s7);
    x8 = _mm256_add_epi32(x8, s8);
    x9 = _mm256_add_epi32(x9, s9);
    x10 = _mm256_add_epi32(x10, s10);
    x11 = _mm256_add_epi32(x11, s11);
    x12 = _mm256_add_epi32(x12, s12);
    x13 = _mm256_add_epi32(x13, s13);
    x14 = _mm256_add_epi32(x14, s14);
    x15 = _mm256_add_epi32(x15, s15);

#define TRANSPOSE4(g0, g1, g2, g3, a, b, c, d)         \
    do {                                               \
        __m256i _t0 = _mm256_unpacklo_epi32((a), (b)); \
        __m256i _t1 = _mm256_unpackhi_epi32((a), (b)); \
        __m256i _t2 = _mm256_unpacklo_epi32((c), (d)); \
        __m256i _t3 = _mm256_unpackhi_epi32((c), (d)); \
        (g0) = _mm256_unpacklo_epi64(_t0, _t2);        \
        (g1) = _mm256_unpackhi_epi64(_t0, _t2);        \
        (g2) = _mm256_unpacklo_epi64(_t1, _t3);        \
        (g3) = _mm256_unpackhi_epi64(_t1, _t3);        \
    } while (0)

    __m256i ga0, ga1, ga2, ga3;
    __m256i gb0, gb1, gb2, gb3;
    __m256i gc0, gc1, gc2, gc3;
    __m256i gd0, gd1, gd2, gd3;
    TRANSPOSE4(ga0, ga1, ga2, ga3, x0, x1, x2, x3);
    TRANSPOSE4(gb0, gb1, gb2, gb3, x4, x5, x6, x7);
    TRANSPOSE4(gc0, gc1, gc2, gc3, x8, x9, x10, x11);
    TRANSPOSE4(gd0, gd1, gd2, gd3, x12, x13, x14, x15);

#undef TRANSPOSE4

#define EMIT_BLOCK_PAIR(off_lo, off_hi, gA, gB, gC, gD)                                      \
    do {                                                                                     \
        __m256i _lo32 = _mm256_permute2x128_si256((gA), (gB), 0x20);                         \
        __m256i _hi32 = _mm256_permute2x128_si256((gC), (gD), 0x20);                         \
        __m256i _LO32 = _mm256_permute2x128_si256((gA), (gB), 0x31);                         \
        __m256i _HI32 = _mm256_permute2x128_si256((gC), (gD), 0x31);                         \
        __m256i _i0 = _mm256_loadu_si256((const __m256i *)(in + (off_lo) + 0));              \
        __m256i _i1 = _mm256_loadu_si256((const __m256i *)(in + (off_lo) + 32));             \
        __m256i _i2 = _mm256_loadu_si256((const __m256i *)(in + (off_hi) + 0));              \
        __m256i _i3 = _mm256_loadu_si256((const __m256i *)(in + (off_hi) + 32));             \
        _mm256_storeu_si256((__m256i *)(out + (off_lo) + 0), _mm256_xor_si256(_lo32, _i0));  \
        _mm256_storeu_si256((__m256i *)(out + (off_lo) + 32), _mm256_xor_si256(_hi32, _i1)); \
        _mm256_storeu_si256((__m256i *)(out + (off_hi) + 0), _mm256_xor_si256(_LO32, _i2));  \
        _mm256_storeu_si256((__m256i *)(out + (off_hi) + 32), _mm256_xor_si256(_HI32, _i3)); \
    } while (0)

    EMIT_BLOCK_PAIR(0 * 64, 4 * 64, ga0, gb0, gc0, gd0);
    EMIT_BLOCK_PAIR(1 * 64, 5 * 64, ga1, gb1, gc1, gd1);
    EMIT_BLOCK_PAIR(2 * 64, 6 * 64, ga2, gb2, gc2, gd2);
    EMIT_BLOCK_PAIR(3 * 64, 7 * 64, ga3, gb3, gc3, gd3);

#undef EMIT_BLOCK_PAIR
}

SPEER_AVX2_TARGET
void speer_chacha20_avx2_keystream8(const uint32_t state[16], uint8_t *out) {
    static const uint8_t zeros[8 * 64] = {0};
    speer_chacha20_avx2_8blocks(state, zeros, out);
}

#endif
