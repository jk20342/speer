#include "speer_internal.h"

#include "ghash.h"

#ifdef SPEER_GHASH_CLMUL_AVAILABLE

#include <emmintrin.h>
#include <tmmintrin.h>
#include <wmmintrin.h>

#if defined(__GNUC__) || defined(__clang__)
#define SPEER_PCLMUL_TARGET __attribute__((target("pclmul,sse4.1,ssse3")))
#else
#define SPEER_PCLMUL_TARGET
#endif

static SPEER_PCLMUL_TARGET __m128i bswap_be(__m128i v) {
    const __m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    return _mm_shuffle_epi8(v, mask);
}

static SPEER_PCLMUL_TARGET __m128i gfmul_clmul(__m128i a, __m128i b) {
    __m128i tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);

    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp6, 31);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);

    tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);

    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);

    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);

    tmp2 = _mm_srli_epi32(tmp3, 1);
    tmp4 = _mm_srli_epi32(tmp3, 2);
    tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);
    tmp3 = _mm_xor_si128(tmp3, tmp2);
    tmp6 = _mm_xor_si128(tmp6, tmp3);

    return tmp6;
}

SPEER_PCLMUL_TARGET
void speer_ghash_clmul_init(speer_ghash_state_t *s, const uint8_t h[16]) {
    s->use_clmul = 1;
    for (int i = 0; i < 16; i++) s->h[i] = h[i];
    __m128i hv = _mm_loadu_si128((const __m128i *)h);
    hv = bswap_be(hv);
    _mm_storeu_si128((__m128i *)s->htables[0], hv);
}

SPEER_PCLMUL_TARGET
void speer_ghash_clmul_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data,
                              size_t len) {
    __m128i hv = _mm_loadu_si128((const __m128i *)s->htables[0]);
    __m128i yv = bswap_be(_mm_loadu_si128((const __m128i *)y));

    while (len >= 16) {
        __m128i d = bswap_be(_mm_loadu_si128((const __m128i *)data));
        yv = _mm_xor_si128(yv, d);
        yv = gfmul_clmul(yv, hv);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        uint8_t blk[16] = {0};
        for (size_t i = 0; i < len; i++) blk[i] = data[i];
        __m128i d = bswap_be(_mm_loadu_si128((const __m128i *)blk));
        yv = _mm_xor_si128(yv, d);
        yv = gfmul_clmul(yv, hv);
    }
    _mm_storeu_si128((__m128i *)y, bswap_be(yv));
}

#else

void speer_ghash_clmul_init(speer_ghash_state_t *s, const uint8_t h[16]) {
    (void)s;
    (void)h;
}
void speer_ghash_clmul_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data,
                              size_t len) {
    (void)s;
    (void)y;
    (void)data;
    (void)len;
}

#endif
