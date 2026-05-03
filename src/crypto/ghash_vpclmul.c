#include "speer_internal.h"

#include "ghash.h"

#if defined(SPEER_GHASH_VPCL_AVAILABLE)

#include <immintrin.h>

#if defined(__GNUC__) || defined(__clang__)
#define SPEER_VPCL_GHASH_TARGET __attribute__((target("vpclmulqdq,pclmul,avx2,sse4.1")))
#else
#define SPEER_VPCL_GHASH_TARGET
#endif

static SPEER_VPCL_GHASH_TARGET __m128i bswap_be_x(__m128i v) {
    const __m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    return _mm_shuffle_epi8(v, mask);
}

/** match ghash_clmul.c gfmul_clmul (XMM). */
static SPEER_VPCL_GHASH_TARGET __m128i gfmul_x(__m128i a, __m128i b) {
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

static SPEER_VPCL_GHASH_TARGET __m256i ymm_srli_si128_8(__m256i x) {
    __m128i xl = _mm256_castsi256_si128(x);
    __m128i xh = _mm256_extracti128_si256(x, 1);
    return _mm256_insertf128_si256(_mm256_castsi128_si256(_mm_srli_si128(xl, 8)),
                                   _mm_srli_si128(xh, 8), 1);
}

static SPEER_VPCL_GHASH_TARGET __m256i ymm_slli_si128_8(__m256i x) {
    __m128i xl = _mm256_castsi256_si128(x);
    __m128i xh = _mm256_extracti128_si256(x, 1);
    return _mm256_insertf128_si256(_mm256_castsi128_si256(_mm_slli_si128(xl, 8)),
                                   _mm_slli_si128(xh, 8), 1);
}

static SPEER_VPCL_GHASH_TARGET __m256i ymm_srli_si128_4(__m256i x) {
    __m128i xl = _mm256_castsi256_si128(x);
    __m128i xh = _mm256_extracti128_si256(x, 1);
    return _mm256_insertf128_si256(_mm256_castsi128_si256(_mm_srli_si128(xl, 4)),
                                   _mm_srli_si128(xh, 4), 1);
}

static SPEER_VPCL_GHASH_TARGET __m256i ymm_slli_si128_4(__m256i x) {
    __m128i xl = _mm256_castsi256_si128(x);
    __m128i xh = _mm256_extracti128_si256(x, 1);
    return _mm256_insertf128_si256(_mm256_castsi128_si256(_mm_slli_si128(xl, 4)),
                                   _mm_slli_si128(xh, 4), 1);
}

static SPEER_VPCL_GHASH_TARGET __m256i ymm_srli_si128_12(__m256i x) {
    __m128i xl = _mm256_castsi256_si128(x);
    __m128i xh = _mm256_extracti128_si256(x, 1);
    return _mm256_insertf128_si256(_mm256_castsi128_si256(_mm_srli_si128(xl, 12)),
                                   _mm_srli_si128(xh, 12), 1);
}

static SPEER_VPCL_GHASH_TARGET __m256i ymm_slli_si128_12(__m256i x) {
    __m128i xl = _mm256_castsi256_si128(x);
    __m128i xh = _mm256_extracti128_si256(x, 1);
    return _mm256_insertf128_si256(_mm256_castsi128_si256(_mm_slli_si128(xl, 12)),
                                   _mm_slli_si128(xh, 12), 1);
}

/** two independent GHASH field multiples (128-bit lanes) in parallel. */
static SPEER_VPCL_GHASH_TARGET __m256i gfmul_y(__m256i a, __m256i b) {
    __m256i tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9, tmp2, tmp4b, tmp5b;
    tmp3 = _mm256_clmulepi64_epi128(a, b, 0x00);
    tmp4 = _mm256_clmulepi64_epi128(a, b, 0x10);
    tmp5 = _mm256_clmulepi64_epi128(a, b, 0x01);
    tmp6 = _mm256_clmulepi64_epi128(a, b, 0x11);

    tmp4 = _mm256_xor_si256(tmp4, tmp5);
    tmp5 = ymm_slli_si128_8(tmp4);
    tmp4 = ymm_srli_si128_8(tmp4);
    tmp3 = _mm256_xor_si256(tmp3, tmp5);
    tmp6 = _mm256_xor_si256(tmp6, tmp4);

    tmp7 = _mm256_srli_epi32(tmp3, 31);
    tmp8 = _mm256_srli_epi32(tmp6, 31);
    tmp3 = _mm256_slli_epi32(tmp3, 1);
    tmp6 = _mm256_slli_epi32(tmp6, 1);

    tmp9 = ymm_srli_si128_12(tmp7);
    tmp8 = ymm_slli_si128_4(tmp8);
    tmp7 = ymm_slli_si128_4(tmp7);
    tmp3 = _mm256_or_si256(tmp3, tmp7);
    tmp6 = _mm256_or_si256(tmp6, tmp8);
    tmp6 = _mm256_or_si256(tmp6, tmp9);

    tmp7 = _mm256_slli_epi32(tmp3, 31);
    tmp8 = _mm256_slli_epi32(tmp3, 30);
    tmp9 = _mm256_slli_epi32(tmp3, 25);

    tmp7 = _mm256_xor_si256(tmp7, tmp8);
    tmp7 = _mm256_xor_si256(tmp7, tmp9);
    tmp8 = ymm_srli_si128_4(tmp7);
    tmp7 = ymm_slli_si128_12(tmp7);
    tmp3 = _mm256_xor_si256(tmp3, tmp7);

    tmp2 = _mm256_srli_epi32(tmp3, 1);
    tmp4b = _mm256_srli_epi32(tmp3, 2);
    tmp5b = _mm256_srli_epi32(tmp3, 7);
    tmp2 = _mm256_xor_si256(tmp2, tmp4b);
    tmp2 = _mm256_xor_si256(tmp2, tmp5b);
    tmp2 = _mm256_xor_si256(tmp2, tmp8);
    tmp3 = _mm256_xor_si256(tmp3, tmp2);
    tmp6 = _mm256_xor_si256(tmp6, tmp3);

    return tmp6;
}

SPEER_VPCL_GHASH_TARGET
void speer_ghash_vpcl_init(speer_ghash_state_t *s, const uint8_t h[16]) {
    s->use_clmul = 0;
    s->use_pmull_arm = 0;
    s->use_vpclmul_x86 = 1;

    for (int i = 0; i < 16; i++) s->h[i] = h[i];
    __m128i hv = _mm_loadu_si128((const __m128i *)h);
    hv = bswap_be_x(hv);
    _mm_storeu_si128((__m128i *)s->htables[0], hv);
    __m128i h2 = gfmul_x(hv, hv);
    __m128i h3 = gfmul_x(h2, hv);
    __m128i h4 = gfmul_x(h3, hv);
    _mm_storeu_si128((__m128i *)s->htables[1], h2);
    _mm_storeu_si128((__m128i *)s->htables[2], h3);
    _mm_storeu_si128((__m128i *)s->htables[3], h4);
}

SPEER_VPCL_GHASH_TARGET
void speer_ghash_vpcl_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data,
                             size_t len) {
    __m128i h1 = _mm_loadu_si128((const __m128i *)s->htables[0]);
    __m128i h2 = _mm_loadu_si128((const __m128i *)s->htables[1]);
    __m128i h3 = _mm_loadu_si128((const __m128i *)s->htables[2]);
    __m128i h4 = _mm_loadu_si128((const __m128i *)s->htables[3]);
    __m128i yv = bswap_be_x(_mm_loadu_si128((const __m128i *)y));

    while (len >= 64) {
        __m128i d0 = bswap_be_x(_mm_loadu_si128((const __m128i *)data));
        __m128i d1 = bswap_be_x(_mm_loadu_si128((const __m128i *)(data + 16)));
        __m128i d2 = bswap_be_x(_mm_loadu_si128((const __m128i *)(data + 32)));
        __m128i d3 = bswap_be_x(_mm_loadu_si128((const __m128i *)(data + 48)));

        __m256i prod_y_d0 = gfmul_y(_mm256_set_m128i(d0, yv), _mm256_set_m128i(h4, h4));
        __m256i prod_d1_d2 = gfmul_y(_mm256_set_m128i(d2, d1), _mm256_set_m128i(h2, h3));

        yv = _mm_xor_si128(_mm256_castsi256_si128(prod_y_d0),
                           _mm256_extracti128_si256(prod_y_d0, 1));
        yv = _mm_xor_si128(yv, _mm256_extracti128_si256(prod_d1_d2, 1));
        yv = _mm_xor_si128(yv, _mm256_castsi256_si128(prod_d1_d2));
        yv = _mm_xor_si128(yv, gfmul_x(d3, h1));

        data += 64;
        len -= 64;
    }
    while (len >= 16) {
        __m128i d = bswap_be_x(_mm_loadu_si128((const __m128i *)data));
        yv = _mm_xor_si128(yv, d);
        yv = gfmul_x(yv, h1);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        uint8_t blk[16] = {0};
        for (size_t i = 0; i < len; i++) blk[i] = data[i];
        __m128i d = bswap_be_x(_mm_loadu_si128((const __m128i *)blk));
        yv = _mm_xor_si128(yv, d);
        yv = gfmul_x(yv, h1);
    }
    _mm_storeu_si128((__m128i *)y, bswap_be_x(yv));
}

#elif defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)

void speer_ghash_vpcl_init(speer_ghash_state_t *s, const uint8_t h[16]) {
    (void)s;
    (void)h;
}

void speer_ghash_vpcl_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data,
                             size_t len) {
    (void)s;
    (void)y;
    (void)data;
    (void)len;
}

#else

void speer_ghash_vpcl_init(speer_ghash_state_t *s, const uint8_t h[16]) {
    (void)s;
    (void)h;
}

void speer_ghash_vpcl_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data,
                             size_t len) {
    (void)s;
    (void)y;
    (void)data;
    (void)len;
}

#endif
