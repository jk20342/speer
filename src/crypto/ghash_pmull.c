#include "speer_internal.h"

#include "ghash.h"

#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__)) && \
    defined(__ARM_FEATURE_CRYPTO) && __ARM_FEATURE_CRYPTO

#include <arm_neon.h>

#if defined(__GNUC__) || defined(__clang__)
#define SPEER_PMULL_TARGET __attribute__((target("+crypto")))
#endif

typedef uint64x2_t xm128;

static SPEER_PMULL_TARGET xm128 xmm_bswap_be(xm128 v) {
    static const uint8_t rev[16] = {15, 14, 13, 12, 11, 10, 9, 8,
                                   7,  6,  5,  4,  3,  2,  1, 0};
    uint8x16_t tbl = vld1q_u8(rev);
    return vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(v), tbl));
}

static SPEER_PMULL_TARGET inline xm128 xm_xor(xm128 a, xm128 b) { return veorq_u64(a, b); }

static SPEER_PMULL_TARGET xm128 xm_srli_epi32_31(xm128 v) {
    return vreinterpretq_u64_u32(vshrq_n_u32(vreinterpretq_u32_u64(v), 31));
}

static SPEER_PMULL_TARGET xm128 xm_srli_epi32_1(xm128 v) {
    return vreinterpretq_u64_u32(vshrq_n_u32(vreinterpretq_u32_u64(v), 1));
}

static SPEER_PMULL_TARGET xm128 xm_srli_epi32_2(xm128 v) {
    return vreinterpretq_u64_u32(vshrq_n_u32(vreinterpretq_u32_u64(v), 2));
}

static SPEER_PMULL_TARGET xm128 xm_srli_epi32_7(xm128 v) {
    return vreinterpretq_u64_u32(vshrq_n_u32(vreinterpretq_u32_u64(v), 7));
}

static SPEER_PMULL_TARGET xm128 xm_slli_epi32_1(xm128 v) {
    return vreinterpretq_u64_u32(vshlq_n_u32(vreinterpretq_u32_u64(v), 1));
}

static SPEER_PMULL_TARGET xm128 xm_slli_epi32_31(xm128 v) {
    return vreinterpretq_u64_u32(vshlq_n_u32(vreinterpretq_u32_u64(v), 31));
}

static SPEER_PMULL_TARGET xm128 xm_slli_epi32_30(xm128 v) {
    return vreinterpretq_u64_u32(vshlq_n_u32(vreinterpretq_u32_u64(v), 30));
}

static SPEER_PMULL_TARGET xm128 xm_slli_epi32_25(xm128 v) {
    return vreinterpretq_u64_u32(vshlq_n_u32(vreinterpretq_u32_u64(v), 25));
}

static SPEER_PMULL_TARGET xm128 xm_slli_si128_8(xm128 x) {
    uint8x16_t z = vdupq_n_u8(0);
    uint8x16_t b = vreinterpretq_u8_u64(x);
    return vreinterpretq_u64_u8(vextq_u8(z, b, 8));
}

static SPEER_PMULL_TARGET xm128 xm_srli_si128_8(xm128 x) {
    uint8x16_t z = vdupq_n_u8(0);
    uint8x16_t b = vreinterpretq_u8_u64(x);
    return vreinterpretq_u64_u8(vextq_u8(b, z, 8));
}

static SPEER_PMULL_TARGET xm128 xm_srli_si128_4(xm128 x) {
    uint8x16_t z = vdupq_n_u8(0);
    uint8x16_t b = vreinterpretq_u8_u64(x);
    return vreinterpretq_u64_u8(vextq_u8(b, z, 4));
}

static SPEER_PMULL_TARGET xm128 xm_slli_si128_4(xm128 x) {
    uint8x16_t z = vdupq_n_u8(0);
    uint8x16_t b = vreinterpretq_u8_u64(x);
    return vreinterpretq_u64_u8(vextq_u8(z, b, 12));
}

static SPEER_PMULL_TARGET xm128 xm_srli_si128_12(xm128 x) {
    uint8x16_t z = vdupq_n_u8(0);
    uint8x16_t b = vreinterpretq_u8_u64(x);
    return vreinterpretq_u64_u8(vextq_u8(b, z, 12));
}

/* Bit-identical port of gfmul_clmul in ghash_clmul.c after xmm byte-reversal */
static SPEER_PMULL_TARGET xm128 gfmul_pmull(xm128 a, xm128 b) {
    poly64_t a0 = vreinterpret_p64_u64(vmov_n_u64(vgetq_lane_u64(a, 0)));
    poly64_t a1 = vreinterpret_p64_u64(vmov_n_u64(vgetq_lane_u64(a, 1)));
    poly64_t b0 = vreinterpret_p64_u64(vmov_n_u64(vgetq_lane_u64(b, 0)));
    poly64_t b1 = vreinterpret_p64_u64(vmov_n_u64(vgetq_lane_u64(b, 1)));

    xm128 tmp3 = vreinterpretq_u64_p128(vmull_p64(a0, b0));
    xm128 tmp4 = vreinterpretq_u64_p128(vmull_p64(a1, b0));
    xm128 tmp5 = vreinterpretq_u64_p128(vmull_p64(a0, b1));
    xm128 tmp6 = vreinterpretq_u64_p128(vmull_p64(a1, b1));

    tmp4 = xm_xor(tmp4, tmp5);
    tmp5 = xm_slli_si128_8(tmp4);
    tmp4 = xm_srli_si128_8(tmp4);
    tmp3 = xm_xor(tmp3, tmp5);
    tmp6 = xm_xor(tmp6, tmp4);

    xm128 tmp7 = xm_srli_epi32_31(tmp3);
    xm128 tmp8 = xm_srli_epi32_31(tmp6);
    tmp3 = xm_slli_epi32_1(tmp3);
    tmp6 = xm_slli_epi32_1(tmp6);

    xm128 tmp9 = xm_srli_si128_12(tmp7);
    tmp8 = xm_slli_si128_4(tmp8);       /* slli_si128(tmp8, 4) */
    tmp7 = xm_slli_si128_4(tmp7);       /* slli_si128(tmp7, 4) */
    tmp3 = xm_xor(tmp3, tmp7);
    tmp6 = xm_xor(tmp6, tmp8);
    tmp6 = xm_xor(tmp6, tmp9);

    tmp7 = xm_slli_epi32_31(tmp3);
    tmp8 = xm_slli_epi32_30(tmp3);
    tmp9 = xm_slli_epi32_25(tmp3);

    tmp7 = xm_xor(tmp7, tmp8);
    tmp7 = xm_xor(tmp7, tmp9);
    tmp8 = xm_srli_si128_4(tmp7);      /* SSE: srli_si128(tmp7, 4) */
    tmp7 = xm_slli_si128_4(xm_slli_si128_8(tmp7));
    tmp3 = xm_xor(tmp3, tmp7);

    xm128 tmp2 = xm_srli_epi32_1(tmp3);
    xm128 tmp4b = xm_srli_epi32_2(tmp3);
    xm128 tmp5b = xm_srli_epi32_7(tmp3);
    tmp2 = xm_xor(tmp2, tmp4b);
    tmp2 = xm_xor(tmp2, tmp5b);
    tmp2 = xm_xor(tmp2, tmp8);
    tmp3 = xm_xor(tmp3, tmp2);
    tmp6 = xm_xor(tmp6, tmp3);

    return tmp6;
}

SPEER_PMULL_TARGET
void speer_ghash_pmull_init(speer_ghash_state_t *s, const uint8_t h[16]) {
    s->use_clmul = 0;
    s->use_pmull_arm = 1;
    s->use_vpclmul_x86 = 0;
    for (int i = 0; i < 16; i++) s->h[i] = h[i];
    xm128 hv = vreinterpretq_u64_u8(vld1q_u8(h));
    hv = xmm_bswap_be(hv);
    vst1q_u8(s->htables[0], vreinterpretq_u8_u64(hv));
    xm128 h2 = gfmul_pmull(hv, hv);
    xm128 h3 = gfmul_pmull(h2, hv);
    xm128 h4 = gfmul_pmull(h3, hv);
    vst1q_u8(s->htables[1], vreinterpretq_u8_u64(h2));
    vst1q_u8(s->htables[2], vreinterpretq_u8_u64(h3));
    vst1q_u8(s->htables[3], vreinterpretq_u8_u64(h4));
}

SPEER_PMULL_TARGET
void speer_ghash_pmull_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data,
                              size_t len) {
    xm128 h1 = vreinterpretq_u64_u8(vld1q_u8(s->htables[0]));
    xm128 h2 = vreinterpretq_u64_u8(vld1q_u8(s->htables[1]));
    xm128 h3 = vreinterpretq_u64_u8(vld1q_u8(s->htables[2]));
    xm128 h4 = vreinterpretq_u64_u8(vld1q_u8(s->htables[3]));
    xm128 yv = xmm_bswap_be(vreinterpretq_u64_u8(vld1q_u8(y)));

    while (len >= 64) {
        xm128 d0 = xmm_bswap_be(vreinterpretq_u64_u8(vld1q_u8(data)));
        xm128 d1 = xmm_bswap_be(vreinterpretq_u64_u8(vld1q_u8(data + 16)));
        xm128 d2 = xmm_bswap_be(vreinterpretq_u64_u8(vld1q_u8(data + 32)));
        xm128 d3 = xmm_bswap_be(vreinterpretq_u64_u8(vld1q_u8(data + 48)));

        xm128 yn = gfmul_pmull(yv, h4);
        yv = xm_xor(yn, gfmul_pmull(d0, h4));
        yv = xm_xor(yv, gfmul_pmull(d1, h3));
        yv = xm_xor(yv, gfmul_pmull(d2, h2));
        yv = xm_xor(yv, gfmul_pmull(d3, h1));

        data += 64;
        len -= 64;
    }
    while (len >= 16) {
        xm128 d = xmm_bswap_be(vreinterpretq_u64_u8(vld1q_u8(data)));
        yv = xm_xor(yv, d);
        yv = gfmul_pmull(yv, h1);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        uint8_t blk[16] = {0};
        for (size_t i = 0; i < len; i++) blk[i] = data[i];
        xm128 d = xmm_bswap_be(vreinterpretq_u64_u8(vld1q_u8(blk)));
        yv = xm_xor(yv, d);
        yv = gfmul_pmull(yv, h1);
    }
    vst1q_u8(y, vreinterpretq_u8_u64(xmm_bswap_be(yv)));
}

#else

void speer_ghash_pmull_init(speer_ghash_state_t *s, const uint8_t h[16]) {
    (void)s;
    (void)h;
}
void speer_ghash_pmull_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data,
                              size_t len) {
    (void)s;
    (void)y;
    (void)data;
    (void)len;
}

#endif
