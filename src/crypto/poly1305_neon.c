#include "speer_internal.h"

#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))

#include <arm_neon.h>

#define SPEER_POLY1305_NEON_TARGET __attribute__((target("+simd")))

SPEER_POLY1305_NEON_TARGET
void speer_poly1305_blocks_neon(uint32_t h[5], const uint32_t r[5], const uint8_t *m, size_t len,
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

        uint32_t a[4] = {h0, h1, h2, h3};
        uint32x4_t vh = vld1q_u32(a);

        uint32_t c0[4] = {r0, s4, s3, s2};
        uint64x2_t p0_lo = vmull_u32(vget_low_u32(vh), vget_low_u32(vld1q_u32(c0)));
        uint64x2_t p0_hi = vmull_u32(vget_high_u32(vh), vget_high_u32(vld1q_u32(c0)));
        uint64_t d0 = vgetq_lane_u64(p0_lo, 0) + vgetq_lane_u64(p0_lo, 1) + vgetq_lane_u64(p0_hi, 0) +
                      vgetq_lane_u64(p0_hi, 1) + (uint64_t)h4 * (uint64_t)s1;

        uint32_t c1[4] = {r1, r0, s4, s3};
        uint64x2_t p1_lo = vmull_u32(vget_low_u32(vh), vget_low_u32(vld1q_u32(c1)));
        uint64x2_t p1_hi = vmull_u32(vget_high_u32(vh), vget_high_u32(vld1q_u32(c1)));
        uint64_t d1 = vgetq_lane_u64(p1_lo, 0) + vgetq_lane_u64(p1_lo, 1) + vgetq_lane_u64(p1_hi, 0) +
                      vgetq_lane_u64(p1_hi, 1) + (uint64_t)h4 * (uint64_t)s2;

        uint32_t c2[4] = {r2, r1, r0, s4};
        uint64x2_t p2_lo = vmull_u32(vget_low_u32(vh), vget_low_u32(vld1q_u32(c2)));
        uint64x2_t p2_hi = vmull_u32(vget_high_u32(vh), vget_high_u32(vld1q_u32(c2)));
        uint64_t d2 = vgetq_lane_u64(p2_lo, 0) + vgetq_lane_u64(p2_lo, 1) + vgetq_lane_u64(p2_hi, 0) +
                      vgetq_lane_u64(p2_hi, 1) + (uint64_t)h4 * (uint64_t)s3;

        uint32_t c3[4] = {r3, r2, r1, r0};
        uint64x2_t p3_lo = vmull_u32(vget_low_u32(vh), vget_low_u32(vld1q_u32(c3)));
        uint64x2_t p3_hi = vmull_u32(vget_high_u32(vh), vget_high_u32(vld1q_u32(c3)));
        uint64_t d3 = vgetq_lane_u64(p3_lo, 0) + vgetq_lane_u64(p3_lo, 1) + vgetq_lane_u64(p3_hi, 0) +
                      vgetq_lane_u64(p3_hi, 1) + (uint64_t)h4 * (uint64_t)s4;

        uint32_t c4[4] = {r4, r3, r2, r1};
        uint64x2_t p4_lo = vmull_u32(vget_low_u32(vh), vget_low_u32(vld1q_u32(c4)));
        uint64x2_t p4_hi = vmull_u32(vget_high_u32(vh), vget_high_u32(vld1q_u32(c4)));
        uint64_t d4 =
            vgetq_lane_u64(p4_lo, 0) + vgetq_lane_u64(p4_lo, 1) + vgetq_lane_u64(p4_hi, 0) +
            vgetq_lane_u64(p4_hi, 1) + (uint64_t)h4 * (uint64_t)r0;

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
