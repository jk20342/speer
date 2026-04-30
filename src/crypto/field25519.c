#include "field25519.h"

#include "speer_internal.h"

#define MASK51 ((uint64_t)0x0007FFFFFFFFFFFFULL)

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 u128;
#define HAVE_U128 1
#endif

void fe25519_0(fe25519 r) {
    r[0] = r[1] = r[2] = r[3] = r[4] = 0;
}

void fe25519_1(fe25519 r) {
    r[0] = 1;
    r[1] = r[2] = r[3] = r[4] = 0;
}

void fe25519_copy(fe25519 r, const fe25519 a) {
    r[0] = a[0];
    r[1] = a[1];
    r[2] = a[2];
    r[3] = a[3];
    r[4] = a[4];
}

void fe25519_add(fe25519 r, const fe25519 a, const fe25519 b) {
    r[0] = a[0] + b[0];
    r[1] = a[1] + b[1];
    r[2] = a[2] + b[2];
    r[3] = a[3] + b[3];
    r[4] = a[4] + b[4];
}

static const uint64_t FOUR_P0 = 0x1FFFFFFFFFFFB4ULL;
static const uint64_t FOUR_PN = 0x1FFFFFFFFFFFFCULL;

void fe25519_sub(fe25519 r, const fe25519 a, const fe25519 b) {
    r[0] = a[0] + FOUR_P0 - b[0];
    r[1] = a[1] + FOUR_PN - b[1];
    r[2] = a[2] + FOUR_PN - b[2];
    r[3] = a[3] + FOUR_PN - b[3];
    r[4] = a[4] + FOUR_PN - b[4];
}

void fe25519_neg(fe25519 r, const fe25519 a) {
    r[0] = FOUR_P0 - a[0];
    r[1] = FOUR_PN - a[1];
    r[2] = FOUR_PN - a[2];
    r[3] = FOUR_PN - a[3];
    r[4] = FOUR_PN - a[4];
}

#if defined(HAVE_U128)
static INLINE void fe25519_reduce_u128(fe25519 r, u128 t[5]) {
    u128 c;
    t[1] += (uint64_t)(t[0] >> 51);
    uint64_t r0 = (uint64_t)t[0] & MASK51;
    t[2] += (uint64_t)(t[1] >> 51);
    uint64_t r1 = (uint64_t)t[1] & MASK51;
    t[3] += (uint64_t)(t[2] >> 51);
    uint64_t r2 = (uint64_t)t[2] & MASK51;
    t[4] += (uint64_t)(t[3] >> 51);
    uint64_t r3 = (uint64_t)t[3] & MASK51;
    c = t[4] >> 51;
    uint64_t r4 = (uint64_t)t[4] & MASK51;
    r0 += (uint64_t)(c * 19);
    r1 += r0 >> 51;
    r0 &= MASK51;
    r[0] = r0;
    r[1] = r1;
    r[2] = r2;
    r[3] = r3;
    r[4] = r4;
}

void fe25519_mul(fe25519 r, const fe25519 a, const fe25519 b) {
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    uint64_t b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4];
    uint64_t b1_19 = b1 * 19;
    uint64_t b2_19 = b2 * 19;
    uint64_t b3_19 = b3 * 19;
    uint64_t b4_19 = b4 * 19;

    u128 t[5];
    t[0] = (u128)a0 * b0 + (u128)a1 * b4_19 + (u128)a2 * b3_19 + (u128)a3 * b2_19 +
           (u128)a4 * b1_19;
    t[1] = (u128)a0 * b1 + (u128)a1 * b0 + (u128)a2 * b4_19 + (u128)a3 * b3_19 + (u128)a4 * b2_19;
    t[2] = (u128)a0 * b2 + (u128)a1 * b1 + (u128)a2 * b0 + (u128)a3 * b4_19 + (u128)a4 * b3_19;
    t[3] = (u128)a0 * b3 + (u128)a1 * b2 + (u128)a2 * b1 + (u128)a3 * b0 + (u128)a4 * b4_19;
    t[4] = (u128)a0 * b4 + (u128)a1 * b3 + (u128)a2 * b2 + (u128)a3 * b1 + (u128)a4 * b0;

    fe25519_reduce_u128(r, t);
}

void fe25519_sq(fe25519 r, const fe25519 a) {
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    uint64_t a0_2 = a0 * 2;
    uint64_t a1_2 = a1 * 2;
    uint64_t a3_19 = a3 * 19;
    uint64_t a4_19 = a4 * 19;

    u128 t[5];
    t[0] = (u128)a0 * a0 + (u128)a1_2 * a4_19 + (u128)(a2 * 2) * a3_19;
    t[1] = (u128)a0_2 * a1 + (u128)a2 * a4_19 * 2 + (u128)a3 * a3_19;
    t[2] = (u128)a0_2 * a2 + (u128)a1 * a1 + (u128)(a3 * 2) * a4_19;
    t[3] = (u128)a0_2 * a3 + (u128)a1_2 * a2 + (u128)a4 * a4_19;
    t[4] = (u128)a0_2 * a4 + (u128)a1_2 * a3 + (u128)a2 * a2;

    fe25519_reduce_u128(r, t);
}

#else

void fe25519_mul(fe25519 r, const fe25519 a, const fe25519 b) {
    (void)r;
    (void)a;
    (void)b;
}
void fe25519_sq(fe25519 r, const fe25519 a) {
    fe25519_mul(r, a, a);
}

#endif

void fe25519_cswap(fe25519 a, fe25519 b, int swap) {
    uint64_t mask = (uint64_t)(0 - (int64_t)(swap & 1));
    for (int i = 0; i < 5; i++) {
        uint64_t t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

void fe25519_frombytes(fe25519 r, const uint8_t in[32]) {
    uint64_t w0 = LOAD64_LE(in + 0);
    uint64_t w1 = LOAD64_LE(in + 8);
    uint64_t w2 = LOAD64_LE(in + 16);
    uint64_t w3 = LOAD64_LE(in + 24);
    r[0] = w0 & MASK51;
    r[1] = ((w0 >> 51) | (w1 << 13)) & MASK51;
    r[2] = ((w1 >> 38) | (w2 << 26)) & MASK51;
    r[3] = ((w2 >> 25) | (w3 << 39)) & MASK51;
    r[4] = (w3 >> 12) & 0x7FFFFFFFFFFFFULL;
}

static void fe25519_carry_full(fe25519 r) {
    uint64_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
    r1 += r0 >> 51;
    r0 &= MASK51;
    r2 += r1 >> 51;
    r1 &= MASK51;
    r3 += r2 >> 51;
    r2 &= MASK51;
    r4 += r3 >> 51;
    r3 &= MASK51;
    r0 += 19 * (r4 >> 51);
    r4 &= MASK51;
    r1 += r0 >> 51;
    r0 &= MASK51;
    r[0] = r0;
    r[1] = r1;
    r[2] = r2;
    r[3] = r3;
    r[4] = r4;
}

void fe25519_tobytes(uint8_t out[32], const fe25519 a) {
    fe25519 t;
    fe25519_copy(t, a);
    fe25519_carry_full(t);
    fe25519_carry_full(t);

    uint64_t q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;

    t[0] += 19 * q;

    uint64_t c;
    c = t[0] >> 51;
    t[0] &= MASK51;
    t[1] += c;
    c = t[1] >> 51;
    t[1] &= MASK51;
    t[2] += c;
    c = t[2] >> 51;
    t[2] &= MASK51;
    t[3] += c;
    c = t[3] >> 51;
    t[3] &= MASK51;
    t[4] += c;
    t[4] &= MASK51;

    uint64_t w0 = t[0] | (t[1] << 51);
    uint64_t w1 = (t[1] >> 13) | (t[2] << 38);
    uint64_t w2 = (t[2] >> 26) | (t[3] << 25);
    uint64_t w3 = (t[3] >> 39) | (t[4] << 12);

    STORE64_LE(out + 0, w0);
    STORE64_LE(out + 8, w1);
    STORE64_LE(out + 16, w2);
    STORE64_LE(out + 24, w3);
}

int fe25519_iszero(const fe25519 a) {
    uint8_t s[32];
    fe25519_tobytes(s, a);
    uint8_t r = 0;
    for (int i = 0; i < 32; i++) r |= s[i];
    return r == 0;
}

int fe25519_isnegative(const fe25519 a) {
    uint8_t s[32];
    fe25519_tobytes(s, a);
    return s[0] & 1;
}

void fe25519_invert(fe25519 r, const fe25519 a) {
    fe25519 t0, t1, t2, t3;
    int i;

    fe25519_sq(t0, a);
    fe25519_sq(t1, t0);
    fe25519_sq(t1, t1);
    fe25519_mul(t1, a, t1);
    fe25519_mul(t0, t0, t1);
    fe25519_sq(t2, t0);
    fe25519_mul(t1, t1, t2);
    fe25519_sq(t2, t1);
    for (i = 1; i < 5; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t2, t1);
    for (i = 1; i < 10; i++) fe25519_sq(t2, t2);
    fe25519_mul(t2, t2, t1);
    fe25519_sq(t3, t2);
    for (i = 1; i < 20; i++) fe25519_sq(t3, t3);
    fe25519_mul(t2, t3, t2);
    fe25519_sq(t2, t2);
    for (i = 1; i < 10; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t2, t1);
    for (i = 1; i < 50; i++) fe25519_sq(t2, t2);
    fe25519_mul(t2, t2, t1);
    fe25519_sq(t3, t2);
    for (i = 1; i < 100; i++) fe25519_sq(t3, t3);
    fe25519_mul(t2, t3, t2);
    fe25519_sq(t2, t2);
    for (i = 1; i < 50; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1);
    for (i = 1; i < 5; i++) fe25519_sq(t1, t1);
    fe25519_mul(r, t1, t0);
}

void fe25519_pow22523(fe25519 r, const fe25519 a) {
    fe25519 t0, t1, t2;
    int i;

    fe25519_sq(t0, a);
    fe25519_sq(t1, t0);
    fe25519_sq(t1, t1);
    fe25519_mul(t1, a, t1);
    fe25519_mul(t0, t0, t1);
    fe25519_sq(t0, t0);
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0);
    for (i = 1; i < 5; i++) fe25519_sq(t1, t1);
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0);
    for (i = 1; i < 10; i++) fe25519_sq(t1, t1);
    fe25519_mul(t1, t1, t0);
    fe25519_sq(t2, t1);
    for (i = 1; i < 20; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1);
    for (i = 1; i < 10; i++) fe25519_sq(t1, t1);
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0);
    for (i = 1; i < 50; i++) fe25519_sq(t1, t1);
    fe25519_mul(t1, t1, t0);
    fe25519_sq(t2, t1);
    for (i = 1; i < 100; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1);
    for (i = 1; i < 50; i++) fe25519_sq(t1, t1);
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t0, t0);
    fe25519_sq(t0, t0);
    fe25519_mul(r, t0, a);
}
