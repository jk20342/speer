#include "speer_internal.h"
#include "field25519.h"

void fe25519_0(fe25519 r) {
    for (int i = 0; i < 16; i++) r[i] = 0;
}

void fe25519_1(fe25519 r) {
    r[0] = 1;
    for (int i = 1; i < 16; i++) r[i] = 0;
}

void fe25519_copy(fe25519 r, const fe25519 a) {
    for (int i = 0; i < 16; i++) r[i] = a[i];
}

void fe25519_add(fe25519 r, const fe25519 a, const fe25519 b) {
    for (int i = 0; i < 16; i++) r[i] = a[i] + b[i];
}

void fe25519_sub(fe25519 r, const fe25519 a, const fe25519 b) {
    for (int i = 0; i < 16; i++) r[i] = a[i] - b[i];
}

void fe25519_neg(fe25519 r, const fe25519 a) {
    for (int i = 0; i < 16; i++) r[i] = -a[i];
}

static void fe25519_carry(fe25519 r) {
    for (int i = 0; i < 16; i++) {
        r[i] += 1LL << 16;
        int64_t c = r[i] >> 16;
        r[(i + 1) & 15] += c - 1 + 37 * (c - 1) * (i == 15);
        r[i] -= c << 16;
    }
}

void fe25519_mul(fe25519 r, const fe25519 a, const fe25519 b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    }
    for (int i = 30; i >= 16; i--) t[i - 16] += 38 * t[i];
    for (int i = 0; i < 16; i++) r[i] = t[i];
    fe25519_carry(r);
    fe25519_carry(r);
}

void fe25519_sq(fe25519 r, const fe25519 a) {
    fe25519_mul(r, a, a);
}

void fe25519_invert(fe25519 r, const fe25519 a) {
    fe25519 c;
    fe25519_copy(c, a);
    for (int i = 253; i >= 0; i--) {
        fe25519_sq(c, c);
        if (i != 2 && i != 4) fe25519_mul(c, c, a);
    }
    fe25519_copy(r, c);
}

void fe25519_pow22523(fe25519 r, const fe25519 a) {
    fe25519 t0, t1, t2;
    int i;

    fe25519_sq(t0, a);
    fe25519_sq(t1, t0); for (i = 1; i < 2; i++) fe25519_sq(t1, t1);
    fe25519_mul(t1, a, t1);
    fe25519_mul(t0, t0, t1);
    fe25519_sq(t0, t0);
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0); for (i = 1; i < 5; i++) fe25519_sq(t1, t1);
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0); for (i = 1; i < 10; i++) fe25519_sq(t1, t1);
    fe25519_mul(t1, t1, t0);
    fe25519_sq(t2, t1); for (i = 1; i < 20; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1); for (i = 1; i < 10; i++) fe25519_sq(t1, t1);
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t1, t0); for (i = 1; i < 50; i++) fe25519_sq(t1, t1);
    fe25519_mul(t1, t1, t0);
    fe25519_sq(t2, t1); for (i = 1; i < 100; i++) fe25519_sq(t2, t2);
    fe25519_mul(t1, t2, t1);
    fe25519_sq(t1, t1); for (i = 1; i < 50; i++) fe25519_sq(t1, t1);
    fe25519_mul(t0, t1, t0);
    fe25519_sq(t0, t0); for (i = 1; i < 2; i++) fe25519_sq(t0, t0);
    fe25519_mul(r, t0, a);
}

void fe25519_cswap(fe25519 a, fe25519 b, int swap) {
    int64_t mask = -(int64_t)(swap & 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

void fe25519_frombytes(fe25519 r, const uint8_t in[32]) {
    for (int i = 0; i < 16; i++) r[i] = (int64_t)in[2 * i] + ((int64_t)in[2 * i + 1] << 8);
    r[15] &= 0x7fff;
}

void fe25519_tobytes(uint8_t out[32], const fe25519 a) {
    fe25519 t, m;
    fe25519_copy(t, a);
    fe25519_carry(t); fe25519_carry(t); fe25519_carry(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        fe25519_cswap(t, m, (int)(1 - b));
    }
    for (int i = 0; i < 16; i++) {
        out[2 * i] = (uint8_t)(t[i] & 0xff);
        out[2 * i + 1] = (uint8_t)((t[i] >> 8) & 0xff);
    }
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
