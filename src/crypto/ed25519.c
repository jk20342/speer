#include "ed25519.h"

#include "speer_internal.h"

#include "ct_helpers.h"
#include "field25519.h"

typedef struct {
    fe25519 X, Y, Z, T;
} ge_p3;

static const fe25519 d = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
                          0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};

static const fe25519 ge_base_x = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                                  0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};

static const fe25519 ge_base_y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                                  0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};

static void ge_p3_0(ge_p3 *h) {
    fe25519_0(h->X);
    fe25519_1(h->Y);
    fe25519_1(h->Z);
    fe25519_0(h->T);
}

static void ge_double(ge_p3 *r, const ge_p3 *p) {
    fe25519 a, b, c, d_, e, f, g, h;
    fe25519_sq(a, p->X);
    fe25519_sq(b, p->Y);
    fe25519_sq(c, p->Z);
    fe25519_add(c, c, c);
    fe25519_neg(d_, a);
    fe25519_add(e, p->X, p->Y);
    fe25519_sq(e, e);
    fe25519_sub(e, e, a);
    fe25519_sub(e, e, b);
    fe25519_add(g, d_, b);
    fe25519_sub(f, g, c);
    fe25519_sub(h, d_, b);
    fe25519_mul(r->X, e, f);
    fe25519_mul(r->Y, g, h);
    fe25519_mul(r->T, e, h);
    fe25519_mul(r->Z, f, g);
}

static void ge_add(ge_p3 *r, const ge_p3 *p, const ge_p3 *q) {
    fe25519 a, b, c, d_, e, f, g, h, t;
    fe25519_sub(a, p->Y, p->X);
    fe25519_sub(t, q->Y, q->X);
    fe25519_mul(a, a, t);
    fe25519_add(b, p->Y, p->X);
    fe25519_add(t, q->Y, q->X);
    fe25519_mul(b, b, t);
    fe25519_mul(c, p->T, q->T);
    fe25519_mul(c, c, d);
    fe25519_add(c, c, c);
    fe25519_mul(d_, p->Z, q->Z);
    fe25519_add(d_, d_, d_);
    fe25519_sub(e, b, a);
    fe25519_sub(f, d_, c);
    fe25519_add(g, d_, c);
    fe25519_add(h, b, a);
    fe25519_mul(r->X, e, f);
    fe25519_mul(r->Y, g, h);
    fe25519_mul(r->T, e, h);
    fe25519_mul(r->Z, f, g);
}

static void ge_cswap(ge_p3 *a, ge_p3 *b, int swap) {
    fe25519_cswap(a->X, b->X, swap);
    fe25519_cswap(a->Y, b->Y, swap);
    fe25519_cswap(a->Z, b->Z, swap);
    fe25519_cswap(a->T, b->T, swap);
}

static void ge_scalarmult(ge_p3 *r, const uint8_t *scalar, const ge_p3 *p) {
    ge_p3 R0, R1;
    ge_p3_0(&R0);
    R1 = *p;
    for (int i = 255; i >= 0; i--) {
        int bit = (scalar[i / 8] >> (i & 7)) & 1;
        ge_cswap(&R0, &R1, bit);
        ge_p3 sum, doubled;
        ge_add(&sum, &R0, &R1);
        ge_double(&doubled, &R0);
        R1 = sum;
        R0 = doubled;
        ge_cswap(&R0, &R1, bit);
    }
    *r = R0;
}

static void ge_p3_tobytes(uint8_t s[32], const ge_p3 *p) {
    fe25519 recip, x, y;
    fe25519_invert(recip, p->Z);
    fe25519_mul(x, p->X, recip);
    fe25519_mul(y, p->Y, recip);
    fe25519_tobytes(s, y);
    s[31] |= (fe25519_isnegative(x) ? 0x80 : 0);
}

/* Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493 */
static const int64_t L_LIMBS[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                                    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                    0,    0,    0,    0,    0,    0,    0,    0,
                                    0,    0,    0,    0,    0,    0,    0,    0x10};

static void modL(uint8_t *r, int64_t x[64]) {
    int64_t carry;
    for (int i = 63; i >= 32; --i) {
        carry = 0;
        int j = i - 32;
        int k = i - 12;
        for (; j < k; ++j) {
            x[j] += carry - 16 * x[i] * L_LIMBS[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (int j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * L_LIMBS[j];
        carry = x[j] >> 8;
        x[j] &= 0xff;
    }
    for (int j = 0; j < 32; ++j) x[j] -= carry * L_LIMBS[j];
    for (int i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 0xff);
    }
}

static void sc_reduce(uint8_t *s) {
    int64_t x[64];
    for (int i = 0; i < 64; i++) x[i] = (uint64_t)s[i];
    for (int i = 0; i < 64; i++) s[i] = 0;
    modL(s, x);
}

static void sc_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c) {
    int64_t x[64];
    for (int i = 0; i < 64; i++) x[i] = 0;
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) { x[i + j] += (int64_t)a[i] * (int64_t)b[j]; }
    }
    for (int i = 0; i < 32; i++) x[i] += (int64_t)c[i];
    modL(s, x);
}

static int ge_frombytes_negate_vartime(ge_p3 *h, const uint8_t *s) {
    fe25519 u, v, v3, vxx, check;

    fe25519_frombytes(h->Y, s);
    fe25519_1(h->Z);
    fe25519_sq(u, h->Y);
    fe25519_mul(v, u, d);
    fe25519_sub(u, u, h->Z);
    fe25519_add(v, v, h->Z);

    fe25519_sq(v3, v);
    fe25519_mul(v3, v3, v);
    fe25519_sq(h->X, v3);
    fe25519_mul(h->X, h->X, v);
    fe25519_mul(h->X, h->X, u);

    fe25519_pow22523(h->X, h->X);
    fe25519_mul(h->X, h->X, v3);
    fe25519_mul(h->X, h->X, u);

    fe25519_sq(vxx, h->X);
    fe25519_mul(vxx, vxx, v);
    fe25519_sub(check, vxx, u);
    if (!fe25519_iszero(check)) {
        fe25519_add(check, vxx, u);
        if (!fe25519_iszero(check)) return -1;
        fe25519 sqrtm1 = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
                          0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};
        fe25519_mul(h->X, h->X, sqrtm1);
    }

    if (fe25519_isnegative(h->X) == ((s[31] >> 7) ? 1 : 0)) { fe25519_neg(h->X, h->X); }
    fe25519_mul(h->T, h->X, h->Y);
    return 0;
}

void speer_ed25519_keypair(uint8_t pk[32], uint8_t sk[32], const uint8_t seed[32]) {
    uint8_t h[64];
    speer_sha512(h, seed, 32);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;

    ge_p3 base, A;
    fe25519_copy(base.X, ge_base_x);
    fe25519_copy(base.Y, ge_base_y);
    fe25519_1(base.Z);
    fe25519_mul(base.T, ge_base_x, ge_base_y);

    ge_scalarmult(&A, h, &base);
    ge_p3_tobytes(pk, &A);
    COPY(sk, seed, 32);
}

void speer_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t pk[32],
                        const uint8_t sk[32]) {
    uint8_t h[64];
    speer_sha512(h, sk, 32);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;

    sha512_ctx_t hctx;
    uint8_t r_hash[64];
    speer_sha512_init(&hctx);
    speer_sha512_update(&hctx, h + 32, 32);
    if (msg_len > 0) speer_sha512_update(&hctx, msg, msg_len);
    speer_sha512_final(&hctx, r_hash);
    sc_reduce(r_hash);

    ge_p3 base, R;
    fe25519_copy(base.X, ge_base_x);
    fe25519_copy(base.Y, ge_base_y);
    fe25519_1(base.Z);
    fe25519_mul(base.T, ge_base_x, ge_base_y);
    ge_scalarmult(&R, r_hash, &base);
    ge_p3_tobytes(sig, &R);

    uint8_t k[64];
    speer_sha512_init(&hctx);
    speer_sha512_update(&hctx, sig, 32);
    speer_sha512_update(&hctx, pk, 32);
    if (msg_len > 0) speer_sha512_update(&hctx, msg, msg_len);
    speer_sha512_final(&hctx, k);
    sc_reduce(k);

    sc_muladd(sig + 32, k, h, r_hash);

    WIPE(h, 64);
    WIPE(r_hash, 64);
    WIPE(k, 64);
    WIPE(&hctx, sizeof(hctx));
}

int speer_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                         const uint8_t pk[32]) {
    if (sig[63] & 0xe0) return -1;

    ge_p3 A;
    if (ge_frombytes_negate_vartime(&A, pk) != 0) return -1;

    sha512_ctx_t hctx;
    uint8_t k[64];
    speer_sha512_init(&hctx);
    speer_sha512_update(&hctx, sig, 32);
    speer_sha512_update(&hctx, pk, 32);
    if (msg_len > 0) speer_sha512_update(&hctx, msg, msg_len);
    speer_sha512_final(&hctx, k);
    sc_reduce(k);

    ge_p3 base, sB, kA, R;
    fe25519_copy(base.X, ge_base_x);
    fe25519_copy(base.Y, ge_base_y);
    fe25519_1(base.Z);
    fe25519_mul(base.T, ge_base_x, ge_base_y);

    ge_scalarmult(&sB, sig + 32, &base);
    ge_scalarmult(&kA, k, &A);
    ge_add(&R, &sB, &kA);

    uint8_t check[32];
    ge_p3_tobytes(check, &R);

    if (!speer_ct_memeq(check, sig, 32)) return -1;
    return 0;
}
