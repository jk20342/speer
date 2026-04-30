#include "ecdsa_p256.h"

#include "speer_internal.h"

#include "bignum.h"

static const uint8_t P256_P[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t P256_N[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
                                   0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
static const uint8_t P256_A[32] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
static const uint8_t P256_B[32] = {0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd,
                                   0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53,
                                   0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b};
static const uint8_t P256_GX[32] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
                                    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
                                    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
                                    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
static const uint8_t P256_GY[32] = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
                                    0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
                                    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
                                    0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};

typedef struct {
    speer_bn_t x, y, z;
    int infinity;
} pt_t;

static speer_bn_t bn_p, bn_n, bn_a, bn_b;
static int p256_initialized = 0;

static void p256_init(void) {
    if (p256_initialized) return;
    speer_bn_from_bytes_be(&bn_p, P256_P, 32);
    speer_bn_from_bytes_be(&bn_n, P256_N, 32);
    speer_bn_from_bytes_be(&bn_a, P256_A, 32);
    speer_bn_from_bytes_be(&bn_b, P256_B, 32);
    p256_initialized = 1;
}

static void pt_set_zero(pt_t *p) {
    speer_bn_zero(&p->x);
    speer_bn_zero(&p->y);
    p->y.limbs[0] = 1;
    p->y.n = 1;
    speer_bn_zero(&p->z);
    p->infinity = 1;
}

static void pt_double(pt_t *r, const pt_t *p) {
    if (p->infinity) {
        *r = *p;
        return;
    }
    /* affine doubling for simplicity (slow but correct) */
    speer_bn_t two_y, three_x2, lam, x2, x2_a, num, inv_den, t;
    speer_bn_addmod(&two_y, &p->y, &p->y, &bn_p);
    if (speer_bn_is_zero(&two_y)) {
        pt_set_zero(r);
        return;
    }
    speer_bn_mulmod(&x2, &p->x, &p->x, &bn_p);
    speer_bn_addmod(&three_x2, &x2, &x2, &bn_p);
    speer_bn_addmod(&three_x2, &three_x2, &x2, &bn_p);
    speer_bn_addmod(&num, &three_x2, &bn_a, &bn_p);
    speer_bn_modinv(&inv_den, &two_y, &bn_p);
    speer_bn_mulmod(&lam, &num, &inv_den, &bn_p);
    speer_bn_t lam2;
    speer_bn_mulmod(&lam2, &lam, &lam, &bn_p);
    speer_bn_t two_x;
    speer_bn_addmod(&two_x, &p->x, &p->x, &bn_p);
    speer_bn_t rx;
    speer_bn_submod(&rx, &lam2, &two_x, &bn_p);
    speer_bn_t diff;
    speer_bn_submod(&diff, &p->x, &rx, &bn_p);
    speer_bn_t t2;
    speer_bn_mulmod(&t2, &lam, &diff, &bn_p);
    speer_bn_t ry;
    speer_bn_submod(&ry, &t2, &p->y, &bn_p);
    speer_bn_copy(&r->x, &rx);
    speer_bn_copy(&r->y, &ry);
    r->infinity = 0;
    (void)x2_a;
    (void)t;
}

static void pt_add(pt_t *r, const pt_t *p, const pt_t *q) {
    if (p->infinity) {
        *r = *q;
        return;
    }
    if (q->infinity) {
        *r = *p;
        return;
    }
    if (speer_bn_cmp(&p->x, &q->x) == 0) {
        speer_bn_t sum;
        speer_bn_addmod(&sum, &p->y, &q->y, &bn_p);
        if (speer_bn_is_zero(&sum)) {
            pt_set_zero(r);
            return;
        }
        pt_double(r, p);
        return;
    }
    speer_bn_t dy, dx, inv_dx, lam, lam2, sum_x, rx, diff_x, t, ry;
    speer_bn_submod(&dy, &q->y, &p->y, &bn_p);
    speer_bn_submod(&dx, &q->x, &p->x, &bn_p);
    speer_bn_modinv(&inv_dx, &dx, &bn_p);
    speer_bn_mulmod(&lam, &dy, &inv_dx, &bn_p);
    speer_bn_mulmod(&lam2, &lam, &lam, &bn_p);
    speer_bn_addmod(&sum_x, &p->x, &q->x, &bn_p);
    speer_bn_submod(&rx, &lam2, &sum_x, &bn_p);
    speer_bn_submod(&diff_x, &p->x, &rx, &bn_p);
    speer_bn_mulmod(&t, &lam, &diff_x, &bn_p);
    speer_bn_submod(&ry, &t, &p->y, &bn_p);
    speer_bn_copy(&r->x, &rx);
    speer_bn_copy(&r->y, &ry);
    r->infinity = 0;
}

static void pt_scalar_mul(pt_t *r, const pt_t *base, const speer_bn_t *k) {
    pt_t res;
    pt_set_zero(&res);
    pt_t cur = *base;
    size_t bits = speer_bn_bit_size(k);
    for (size_t i = 0; i < bits; i++) {
        if (speer_bn_get_bit(k, i)) {
            pt_t t;
            pt_add(&t, &res, &cur);
            res = t;
        }
        pt_t t;
        pt_double(&t, &cur);
        cur = t;
    }
    *r = res;
}

int speer_ecdsa_p256_verify(const uint8_t pubkey[64], const uint8_t *msg_hash, size_t msg_hash_len,
                            const uint8_t *sig_r, size_t sig_r_len, const uint8_t *sig_s,
                            size_t sig_s_len) {
    p256_init();

    speer_bn_t r, s;
    if (speer_bn_from_bytes_be(&r, sig_r, sig_r_len) != 0) return -1;
    if (speer_bn_from_bytes_be(&s, sig_s, sig_s_len) != 0) return -1;
    if (speer_bn_is_zero(&r) || speer_bn_cmp(&r, &bn_n) >= 0) return -1;
    if (speer_bn_is_zero(&s) || speer_bn_cmp(&s, &bn_n) >= 0) return -1;

    speer_bn_t e;
    if (msg_hash_len > 32) msg_hash_len = 32;
    speer_bn_from_bytes_be(&e, msg_hash, msg_hash_len);

    speer_bn_t s_inv;
    if (speer_bn_modinv(&s_inv, &s, &bn_n) != 0) return -1;

    speer_bn_t u1, u2;
    speer_bn_mulmod(&u1, &e, &s_inv, &bn_n);
    speer_bn_mulmod(&u2, &r, &s_inv, &bn_n);

    pt_t G, Q;
    speer_bn_from_bytes_be(&G.x, P256_GX, 32);
    speer_bn_from_bytes_be(&G.y, P256_GY, 32);
    G.infinity = 0;

    speer_bn_from_bytes_be(&Q.x, pubkey, 32);
    speer_bn_from_bytes_be(&Q.y, pubkey + 32, 32);
    Q.infinity = 0;

    pt_t u1G, u2Q, R;
    pt_scalar_mul(&u1G, &G, &u1);
    pt_scalar_mul(&u2Q, &Q, &u2);
    pt_add(&R, &u1G, &u2Q);

    if (R.infinity) return -1;

    speer_bn_t rx_mod_n;
    speer_bn_mod(&rx_mod_n, &R.x, &bn_n);

    if (speer_bn_cmp(&rx_mod_n, &r) != 0) return -1;
    return 0;
}
