#include "bignum.h"

#include "speer_internal.h"

#define LIMBS SPEER_BN_MAX_LIMBS

static void normalize(speer_bn_t *a) {
    while (a->n > 0 && a->limbs[a->n - 1] == 0) a->n--;
}

void speer_bn_zero(speer_bn_t *a) {
    ZERO(a->limbs, sizeof(a->limbs));
    a->n = 0;
}

void speer_bn_copy(speer_bn_t *r, const speer_bn_t *a) {
    *r = *a;
}

int speer_bn_from_bytes_be(speer_bn_t *a, const uint8_t *in, size_t len) {
    speer_bn_zero(a);
    while (len > 0 && in[0] == 0) {
        in++;
        len--;
    }
    if (len == 0) return 0;
    size_t need = (len + 3) / 4;
    if (need > LIMBS) return -1;
    a->n = need;
    for (size_t i = 0; i < len; i++) {
        size_t byte_idx_from_lsb = len - 1 - i;
        size_t limb = byte_idx_from_lsb / 4;
        size_t shift = (byte_idx_from_lsb & 3) * 8;
        a->limbs[limb] |= (uint32_t)in[i] << shift;
    }
    normalize(a);
    return 0;
}

int speer_bn_to_bytes_be(uint8_t *out, size_t out_len, const speer_bn_t *a) {
    size_t bs = speer_bn_byte_size(a);
    if (bs > out_len) return -1;
    ZERO(out, out_len);
    for (size_t i = 0; i < bs; i++) {
        size_t byte_idx_from_lsb = i;
        size_t limb = byte_idx_from_lsb / 4;
        size_t shift = (byte_idx_from_lsb & 3) * 8;
        out[out_len - 1 - i] = (uint8_t)((a->limbs[limb] >> shift) & 0xff);
    }
    return 0;
}

size_t speer_bn_byte_size(const speer_bn_t *a) {
    if (a->n == 0) return 0;
    uint32_t hi = a->limbs[a->n - 1];
    size_t b = 0;
    while (hi) {
        b++;
        hi >>= 8;
    }
    return (a->n - 1) * 4 + (b == 0 ? 1 : b);
}

int speer_bn_cmp(const speer_bn_t *a, const speer_bn_t *b) {
    if (a->n != b->n) return a->n > b->n ? 1 : -1;
    for (size_t i = a->n; i-- > 0;) {
        if (a->limbs[i] != b->limbs[i]) return a->limbs[i] > b->limbs[i] ? 1 : -1;
    }
    return 0;
}

int speer_bn_is_zero(const speer_bn_t *a) {
    return a->n == 0;
}

int speer_bn_is_odd(const speer_bn_t *a) {
    return a->n > 0 && (a->limbs[0] & 1);
}

int speer_bn_get_bit(const speer_bn_t *a, size_t i) {
    size_t limb = i / 32;
    size_t bit = i & 31;
    if (limb >= a->n) return 0;
    return (int)((a->limbs[limb] >> bit) & 1);
}

size_t speer_bn_bit_size(const speer_bn_t *a) {
    if (a->n == 0) return 0;
    uint32_t hi = a->limbs[a->n - 1];
    size_t b = 0;
    while (hi) {
        b++;
        hi >>= 1;
    }
    return (a->n - 1) * 32 + b;
}

void speer_bn_add(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *b) {
    size_t mx = a->n > b->n ? a->n : b->n;
    if (mx + 1 > LIMBS) return;
    uint64_t c = 0;
    for (size_t i = 0; i < mx; i++) {
        uint64_t av = i < a->n ? a->limbs[i] : 0;
        uint64_t bv = i < b->n ? b->limbs[i] : 0;
        uint64_t s = av + bv + c;
        r->limbs[i] = (uint32_t)s;
        c = s >> 32;
    }
    r->limbs[mx] = (uint32_t)c;
    r->n = mx + (c ? 1 : 0);
    for (size_t i = r->n; i < LIMBS; i++) r->limbs[i] = 0;
    normalize(r);
}

int speer_bn_sub(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *b) {
    if (speer_bn_cmp(a, b) < 0) return -1;
    int64_t br = 0;
    for (size_t i = 0; i < a->n; i++) {
        uint64_t bv = i < b->n ? b->limbs[i] : 0;
        int64_t s = (int64_t)a->limbs[i] - (int64_t)bv - br;
        if (s < 0) {
            s += (int64_t)1 << 32;
            br = 1;
        } else
            br = 0;
        r->limbs[i] = (uint32_t)s;
    }
    r->n = a->n;
    for (size_t i = r->n; i < LIMBS; i++) r->limbs[i] = 0;
    normalize(r);
    return 0;
}

void speer_bn_shr1(speer_bn_t *a) {
    uint32_t c = 0;
    for (size_t i = a->n; i-- > 0;) {
        uint32_t nc = a->limbs[i] & 1;
        a->limbs[i] = (a->limbs[i] >> 1) | (c << 31);
        c = nc;
    }
    normalize(a);
}

void speer_bn_shl1(speer_bn_t *a) {
    uint32_t c = 0;
    for (size_t i = 0; i < a->n; i++) {
        uint32_t nc = a->limbs[i] >> 31;
        a->limbs[i] = (a->limbs[i] << 1) | c;
        c = nc;
    }
    if (c && a->n < LIMBS) { a->limbs[a->n++] = c; }
}

static void shl_n_bits(speer_bn_t *a, size_t shift) {
    if (shift == 0 || a->n == 0) return;
    size_t limb_shift = shift / 32;
    size_t bit_shift = shift & 31;

    if (bit_shift > 0) {
        uint32_t carry = 0;
        for (size_t i = 0; i < a->n; i++) {
            uint32_t v = a->limbs[i];
            a->limbs[i] = (v << bit_shift) | carry;
            carry = v >> (32 - bit_shift);
        }
        if (carry && a->n < LIMBS) { a->limbs[a->n++] = carry; }
    }

    if (limb_shift > 0) {
        size_t new_n = a->n + limb_shift;
        if (new_n > LIMBS) new_n = LIMBS;
        for (size_t i = new_n; i > limb_shift;) {
            i--;
            size_t src = i - limb_shift;
            a->limbs[i] = (src < a->n) ? a->limbs[src] : 0;
        }
        for (size_t i = 0; i < limb_shift && i < new_n; i++) a->limbs[i] = 0;
        a->n = new_n;
    }

    while (a->n > 0 && a->limbs[a->n - 1] == 0) a->n--;
}

void speer_bn_mod(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *m) {
    speer_bn_copy(r, a);
    if (m->n == 0) return;
    while (speer_bn_cmp(r, m) >= 0) {
        size_t shift = speer_bn_bit_size(r) - speer_bn_bit_size(m);
        speer_bn_t t = *m;
        shl_n_bits(&t, shift);
        if (speer_bn_cmp(r, &t) < 0) speer_bn_shr1(&t);
        speer_bn_t tmp;
        if (speer_bn_sub(&tmp, r, &t) == 0) {
            speer_bn_copy(r, &tmp);
        } else {
            break;
        }
    }
}

void speer_bn_addmod(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *b, const speer_bn_t *m) {
    speer_bn_t s;
    speer_bn_add(&s, a, b);
    speer_bn_mod(r, &s, m);
}

void speer_bn_submod(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *b, const speer_bn_t *m) {
    speer_bn_t am, bm, t;
    speer_bn_mod(&am, a, m);
    speer_bn_mod(&bm, b, m);
    if (speer_bn_cmp(&am, &bm) >= 0) {
        speer_bn_sub(&t, &am, &bm);
        speer_bn_copy(r, &t);
    } else {
        speer_bn_t mb;
        speer_bn_zero(&mb);
        speer_bn_sub(&mb, m, &bm);
        speer_bn_add(&t, &am, &mb);
        speer_bn_mod(r, &t, m);
    }
}

void speer_bn_mulmod(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *b, const speer_bn_t *m) {
    /* schoolbook multiplication with reduction */
    uint32_t prod[2 * LIMBS] = {0};
    size_t n = a->n + b->n;
    if (n > 2 * LIMBS) return;
    for (size_t i = 0; i < a->n; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b->n; j++) {
            uint64_t v = (uint64_t)prod[i + j] + (uint64_t)a->limbs[i] * b->limbs[j] + carry;
            prod[i + j] = (uint32_t)v;
            carry = v >> 32;
        }
        prod[i + b->n] += (uint32_t)carry;
    }
    speer_bn_t big;
    speer_bn_zero(&big);
    big.n = n;
    if (big.n > LIMBS) big.n = LIMBS;
    for (size_t i = 0; i < big.n; i++) big.limbs[i] = prod[i];
    if (n > LIMBS) {
        speer_bn_t rem;
        speer_bn_zero(&rem);
        for (size_t bit = 2 * LIMBS * 32; bit-- > 0;) {
            speer_bn_shl1(&rem);
            size_t limb = bit / 32;
            size_t b_idx = bit & 31;
            uint32_t bit_val = (prod[limb] >> b_idx) & 1u;
            rem.limbs[0] |= bit_val;
            if (bit_val) {
                size_t k = LIMBS;
                while (k > 0 && rem.limbs[k - 1] == 0) k--;
                rem.n = k;
            }
            if (speer_bn_cmp(&rem, m) >= 0) {
                speer_bn_t t;
                speer_bn_sub(&t, &rem, m);
                speer_bn_copy(&rem, &t);
            }
        }
        speer_bn_copy(r, &rem);
        return;
    }
    speer_bn_mod(r, &big, m);
}

static void bn_cswap(speer_bn_t *a, speer_bn_t *b, int swap) {
    uint32_t mask = (uint32_t)(0u - (uint32_t)(swap & 1));
    for (size_t i = 0; i < LIMBS; i++) {
        uint32_t t = mask & (a->limbs[i] ^ b->limbs[i]);
        a->limbs[i] ^= t;
        b->limbs[i] ^= t;
    }
    size_t na = a->n;
    size_t nb = b->n;
    size_t mask_sz = (size_t)0 - (size_t)(swap & 1);
    size_t ts = (na ^ nb) & mask_sz;
    a->n = na ^ ts;
    b->n = nb ^ ts;
}

void speer_bn_modexp(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *e, const speer_bn_t *m) {
    speer_bn_t R0, R1, base;
    speer_bn_zero(&R0);
    R0.limbs[0] = 1;
    R0.n = 1;
    speer_bn_mod(&base, a, m);
    speer_bn_copy(&R1, &base);

    size_t bits = speer_bn_bit_size(e);
    if (bits == 0) {
        speer_bn_copy(r, &R0);
        return;
    }

    for (size_t i = bits; i-- > 0;) {
        int bit = speer_bn_get_bit(e, i);
        bn_cswap(&R0, &R1, bit);
        speer_bn_t t1, t2;
        speer_bn_mulmod(&t1, &R0, &R1, m);
        speer_bn_mulmod(&t2, &R0, &R0, m);
        speer_bn_copy(&R1, &t1);
        speer_bn_copy(&R0, &t2);
        bn_cswap(&R0, &R1, bit);
    }
    speer_bn_copy(r, &R0);
}

int speer_bn_modinv(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *m) {
    if (!speer_bn_is_odd(m)) return -1;
    speer_bn_t u, v, x1, x2, mm;
    speer_bn_copy(&u, a);
    speer_bn_copy(&v, m);
    speer_bn_copy(&mm, m);
    speer_bn_zero(&x1);
    x1.limbs[0] = 1;
    x1.n = 1;
    speer_bn_zero(&x2);

    while (!speer_bn_is_zero(&u) && !speer_bn_is_zero(&v)) {
        while (!speer_bn_is_odd(&u)) {
            speer_bn_shr1(&u);
            if (speer_bn_is_odd(&x1)) {
                speer_bn_t t;
                speer_bn_add(&t, &x1, &mm);
                speer_bn_copy(&x1, &t);
            }
            speer_bn_shr1(&x1);
        }
        while (!speer_bn_is_odd(&v)) {
            speer_bn_shr1(&v);
            if (speer_bn_is_odd(&x2)) {
                speer_bn_t t;
                speer_bn_add(&t, &x2, &mm);
                speer_bn_copy(&x2, &t);
            }
            speer_bn_shr1(&x2);
        }
        if (speer_bn_cmp(&u, &v) >= 0) {
            speer_bn_t t;
            speer_bn_sub(&t, &u, &v);
            speer_bn_copy(&u, &t);
            speer_bn_submod(&x1, &x1, &x2, &mm);
        } else {
            speer_bn_t t;
            speer_bn_sub(&t, &v, &u);
            speer_bn_copy(&v, &t);
            speer_bn_submod(&x2, &x2, &x1, &mm);
        }
    }
    if (speer_bn_is_zero(&v)) return -1;
    speer_bn_copy(r, &x2);
    return 0;
}
