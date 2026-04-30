#include "speer_internal.h"

static const uint32_t chacha_const[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

static INLINE uint32_t load32(const uint8_t *p) {
    return LOAD32_LE(p);
}

static INLINE void store32(uint8_t *p, uint32_t v) {
    STORE32_LE(p, v);
}

static INLINE uint32_t rotl32(uint32_t x, int n) {
    return ROTL32(x, n);
}

#define QR(a, b, c, d)         \
    do {                       \
        a += b;                \
        d = rotl32(d ^ a, 16); \
        c += d;                \
        b = rotl32(b ^ c, 12); \
        a += b;                \
        d = rotl32(d ^ a, 8);  \
        c += d;                \
        b = rotl32(b ^ c, 7);  \
    } while (0)

#define ROUNDS 20

void speer_chacha_init(speer_chacha_ctx_t *ctx, const uint8_t key[32], const uint8_t nonce[12]) {
    ctx->state[0] = chacha_const[0];
    ctx->state[1] = chacha_const[1];
    ctx->state[2] = chacha_const[2];
    ctx->state[3] = chacha_const[3];
    ctx->state[4] = load32(key + 0);
    ctx->state[5] = load32(key + 4);
    ctx->state[6] = load32(key + 8);
    ctx->state[7] = load32(key + 12);
    ctx->state[8] = load32(key + 16);
    ctx->state[9] = load32(key + 20);
    ctx->state[10] = load32(key + 24);
    ctx->state[11] = load32(key + 28);
    ctx->state[12] = 0;
    ctx->state[13] = load32(nonce + 0);
    ctx->state[14] = load32(nonce + 4);
    ctx->state[15] = load32(nonce + 8);
    ctx->idx = 64;
}

void speer_chacha_block(speer_chacha_ctx_t *ctx, uint8_t out[64]) {
    uint32_t x[16];
    uint32_t *s = ctx->state;

    for (int i = 0; i < 16; i++) x[i] = s[i];

    for (int i = 0; i < ROUNDS; i += 2) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }

    for (int i = 0; i < 16; i++) x[i] += s[i];

    for (int i = 0; i < 16; i++) store32(out + 4 * i, x[i]);

    s[12]++;
    if (UNLIKELY(s[12] == 0)) s[13]++;
}

void speer_chacha_crypt(speer_chacha_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t len) {
    uint8_t buf[64];

    while (len > 0) {
        if (ctx->idx == 64) {
            speer_chacha_block(ctx, buf);
            ctx->idx = 0;
        }

        size_t n = MIN(len, 64 - ctx->idx);
        for (size_t i = 0; i < n; i++) { out[i] = in[i] ^ buf[ctx->idx + i]; }

        out += n;
        in += n;
        len -= n;
        ctx->idx += n;
    }
}

static void poly1305_blocks(uint32_t h[5], uint32_t r[5], const uint8_t *m, size_t len,
                            uint32_t padbit) {
    const uint32_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
    const uint32_t s1 = r0 * 5, s2 = r1 * 5, s3 = r2 * 5, s4 = r3 * 5;
    uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];

    while (len >= 16) {
        uint64_t t0 = load32(m + 0);
        uint64_t t1 = load32(m + 4);
        uint64_t t2 = load32(m + 8);
        uint64_t t3 = load32(m + 12);

        h0 += (t0) & 0x3ffffff;
        h1 += ((((t1) << 32) | (t0)) >> 26) & 0x3ffffff;
        h2 += ((((t2) << 32) | (t1)) >> 20) & 0x3ffffff;
        h3 += ((((t3) << 32) | (t2)) >> 14) & 0x3ffffff;
        h4 += (uint32_t)(((t3) >> 8) | ((uint64_t)padbit << 24));

        uint64_t d0 = (h0 * r0) + (h1 * s4) + (h2 * s3) + (h3 * s2) + (h4 * s1);
        uint64_t d1 = (h0 * r1) + (h1 * r0) + (h2 * s4) + (h3 * s3) + (h4 * s2);
        uint64_t d2 = (h0 * r2) + (h1 * r1) + (h2 * r0) + (h3 * s4) + (h4 * s3);
        uint64_t d3 = (h0 * r3) + (h1 * r2) + (h2 * r1) + (h3 * r0) + (h4 * s4);
        uint64_t d4 = (h0 * r4) + (h1 * r3) + (h2 * r2) + (h3 * r1) + (h4 * r0);

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

void speer_poly1305(uint8_t mac[16], const uint8_t *msg, size_t len, const uint8_t key[32]) {
    uint32_t r[5], h[5] = {0};
    uint8_t s[16];

    r[0] = (load32(key + 0) >> 0) & 0x3ffffff;
    r[1] = (load32(key + 3) >> 2) & 0x3ffff03;
    r[2] = (load32(key + 6) >> 4) & 0x3ffc0ff;
    r[3] = (load32(key + 9) >> 6) & 0x3f03fff;
    r[4] = (load32(key + 12) >> 8) & 0x00fffff;

    COPY(s, key + 16, 16);

    size_t blocks = len >> 4;
    size_t rem = len & 0xf;

    if (LIKELY(blocks > 0)) {
        poly1305_blocks(h, r, msg, blocks * 16, 1);
        msg += blocks * 16;
    }

    if (rem > 0) {
        uint8_t block[16];
        ZERO(block, 16);
        COPY(block, msg, rem);
        block[rem] = 1;
        poly1305_blocks(h, r, block, 16, 0);
    }

    uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
    uint32_t g0, g1, g2, g3, g4;
    uint32_t c, mask;

    c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    g4 = h4 + c;
    c = g4 >> 26;
    g4 &= 0x3ffffff;
    g0 += c * 5;

    mask = 0u - (c ^ 1u);
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    uint64_t f = h0 + load32(s + 0);
    h0 = (uint32_t)f;
    f = h1 + load32(s + 4) + (f >> 32);
    h1 = (uint32_t)f;
    f = h2 + load32(s + 8) + (f >> 32);
    h2 = (uint32_t)f;
    f = h3 + load32(s + 12) + (f >> 32);
    h3 = (uint32_t)f;

    store32(mac + 0, h0);
    store32(mac + 4, h1);
    store32(mac + 8, h2);
    store32(mac + 12, h3);
}

typedef long long i64;
typedef i64 gf[16];

static const gf gf_121665 = {0xdb41, 1};

static void car25519(gf o) {
    for (int i = 0; i < 16; i++) {
        o[i] += 1LL << 16;
        i64 c = o[i] >> 16;
        o[(i + 1) & 15] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    i64 c = ~(i64)(b - 1);
    for (int i = 0; i < 16; i++) {
        i64 t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void unpack25519(gf o, const uint8_t n[32]) {
    for (int i = 0; i < 16; i++) o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void pack25519(uint8_t o[32], const gf n) {
    gf m, t;
    for (int i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        i64 b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - (int)b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void fe_add(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void fe_sub(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void fe_mul(gf o, const gf a, const gf b) {
    i64 t[31] = {0};
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    }
    for (int i = 30; i >= 16; i--) t[i - 16] += 38 * t[i];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void fe_sqr(gf o, const gf a) {
    fe_mul(o, a, a);
}

static void inv25519(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; a++) c[a] = i[a];
    for (int a = 253; a >= 0; a--) {
        fe_sqr(c, c);
        if (a != 2 && a != 4) fe_mul(c, c, i);
    }
    for (int a = 0; a < 16; a++) o[a] = c[a];
}

static void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t z[32];
    gf x, a, b, c, d, e, f;

    COPY(z, scalar, 32);
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;

    unpack25519(x, point);
    for (int i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;

    for (int i = 254; i >= 0; i--) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        fe_add(e, a, c);
        fe_sub(a, a, c);
        fe_add(c, b, d);
        fe_sub(b, b, d);
        fe_sqr(d, e);
        fe_sqr(f, a);
        fe_mul(a, c, a);
        fe_mul(c, b, e);
        fe_add(e, a, c);
        fe_sub(a, a, c);
        fe_sqr(b, a);
        fe_sub(c, d, f);
        fe_mul(a, c, gf_121665);
        fe_add(a, a, d);
        fe_mul(c, c, a);
        fe_mul(a, d, f);
        fe_mul(d, b, x);
        fe_sqr(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    fe_mul(a, a, c);
    pack25519(out, a);
}

static const uint8_t x25519_base_point[32] = {9};

int speer_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t e[32];
    COPY(e, scalar, 32);
    e[0] &= 0xf8;
    e[31] = (e[31] & 0x7f) | 0x40;
    x25519_scalar_mult(out, e, point);
    return 0;
}

void speer_x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    speer_x25519(out, scalar, x25519_base_point);
}
