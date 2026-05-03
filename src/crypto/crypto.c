#include "speer_internal.h"

#include "cpu_features.h"
#include "field25519.h"

#if (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)) && \
    (defined(__GNUC__) || defined(__clang__))
#define SPEER_HAS_CHACHA_AVX2 1
void speer_chacha20_avx2_8blocks(const uint32_t state[16], const uint8_t *in, uint8_t *out);
#endif

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#define SPEER_HAS_POLY1305_AVX2 1
void speer_poly1305_blocks_avx2(uint32_t h[5], const uint32_t r[5], const uint8_t *m, size_t len,
                                uint32_t padbit);
#endif

#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
#define SPEER_HAS_POLY1305_NEON 1
void speer_poly1305_blocks_neon(uint32_t h[5], const uint32_t r[5], const uint8_t *m, size_t len,
                                uint32_t padbit);
#endif

static const uint32_t chacha_const[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

#define QR(a, b, c, d)         \
    do {                       \
        a += b;                \
        d = ROTL32(d ^ a, 16); \
        c += d;                \
        b = ROTL32(b ^ c, 12); \
        a += b;                \
        d = ROTL32(d ^ a, 8);  \
        c += d;                \
        b = ROTL32(b ^ c, 7);  \
    } while (0)

#define ROUNDS 20

void speer_chacha_init(speer_chacha_ctx_t *ctx, const uint8_t key[32], const uint8_t nonce[12]) {
    ctx->state[0] = chacha_const[0];
    ctx->state[1] = chacha_const[1];
    ctx->state[2] = chacha_const[2];
    ctx->state[3] = chacha_const[3];
    ctx->state[4] = LOAD32_LE(key + 0);
    ctx->state[5] = LOAD32_LE(key + 4);
    ctx->state[6] = LOAD32_LE(key + 8);
    ctx->state[7] = LOAD32_LE(key + 12);
    ctx->state[8] = LOAD32_LE(key + 16);
    ctx->state[9] = LOAD32_LE(key + 20);
    ctx->state[10] = LOAD32_LE(key + 24);
    ctx->state[11] = LOAD32_LE(key + 28);
    ctx->state[12] = 0;
    ctx->state[13] = LOAD32_LE(nonce + 0);
    ctx->state[14] = LOAD32_LE(nonce + 4);
    ctx->state[15] = LOAD32_LE(nonce + 8);
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

    for (int i = 0; i < 16; i++) STORE32_LE(out + 4 * i, x[i]);

    s[12]++;
}

int speer_chacha_block_counter_at_max(const speer_chacha_ctx_t *ctx) {
    return ctx->state[12] == 0xffffffffu;
}

#if defined(SPEER_HAS_POLY1305_AVX2)
SPEER_CACHED_DETECT(poly1305_use_avx2, speer_cpu_has_avx2())
#endif

#if defined(SPEER_HAS_POLY1305_NEON)
SPEER_CACHED_DETECT(poly1305_use_neon, 1)
#endif

#if defined(SPEER_HAS_CHACHA_AVX2)
SPEER_CACHED_DETECT(chacha_use_avx2, speer_cpu_has_avx2())
#endif

void speer_chacha_crypt(speer_chacha_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t len) {
    uint8_t buf[64];

#if defined(SPEER_HAS_CHACHA_AVX2)
    if (ctx->idx == 64 && len >= 8 * 64 && chacha_use_avx2()) {
        size_t bulk = (len / (8 * 64)) * (8 * 64);
        size_t blocks = bulk / 64;
        size_t i = 0;
        while (i + (8 * 64) <= bulk) {
            speer_chacha20_avx2_8blocks(ctx->state, in + i, out + i);
            ctx->state[12] += 8;
            i += 8 * 64;
        }
        in += bulk;
        out += bulk;
        len -= bulk;
        (void)blocks;
    }
#endif

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
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];

    while (len >= 16) {
        uint64_t t0 = LOAD32_LE(m + 0);
        uint64_t t1 = LOAD32_LE(m + 4);
        uint64_t t2 = LOAD32_LE(m + 8);
        uint64_t t3 = LOAD32_LE(m + 12);

        h0 += (t0) & 0x3ffffff;
        h1 += ((((t1) << 32) | (t0)) >> 26) & 0x3ffffff;
        h2 += ((((t2) << 32) | (t1)) >> 20) & 0x3ffffff;
        h3 += ((((t3) << 32) | (t2)) >> 14) & 0x3ffffff;
        h4 += (uint32_t)(((t3) >> 8) | ((uint64_t)padbit << 24));

        uint64_t d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) +
                      ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        uint64_t d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) +
                      ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        uint64_t d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) +
                      ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        uint64_t d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) +
                      ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        uint64_t d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) +
                      ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

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

    r[0] = (LOAD32_LE(key + 0) >> 0) & 0x3ffffff;
    r[1] = (LOAD32_LE(key + 3) >> 2) & 0x3ffff03;
    r[2] = (LOAD32_LE(key + 6) >> 4) & 0x3ffc0ff;
    r[3] = (LOAD32_LE(key + 9) >> 6) & 0x3f03fff;
    r[4] = (LOAD32_LE(key + 12) >> 8) & 0x00fffff;

    COPY(s, key + 16, 16);

    size_t blocks = len >> 4;
    size_t rem = len & 0xf;

    if (LIKELY(blocks > 0)) {
#if defined(SPEER_HAS_POLY1305_AVX2)
        if (blocks >= 4 && poly1305_use_avx2()) {
            speer_poly1305_blocks_avx2(h, r, msg, blocks * 16, 1);
        } else
#endif
#if defined(SPEER_HAS_POLY1305_NEON)
        if (blocks >= 4 && poly1305_use_neon()) {
            speer_poly1305_blocks_neon(h, r, msg, blocks * 16, 1);
        } else
#endif
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
    g4 = h4 + c - (1u << 26);

    mask = (g4 >> 31) - 1u;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    uint64_t f = (uint64_t)h0 + LOAD32_LE(s + 0);
    h0 = (uint32_t)f;
    f = (uint64_t)h1 + LOAD32_LE(s + 4) + (f >> 32);
    h1 = (uint32_t)f;
    f = (uint64_t)h2 + LOAD32_LE(s + 8) + (f >> 32);
    h2 = (uint32_t)f;
    f = (uint64_t)h3 + LOAD32_LE(s + 12) + (f >> 32);
    h3 = (uint32_t)f;

    STORE32_LE(mac + 0, h0);
    STORE32_LE(mac + 4, h1);
    STORE32_LE(mac + 8, h2);
    STORE32_LE(mac + 12, h3);
}

static const fe25519 fe_121665 = {121665ULL, 0, 0, 0, 0};

static void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t z[32];
    fe25519 x, a, b, c, d, e, f;

    COPY(z, scalar, 32);
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;

    fe25519_frombytes(x, point);
    fe25519_copy(b, x);
    fe25519_0(a);
    fe25519_0(c);
    fe25519_0(d);
    a[0] = d[0] = 1;

    int swap = 0;
    for (int i = 254; i >= 0; i--) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        swap ^= r;
        fe25519_cswap(a, b, swap);
        fe25519_cswap(c, d, swap);
        swap = r;
        fe25519_add(e, a, c);
        fe25519_sub(a, a, c);
        fe25519_add(c, b, d);
        fe25519_sub(b, b, d);
        fe25519_sq(d, e);
        fe25519_sq(f, a);
        fe25519_mul(a, c, a);
        fe25519_mul(c, b, e);
        fe25519_add(e, a, c);
        fe25519_sub(a, a, c);
        fe25519_sq(b, a);
        fe25519_sub(c, d, f);
        fe25519_mul(a, c, fe_121665);
        fe25519_add(a, a, d);
        fe25519_mul(c, c, a);
        fe25519_mul(a, d, f);
        fe25519_mul(d, b, x);
        fe25519_sq(b, e);
    }
    fe25519_cswap(a, b, swap);
    fe25519_cswap(c, d, swap);
    fe25519_invert(c, c);
    fe25519_mul(a, a, c);
    fe25519_tobytes(out, a);
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
