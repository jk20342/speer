#include "speer_internal.h"

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32

static const uint32_t k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static INLINE uint32_t rotr(uint32_t x, int n) {
    return ROTR32(x, n);
}

#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define EP1(x)       (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define SIG0(x)      (rotr(x, 7) ^ rotr(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (rotr(x, 17) ^ rotr(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t *data) {
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++) { m[i] = LOAD32_BE(data + i * 4); }
    for (int i = 16; i < 64; i++) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + k256[i] + m[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void speer_sha256_init(void *state) {
    sha256_ctx_t *ctx = (sha256_ctx_t *)state;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->bit_count = 0;
    ctx->buffer_used = 0;
}

void speer_sha256_update(void *state, const uint8_t *in, size_t len) {
    sha256_ctx_t *ctx = (sha256_ctx_t *)state;

    while (len > 0) {
        size_t space = SHA256_BLOCK_SIZE - ctx->buffer_used;
        size_t to_copy = MIN(len, space);

        COPY(ctx->buffer + ctx->buffer_used, in, to_copy);
        ctx->buffer_used += to_copy;
        in += to_copy;
        len -= to_copy;

        if (ctx->buffer_used == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, ctx->buffer);
            ctx->bit_count += SHA256_BLOCK_SIZE * 8;
            ctx->buffer_used = 0;
        }
    }
}

void speer_sha256_final(void *state, uint8_t out[32]) {
    sha256_ctx_t *ctx = (sha256_ctx_t *)state;

    ctx->bit_count += ctx->buffer_used * 8;

    ctx->buffer[ctx->buffer_used++] = 0x80;

    if (ctx->buffer_used > 56) {
        ZERO(ctx->buffer + ctx->buffer_used, SHA256_BLOCK_SIZE - ctx->buffer_used);
        sha256_transform(ctx, ctx->buffer);
        ZERO(ctx->buffer, 56);
    } else {
        ZERO(ctx->buffer + ctx->buffer_used, 56 - ctx->buffer_used);
    }

    uint64_t bit_count = ctx->bit_count;
    for (int i = 0; i < 8; i++) { ctx->buffer[56 + i] = (uint8_t)(bit_count >> (56 - 8 * i)); }
    sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; i++) { STORE32_BE(out + i * 4, ctx->state[i]); }
}

void speer_sha256(uint8_t out[32], const uint8_t *in, size_t len) {
    sha256_ctx_t ctx;
    speer_sha256_init(&ctx);
    speer_sha256_update(&ctx, in, len);
    speer_sha256_final(&ctx, out);
}

static void hmac_sha256(uint8_t out[32], const uint8_t *key, size_t key_len, const uint8_t *a,
                        size_t a_len, const uint8_t *b, size_t b_len, const uint8_t *c,
                        size_t c_len) {
    uint8_t key_block[SHA256_BLOCK_SIZE] = {0};
    uint8_t ipad[SHA256_BLOCK_SIZE];
    uint8_t opad[SHA256_BLOCK_SIZE];
    uint8_t inner[SHA256_DIGEST_SIZE];
    sha256_ctx_t ctx;

    if (key && key_len > SHA256_BLOCK_SIZE) {
        speer_sha256(key_block, key, key_len);
    } else if (key && key_len > 0) {
        COPY(key_block, key, key_len);
    }

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    speer_sha256_init(&ctx);
    speer_sha256_update(&ctx, ipad, SHA256_BLOCK_SIZE);
    if (a && a_len > 0) speer_sha256_update(&ctx, a, a_len);
    if (b && b_len > 0) speer_sha256_update(&ctx, b, b_len);
    if (c && c_len > 0) speer_sha256_update(&ctx, c, c_len);
    speer_sha256_final(&ctx, inner);

    speer_sha256_init(&ctx);
    speer_sha256_update(&ctx, opad, SHA256_BLOCK_SIZE);
    speer_sha256_update(&ctx, inner, SHA256_DIGEST_SIZE);
    speer_sha256_final(&ctx, out);
}

void speer_hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                        size_t ikm_len) {
    hmac_sha256(prk, salt, salt_len, ikm, ikm_len, NULL, 0, NULL, 0);
}

void speer_hkdf_expand(uint8_t *okm, size_t okm_len, const uint8_t prk[32], const uint8_t *info,
                       size_t info_len) {
    uint8_t t[32];
    uint8_t t_prev[32] = {0};
    size_t t_prev_len = 0;

    size_t n = (okm_len + 31) / 32;
    if (n > 255) {
        ZERO(okm, okm_len);
        return;
    }

    for (size_t i = 1; i <= n; i++) {
        uint8_t counter = (uint8_t)i;
        hmac_sha256(t, prk, 32, t_prev, t_prev_len, info, info_len, &counter, 1);

        size_t to_copy = MIN(32, okm_len - (i - 1) * 32);
        COPY(okm + (i - 1) * 32, t, to_copy);

        COPY(t_prev, t, 32);
        t_prev_len = 32;
    }
}

void speer_hkdf(uint8_t *okm, size_t okm_len, const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len) {
    uint8_t prk[32];
    speer_hkdf_extract(prk, salt, salt_len, ikm, ikm_len);
    speer_hkdf_expand(okm, okm_len, prk, info, info_len);
}
