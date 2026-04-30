#include "speer_internal.h"
#include "hash_iface.h"

typedef struct {
    uint64_t state[8];
    uint64_t bit_count_lo;
    uint64_t bit_count_hi;
    uint8_t buffer[128];
    size_t buffer_used;
    size_t digest_size;
} sha512_ctx_t;

static const uint64_t k512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static const uint64_t sha512_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint64_t sha384_iv[8] = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
};

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_512(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define EP1_512(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define SIG0_512(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ ((x) >> 7))
#define SIG1_512(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ ((x) >> 6))

static uint64_t load64_be(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static void store64_be(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

static void sha512_transform(sha512_ctx_t* ctx, const uint8_t* data) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) w[i] = load64_be(data + i * 8);
    for (int i = 16; i < 80; i++) w[i] = SIG1_512(w[i-2]) + w[i-7] + SIG0_512(w[i-15]) + w[i-16];

    uint64_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint64_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + EP1_512(e) + CH64(e, f, g) + k512[i] + w[i];
        uint64_t t2 = EP0_512(a) + MAJ64(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha512_init_common(sha512_ctx_t* ctx, const uint64_t iv[8], size_t digest_size) {
    for (int i = 0; i < 8; i++) ctx->state[i] = iv[i];
    ctx->bit_count_lo = 0;
    ctx->bit_count_hi = 0;
    ctx->buffer_used = 0;
    ctx->digest_size = digest_size;
}

static void sha512_update_impl(sha512_ctx_t* ctx, const uint8_t* in, size_t len) {
    while (len > 0) {
        size_t space = 128 - ctx->buffer_used;
        size_t to_copy = MIN(len, space);
        COPY(ctx->buffer + ctx->buffer_used, in, to_copy);
        ctx->buffer_used += to_copy;
        in += to_copy;
        len -= to_copy;
        if (ctx->buffer_used == 128) {
            sha512_transform(ctx, ctx->buffer);
            uint64_t old_lo = ctx->bit_count_lo;
            ctx->bit_count_lo += 1024;
            if (ctx->bit_count_lo < old_lo) ctx->bit_count_hi++;
            ctx->buffer_used = 0;
        }
    }
}

static void sha512_final_impl(sha512_ctx_t* ctx, uint8_t* out) {
    uint64_t old_lo = ctx->bit_count_lo;
    ctx->bit_count_lo += (uint64_t)ctx->buffer_used * 8;
    if (ctx->bit_count_lo < old_lo) ctx->bit_count_hi++;

    ctx->buffer[ctx->buffer_used++] = 0x80;

    if (ctx->buffer_used > 112) {
        ZERO(ctx->buffer + ctx->buffer_used, 128 - ctx->buffer_used);
        sha512_transform(ctx, ctx->buffer);
        ZERO(ctx->buffer, 112);
    } else {
        ZERO(ctx->buffer + ctx->buffer_used, 112 - ctx->buffer_used);
    }

    store64_be(ctx->buffer + 112, ctx->bit_count_hi);
    store64_be(ctx->buffer + 120, ctx->bit_count_lo);
    sha512_transform(ctx, ctx->buffer);

    size_t words = ctx->digest_size / 8;
    for (size_t i = 0; i < words; i++) store64_be(out + i * 8, ctx->state[i]);
}

void speer_sha512(uint8_t out[64], const uint8_t* in, size_t len) {
    sha512_ctx_t ctx;
    sha512_init_common(&ctx, sha512_iv, 64);
    sha512_update_impl(&ctx, in, len);
    sha512_final_impl(&ctx, out);
}

void speer_sha384(uint8_t out[48], const uint8_t* in, size_t len) {
    sha512_ctx_t ctx;
    sha512_init_common(&ctx, sha384_iv, 48);
    sha512_update_impl(&ctx, in, len);
    sha512_final_impl(&ctx, out);
}

static void sha512_init_iface(void* ctx) { sha512_init_common((sha512_ctx_t*)ctx, sha512_iv, 64); }
static void sha384_init_iface(void* ctx) { sha512_init_common((sha512_ctx_t*)ctx, sha384_iv, 48); }
static void sha512_update_iface(void* ctx, const uint8_t* d, size_t l) { sha512_update_impl((sha512_ctx_t*)ctx, d, l); }
static void sha512_final_iface(void* ctx, uint8_t* out) { sha512_final_impl((sha512_ctx_t*)ctx, out); }
static void sha512_oneshot_iface(uint8_t* out, const uint8_t* d, size_t l) { speer_sha512(out, d, l); }
static void sha384_oneshot_iface(uint8_t* out, const uint8_t* d, size_t l) { speer_sha384(out, d, l); }

static void sha256_init_iface(void* ctx) { speer_sha256_init(ctx); }
static void sha256_update_iface(void* ctx, const uint8_t* d, size_t l) { speer_sha256_update(ctx, d, l); }
static void sha256_final_iface(void* ctx, uint8_t* out) { speer_sha256_final(ctx, out); }
static void sha256_oneshot_iface(uint8_t* out, const uint8_t* d, size_t l) { speer_sha256(out, d, l); }

const speer_hash_iface_t speer_hash_sha256 = {
    .name = "sha256", .digest_size = 32, .block_size = 64,
    .init = sha256_init_iface, .update = sha256_update_iface,
    .final = sha256_final_iface, .oneshot = sha256_oneshot_iface
};

const speer_hash_iface_t speer_hash_sha384 = {
    .name = "sha384", .digest_size = 48, .block_size = 128,
    .init = sha384_init_iface, .update = sha512_update_iface,
    .final = sha512_final_iface, .oneshot = sha384_oneshot_iface
};

const speer_hash_iface_t speer_hash_sha512 = {
    .name = "sha512", .digest_size = 64, .block_size = 128,
    .init = sha512_init_iface, .update = sha512_update_iface,
    .final = sha512_final_iface, .oneshot = sha512_oneshot_iface
};

void speer_hmac(const speer_hash_iface_t* h,
                uint8_t* out,
                const uint8_t* key, size_t key_len,
                const uint8_t* data, size_t data_len) {
    uint8_t k[SPEER_HASH_MAX_BLOCK] = {0};
    if (key_len > h->block_size) {
        h->oneshot(k, key, key_len);
    } else if (key_len > 0) {
        COPY(k, key, key_len);
    }

    uint8_t ipad[SPEER_HASH_MAX_BLOCK];
    uint8_t opad[SPEER_HASH_MAX_BLOCK];
    for (size_t i = 0; i < h->block_size; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    uint8_t inner[SPEER_HASH_MAX_DIGEST];
    uint8_t ctx[SPEER_HASH_MAX_CTX];
    h->init(ctx);
    h->update(ctx, ipad, h->block_size);
    h->update(ctx, data, data_len);
    h->final(ctx, inner);

    h->init(ctx);
    h->update(ctx, opad, h->block_size);
    h->update(ctx, inner, h->digest_size);
    h->final(ctx, out);
}

void speer_hkdf2_extract(const speer_hash_iface_t* h,
                         uint8_t* prk,
                         const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm, size_t ikm_len) {
    uint8_t zero_salt[SPEER_HASH_MAX_DIGEST] = {0};
    if (!salt || salt_len == 0) {
        salt = zero_salt;
        salt_len = h->digest_size;
    }
    speer_hmac(h, prk, salt, salt_len, ikm, ikm_len);
}

void speer_hkdf2_expand(const speer_hash_iface_t* h,
                        uint8_t* okm, size_t okm_len,
                        const uint8_t* prk, size_t prk_len,
                        const uint8_t* info, size_t info_len) {
    uint8_t t[SPEER_HASH_MAX_DIGEST];
    size_t t_len = 0;
    size_t n = (okm_len + h->digest_size - 1) / h->digest_size;

    for (size_t i = 1; i <= n; i++) {
        uint8_t buf[SPEER_HASH_MAX_DIGEST + 256 + 1];
        size_t buf_len = 0;
        if (t_len > 0) { COPY(buf, t, t_len); buf_len += t_len; }
        if (info_len > 0) { COPY(buf + buf_len, info, info_len); buf_len += info_len; }
        buf[buf_len++] = (uint8_t)i;

        speer_hmac(h, t, prk, prk_len, buf, buf_len);
        t_len = h->digest_size;

        size_t to_copy = MIN(t_len, okm_len - (i-1) * h->digest_size);
        COPY(okm + (i-1) * h->digest_size, t, to_copy);
    }
}

void speer_hkdf2(const speer_hash_iface_t* h,
                 uint8_t* okm, size_t okm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* info, size_t info_len) {
    uint8_t prk[SPEER_HASH_MAX_DIGEST];
    speer_hkdf2_extract(h, prk, salt, salt_len, ikm, ikm_len);
    speer_hkdf2_expand(h, okm, okm_len, prk, h->digest_size, info, info_len);
}

void speer_hkdf_expand_label(const speer_hash_iface_t* h,
                             uint8_t* out, size_t out_len,
                             const uint8_t* secret, size_t secret_len,
                             const char* label,
                             const uint8_t* context, size_t context_len) {
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t pos = 0;
    info[pos++] = (uint8_t)(out_len >> 8);
    info[pos++] = (uint8_t)(out_len & 0xff);

    size_t label_len = 0;
    while (label[label_len]) label_len++;
    size_t total_label = 6 + label_len;
    if (total_label > 255) total_label = 255;
    info[pos++] = (uint8_t)total_label;
    COPY(info + pos, "tls13 ", 6); pos += 6;
    COPY(info + pos, label, total_label - 6); pos += total_label - 6;

    if (context_len > 255) context_len = 255;
    info[pos++] = (uint8_t)context_len;
    if (context_len > 0) { COPY(info + pos, context, context_len); pos += context_len; }

    speer_hkdf2_expand(h, out, out_len, secret, secret_len, info, pos);
}
