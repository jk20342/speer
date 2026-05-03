#include "aes.h"

#include "speer_internal.h"

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))

#include <immintrin.h>
#include <wmmintrin.h>

#define SPEER_VAES_TARGET __attribute__((target("vaes", "avx2")))

static SPEER_VAES_TARGET INLINE __m128i load_round_key(const uint32_t *rk, int idx) {
    return _mm_loadu_si128((const __m128i *)(rk + idx * 4));
}

static SPEER_VAES_TARGET __m128i vaes_ctr_inc(__m128i ctr, uint64_t add) {
    uint8_t buf[16];
    _mm_storeu_si128((__m128i *)buf, ctr);
    uint64_t lo = ((uint64_t)buf[12] << 24) | ((uint64_t)buf[13] << 16) | ((uint64_t)buf[14] << 8) |
                  (uint64_t)buf[15];
    lo += add;
    buf[12] = (uint8_t)(lo >> 24);
    buf[13] = (uint8_t)(lo >> 16);
    buf[14] = (uint8_t)(lo >> 8);
    buf[15] = (uint8_t)lo;
    return _mm_loadu_si128((const __m128i *)buf);
}

SPEER_VAES_TARGET
void speer_aes_ctr_vaes(const speer_aes_key_t *k, const uint8_t nonce[16], uint8_t *out,
                        const uint8_t *in, size_t len) {
    const uint32_t *rk = k->round_keys;
    int nr = k->nr;
    __m128i ctr = _mm_loadu_si128((const __m128i *)nonce);
    __m128i rk0 = load_round_key(rk, 0);

    while (len >= 128) {
        __m128i b0 = _mm_xor_si128(ctr, rk0);
        __m128i b1 = _mm_xor_si128(vaes_ctr_inc(ctr, 1), rk0);
        __m128i b2 = _mm_xor_si128(vaes_ctr_inc(ctr, 2), rk0);
        __m128i b3 = _mm_xor_si128(vaes_ctr_inc(ctr, 3), rk0);
        __m128i b4 = _mm_xor_si128(vaes_ctr_inc(ctr, 4), rk0);
        __m128i b5 = _mm_xor_si128(vaes_ctr_inc(ctr, 5), rk0);
        __m128i b6 = _mm_xor_si128(vaes_ctr_inc(ctr, 6), rk0);
        __m128i b7 = _mm_xor_si128(vaes_ctr_inc(ctr, 7), rk0);

        __m256i y01 =
            _mm256_insertf128_si256(_mm256_castsi128_si256(b0), b1, 1);
        __m256i y23 =
            _mm256_insertf128_si256(_mm256_castsi128_si256(b2), b3, 1);
        __m256i y45 =
            _mm256_insertf128_si256(_mm256_castsi128_si256(b4), b5, 1);
        __m256i y67 =
            _mm256_insertf128_si256(_mm256_castsi128_si256(b6), b7, 1);

        for (int r = 1; r < nr; r++) {
            __m128i rkr = load_round_key(rk, r);
            y01 = _mm256_aesenc_epi128(y01, rkr);
            y23 = _mm256_aesenc_epi128(y23, rkr);
            y45 = _mm256_aesenc_epi128(y45, rkr);
            y67 = _mm256_aesenc_epi128(y67, rkr);
        }

        __m128i rkN = load_round_key(rk, nr);
        y01 = _mm256_aesenclast_epi128(y01, rkN);
        y23 = _mm256_aesenclast_epi128(y23, rkN);
        y45 = _mm256_aesenclast_epi128(y45, rkN);
        y67 = _mm256_aesenclast_epi128(y67, rkN);

        __m128i p0 = _mm_loadu_si128((const __m128i *)(in + 0));
        __m128i p1 = _mm_loadu_si128((const __m128i *)(in + 16));
        __m128i p2 = _mm_loadu_si128((const __m128i *)(in + 32));
        __m128i p3 = _mm_loadu_si128((const __m128i *)(in + 48));
        __m128i p4 = _mm_loadu_si128((const __m128i *)(in + 64));
        __m128i p5 = _mm_loadu_si128((const __m128i *)(in + 80));
        __m128i p6 = _mm_loadu_si128((const __m128i *)(in + 96));
        __m128i p7 = _mm_loadu_si128((const __m128i *)(in + 112));

        _mm_storeu_si128((__m128i *)(out + 0),
                         _mm_xor_si128(_mm256_castsi256_si128(y01), p0));
        _mm_storeu_si128((__m128i *)(out + 16),
                         _mm_xor_si128(_mm256_extracti128_si256(y01, 1), p1));
        _mm_storeu_si128((__m128i *)(out + 32),
                         _mm_xor_si128(_mm256_castsi256_si128(y23), p2));
        _mm_storeu_si128((__m128i *)(out + 48),
                         _mm_xor_si128(_mm256_extracti128_si256(y23, 1), p3));
        _mm_storeu_si128((__m128i *)(out + 64),
                         _mm_xor_si128(_mm256_castsi256_si128(y45), p4));
        _mm_storeu_si128((__m128i *)(out + 80),
                         _mm_xor_si128(_mm256_extracti128_si256(y45, 1), p5));
        _mm_storeu_si128((__m128i *)(out + 96),
                         _mm_xor_si128(_mm256_castsi256_si128(y67), p6));
        _mm_storeu_si128((__m128i *)(out + 112),
                         _mm_xor_si128(_mm256_extracti128_si256(y67, 1), p7));

        ctr = vaes_ctr_inc(ctr, 8);
        in += 128;
        out += 128;
        len -= 128;
    }

    while (len >= 16) {
        __m128i b = _mm_xor_si128(ctr, rk0);
        for (int r = 1; r < nr; r++) b = _mm_aesenc_si128(b, load_round_key(rk, r));
        b = _mm_aesenclast_si128(b, load_round_key(rk, nr));
        __m128i p = _mm_loadu_si128((const __m128i *)in);
        _mm_storeu_si128((__m128i *)out, _mm_xor_si128(b, p));
        ctr = vaes_ctr_inc(ctr, 1);
        in += 16;
        out += 16;
        len -= 16;
    }

    if (len > 0) {
        uint8_t ks[16];
        __m128i b = _mm_xor_si128(ctr, rk0);
        for (int r = 1; r < nr; r++) b = _mm_aesenc_si128(b, load_round_key(rk, r));
        b = _mm_aesenclast_si128(b, load_round_key(rk, nr));
        _mm_storeu_si128((__m128i *)ks, b);
        for (size_t i = 0; i < len; i++) out[i] = in[i] ^ ks[i];
    }
}

#elif defined(__x86_64__) || defined(__i386__)

void speer_aes_ctr_vaes(const speer_aes_key_t *k, const uint8_t nonce[16], uint8_t *out,
                        const uint8_t *in, size_t len) {
    (void)k;
    (void)nonce;
    (void)out;
    (void)in;
    (void)len;
}

#else

void speer_aes_ctr_vaes(const speer_aes_key_t *k, const uint8_t nonce[16], uint8_t *out,
                        const uint8_t *in, size_t len) {
    (void)k;
    (void)nonce;
    (void)out;
    (void)in;
    (void)len;
}

#endif
