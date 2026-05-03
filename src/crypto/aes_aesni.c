#include "speer_internal.h"

#include "aes.h"

#ifdef SPEER_AESNI_AVAILABLE

#include <emmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>

#if defined(__GNUC__) || defined(__clang__)
#define SPEER_AESNI_TARGET __attribute__((target("aes,sse4.1")))
#else
#define SPEER_AESNI_TARGET
#endif

static SPEER_AESNI_TARGET __m128i aes128_assist(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 4);
    temp1 = _mm_xor_si128(temp1, temp3);
    return _mm_xor_si128(temp1, temp2);
}

static SPEER_AESNI_TARGET void aes192_assist(__m128i *t1, __m128i *t2, __m128i *t3) {
    __m128i temp4;
    *t2 = _mm_shuffle_epi32(*t2, 0x55);
    temp4 = _mm_slli_si128(*t1, 4);
    *t1 = _mm_xor_si128(*t1, temp4);
    temp4 = _mm_slli_si128(temp4, 4);
    *t1 = _mm_xor_si128(*t1, temp4);
    temp4 = _mm_slli_si128(temp4, 4);
    *t1 = _mm_xor_si128(*t1, temp4);
    *t1 = _mm_xor_si128(*t1, *t2);
    *t2 = _mm_shuffle_epi32(*t1, 0xff);
    temp4 = _mm_slli_si128(*t3, 4);
    *t3 = _mm_xor_si128(*t3, temp4);
    *t3 = _mm_xor_si128(*t3, *t2);
}

static SPEER_AESNI_TARGET void aes256_assist1(__m128i *t1, __m128i *t2) {
    __m128i temp4;
    *t2 = _mm_shuffle_epi32(*t2, 0xff);
    temp4 = _mm_slli_si128(*t1, 4);
    *t1 = _mm_xor_si128(*t1, temp4);
    temp4 = _mm_slli_si128(temp4, 4);
    *t1 = _mm_xor_si128(*t1, temp4);
    temp4 = _mm_slli_si128(temp4, 4);
    *t1 = _mm_xor_si128(*t1, temp4);
    *t1 = _mm_xor_si128(*t1, *t2);
}

static SPEER_AESNI_TARGET void aes256_assist2(__m128i *t1, __m128i *t3) {
    __m128i temp2, temp4;
    temp4 = _mm_aeskeygenassist_si128(*t1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128(*t3, 4);
    *t3 = _mm_xor_si128(*t3, temp4);
    temp4 = _mm_slli_si128(temp4, 4);
    *t3 = _mm_xor_si128(*t3, temp4);
    temp4 = _mm_slli_si128(temp4, 4);
    *t3 = _mm_xor_si128(*t3, temp4);
    *t3 = _mm_xor_si128(*t3, temp2);
}

static SPEER_AESNI_TARGET void store_round_key(uint32_t *rk, int idx, __m128i v) {
    _mm_storeu_si128((__m128i *)(rk + idx * 4), v);
}

static SPEER_AESNI_TARGET __m128i load_round_key(const uint32_t *rk, int idx) {
    return _mm_loadu_si128((const __m128i *)(rk + idx * 4));
}

SPEER_AESNI_TARGET
/*
 * aes-ni key expansion for encrypt; fills speer_aes_key_t round key schedule
 * supports 128/192/256-bit keys and matches software speer_aes_encrypt path
 * uses aeskeygenassist and shuffles to derive full nr rounds mirrored in decrypt
 * writes round key material as contiguous u32 words expected by simd encrypt kernel
 */
void speer_aes_set_encrypt_key_aesni(speer_aes_key_t *k, const uint8_t *key, size_t key_bits) {
    __m128i t1, t2, t3;
    uint32_t *rk = k->round_keys;

    if (key_bits == 128) {
        k->nr = 10;
        t1 = _mm_loadu_si128((const __m128i *)key);
        store_round_key(rk, 0, t1);
        t2 = _mm_aeskeygenassist_si128(t1, 0x01);
        t1 = aes128_assist(t1, t2);
        store_round_key(rk, 1, t1);
        t2 = _mm_aeskeygenassist_si128(t1, 0x02);
        t1 = aes128_assist(t1, t2);
        store_round_key(rk, 2, t1);
        t2 = _mm_aeskeygenassist_si128(t1, 0x04);
        t1 = aes128_assist(t1, t2);
        store_round_key(rk, 3, t1);
        t2 = _mm_aeskeygenassist_si128(t1, 0x08);
        t1 = aes128_assist(t1, t2);
        store_round_key(rk, 4, t1);
        t2 = _mm_aeskeygenassist_si128(t1, 0x10);
        t1 = aes128_assist(t1, t2);
        store_round_key(rk, 5, t1);
        t2 = _mm_aeskeygenassist_si128(t1, 0x20);
        t1 = aes128_assist(t1, t2);
        store_round_key(rk, 6, t1);
        t2 = _mm_aeskeygenassist_si128(t1, 0x40);
        t1 = aes128_assist(t1, t2);
        store_round_key(rk, 7, t1);
        t2 = _mm_aeskeygenassist_si128(t1, 0x80);
        t1 = aes128_assist(t1, t2);
        store_round_key(rk, 8, t1);
        t2 = _mm_aeskeygenassist_si128(t1, 0x1b);
        t1 = aes128_assist(t1, t2);
        store_round_key(rk, 9, t1);
        t2 = _mm_aeskeygenassist_si128(t1, 0x36);
        t1 = aes128_assist(t1, t2);
        store_round_key(rk, 10, t1);
        k->use_aesni = 1;
        return;
    }

    if (key_bits == 192) {
        k->nr = 12;
        t1 = _mm_loadu_si128((const __m128i *)key);
        t3 = _mm_loadu_si128((const __m128i *)(key + 16));
        t3 = _mm_unpacklo_epi64(t3, t3);
        store_round_key(rk, 0, t1);

        uint8_t schedule[13 * 16];
        _mm_storeu_si128((__m128i *)(schedule + 0), t1);
        _mm_storel_epi64((__m128i *)(schedule + 16), t3);
        size_t pos = 24;

#define AES192_STEP(rcon)                                                            \
    do {                                                                             \
        t2 = _mm_aeskeygenassist_si128(t3, rcon);                                    \
        aes192_assist(&t1, &t2, &t3);                                                \
        uint8_t tmp[16];                                                             \
        _mm_storeu_si128((__m128i *)tmp, t1);                                        \
        for (int j = 0; j < 16 && pos < 13 * 16; j++, pos++) schedule[pos] = tmp[j]; \
        _mm_storel_epi64((__m128i *)tmp, t3);                                        \
        for (int j = 0; j < 8 && pos < 13 * 16; j++, pos++) schedule[pos] = tmp[j];  \
    } while (0)
        AES192_STEP(0x01);
        AES192_STEP(0x02);
        AES192_STEP(0x04);
        AES192_STEP(0x08);
        AES192_STEP(0x10);
        AES192_STEP(0x20);
        AES192_STEP(0x40);
        AES192_STEP(0x80);
#undef AES192_STEP
        for (int i = 0; i <= 12; i++) {
            __m128i v = _mm_loadu_si128((const __m128i *)(schedule + i * 16));
            store_round_key(rk, i, v);
        }
        k->use_aesni = 1;
        return;
    }

    if (key_bits == 256) {
        k->nr = 14;
        t1 = _mm_loadu_si128((const __m128i *)key);
        t3 = _mm_loadu_si128((const __m128i *)(key + 16));
        store_round_key(rk, 0, t1);
        store_round_key(rk, 1, t3);

        t2 = _mm_aeskeygenassist_si128(t3, 0x01);
        aes256_assist1(&t1, &t2);
        store_round_key(rk, 2, t1);
        aes256_assist2(&t1, &t3);
        store_round_key(rk, 3, t3);

        t2 = _mm_aeskeygenassist_si128(t3, 0x02);
        aes256_assist1(&t1, &t2);
        store_round_key(rk, 4, t1);
        aes256_assist2(&t1, &t3);
        store_round_key(rk, 5, t3);

        t2 = _mm_aeskeygenassist_si128(t3, 0x04);
        aes256_assist1(&t1, &t2);
        store_round_key(rk, 6, t1);
        aes256_assist2(&t1, &t3);
        store_round_key(rk, 7, t3);

        t2 = _mm_aeskeygenassist_si128(t3, 0x08);
        aes256_assist1(&t1, &t2);
        store_round_key(rk, 8, t1);
        aes256_assist2(&t1, &t3);
        store_round_key(rk, 9, t3);

        t2 = _mm_aeskeygenassist_si128(t3, 0x10);
        aes256_assist1(&t1, &t2);
        store_round_key(rk, 10, t1);
        aes256_assist2(&t1, &t3);
        store_round_key(rk, 11, t3);

        t2 = _mm_aeskeygenassist_si128(t3, 0x20);
        aes256_assist1(&t1, &t2);
        store_round_key(rk, 12, t1);
        aes256_assist2(&t1, &t3);
        store_round_key(rk, 13, t3);

        t2 = _mm_aeskeygenassist_si128(t3, 0x40);
        aes256_assist1(&t1, &t2);
        store_round_key(rk, 14, t1);
        k->use_aesni = 1;
        return;
    }

    k->nr = 0;
    k->use_aesni = 0;
}

SPEER_AESNI_TARGET
void speer_aes_encrypt_aesni(const speer_aes_key_t *k, const uint8_t in[16], uint8_t out[16]) {
    const uint32_t *rk = k->round_keys;
    int nr = k->nr;
    __m128i s = _mm_loadu_si128((const __m128i *)in);
    s = _mm_xor_si128(s, load_round_key(rk, 0));
    for (int i = 1; i < nr; i++) { s = _mm_aesenc_si128(s, load_round_key(rk, i)); }
    s = _mm_aesenclast_si128(s, load_round_key(rk, nr));
    _mm_storeu_si128((__m128i *)out, s);
}

static SPEER_AESNI_TARGET __m128i aesni_increment(__m128i ctr, uint64_t add) {
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

SPEER_AESNI_TARGET
void speer_aes_ctr_aesni(const speer_aes_key_t *k, const uint8_t nonce[16], uint8_t *out,
                         const uint8_t *in, size_t len) {
    const uint32_t *rk = k->round_keys;
    int nr = k->nr;
    __m128i ctr = _mm_loadu_si128((const __m128i *)nonce);
    __m128i rk0 = load_round_key(rk, 0);

    while (len >= 128) {
        __m128i b0 = _mm_xor_si128(ctr, rk0);
        __m128i b1 = _mm_xor_si128(aesni_increment(ctr, 1), rk0);
        __m128i b2 = _mm_xor_si128(aesni_increment(ctr, 2), rk0);
        __m128i b3 = _mm_xor_si128(aesni_increment(ctr, 3), rk0);
        __m128i b4 = _mm_xor_si128(aesni_increment(ctr, 4), rk0);
        __m128i b5 = _mm_xor_si128(aesni_increment(ctr, 5), rk0);
        __m128i b6 = _mm_xor_si128(aesni_increment(ctr, 6), rk0);
        __m128i b7 = _mm_xor_si128(aesni_increment(ctr, 7), rk0);

        for (int r = 1; r < nr; r++) {
            __m128i rkr = load_round_key(rk, r);
            b0 = _mm_aesenc_si128(b0, rkr);
            b1 = _mm_aesenc_si128(b1, rkr);
            b2 = _mm_aesenc_si128(b2, rkr);
            b3 = _mm_aesenc_si128(b3, rkr);
            b4 = _mm_aesenc_si128(b4, rkr);
            b5 = _mm_aesenc_si128(b5, rkr);
            b6 = _mm_aesenc_si128(b6, rkr);
            b7 = _mm_aesenc_si128(b7, rkr);
        }
        __m128i rkN = load_round_key(rk, nr);
        b0 = _mm_aesenclast_si128(b0, rkN);
        b1 = _mm_aesenclast_si128(b1, rkN);
        b2 = _mm_aesenclast_si128(b2, rkN);
        b3 = _mm_aesenclast_si128(b3, rkN);
        b4 = _mm_aesenclast_si128(b4, rkN);
        b5 = _mm_aesenclast_si128(b5, rkN);
        b6 = _mm_aesenclast_si128(b6, rkN);
        b7 = _mm_aesenclast_si128(b7, rkN);

        __m128i p0 = _mm_loadu_si128((const __m128i *)(in + 0));
        __m128i p1 = _mm_loadu_si128((const __m128i *)(in + 16));
        __m128i p2 = _mm_loadu_si128((const __m128i *)(in + 32));
        __m128i p3 = _mm_loadu_si128((const __m128i *)(in + 48));
        __m128i p4 = _mm_loadu_si128((const __m128i *)(in + 64));
        __m128i p5 = _mm_loadu_si128((const __m128i *)(in + 80));
        __m128i p6 = _mm_loadu_si128((const __m128i *)(in + 96));
        __m128i p7 = _mm_loadu_si128((const __m128i *)(in + 112));

        _mm_storeu_si128((__m128i *)(out + 0), _mm_xor_si128(b0, p0));
        _mm_storeu_si128((__m128i *)(out + 16), _mm_xor_si128(b1, p1));
        _mm_storeu_si128((__m128i *)(out + 32), _mm_xor_si128(b2, p2));
        _mm_storeu_si128((__m128i *)(out + 48), _mm_xor_si128(b3, p3));
        _mm_storeu_si128((__m128i *)(out + 64), _mm_xor_si128(b4, p4));
        _mm_storeu_si128((__m128i *)(out + 80), _mm_xor_si128(b5, p5));
        _mm_storeu_si128((__m128i *)(out + 96), _mm_xor_si128(b6, p6));
        _mm_storeu_si128((__m128i *)(out + 112), _mm_xor_si128(b7, p7));

        ctr = aesni_increment(ctr, 8);
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
        ctr = aesni_increment(ctr, 1);
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

#else

void speer_aes_set_encrypt_key_aesni(speer_aes_key_t *k, const uint8_t *key, size_t key_bits) {
    (void)k;
    (void)key;
    (void)key_bits;
}
void speer_aes_encrypt_aesni(const speer_aes_key_t *k, const uint8_t in[16], uint8_t out[16]) {
    (void)k;
    (void)in;
    (void)out;
}
void speer_aes_ctr_aesni(const speer_aes_key_t *k, const uint8_t nonce[16], uint8_t *out,
                         const uint8_t *in, size_t len) {
    (void)k;
    (void)nonce;
    (void)out;
    (void)in;
    (void)len;
}

#endif
