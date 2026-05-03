#include "speer_internal.h"

#include "aes.h"

#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))

#include <arm_neon.h>

#define SPEER_ARM_AES_TARGET __attribute__((target("+crypto")))

static SPEER_ARM_AES_TARGET INLINE uint8x16_t load_rk_u8(const speer_aes_key_t *k, int word_base) {
    uint32x4_t w = vld1q_u32(&k->round_keys[word_base]);
    return vreinterpretq_u8_u32(w);
}

SPEER_ARM_AES_TARGET
void speer_aes_encrypt_armv8(const speer_aes_key_t *k, const uint8_t in[16], uint8_t out[16]) {
    int nr = k->nr;
    uint8x16_t state = vld1q_u8(in);
    state = vaesmcq_u8(vaeseq_u8(state, load_rk_u8(k, 0)));

    for (int rr = 1; rr <= nr - 2; rr++) {
        state = vaesmcq_u8(vaeseq_u8(state, load_rk_u8(k, rr * 4)));
    }

    state = vaeseq_u8(state, load_rk_u8(k, (nr - 1) * 4));
    state = veorq_u8(state, load_rk_u8(k, nr * 4));
    vst1q_u8(out, state);
}

SPEER_ARM_AES_TARGET
void speer_aes_ctr_armv8(const speer_aes_key_t *k, const uint8_t nonce[16], uint8_t *out,
                         const uint8_t *in, size_t len) {
    uint8_t ctr[16];
    COPY(ctr, nonce, 16);

    while (len > 0) {
        uint8_t ks[16];
        speer_aes_encrypt_armv8(k, ctr, ks);
        size_t n = len < 16 ? len : 16;
        for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(in[i] ^ ks[i]);
        out += n;
        in += n;
        len -= n;
        for (int i = 15; i >= 0; i--) {
            ctr[i]++;
            if (ctr[i] != 0) break;
        }
    }
}

#else

void speer_aes_encrypt_armv8(const speer_aes_key_t *k, const uint8_t in[16], uint8_t out[16]) {
    (void)k;
    (void)in;
    (void)out;
}

void speer_aes_ctr_armv8(const speer_aes_key_t *k, const uint8_t nonce[16], uint8_t *out,
                         const uint8_t *in, size_t len) {
    (void)k;
    (void)nonce;
    (void)out;
    (void)in;
    (void)len;
}

#endif
