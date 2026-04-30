#include "header_protect.h"

#include "speer_internal.h"

#include "aes.h"

int speer_hp_init(speer_hp_ctx_t *ctx, speer_hp_alg_t alg, const uint8_t *hp_key) {
    ZERO(ctx, sizeof(*ctx));
    ctx->alg = alg;
    switch (alg) {
    case SPEER_HP_AES_128:
        ctx->key_len = 16;
        break;
    case SPEER_HP_AES_256:
        ctx->key_len = 32;
        break;
    case SPEER_HP_CHACHA:
        ctx->key_len = 32;
        break;
    default:
        return -1;
    }
    COPY(ctx->key, hp_key, ctx->key_len);
    return 0;
}

int speer_hp_mask(const speer_hp_ctx_t *ctx, const uint8_t sample[16], uint8_t mask[5]) {
    if (ctx->alg == SPEER_HP_AES_128 || ctx->alg == SPEER_HP_AES_256) {
        speer_aes_key_t k;
        speer_aes_set_encrypt_key(&k, ctx->key, ctx->key_len * 8);
        uint8_t block[16];
        speer_aes_encrypt(&k, sample, block);
        COPY(mask, block, 5);
        return 0;
    }
    if (ctx->alg == SPEER_HP_CHACHA) {
        speer_chacha_ctx_t cc;
        uint8_t nonce[12];
        COPY(nonce, sample + 4, 12);
        speer_chacha_init(&cc, ctx->key, nonce);
        cc.state[12] = (uint32_t)sample[0] | ((uint32_t)sample[1] << 8) |
                       ((uint32_t)sample[2] << 16) | ((uint32_t)sample[3] << 24);
        uint8_t zeros[5] = {0, 0, 0, 0, 0};
        speer_chacha_crypt(&cc, mask, zeros, 5);
        return 0;
    }
    return -1;
}

int speer_hp_protect(const speer_hp_ctx_t *ctx, uint8_t *pkt, size_t pkt_len, size_t pn_offset,
                     size_t pn_length) {
    if (pn_length < 1 || pn_length > 4) return -1;
    size_t sample_off = pn_offset + 4;
    if (sample_off + 16 > pkt_len) return -1;
    uint8_t mask[5];
    if (speer_hp_mask(ctx, pkt + sample_off, mask) != 0) return -1;
    int is_long = (pkt[0] & 0x80) != 0;
    pkt[0] ^= mask[0] & (is_long ? 0x0f : 0x1f);
    for (size_t i = 0; i < pn_length; i++) pkt[pn_offset + i] ^= mask[1 + i];
    return 0;
}

int speer_hp_unprotect(const speer_hp_ctx_t *ctx, uint8_t *pkt, size_t pkt_len, size_t pn_offset,
                       size_t *out_pn_length) {
    size_t sample_off = pn_offset + 4;
    if (sample_off + 16 > pkt_len) return -1;
    uint8_t mask[5];
    if (speer_hp_mask(ctx, pkt + sample_off, mask) != 0) return -1;
    int is_long = (pkt[0] & 0x80) != 0;
    pkt[0] ^= mask[0] & (is_long ? 0x0f : 0x1f);
    size_t pn_len = (pkt[0] & 0x03) + 1;
    if (pn_offset + pn_len > pkt_len) return -1;
    for (size_t i = 0; i < pn_len; i++) pkt[pn_offset + i] ^= mask[1 + i];
    if (out_pn_length) *out_pn_length = pn_len;
    return 0;
}
