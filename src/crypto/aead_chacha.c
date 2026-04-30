#include "speer_internal.h"
#include "aead_iface.h"
#include "ct_helpers.h"

static int chacha20_poly1305_seal(const uint8_t* key,
                                   const uint8_t* nonce,
                                   const uint8_t* aad, size_t aad_len,
                                   const uint8_t* pt, size_t pt_len,
                                   uint8_t* out_ct,
                                   uint8_t* out_tag) {
    speer_chacha_ctx_t ctx;
    speer_chacha_init(&ctx, key, nonce);

    uint8_t poly_key[64];
    speer_chacha_block(&ctx, poly_key);

    speer_chacha_crypt(&ctx, out_ct, pt, pt_len);

    size_t aad_pad = (16 - (aad_len & 15)) & 15;
    size_t ct_pad = (16 - (pt_len & 15)) & 15;
    size_t mac_len = aad_len + aad_pad + pt_len + ct_pad + 16;
    uint8_t* mac_in = (uint8_t*)malloc(mac_len);
    if (!mac_in) return -1;

    size_t pos = 0;
    if (aad_len > 0) { COPY(mac_in + pos, aad, aad_len); pos += aad_len; }
    if (aad_pad > 0) { ZERO(mac_in + pos, aad_pad); pos += aad_pad; }
    if (pt_len > 0) { COPY(mac_in + pos, out_ct, pt_len); pos += pt_len; }
    if (ct_pad > 0) { ZERO(mac_in + pos, ct_pad); pos += ct_pad; }
    STORE64_LE(mac_in + pos, (uint64_t)aad_len); pos += 8;
    STORE64_LE(mac_in + pos, (uint64_t)pt_len); pos += 8;

    speer_poly1305(out_tag, mac_in, mac_len, poly_key);
    free(mac_in);
    return 0;
}

static int chacha20_poly1305_open(const uint8_t* key,
                                   const uint8_t* nonce,
                                   const uint8_t* aad, size_t aad_len,
                                   const uint8_t* ct, size_t ct_len,
                                   const uint8_t* tag,
                                   uint8_t* out_pt) {
    speer_chacha_ctx_t ctx;
    speer_chacha_init(&ctx, key, nonce);

    uint8_t poly_key[64];
    speer_chacha_block(&ctx, poly_key);

    size_t aad_pad = (16 - (aad_len & 15)) & 15;
    size_t ct_pad = (16 - (ct_len & 15)) & 15;
    size_t mac_len = aad_len + aad_pad + ct_len + ct_pad + 16;
    uint8_t* mac_in = (uint8_t*)malloc(mac_len);
    if (!mac_in) return -1;

    size_t pos = 0;
    if (aad_len > 0) { COPY(mac_in + pos, aad, aad_len); pos += aad_len; }
    if (aad_pad > 0) { ZERO(mac_in + pos, aad_pad); pos += aad_pad; }
    if (ct_len > 0) { COPY(mac_in + pos, ct, ct_len); pos += ct_len; }
    if (ct_pad > 0) { ZERO(mac_in + pos, ct_pad); pos += ct_pad; }
    STORE64_LE(mac_in + pos, (uint64_t)aad_len); pos += 8;
    STORE64_LE(mac_in + pos, (uint64_t)ct_len); pos += 8;

    uint8_t computed[16];
    speer_poly1305(computed, mac_in, mac_len, poly_key);
    free(mac_in);

    if (!speer_ct_memeq(computed, tag, 16)) return -1;

    speer_chacha_crypt(&ctx, out_pt, ct, ct_len);
    return 0;
}

const speer_aead_iface_t speer_aead_chacha20_poly1305 = {
    .name = "chacha20-poly1305",
    .key_len = 32, .nonce_len = 12, .tag_len = 16,
    .seal = chacha20_poly1305_seal,
    .open = chacha20_poly1305_open
};
