#include "speer_internal.h"

#include "aead_iface.h"
#include "aes.h"
#include "ct_helpers.h"
#include "ghash.h"

static void aes_gcm_absorb_lengths(speer_ghash_state_t *gs, uint8_t y[16], size_t aad_len,
                                   size_t ct_len) {
    uint8_t lens[16];
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; i++) lens[i] = (uint8_t)(aad_bits >> ((7 - i) * 8));
    for (int i = 0; i < 8; i++) lens[8 + i] = (uint8_t)(ct_bits >> ((7 - i) * 8));
    speer_ghash_absorb(gs, y, lens, 16);
}

static int aes_gcm_seal_n(size_t key_bits, const uint8_t *key, const uint8_t *nonce,
                          const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
                          uint8_t *out_ct, uint8_t *out_tag) {
    speer_aes_key_t k;
    speer_aes_set_encrypt_key(&k, key, key_bits);

    uint8_t h[16] = {0};
    uint8_t zero[16] = {0};
    speer_aes_encrypt(&k, zero, h);

    speer_ghash_state_t gs;
    speer_ghash_init(&gs, h);

    uint8_t j0[16] = {0};
    COPY(j0, nonce, 12);
    j0[15] = 1;

    uint8_t ctr[16];
    COPY(ctr, j0, 16);
    for (int i = 15; i >= 12; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }

    speer_aes_ctr(&k, ctr, out_ct, pt, pt_len);

    uint8_t y[16] = {0};
    speer_ghash_absorb(&gs, y, aad, aad_len);
    speer_ghash_absorb(&gs, y, out_ct, pt_len);

    aes_gcm_absorb_lengths(&gs, y, aad_len, pt_len);

    uint8_t s[16];
    speer_aes_encrypt(&k, j0, s);
    for (int i = 0; i < 16; i++) out_tag[i] = y[i] ^ s[i];

    WIPE(&k, sizeof(k));
    WIPE(&gs, sizeof(gs));
    WIPE(h, 16);
    WIPE(s, 16);
    return 0;
}

static int aes_gcm_open_n(size_t key_bits, const uint8_t *key, const uint8_t *nonce,
                          const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
                          const uint8_t *tag, uint8_t *out_pt) {
    speer_aes_key_t k;
    speer_aes_set_encrypt_key(&k, key, key_bits);

    uint8_t h[16] = {0};
    uint8_t zero[16] = {0};
    speer_aes_encrypt(&k, zero, h);

    speer_ghash_state_t gs;
    speer_ghash_init(&gs, h);

    uint8_t j0[16] = {0};
    COPY(j0, nonce, 12);
    j0[15] = 1;

    uint8_t y[16] = {0};
    speer_ghash_absorb(&gs, y, aad, aad_len);
    speer_ghash_absorb(&gs, y, ct, ct_len);

    aes_gcm_absorb_lengths(&gs, y, aad_len, ct_len);

    uint8_t s[16];
    speer_aes_encrypt(&k, j0, s);
    uint8_t expected[16];
    for (int i = 0; i < 16; i++) expected[i] = y[i] ^ s[i];

    int eq = speer_ct_memeq(expected, tag, 16);

    WIPE(h, 16);
    WIPE(s, 16);
    WIPE(expected, 16);
    WIPE(&gs, sizeof(gs));

    if (!eq) {
        WIPE(&k, sizeof(k));
        return -1;
    }

    uint8_t ctr[16];
    COPY(ctr, j0, 16);
    for (int i = 15; i >= 12; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }
    speer_aes_ctr(&k, ctr, out_pt, ct, ct_len);
    WIPE(&k, sizeof(k));
    return 0;
}

static int aes128_gcm_seal(const uint8_t *k, const uint8_t *n, const uint8_t *aad, size_t al,
                           const uint8_t *p, size_t pl, uint8_t *oc, uint8_t *ot) {
    return aes_gcm_seal_n(128, k, n, aad, al, p, pl, oc, ot);
}
static int aes128_gcm_open(const uint8_t *k, const uint8_t *n, const uint8_t *aad, size_t al,
                           const uint8_t *c, size_t cl, const uint8_t *t, uint8_t *op) {
    return aes_gcm_open_n(128, k, n, aad, al, c, cl, t, op);
}
static int aes256_gcm_seal(const uint8_t *k, const uint8_t *n, const uint8_t *aad, size_t al,
                           const uint8_t *p, size_t pl, uint8_t *oc, uint8_t *ot) {
    return aes_gcm_seal_n(256, k, n, aad, al, p, pl, oc, ot);
}
static int aes256_gcm_open(const uint8_t *k, const uint8_t *n, const uint8_t *aad, size_t al,
                           const uint8_t *c, size_t cl, const uint8_t *t, uint8_t *op) {
    return aes_gcm_open_n(256, k, n, aad, al, c, cl, t, op);
}

const speer_aead_iface_t speer_aead_aes128_gcm = {.name = "aes-128-gcm",
                                                  .key_len = 16,
                                                  .nonce_len = 12,
                                                  .tag_len = 16,
                                                  .seal = aes128_gcm_seal,
                                                  .open = aes128_gcm_open};
const speer_aead_iface_t speer_aead_aes256_gcm = {.name = "aes-256-gcm",
                                                  .key_len = 32,
                                                  .nonce_len = 12,
                                                  .tag_len = 16,
                                                  .seal = aes256_gcm_seal,
                                                  .open = aes256_gcm_open};

int speer_aes_gcm_encrypt(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32],
                          const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                          uint8_t tag[16]) {
    return aes_gcm_seal_n(256, key, iv, aad, aad_len, in, len, out, tag);
}

int speer_aes_gcm_decrypt(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32],
                          const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                          const uint8_t tag[16]) {
    return aes_gcm_open_n(256, key, iv, aad, aad_len, in, len, tag, out);
}
