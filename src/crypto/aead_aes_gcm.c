#include "speer_internal.h"

#include "aead_iface.h"
#include "aes.h"
#include "ct_helpers.h"

static void gf_mul(uint8_t z[16], const uint8_t x[16], const uint8_t y[16]) {
    uint8_t v[16];
    uint8_t r[16] = {0};
    COPY(v, y, 16);
    for (int i = 0; i < 128; i++) {
        int byte = i / 8;
        int bit = 7 - (i & 7);
        if ((x[byte] >> bit) & 1) {
            for (int k = 0; k < 16; k++) r[k] ^= v[k];
        }
        int lsb = v[15] & 1;
        for (int k = 15; k > 0; k--) v[k] = (uint8_t)((v[k] >> 1) | ((v[k - 1] & 1) << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    COPY(z, r, 16);
}

static void ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t *data, size_t len) {
    while (len >= 16) {
        for (int i = 0; i < 16; i++) y[i] ^= data[i];
        gf_mul(y, y, h);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        uint8_t blk[16] = {0};
        COPY(blk, data, len);
        for (int i = 0; i < 16; i++) y[i] ^= blk[i];
        gf_mul(y, y, h);
    }
}

static int aes_gcm_seal_n(size_t key_bits, const uint8_t *key, const uint8_t *nonce,
                          const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
                          uint8_t *out_ct, uint8_t *out_tag) {
    speer_aes_key_t k;
    speer_aes_set_encrypt_key(&k, key, key_bits);

    uint8_t h[16] = {0};
    uint8_t zero[16] = {0};
    speer_aes_encrypt(&k, zero, h);

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
    ghash_update(y, h, aad, aad_len);
    ghash_update(y, h, out_ct, pt_len);

    uint8_t lens[16];
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)pt_len * 8;
    for (int i = 0; i < 8; i++) lens[i] = (uint8_t)(aad_bits >> ((7 - i) * 8));
    for (int i = 0; i < 8; i++) lens[8 + i] = (uint8_t)(ct_bits >> ((7 - i) * 8));
    ghash_update(y, h, lens, 16);

    uint8_t s[16];
    speer_aes_encrypt(&k, j0, s);
    for (int i = 0; i < 16; i++) out_tag[i] = y[i] ^ s[i];
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

    uint8_t j0[16] = {0};
    COPY(j0, nonce, 12);
    j0[15] = 1;

    uint8_t y[16] = {0};
    ghash_update(y, h, aad, aad_len);
    ghash_update(y, h, ct, ct_len);

    uint8_t lens[16];
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; i++) lens[i] = (uint8_t)(aad_bits >> ((7 - i) * 8));
    for (int i = 0; i < 8; i++) lens[8 + i] = (uint8_t)(ct_bits >> ((7 - i) * 8));
    ghash_update(y, h, lens, 16);

    uint8_t s[16];
    speer_aes_encrypt(&k, j0, s);
    uint8_t expected[16];
    for (int i = 0; i < 16; i++) expected[i] = y[i] ^ s[i];

    if (!speer_ct_memeq(expected, tag, 16)) return -1;

    uint8_t ctr[16];
    COPY(ctr, j0, 16);
    for (int i = 15; i >= 12; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }
    speer_aes_ctr(&k, ctr, out_pt, ct, ct_len);
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
