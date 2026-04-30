#include "speer_internal.h"

#include "ghash.h"

static const uint8_t R_BYTE0[16] = {0x00, 0x1c, 0x38, 0x24, 0x70, 0x6c, 0x48, 0x54,
                                    0xe1, 0xfd, 0xd9, 0xc5, 0x91, 0x8d, 0xa9, 0xb5};
static const uint8_t R_BYTE1[16] = {0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0,
                                    0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0};

static void shift_x_one(uint8_t v[16]) {
    uint8_t lsb = v[15] & 1;
    for (int k = 15; k > 0; k--) v[k] = (uint8_t)((v[k] >> 1) | ((v[k - 1] & 1) << 7));
    v[0] >>= 1;
    v[0] ^= (uint8_t)((uint32_t)0u - (uint32_t)lsb) & 0xe1;
}

static void shift_x4(uint8_t z[16]) {
    uint8_t spilled = z[15] & 0x0f;
    for (int k = 15; k > 0; k--) z[k] = (uint8_t)((z[k] >> 4) | (z[k - 1] << 4));
    z[0] >>= 4;
    z[0] ^= R_BYTE0[spilled];
    z[1] ^= R_BYTE1[spilled];
}

static void compute_table(uint8_t T[16][16], const uint8_t h[16]) {
    for (int i = 0; i < 16; i++) T[0][i] = 0;
    for (int i = 0; i < 16; i++) T[8][i] = h[i];
    for (int i = 0; i < 16; i++) T[4][i] = T[8][i];
    shift_x_one(T[4]);
    for (int i = 0; i < 16; i++) T[2][i] = T[4][i];
    shift_x_one(T[2]);
    for (int i = 0; i < 16; i++) T[1][i] = T[2][i];
    shift_x_one(T[1]);
    for (int k = 1; k < 16; k++) {
        if (k == 1 || k == 2 || k == 4 || k == 8) continue;
        int hi = k & -k;
        int rest = k ^ hi;
        for (int i = 0; i < 16; i++) T[k][i] = T[hi][i] ^ T[rest][i];
    }
}

static void gf_mul_table(uint8_t z[16], const uint8_t y[16], uint8_t T[16][16]) {
    uint8_t tmp[16];
    int idx = y[15] & 0x0f;
    for (int i = 0; i < 16; i++) tmp[i] = T[idx][i];

    for (int i = 15; i >= 0; i--) {
        if (i != 15) {
            shift_x4(tmp);
            int idx2 = y[i] & 0x0f;
            for (int j = 0; j < 16; j++) tmp[j] ^= T[idx2][j];
        }
        shift_x4(tmp);
        int idx3 = (y[i] >> 4) & 0x0f;
        for (int j = 0; j < 16; j++) tmp[j] ^= T[idx3][j];
    }

    for (int i = 0; i < 16; i++) z[i] = tmp[i];
}

void speer_ghash_soft_init(speer_ghash_state_t *s, const uint8_t h[16]) {
    s->use_clmul = 0;
    for (int i = 0; i < 16; i++) s->h[i] = h[i];
    compute_table(s->htables, h);
}

void speer_ghash_soft_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data,
                             size_t len) {
    while (len >= 16) {
        for (int i = 0; i < 16; i++) y[i] ^= data[i];
        gf_mul_table(y, y, s->htables);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        uint8_t blk[16] = {0};
        for (size_t i = 0; i < len; i++) blk[i] = data[i];
        for (int i = 0; i < 16; i++) y[i] ^= blk[i];
        gf_mul_table(y, y, s->htables);
    }
}
