#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "aead_iface.h"
#include "ed25519.h"
#include "field25519.h"

extern const speer_aead_iface_t speer_aead_aes128_gcm;
extern const speer_aead_iface_t speer_aead_aes256_gcm;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    uint8_t mode = data[0] % 5;

    switch (mode) {
    case 0: {
        uint8_t pk[32], sk[32];
        uint8_t seed[32] = {0};
        memcpy(seed, data + 1, size - 1 > 32 ? 32 : size - 1);
        speer_ed25519_keypair(pk, sk, seed);
        break;
    }
    case 1: {
        if (size > 96) {
            uint8_t sig[64];
            uint8_t msg[32] = {0};
            uint8_t pk[32], sk[32];
            memcpy(pk, data + 1, 32);
            memcpy(sk, data + 33, 32);
            speer_ed25519_sign(sig, msg, 32, pk, sk);
        }
        break;
    }
    case 2: {
        if (size > 96) {
            uint8_t msg[32] = {0};
            uint8_t pk[32], sig[64];
            memcpy(sig, data + 1, 64);
            memcpy(pk, data + 65, 32);
            speer_ed25519_verify(sig, msg, 32, pk);
        }
        break;
    }
    case 3: {
        uint8_t ct[256], tag[16], pt[256];
        size_t pt_len = size - 1 > 256 ? 256 : size - 1;
        uint8_t key[16] = {0}, iv[12] = {0};
        speer_aead_aes128_gcm.seal(key, iv, NULL, 0, data + 1, pt_len, ct, tag);
        speer_aead_aes128_gcm.open(key, iv, NULL, 0, ct, pt_len, tag, pt);
        break;
    }
    case 4: {
        uint8_t ct[256], tag[16], pt[256];
        size_t pt_len = size - 1 > 256 ? 256 : size - 1;
        uint8_t key[32] = {0}, iv[12] = {0};
        speer_aead_aes256_gcm.seal(key, iv, NULL, 0, data + 1, pt_len, ct, tag);
        speer_aead_aes256_gcm.open(key, iv, NULL, 0, ct, pt_len, tag, pt);
        break;
    }
    }

    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc < 2) {
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput((const uint8_t *)"", 0);

        uint8_t seed[33] = {0};
        LLVMFuzzerTestOneInput(seed, sizeof(seed));

        uint8_t sign[100] = {1};
        LLVMFuzzerTestOneInput(sign, sizeof(sign));

        uint8_t aead[128] = {3};
        LLVMFuzzerTestOneInput(aead, sizeof(aead));

        return 0;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(sz);
    if (!data) {
        fclose(f);
        return 1;
    }

    fread(data, 1, sz, f);
    fclose(f);

    LLVMFuzzerTestOneInput(data, sz);
    free(data);

    return 0;
}
#endif
