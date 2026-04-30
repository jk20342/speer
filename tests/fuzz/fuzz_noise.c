#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "speer_internal.h"

static uint8_t local_pubkey[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static uint8_t local_privkey[32] = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
};

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    speer_handshake_t hs;
    uint8_t out[128];

    speer_noise_xx_init(&hs, local_pubkey, local_privkey);

    if (size >= 32) {
        speer_noise_xx_read_msg1(&hs, data);
        speer_noise_xx_write_msg2(&hs, out);

        if (size >= 48) {
            speer_noise_xx_read_msg3(&hs, data);
        }
    }

    speer_noise_xx_init(&hs, local_pubkey, local_privkey);
    speer_noise_xx_write_msg1(&hs, out);

    if (size >= 80) {
        speer_noise_xx_read_msg2(&hs, data);
        speer_noise_xx_write_msg3(&hs, out);

        uint8_t send_key[32], recv_key[32];
        speer_noise_xx_split(&hs, send_key, recv_key);
    }

    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char** argv) {
    if (argc < 2) {
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput((const uint8_t*)"", 0);

        uint8_t buf[256] = {0};
        for (size_t i = 0; i <= 256; i++) {
            LLVMFuzzerTestOneInput(buf, i);
        }

        for (int i = 0; i < 256; i++) buf[i] = (uint8_t)i;
        LLVMFuzzerTestOneInput(buf, 256);

        return 0;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t* data = malloc(size);
    if (!data) {
        fclose(f);
        return 1;
    }

    fread(data, 1, size, f);
    fclose(f);

    LLVMFuzzerTestOneInput(data, size);
    free(data);

    return 0;
}
#endif
