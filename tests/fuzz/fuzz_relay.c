#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "circuit_relay.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t mode = data[0] % 4;

    switch (mode) {
    case 0: {
        uint8_t buf[256];
        size_t len;
        speer_relay_encode_hop_reserve(buf, sizeof(buf), &len);
        break;
    }
    case 1: {
        if (size > 10) {
            uint8_t buf[256];
            size_t len;
            speer_relay_encode_hop_connect(buf, sizeof(buf), &len, data + 1,
                                           size - 1 > 64 ? 64 : size - 1);
        }
        break;
    }
    case 2: {
        uint8_t buf[512];
        size_t len;
        int status = 100 + (data[1] % 200);
        speer_relay_reservation_t res;
        memset(&res, 0, sizeof(res));
        speer_relay_encode_hop_status(buf, sizeof(buf), &len, status, &res);
        break;
    }
    case 3: {
        speer_relay_msg_type_t type;
        int status;
        speer_relay_reservation_t res;
        uint8_t peer_id[64];
        size_t peer_id_len;
        speer_relay_decode(data + 1, size - 1, &type, &status, &res, peer_id, &peer_id_len);
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

        uint8_t decode[32];
        decode[0] = 0x03;
        memset(decode + 1, 0xcc, 28);
        LLVMFuzzerTestOneInput(decode, sizeof(decode));

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
