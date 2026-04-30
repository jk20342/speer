#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "quic_pkt.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t mode = data[0] % 3;

    switch (mode) {
    case 0: {
        if (size > 20) {
            uint8_t dcid[20];
            memcpy(dcid, data + 1, 20);

            speer_quic_keys_t client_keys, server_keys;
            speer_quic_keys_init_initial(&client_keys, &server_keys, dcid, 20, QUIC_VERSION_V1);

            uint8_t out[2048];
            size_t out_len;
            speer_quic_pkt_t pkt = {
                .is_long = 1,
                .pkt_type = QUIC_PT_INITIAL,
                .version = QUIC_VERSION_V1,
                .dcid_len = 20,
            };
            memcpy(pkt.dcid, dcid, 20);
            pkt.payload = (uint8_t *)data + 21;
            pkt.payload_len = size > 1024 ? 1024 : size - 21;
            pkt.pkt_num = 0;
            pkt.pn_length = 1;

            speer_quic_pkt_encode_long(out, sizeof(out), &out_len, &pkt, &client_keys);
        }
        break;
    }
    case 1: {
        if (size > 20) {
            uint8_t dcid[20];
            memcpy(dcid, data + 1, 20);

            speer_quic_keys_t keys;
            speer_quic_keys_init_initial(&keys, NULL, dcid, 20, QUIC_VERSION_V1);

            speer_quic_pkt_t pkt;
            uint8_t *pkt_buf = (uint8_t *)data + 21;
            size_t pkt_len = size - 21;
            speer_quic_pkt_decode_long(&pkt, pkt_buf, pkt_len, &keys);
        }
        break;
    }
    case 2: {
        uint64_t largest = 0;
        uint64_t truncated = 0;
        for (size_t i = 1; i < size && i < 9; i++) { largest = (largest << 8) | data[i]; }
        for (size_t i = 9; i < size && i < 17; i++) { truncated = (truncated << 8) | data[i]; }
        size_t nbits = (data[0] % 4) * 8 + 8;
        speer_quic_decode_pn(largest, truncated, nbits);
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

        uint8_t initial[64];
        initial[0] = 0x00;
        memset(initial + 1, 0xab, 20);
        memset(initial + 21, 0xcd, 40);
        LLVMFuzzerTestOneInput(initial, sizeof(initial));

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
