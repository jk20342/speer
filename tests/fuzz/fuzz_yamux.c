#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "yamux.h"

static int dummy_send(void *user, const uint8_t *data, size_t len) {
    (void)user;
    (void)data;
    (void)len;
    return 0;
}

static int dummy_recv(void *user, uint8_t *buf, size_t cap, size_t *out_n) {
    (void)user;
    (void)buf;
    (void)cap;
    *out_n = 0;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0;

    speer_yamux_session_t mux;
    uint8_t is_initiator = data[0] & 0x01;
    speer_yamux_init(&mux, is_initiator, dummy_send, dummy_recv, NULL);

    speer_yamux_hdr_t hdr;
    if (speer_yamux_hdr_unpack(&hdr, data + 1) == 0) { (void)hdr; }

    if (size > 13) {
        speer_yamux_stream_t *st = speer_yamux_open_stream(&mux);
        if (st) {
            speer_yamux_stream_write(&mux, st, data + 13, size - 13 > 256 ? 256 : size - 13);
            speer_yamux_stream_close(&mux, st);
        }
    }

    uint8_t packed[12];
    speer_yamux_hdr_t hdr2 = {
        .version = 0,
        .type = data[0] % 4,
        .flags = (data[1] << 8) | data[2],
        .stream_id = ((uint32_t)data[3] << 24) | ((uint32_t)data[4] << 16) |
                     ((uint32_t)data[5] << 8) | data[6],
        .length = ((uint32_t)data[7] << 24) | ((uint32_t)data[8] << 16) | ((uint32_t)data[9] << 8) |
                  data[10],
    };
    speer_yamux_hdr_pack(packed, &hdr2);

    speer_yamux_close(&mux);
    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc < 2) {
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput((const uint8_t *)"", 0);

        uint8_t valid[24] = {0x00};
        memset(valid + 1, 0x00, 12);
        valid[13] = 0x00;
        valid[14] = 0x00;
        valid[15] = 0x00;
        valid[16] = 0x01;
        LLVMFuzzerTestOneInput(valid, sizeof(valid));

        uint8_t large[128];
        memset(large, 0, sizeof(large));
        large[0] = 0x01;
        LLVMFuzzerTestOneInput(large, sizeof(large));

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
