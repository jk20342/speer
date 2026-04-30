#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "protobuf.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t mode = data[0] % 2;

    switch (mode) {
    case 0: {
        speer_pb_reader_t r;
        speer_pb_reader_init(&r, data + 1, size - 1);

        uint32_t field, wire;
        uint64_t val;
        while (speer_pb_read_tag(&r, &field, &wire) == 0) {
            switch (wire) {
            case 0:
                speer_pb_read_varint(&r, &val);
                break;
            case 2: {
                const uint8_t *v;
                size_t len;
                speer_pb_read_bytes(&r, &v, &len);
                break;
            }
            case 5:
                speer_pb_skip(&r, 5);
                break;
            case 1:
                speer_pb_skip(&r, 1);
                break;
            }
        }
        break;
    }
    case 1: {
        uint8_t buf[512];
        speer_pb_writer_t w;
        speer_pb_writer_init(&w, buf, sizeof(buf));

        for (size_t i = 1; i < size && i < 100; i += 4) {
            uint32_t field = (data[i] % 20) + 1;
            uint8_t wire = data[i + 1] % 5;

            switch (wire) {
            case 0: {
                uint64_t val = data[i + 2];
                speer_pb_write_tag(&w, field, 0);
                speer_pb_write_varint(&w, val);
                break;
            }
            case 2: {
                uint8_t tmp[16] = {0};
                speer_pb_write_bytes_field(&w, field, tmp, data[i + 2] % 16);
                break;
            }
            case 5: {
                int32_t val = 0;
                speer_pb_write_int32_field(&w, field, val);
                break;
            }
            case 1: {
                int64_t val = 0;
                speer_pb_write_int64_field(&w, field, val);
                break;
            }
            }
        }
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

        uint8_t pb[] = {0x08, 0x01, 0x12, 0x04, 't', 'e', 's', 't'};
        LLVMFuzzerTestOneInput(pb, sizeof(pb));

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
