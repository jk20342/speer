#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "length_prefix.h"
#include "varint.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    uint8_t mode = data[0] % 4;

    switch (mode) {
    case 0: {
        uint64_t val;
        speer_uvarint_decode(data + 1, size - 1, &val);
        break;
    }
    case 1: {
        if (size > 10) {
            uint8_t buf[16];
            uint64_t val = 0;
            for (size_t i = 1; i < size && i < 9; i++) { val = (val << 8) | data[i]; }
            speer_uvarint_encode(buf, sizeof(buf), val);
        }
        break;
    }
    case 2: {
        const uint8_t *payload;
        size_t payload_len;
        size_t consumed;
        speer_lp_uvar_read(data + 1, size - 1, &payload, &payload_len, &consumed);
        break;
    }
    case 3: {
        if (size > 8) {
            uint8_t buf[65544];
            size_t written;
            size_t len = size - 9 > 65536 ? 65536 : size - 9;
            speer_lp_uvar_write(buf, sizeof(buf), data + 9, len, &written);
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

        uint8_t small[] = {0x01, 0x7f};
        LLVMFuzzerTestOneInput(small, sizeof(small));

        uint8_t large_varint[] = {0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x01};
        LLVMFuzzerTestOneInput(large_varint, sizeof(large_varint));

        uint8_t lp[] = {0x02, 0x04, 0xaa, 0xbb, 0xcc, 0xdd};
        LLVMFuzzerTestOneInput(lp, sizeof(lp));

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
