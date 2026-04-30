#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "buffer_pool.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    speer_buf_pool_t *pool = speer_buf_pool_create(1024, 16);
    if (!pool) return 0;

    size_t pos = 0;
    while (pos < size) {
        uint8_t op = data[pos] % 3;
        pos++;

        switch (op) {
        case 0: {
            size_t sz;
            uint8_t *buf = speer_buf_pool_acquire(pool, &sz);
            if (buf) {
                if (pos < size) {
                    size_t write_len = size - pos > sz ? sz : size - pos;
                    memcpy(buf, data + pos, write_len);
                    pos += write_len;
                }
                speer_buf_pool_release(pool, buf);
            }
            break;
        }
        case 1: {
            size_t sz;
            uint8_t *buf = speer_buf_pool_acquire(pool, &sz);
            if (buf) { speer_buf_pool_release(pool, buf); }
            break;
        }
        case 2: {
            (void)speer_buf_pool_in_use(pool);
            (void)speer_buf_pool_capacity(pool);
            break;
        }
        }
    }

    speer_buf_pool_destroy(pool);
    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc < 2) {
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput((const uint8_t *)"", 0);

        uint8_t ops[] = {0x00, 0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01};
        LLVMFuzzerTestOneInput(ops, sizeof(ops));

        uint8_t random[256];
        for (int i = 0; i < 256; i++) random[i] = (uint8_t)i;
        LLVMFuzzerTestOneInput(random, sizeof(random));

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
