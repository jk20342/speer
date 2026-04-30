#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "dht.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t node_id[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                           0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                           0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

    dht_t dht;
    dht_init(&dht, node_id);

    uint8_t mode = data[0] % 5;

    switch (mode) {
    case 0: {
        uint8_t response[256];
        size_t response_len;
        if (size > 32) {
            dht_handle_ping(&dht, data + 1, "127.0.0.1:1234", response, &response_len);
        }
        break;
    }
    case 1: {
        if (size > 32) {
            uint8_t target[32];
            memcpy(target, data + 1, 32);
            uint8_t response[512];
            size_t response_len;
            dht_handle_find_node(&dht, target, response, &response_len);
        }
        break;
    }
    case 2: {
        if (size > 32) {
            uint8_t key[32];
            memcpy(key, data + 1, 32);
            uint8_t response[512];
            size_t response_len;
            dht_value_t val;
            dht_handle_find_value(&dht, key, response, &response_len, &val);
        }
        break;
    }
    case 3: {
        if (size > 64) {
            uint8_t key[32], publisher[32];
            memcpy(key, data + 1, 32);
            memcpy(publisher, data + 33, 32);
            size_t val_len = size > 96 ? 32 : size - 64;
            dht_handle_store(&dht, key, data + 65, val_len, publisher);
        }
        break;
    }
    case 4: {
        if (size > 32) {
            uint8_t id[32];
            memcpy(id, data + 1, 32);
            char addr[64];
            snprintf(addr, sizeof(addr), "192.168.%d.%d:%d", data[size / 2] % 256,
                     data[size / 3] % 256, 4000 + (data[0] % 1000));
            dht_add_node(&dht, id, addr);
        }
        break;
    }
    }

    dht_free(&dht);
    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc < 2) {
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput((const uint8_t *)"", 0);

        uint8_t ping[40];
        ping[0] = 0x00;
        memset(ping + 1, 0xaa, 32);
        ping[33] = 0;
        LLVMFuzzerTestOneInput(ping, sizeof(ping));

        uint8_t find[36];
        find[0] = 0x01;
        memset(find + 1, 0xbb, 32);
        LLVMFuzzerTestOneInput(find, sizeof(find));

        uint8_t large[4096];
        large[0] = 0x02;
        memset(large + 1, 0x55, sizeof(large) - 1);
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
