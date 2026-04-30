#include "speer_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t plaintext[SPEER_MAX_PACKET_SIZE];
    size_t plaintext_len;
    uint8_t cid[SPEER_MAX_CID_LEN];
    uint8_t cid_len;
    uint64_t pkt_num;
    uint8_t key[32] = {0};

    speer_packet_decode(plaintext, &plaintext_len, data, size, cid, &cid_len, &pkt_num, key);

    if (size > 0 && size <= SPEER_MAX_PACKET_SIZE - 64) {
        uint8_t encoded[SPEER_MAX_PACKET_SIZE];
        size_t encoded_len;
        uint8_t test_cid[SPEER_CONNECTION_ID_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8};

        speer_packet_encode(encoded, &encoded_len, data, size, test_cid, SPEER_CONNECTION_ID_SIZE,
                            0, key);
    }

    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc < 2) {
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput((const uint8_t *)"", 0);

        uint8_t sample1[] = {0x01, 0x02, 0x03, 0x04};
        LLVMFuzzerTestOneInput(sample1, sizeof(sample1));

        uint8_t sample2[256] = {0};
        LLVMFuzzerTestOneInput(sample2, sizeof(sample2));

        return 0;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(size);
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
