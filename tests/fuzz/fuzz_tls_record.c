#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "tls13_keysched.h"
#include "tls13_record.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};

    speer_tls13_keys_t keys;
    memcpy(keys.key, key, 32);
    memcpy(keys.iv, iv, 12);
    memcpy(keys.hp, key, 32);

    speer_tls13_suite_t suite;
    speer_tls13_suite_init(&suite, 0x1301);

    uint8_t mode = data[0] % 2;

    switch (mode) {
    case 0: {
        speer_tls13_record_dir_t rec;
        speer_tls13_record_dir_init(&rec, &suite, &keys);

        uint8_t plaintext[16384];
        size_t plaintext_len;
        uint8_t inner_type;
        speer_tls13_record_open(&rec, data + 1, size - 1, plaintext, sizeof(plaintext),
                                &plaintext_len, &inner_type);
        break;
    }
    case 1: {
        speer_tls13_record_dir_t rec;
        speer_tls13_record_dir_init(&rec, &suite, &keys);

        uint8_t ciphertext[16416];
        size_t ciphertext_len;
        uint8_t content_type = data[1] % 4;
        uint8_t *pt = (uint8_t *)data + 2;
        size_t pt_len = size > 2 ? (size - 2 > 16384 ? 16384 : size - 2) : 0;

        speer_tls13_record_seal(&rec, content_type, pt, pt_len, ciphertext, sizeof(ciphertext),
                                &ciphertext_len);
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

        uint8_t record[128] = {0x00, 0x17, 0x03, 0x03, 0x00, 0x10};
        memset(record + 6, 0xaa, 22);
        LLVMFuzzerTestOneInput(record, sizeof(record));

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
