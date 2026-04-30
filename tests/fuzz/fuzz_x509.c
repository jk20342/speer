#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "asn1.h"
#include "x509_libp2p.h"
#include "x509_webpki.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    uint8_t mode = data[0] % 4;

    switch (mode) {
    case 0: {
        speer_x509_libp2p_t cert;
        speer_x509_libp2p_parse(&cert, data + 1, size - 1);
        break;
    }
    case 1: {
        speer_x509_t x509;
        speer_x509_parse(&x509, data + 1, size - 1);
        break;
    }
    case 2: {
        speer_asn1_t asn1;
        if (speer_asn1_parse(data + 1, size - 1, &asn1) == 0) {
            if (asn1.tag == ASN1_SEQUENCE) {
                const uint8_t *cursor, *end;
                speer_asn1_seq_iter_init(&asn1, &cursor, &end);
                speer_asn1_t elem;
                while (speer_asn1_seq_next(&cursor, end, &elem) == 0) { (void)elem; }
            }
        }
        break;
    }
    case 3: {
        speer_x509_t x509;
        if (speer_x509_parse(&x509, data + 1, size - 1) == 0) {
            speer_x509_match_hostname(&x509, "test.example.com");
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

        uint8_t minimal[] = {0x30, 0x03, 0x01, 0x01, 0x00};
        LLVMFuzzerTestOneInput(minimal, sizeof(minimal));

        uint8_t large[4096];
        memset(large, 0x30, sizeof(large));
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
