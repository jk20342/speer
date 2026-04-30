#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "multistream.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t buf[256];
    size_t pos = 0;

    for (size_t i = 0; i < size && i < 200; i++) {
        if (data[i] < 32 || data[i] > 126) continue;
        buf[pos++] = data[i];
        if (pos >= sizeof(buf) - 1) break;
    }

    if (pos > 0) {
        buf[pos] = '\0';
        if (strncmp((char *)buf, "/", 1) == 0) { (void)buf; }
    }

    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc < 2) {
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput((const uint8_t *)"", 0);

        uint8_t proto[] = "/multistream/1.0.0\n";
        LLVMFuzzerTestOneInput(proto, sizeof(proto) - 1);

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
