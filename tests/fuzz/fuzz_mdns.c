#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MDNS_MAX_PACKET_SIZE 512

typedef struct {
    uint16_t id, flags, questions, answers, authority, additional;
} mdns_header_t;

typedef struct {
    char name[256];
    uint16_t type, class, rdlength;
    uint32_t ttl;
    uint8_t rdata[256];
} mdns_record_t;

static int fuzz_mdns_parse(const uint8_t* data, size_t size,
                            mdns_header_t* hdr, mdns_record_t* recs, int max_rec) {
    if (size < 12) return -1;

    hdr->id = (data[0] << 8) | data[1];
    hdr->flags = (data[2] << 8) | data[3];
    hdr->questions = (data[4] << 8) | data[5];
    hdr->answers = (data[6] << 8) | data[7];
    hdr->authority = (data[8] << 8) | data[9];
    hdr->additional = (data[10] << 8) | data[11];

    if (hdr->questions > 100 || hdr->answers > 100) return -1;

    size_t pos = 12;
    int rec_count = 0;

    for (int i = 0; i < hdr->questions && pos < size; i++) {
        while (pos < size) {
            uint8_t len = data[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xc0) == 0xc0) { pos += 2; break; }
            pos += len + 1;
            if (pos > size) return -1;
        }
        pos += 4;
    }

    for (int i = 0; i < hdr->answers && pos < size && rec_count < max_rec; i++) {
        mdns_record_t* r = &recs[rec_count++];
        size_t np = 0;
        r->name[0] = '\0';

        while (pos < size && np < 255) {
            uint8_t len = data[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xc0) == 0xc0) { pos += 2; break; }
            if (pos + len >= size) return -1;
            pos++;
            for (int j = 0; j < len && np < 255; j++) r->name[np++] = data[pos++];
            if (np < 255) r->name[np++] = '.';
        }
        if (np > 0 && r->name[np-1] == '.') r->name[np-1] = '\0';

        if (pos + 10 > size) return -1;
        r->type = (data[pos] << 8) | data[pos+1]; pos += 2;
        r->class = (data[pos] << 8) | data[pos+1]; pos += 2;
        r->ttl = ((uint32_t)data[pos] << 24) | ((uint32_t)data[pos+1] << 16) |
                 ((uint32_t)data[pos+2] << 8) | data[pos+3]; pos += 4;
        r->rdlength = (data[pos] << 8) | data[pos+1]; pos += 2;

        if (r->rdlength > 256) r->rdlength = 256;
        if (pos + r->rdlength > size) return -1;
        memcpy(r->rdata, data + pos, r->rdlength);
        pos += r->rdlength;
    }

    return rec_count;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    mdns_header_t hdr;
    mdns_record_t recs[16];

    if (size > MDNS_MAX_PACKET_SIZE) size = MDNS_MAX_PACKET_SIZE;
    fuzz_mdns_parse(data, size, &hdr, recs, 16);

    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char** argv) {
    if (argc < 2) {
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput((const uint8_t*)"", 0);

        uint8_t minimal[12] = {0};
        LLVMFuzzerTestOneInput(minimal, sizeof(minimal));

        uint8_t valid[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x04, 't', 'e', 's', 't', 0x05, 'l', 'o', 'c', 'a', 'l',
            0x00, 0x00, 0x01, 0x00, 0x01
        };
        LLVMFuzzerTestOneInput(valid, sizeof(valid));

        return 0;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t* data = malloc(size);
    if (!data) { fclose(f); return 1; }

    fread(data, 1, size, f);
    fclose(f);

    LLVMFuzzerTestOneInput(data, size);
    free(data);

    return 0;
}
#endif
