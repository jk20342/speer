#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "protobuf.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static const uint8_t kSha256Empty[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

int main(void) {
    uint8_t h[32];
    speer_sha256(h, NULL, 0);
    if (memcmp(h, kSha256Empty, 32) != 0) FAIL("sha256 empty mismatch\n");

    uint8_t ctx_storage[256];
    speer_sha256_init(ctx_storage);
    speer_sha256_update(ctx_storage, (const uint8_t *)"abc", 3);
    speer_sha256_final(ctx_storage, h);
    static const uint8_t kAbc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    uint8_t h2[32];
    speer_sha256(h2, (const uint8_t *)"abc", 3);
    if (memcmp(h, kAbc, 32) != 0 || memcmp(h2, kAbc, 32) != 0) FAIL("sha256 abc\n");

    const int64_t neg_shift40 = -(int64_t)((uint64_t)1 << 40);

    uint8_t buf[128];
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, buf, sizeof(buf));
    if (speer_pb_write_int32_field(&w, 3, -42) != 0 || speer_pb_write_bool_field(&w, 4, 1) != 0 ||
        speer_pb_write_bytes_field(&w, 5, (const uint8_t *)"abc", 3) != 0 ||
        speer_pb_write_string_field(&w, 6, "hi") != 0 ||
        speer_pb_write_int64_field(&w, 7, neg_shift40) != 0)
        FAIL("pb write\n");

    speer_pb_reader_t r;
    speer_pb_reader_init(&r, buf, w.pos);
    int saw = 0;
    while (r.pos < r.len) {
        uint32_t f, wire;
        if (speer_pb_read_tag(&r, &f, &wire) != 0) FAIL("pb tag\n");
        if (f == 3 && wire == PB_WIRE_VARINT) {
            int32_t v;
            if (speer_pb_read_int32(&r, &v) != 0 || v != -42) FAIL("pb int32\n");
            saw |= 1;
        } else if (f == 4 && wire == PB_WIRE_VARINT) {
            int bv;
            if (speer_pb_read_bool(&r, &bv) != 0 || bv != 1) FAIL("pb bool\n");
            saw |= 2;
        } else if (f == 5 && wire == PB_WIRE_LEN) {
            const uint8_t *d;
            size_t l;
            if (speer_pb_read_bytes(&r, &d, &l) != 0 || l != 3 || memcmp(d, "abc", 3) != 0)
                FAIL("pb bytes\n");
            saw |= 4;
        } else if (f == 6 && wire == PB_WIRE_LEN) {
            const char *str;
            size_t sl;
            if (speer_pb_read_string(&r, &str, &sl) != 0 || sl != 2 || memcmp(str, "hi", 2) != 0)
                FAIL("pb string\n");
            saw |= 8;
        } else if (f == 7 && wire == PB_WIRE_VARINT) {
            int64_t v64;
            if (speer_pb_read_int64(&r, &v64) != 0 || v64 != neg_shift40) FAIL("pb int64\n");
            saw |= 16;
        } else if (speer_pb_skip(&r, wire) != 0)
            FAIL("pb skip\n");
    }
    if (saw != 31) FAIL("pb fields incomplete saw=%d\n", saw);

    uint8_t junk[] = {0x08, 0x01, 0x11, 1, 2, 3, 4, 5, 6, 7, 8};
    speer_pb_reader_init(&r, junk, sizeof(junk));
    uint32_t f, wire;
    if (speer_pb_read_tag(&r, &f, &wire) != 0 || f != 1) FAIL("junk tag1\n");
    int32_t iv;
    if (speer_pb_read_int32(&r, &iv) != 0 || iv != 1) FAIL("junk int\n");
    if (speer_pb_read_tag(&r, &f, &wire) != 0 || wire != PB_WIRE_64BIT) FAIL("junk wire64\n");
    if (speer_pb_skip(&r, wire) != 0) FAIL("skip 64\n");

    puts("protobuf_sha256: ok");
    return 0;
}
