#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "identify.h"
#include "protobuf.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static int test_field_oversize(uint32_t field, size_t pad_len) {
    uint8_t buf[1024];
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, buf, sizeof(buf));
    uint8_t big[600];
    memset(big, 'A', sizeof(big));
    if (pad_len > sizeof(big)) pad_len = sizeof(big);
    if (speer_pb_write_bytes_field(&w, field, big, pad_len) != 0) return 0;
    speer_identify_t id;
    int rc = speer_identify_decode(&id, buf, w.pos);
    if (rc == 0) FAIL("identify_decode accepted oversized field %u (%zu bytes)\n", field, pad_len);
    return 0;
}

int main(void) {
    if (test_field_oversize(1, 600)) return 1;
    if (test_field_oversize(2, 600)) return 1;
    if (test_field_oversize(4, 600)) return 1;

    uint8_t buf[256];
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, buf, sizeof(buf));
    uint8_t pk[32] = {1, 2, 3};
    if (speer_pb_write_bytes_field(&w, 1, pk, sizeof(pk)) != 0) FAIL("encode pubkey\n");
    if (speer_pb_write_string_field(&w, 5, "/test/1.0") != 0) FAIL("encode protover\n");
    speer_identify_t id;
    if (speer_identify_decode(&id, buf, w.pos) != 0) FAIL("decode happy path\n");
    if (id.pubkey_proto_len != 32) FAIL("pubkey_proto_len wrong\n");
    if (strcmp(id.protocol_version, "/test/1.0") != 0) FAIL("protover wrong\n");

    puts("identify: ok");
    return 0;
}
