#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "asn1.h"
#include "length_prefix.h"
#include "multiaddr.h"
#include "protobuf.h"
#include "varint.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static int test_lp_overflow(void) {
    uint8_t buf[10] = {0};
    uint64_t huge = (uint64_t)0xFFFFFFFFFFFFFFFFull;
    size_t n = speer_uvarint_encode(buf, sizeof(buf), huge);
    if (n == 0) return 0;
    const uint8_t *out;
    size_t out_len;
    size_t consumed;
    if (speer_lp_uvar_read(buf, n, &out, &out_len, &consumed) == 0)
        FAIL("lp_uvar_read accepted huge plen\n");
    return 0;
}

static int test_asn1_length_overflow(void) {
    uint8_t buf[] = {0x04, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x00};
    speer_asn1_t out;
    if (speer_asn1_parse(buf, sizeof(buf), &out) == 0) FAIL("asn1_parse accepted huge length\n");
    return 0;
}

static int test_asn1_high_tag_form(void) {
    uint8_t buf[] = {0x1f, 0x01, 0x01, 0x00};
    speer_asn1_t out;
    if (speer_asn1_parse(buf, sizeof(buf), &out) == 0) FAIL("asn1_parse accepted high-tag-form\n");
    return 0;
}

static int test_protobuf_size_truncation(void) {
    uint8_t buf[20];
    buf[0] = (1 << 3) | 2;
    int i = 1;
    for (int j = 0; j < 9; j++) buf[i++] = 0xff;
    buf[i++] = 0x7f;
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, buf, (size_t)i);
    uint32_t f, w;
    if (speer_pb_read_tag(&r, &f, &w) != 0) return 0;
    const uint8_t *d;
    size_t l;
    if (speer_pb_read_bytes(&r, &d, &l) == 0) FAIL("pb_read_bytes accepted huge length\n");
    return 0;
}

static int test_multiaddr_huge_p2p(void) {
    uint8_t bytes[64];
    size_t n = 0;
    bytes[n++] = SPEER_MA_IP4;
    bytes[n++] = 1;
    bytes[n++] = 2;
    bytes[n++] = 3;
    bytes[n++] = 4;
    bytes[n++] = SPEER_MA_P2P > 127 ? (SPEER_MA_P2P & 0x7f) | 0x80 : SPEER_MA_P2P;
    if (SPEER_MA_P2P > 127) bytes[n++] = (SPEER_MA_P2P >> 7) & 0x7f;
    bytes[n++] = 100;
    speer_multiaddr_t ma;
    ma.len = n;
    memcpy(ma.bytes, bytes, n);
    const uint8_t *id;
    size_t idl;
    if (speer_multiaddr_get_p2p_id(&ma, &id, &idl) == 0)
        FAIL("multiaddr_get_p2p_id accepted oversized claim\n");
    return 0;
}

int main(void) {
    if (test_lp_overflow()) return 1;
    if (test_asn1_length_overflow()) return 1;
    if (test_asn1_high_tag_form()) return 1;
    if (test_protobuf_size_truncation()) return 1;
    if (test_multiaddr_huge_p2p()) return 1;
    puts("parser_robustness: ok");
    return 0;
}
