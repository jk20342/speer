#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "length_prefix.h"
#include "varint.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static int test_uvar_roundtrip(uint64_t v) {
    uint8_t buf[16];
    size_t n = speer_uvarint_encode(buf, sizeof(buf), v);
    if (n == 0 || n != speer_uvarint_size(v))
        FAIL("uvar size mismatch for %llu\n", (unsigned long long)v);
    uint64_t d = 0;
    size_t k = speer_uvarint_decode(buf, n, &d);
    if (k != n || d != v) FAIL("uvar roundtrip fail %llu\n", (unsigned long long)v);
    return 0;
}

static int test_qvar_roundtrip(uint64_t v) {
    uint8_t buf[16];
    size_t n = speer_qvarint_encode(buf, sizeof(buf), v);
    if (n == 0 || n != speer_qvarint_size(v)) FAIL("qvar size mismatch\n");
    uint64_t d = 0;
    size_t k = speer_qvarint_decode(buf, n, &d);
    if (k != n || d != v) FAIL("qvar roundtrip fail %llu\n", (unsigned long long)v);
    return 0;
}

int main(void) {
    if (test_uvar_roundtrip(0) || test_uvar_roundtrip(127) || test_uvar_roundtrip(128) ||
        test_uvar_roundtrip(16383) || test_uvar_roundtrip(16384))
        return 1;

    uint8_t over[12];
    memset(over, 0x80, sizeof(over));
    over[10] = 0x01;
    if (speer_uvarint_decode(over, sizeof(over), NULL) != 0) FAIL("uvar should reject >10 bytes\n");

    if (test_qvar_roundtrip(0) || test_qvar_roundtrip(63) || test_qvar_roundtrip(64) ||
        test_qvar_roundtrip(16383) || test_qvar_roundtrip(16384) ||
        test_qvar_roundtrip(1073741823ULL) || test_qvar_roundtrip(1073741824ULL) ||
        test_qvar_roundtrip((1ULL << 62) - 1))
        return 1;

    if (speer_qvarint_encode(NULL, 0, 64) != 0) FAIL("qvar encode cap 0\n");
    uint8_t qtmp[8];
    if (speer_qvarint_encode(qtmp, 7, (1ULL << 62) - 1) != 0)
        FAIL("qvar needs 8 bytes for large values\n");
    if (speer_qvarint_encode(qtmp, 8, (1ULL << 62) - 1) != 8) FAIL("qvar 8-byte encode\n");
    if (speer_qvarint_encode(qtmp, 8, (1ULL << 62)) != 0) FAIL("qvar reject >= 2^62\n");

    if (speer_qvarint_peek_len(0x00) != 1 || speer_qvarint_peek_len(0x40) != 2 ||
        speer_qvarint_peek_len(0x80) != 4 || speer_qvarint_peek_len(0xc0) != 8)
        FAIL("qvar_peek_len\n");

    uint8_t lp[256];
    const uint8_t *pay;
    size_t plen, wn, cons;
    uint8_t hello[] = "hello";

    if (speer_lp_u16_write(lp, sizeof(lp), hello, sizeof(hello) - 1, &wn) != 0 || wn != 2 + 5)
        FAIL("lp_u16_write\n");
    if (speer_lp_u16_read(lp, wn, &pay, &plen, &cons) != 0 || plen != 5 || cons != wn ||
        memcmp(pay, hello, 5) != 0)
        FAIL("lp_u16_read\n");
    if (speer_lp_u16_read(lp, 6, &pay, &plen, &cons) == 0) FAIL("lp_u16_read truncated\n");

    if (speer_lp_uvar_write(lp, sizeof(lp), hello, sizeof(hello) - 1, &wn) != 0)
        FAIL("lp_uvar_write\n");
    if (speer_lp_uvar_read(lp, wn, &pay, &plen, &cons) != 0 || plen != 5 ||
        memcmp(pay, hello, 5) != 0 || cons != wn)
        FAIL("lp_uvar_read\n");

    static uint8_t huge[0xffff];
    static uint8_t lp_big[2 + 0xffff];
    if (speer_lp_u16_write(lp_big, sizeof(lp_big), huge, 0xffff, NULL) != 0)
        FAIL("lp_u16 max len\n");
    if (speer_lp_u16_write(lp, sizeof(lp), huge, 0x10000, NULL) == 0)
        FAIL("lp_u16 reject overflow\n");

    puts("varint_length_prefix: ok");
    return 0;
}
