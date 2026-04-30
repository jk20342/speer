#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "buf_cursor.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    /* u8 + u16be + u24be + u32be + u64be = 1 + 2 + 3 + 4 + 8 bytes */
    const uint8_t in[] = {
        0x01, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    };
    speer_rcur_t rc;
    speer_rcur_init(&rc, in, sizeof(in));

    if (speer_rcur_u8(&rc) != 1) FAIL("rcur u8\n");
    if (speer_rcur_u16be(&rc) != 0x1234) FAIL("rcur u16be\n");
    if (speer_rcur_u24be(&rc) != 0x56789a) FAIL("rcur u24be\n");
    if (speer_rcur_u32be(&rc) != 0xbcdef011) FAIL("rcur u32be\n");
    if (speer_rcur_u64be(&rc) != 0x2233445566778899ULL) FAIL("rcur u64be\n");

    if (rc.err) FAIL("rcur unexpected err\n");
    if (!speer_rcur_eof(&rc)) FAIL("rcur should eof\n");

    speer_rcur_init(&rc, in, 2);
    (void)speer_rcur_u32be(&rc);
    if (!rc.err) FAIL("rcur should set err on overrun\n");

    uint8_t out[32];
    speer_wcur_t wc;
    speer_wcur_init(&wc, out, sizeof(out));
    if (speer_wcur_u8(&wc, 0xab) != 0 || speer_wcur_u16be(&wc, 0xcdef) != 0 ||
        speer_wcur_u24be(&wc, 0x010203) != 0 || speer_wcur_u32be(&wc, 0x44556677) != 0 ||
        speer_wcur_u64be(&wc, 0x8899aabbccddeeffULL) != 0)
        FAIL("wcur writes\n");
    uint8_t blob[] = {1, 2, 3};
    if (speer_wcur_bytes(&wc, blob, sizeof(blob)) != 0) FAIL("wcur bytes\n");
    uint8_t *slot = speer_wcur_reserve(&wc, 4);
    if (!slot) FAIL("reserve\n");
    memset(slot, 0xee, 4);

    static const uint8_t exp[] = {
        0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 1,    2,    3,    0xee, 0xee, 0xee, 0xee,
    };
    if (wc.pos != sizeof(exp) || memcmp(out, exp, sizeof(exp)) != 0) FAIL("wcur layout\n");

    speer_wcur_init(&wc, out, 3);
    if (speer_wcur_u32be(&wc, 0) == 0 || !wc.err) FAIL("wcur overrun\n");

    puts("buf_cursor: ok");
    return 0;
}
