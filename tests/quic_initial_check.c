#include "speer_internal.h"
#include "quic_pkt.h"
#include "header_protect.h"
#include "hash_iface.h"
#include <stdio.h>
#include <string.h>

/* RFC 9001 Appendix A.1: Keys derived from
 * Destination Connection ID = 0x8394c8f03e515708
 *
 * client initial secret = c00cf151ca5be075ed0ebfb5c80323c4
 *                         2d6b7db67881289af4008f1f6c357aef
 * client key  = 1f369613dd76d5467730efcbe3b1a22d
 * client iv   = fa044b2f42a3fd3b46fb255c
 * client hp   = 9f50449e04a0e810283a1e9933adedd2
 * server initial secret = 3c9bf6a9c1c8c71819876967bd8b979e
 *                         fd98ec665edf27f22c06e95943a2af09
 * server key  = cf3a5331653c364c88f0f379b6067e37
 * server iv   = 0ac1493ca1905853b0bba03e
 * server hp   = c206b8d9b9f0f37644430b490eeaa314
 */
static const uint8_t DCID[8] = { 0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08 };
static const uint8_t CKEY[16]= { 0x1f,0x36,0x96,0x13,0xdd,0x76,0xd5,0x46,0x77,0x30,0xef,0xcb,0xe3,0xb1,0xa2,0x2d };
static const uint8_t CIV [12]= { 0xfa,0x04,0x4b,0x2f,0x42,0xa3,0xfd,0x3b,0x46,0xfb,0x25,0x5c };
static const uint8_t CHP [16]= { 0x9f,0x50,0x44,0x9e,0x04,0xa0,0xe8,0x10,0x28,0x3a,0x1e,0x99,0x33,0xad,0xed,0xd2 };
static const uint8_t SKEY[16]= { 0xcf,0x3a,0x53,0x31,0x65,0x3c,0x36,0x4c,0x88,0xf0,0xf3,0x79,0xb6,0x06,0x7e,0x37 };
static const uint8_t SIV [12]= { 0x0a,0xc1,0x49,0x3c,0xa1,0x90,0x58,0x53,0xb0,0xbb,0xa0,0x3e };
static const uint8_t SHP [16]= { 0xc2,0x06,0xb8,0xd9,0xb9,0xf0,0xf3,0x76,0x44,0x43,0x0b,0x49,0x0e,0xea,0xa3,0x14 };

static int eq(const char* tag, const uint8_t* a, const uint8_t* b, size_t n) {
    if (memcmp(a, b, n) == 0) { printf("  %s ok\n", tag); return 0; }
    printf("  %s MISMATCH\n    got: ", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", a[i]);
    printf("\n    exp: ");
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
    return -1;
}

int main(void) {
    speer_quic_keys_t ck, sk;
    speer_quic_keys_init_initial(&ck, &sk, DCID, sizeof(DCID));
    int fail = 0;
    fail |= eq("client key", ck.key, CKEY, 16);
    fail |= eq("client iv ", ck.iv,  CIV,  12);
    fail |= eq("client hp ", ck.hp.key, CHP, 16);
    fail |= eq("server key", sk.key, SKEY, 16);
    fail |= eq("server iv ", sk.iv,  SIV,  12);
    fail |= eq("server hp ", sk.hp.key, SHP, 16);
    if (fail) { printf("quic initial keys: FAIL\n"); return 1; }
    printf("quic initial keys: ok\n");
    return 0;
}
