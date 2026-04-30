#include "speer_internal.h"
#include "asn1.h"
#include <stdio.h>
#include <string.h>

#define FAIL(...) do { fprintf(stderr, __VA_ARGS__); return 1; } while (0)

/* SEQUENCE { INTEGER 42 } */
static const uint8_t kSeqInt[] = { 0x30, 0x03, 0x02, 0x01, 0x2a };

/* OID 2.5.4.3 (commonName) */
static const uint8_t kOidCn[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };

int main(void) {
    speer_asn1_t root;
    if (speer_asn1_parse(kSeqInt, sizeof(kSeqInt), &root) != 0 || root.tag != ASN1_SEQUENCE)
        FAIL("asn1_parse seq\n");

    const uint8_t *cur = NULL, *end = NULL;
    if (speer_asn1_seq_iter_init(&root, &cur, &end) != 0) FAIL("seq_iter_init\n");

    speer_asn1_t child;
    if (speer_asn1_seq_next(&cur, end, &child) != 0 || child.tag != ASN1_INTEGER)
        FAIL("seq_next\n");
    uint32_t v = 0;
    if (speer_asn1_get_int_u32(&child, &v) != 0 || v != 42) FAIL("get_int_u32\n");
    if (speer_asn1_seq_next(&cur, end, &child) == 0) FAIL("seq should end\n");

    speer_asn1_t oid;
    if (speer_asn1_parse(kOidCn, sizeof(kOidCn), &oid) != 0 || oid.tag != ASN1_OID)
        FAIL("parse oid\n");
    uint8_t raw[] = { 0x55, 0x04, 0x03 };
    if (!speer_asn1_oid_eq(&oid, raw, sizeof(raw))) FAIL("oid_eq positive\n");
    if (speer_asn1_oid_eq(&oid, raw, 2)) FAIL("oid_eq negative len\n");

    static const uint8_t kBitStr[] = { 0x03, 0x04, 0x00, 0x01, 0x02, 0x03 };
    speer_asn1_t bs;
    if (speer_asn1_parse(kBitStr, sizeof(kBitStr), &bs) != 0) FAIL("bitstr parse\n");
    const uint8_t* bits = NULL;
    size_t bc = 0;
    uint8_t unused = 0xff;
    if (speer_asn1_get_bit_string(&bs, &bits, &bc, &unused) != 0 || unused != 0 || bc != 3 ||
        bits[0] != 1 || bits[1] != 2 || bits[2] != 3)
        FAIL("get_bit_string\n");

    if (speer_asn1_parse(kSeqInt, 2, &root) == 0) FAIL("reject truncated\n");

    puts("asn1: ok");
    return 0;
}
