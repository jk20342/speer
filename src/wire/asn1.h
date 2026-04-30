#ifndef SPEER_ASN1_H
#define SPEER_ASN1_H

#include <stdint.h>
#include <stddef.h>

#define ASN1_BOOLEAN          0x01
#define ASN1_INTEGER          0x02
#define ASN1_BIT_STRING       0x03
#define ASN1_OCTET_STRING     0x04
#define ASN1_NULL             0x05
#define ASN1_OID              0x06
#define ASN1_UTF8_STRING      0x0c
#define ASN1_PRINTABLE_STRING 0x13
#define ASN1_T61_STRING       0x14
#define ASN1_IA5_STRING       0x16
#define ASN1_UTCTIME          0x17
#define ASN1_GENERALIZEDTIME  0x18
#define ASN1_SEQUENCE         0x30
#define ASN1_SET              0x31
#define ASN1_CTX_TAG_BASE     0xa0

typedef struct {
    uint8_t tag;
    const uint8_t* value;
    size_t value_len;
    const uint8_t* tlv_start;
    size_t tlv_total_len;
} speer_asn1_t;

int speer_asn1_parse(const uint8_t* in, size_t in_len, speer_asn1_t* out);
int speer_asn1_seq_iter_init(const speer_asn1_t* seq, const uint8_t** cursor, const uint8_t** end);
int speer_asn1_seq_next(const uint8_t** cursor, const uint8_t* end, speer_asn1_t* out);
int speer_asn1_oid_eq(const speer_asn1_t* node, const uint8_t* oid_bytes, size_t oid_len);
int speer_asn1_get_int_u32(const speer_asn1_t* node, uint32_t* out);
int speer_asn1_get_bit_string(const speer_asn1_t* node, const uint8_t** bits, size_t* bit_count, uint8_t* unused_bits);

#endif
