#include "asn1.h"

#include "speer_internal.h"

int speer_asn1_parse(const uint8_t *in, size_t in_len, speer_asn1_t *out) {
    if (in_len < 2) return -1;
    out->tlv_start = in;
    out->tag = in[0];
    size_t pos = 1;
    size_t len;
    uint8_t b = in[pos++];
    if ((b & 0x80) == 0) {
        len = b;
    } else {
        size_t nbytes = b & 0x7f;
        if (nbytes == 0 || nbytes > 4) return -1;
        if (pos + nbytes > in_len) return -1;
        len = 0;
        for (size_t i = 0; i < nbytes; i++) len = (len << 8) | in[pos++];
    }
    if (pos + len > in_len) return -1;
    out->value = in + pos;
    out->value_len = len;
    out->tlv_total_len = pos + len;
    return 0;
}

int speer_asn1_seq_iter_init(const speer_asn1_t *seq, const uint8_t **cursor, const uint8_t **end) {
    if ((seq->tag & 0x1f) != 0x10 && seq->tag != ASN1_SEQUENCE && seq->tag != ASN1_SET) {
        return -1;
    }
    *cursor = seq->value;
    *end = seq->value + seq->value_len;
    return 0;
}

int speer_asn1_seq_next(const uint8_t **cursor, const uint8_t *end, speer_asn1_t *out) {
    if (*cursor >= end) return -1;
    if (speer_asn1_parse(*cursor, (size_t)(end - *cursor), out) != 0) return -1;
    *cursor += out->tlv_total_len;
    return 0;
}

int speer_asn1_oid_eq(const speer_asn1_t *node, const uint8_t *oid_bytes, size_t oid_len) {
    if (node->tag != ASN1_OID) return 0;
    if (node->value_len != oid_len) return 0;
    for (size_t i = 0; i < oid_len; i++) {
        if (node->value[i] != oid_bytes[i]) return 0;
    }
    return 1;
}

int speer_asn1_get_int_u32(const speer_asn1_t *node, uint32_t *out) {
    if (node->tag != ASN1_INTEGER) return -1;
    if (node->value_len == 0 || node->value_len > 5) return -1;
    size_t off = 0;
    if (node->value_len == 5) {
        if (node->value[0] != 0) return -1;
        off = 1;
    }
    uint32_t v = 0;
    for (size_t i = off; i < node->value_len; i++) v = (v << 8) | node->value[i];
    if (out) *out = v;
    return 0;
}

int speer_asn1_get_bit_string(const speer_asn1_t *node, const uint8_t **bits, size_t *bit_count,
                              uint8_t *unused_bits) {
    if (node->tag != ASN1_BIT_STRING) return -1;
    if (node->value_len < 1) return -1;
    if (unused_bits) *unused_bits = node->value[0];
    if (bits) *bits = node->value + 1;
    if (bit_count) *bit_count = node->value_len - 1;
    return 0;
}
