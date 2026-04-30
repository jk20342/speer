#include "varint.h"

#include "speer_internal.h"

size_t speer_uvarint_encode(uint8_t *out, size_t cap, uint64_t v) {
    size_t n = 0;
    while (v >= 0x80) {
        if (n >= cap) return 0;
        out[n++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    if (n >= cap) return 0;
    out[n++] = (uint8_t)v;
    return n;
}

size_t speer_uvarint_decode(const uint8_t *in, size_t in_len, uint64_t *out) {
    uint64_t v = 0;
    size_t shift = 0;
    size_t i = 0;
    while (i < in_len) {
        uint8_t b = in[i++];
        if (shift >= 64) return 0;
        if (shift == 63 && b > 1) return 0;
        v |= ((uint64_t)(b & 0x7f)) << shift;
        if ((b & 0x80) == 0) {
            if (out) *out = v;
            return i;
        }
        shift += 7;
        if (i >= 10) return 0;
    }
    return 0;
}

size_t speer_uvarint_size(uint64_t v) {
    size_t n = 1;
    while (v >= 0x80) {
        v >>= 7;
        n++;
    }
    return n;
}

size_t speer_qvarint_encode(uint8_t *out, size_t cap, uint64_t v) {
    if (v < 64ULL) {
        if (cap < 1) return 0;
        out[0] = (uint8_t)v;
        return 1;
    } else if (v < 16384ULL) {
        if (cap < 2) return 0;
        out[0] = (uint8_t)(0x40 | ((v >> 8) & 0x3f));
        out[1] = (uint8_t)(v & 0xff);
        return 2;
    } else if (v < 1073741824ULL) {
        if (cap < 4) return 0;
        out[0] = (uint8_t)(0x80 | ((v >> 24) & 0x3f));
        out[1] = (uint8_t)((v >> 16) & 0xff);
        out[2] = (uint8_t)((v >> 8) & 0xff);
        out[3] = (uint8_t)(v & 0xff);
        return 4;
    } else if (v < (1ULL << 62)) {
        if (cap < 8) return 0;
        out[0] = (uint8_t)(0xc0 | ((v >> 56) & 0x3f));
        for (int i = 1; i < 8; i++) out[i] = (uint8_t)((v >> ((7 - i) * 8)) & 0xff);
        return 8;
    }
    return 0;
}

size_t speer_qvarint_decode(const uint8_t *in, size_t in_len, uint64_t *out) {
    if (in_len < 1) return 0;
    uint8_t prefix = in[0] >> 6;
    size_t n = (size_t)1 << prefix;
    if (in_len < n) return 0;
    uint64_t v = (uint64_t)(in[0] & 0x3f);
    for (size_t i = 1; i < n; i++) v = (v << 8) | in[i];
    if (out) *out = v;
    return n;
}

size_t speer_qvarint_size(uint64_t v) {
    if (v < 64ULL) return 1;
    if (v < 16384ULL) return 2;
    if (v < 1073741824ULL) return 4;
    return 8;
}

size_t speer_qvarint_peek_len(uint8_t first_byte) {
    return (size_t)1 << (first_byte >> 6);
}
