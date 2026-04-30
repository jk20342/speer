#include "length_prefix.h"

#include "speer_internal.h"

#include "varint.h"

int speer_lp_u16_write(uint8_t *out, size_t cap, const uint8_t *data, size_t len, size_t *written) {
    if (len > 0xffff) return -1;
    if (cap < 2 + len) return -1;
    out[0] = (uint8_t)(len >> 8);
    out[1] = (uint8_t)(len & 0xff);
    if (len > 0) COPY(out + 2, data, len);
    if (written) *written = 2 + len;
    return 0;
}

int speer_lp_u16_read(const uint8_t *in, size_t in_len, const uint8_t **payload,
                      size_t *payload_len, size_t *consumed) {
    if (in_len < 2) return -1;
    size_t plen = ((size_t)in[0] << 8) | in[1];
    if (plen > in_len - 2) return -1;
    if (payload) *payload = in + 2;
    if (payload_len) *payload_len = plen;
    if (consumed) *consumed = 2 + plen;
    return 0;
}

int speer_lp_uvar_write(uint8_t *out, size_t cap, const uint8_t *data, size_t len,
                        size_t *written) {
    size_t n = speer_uvarint_encode(out, cap, (uint64_t)len);
    if (n == 0) return -1;
    if (cap < n + len) return -1;
    if (len > 0) COPY(out + n, data, len);
    if (written) *written = n + len;
    return 0;
}

int speer_lp_uvar_read(const uint8_t *in, size_t in_len, const uint8_t **payload,
                       size_t *payload_len, size_t *consumed) {
    uint64_t plen = 0;
    size_t n = speer_uvarint_decode(in, in_len, &plen);
    if (n == 0) return -1;
    if (plen > (uint64_t)(SIZE_MAX - n)) return -1;
    if (plen > (uint64_t)(in_len - n)) return -1;
    if (payload) *payload = in + n;
    if (payload_len) *payload_len = (size_t)plen;
    if (consumed) *consumed = n + (size_t)plen;
    return 0;
}
