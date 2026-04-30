#include "peer_id.h"

#include "speer_internal.h"

#include <string.h>

#include "protobuf.h"

int speer_libp2p_pubkey_proto_encode(uint8_t *out, size_t cap, speer_libp2p_keytype_t kt,
                                     const uint8_t *key, size_t key_len, size_t *out_len) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, (int32_t)kt) != 0) return -1;
    if (speer_pb_write_bytes_field(&w, 2, key, key_len) != 0) return -1;
    if (out_len) *out_len = w.pos;
    return 0;
}

int speer_libp2p_pubkey_proto_decode(const uint8_t *in, size_t in_len, speer_libp2p_keytype_t *kt,
                                     const uint8_t **key, size_t *key_len) {
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, in, in_len);
    int got_type = 0, got_data = 0;
    speer_libp2p_keytype_t local_kt = (speer_libp2p_keytype_t)0;
    const uint8_t *local_key = NULL;
    size_t local_key_len = 0;
    while (r.pos < r.len) {
        uint32_t f, wire;
        if (speer_pb_read_tag(&r, &f, &wire) != 0) return -1;
        if (f == 1 && wire == PB_WIRE_VARINT) {
            if (got_type) return -1;
            int32_t v;
            if (speer_pb_read_int32(&r, &v) != 0) return -1;
            if (v < 0 || v > 3) return -1;
            local_kt = (speer_libp2p_keytype_t)v;
            got_type = 1;
        } else if (f == 2 && wire == PB_WIRE_LEN) {
            if (got_data) return -1;
            const uint8_t *d;
            size_t l;
            if (speer_pb_read_bytes(&r, &d, &l) != 0) return -1;
            local_key = d;
            local_key_len = l;
            got_data = 1;
        } else {
            return -1;
        }
    }
    if (!got_type || !got_data) return -1;

    uint8_t reenc[1024];
    size_t reenc_len = 0;
    if (speer_libp2p_pubkey_proto_encode(reenc, sizeof(reenc), local_kt, local_key, local_key_len,
                                         &reenc_len) != 0)
        return -1;
    if (reenc_len != in_len || memcmp(reenc, in, in_len) != 0) return -1;

    if (kt) *kt = local_kt;
    if (key) *key = local_key;
    if (key_len) *key_len = local_key_len;
    return 0;
}

int speer_peer_id_from_pubkey_bytes(uint8_t *out, size_t out_cap, const uint8_t *pubkey_proto,
                                    size_t pubkey_proto_len, size_t *out_len) {
    if (pubkey_proto_len <= 42) {
        if (out_cap < 2 + pubkey_proto_len) return -1;
        out[0] = 0x00;
        out[1] = (uint8_t)pubkey_proto_len;
        COPY(out + 2, pubkey_proto, pubkey_proto_len);
        if (out_len) *out_len = 2 + pubkey_proto_len;
        return 0;
    }
    if (out_cap < 34) return -1;
    out[0] = 0x12;
    out[1] = 0x20;
    speer_sha256(out + 2, pubkey_proto, pubkey_proto_len);
    if (out_len) *out_len = 34;
    return 0;
}

static const char b58alpha[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int speer_peer_id_to_b58(char *out, size_t out_cap, const uint8_t *peer_id, size_t peer_id_len) {
    if (peer_id_len == 0 || out_cap == 0) return -1;
    size_t zeroes = 0;
    while (zeroes < peer_id_len && peer_id[zeroes] == 0) zeroes++;
    size_t buflen = peer_id_len * 138 / 100 + 1;
    uint8_t *buf = (uint8_t *)calloc(buflen, 1);
    if (!buf) return -1;
    size_t length = 0;
    for (size_t i = zeroes; i < peer_id_len; i++) {
        uint32_t carry = peer_id[i];
        size_t j = 0;
        for (size_t k = buflen; k > 0; k--) {
            size_t idx = k - 1;
            if (idx < buflen - length || carry) {
                carry += (uint32_t)256 * buf[idx];
                buf[idx] = (uint8_t)(carry % 58);
                carry /= 58;
                j++;
                if (j > length) length = j;
            }
        }
    }
    size_t offset = buflen - length;
    while (offset < buflen && buf[offset] == 0) offset++;
    size_t total = zeroes + (buflen - offset);
    if (total + 1 > out_cap) {
        free(buf);
        return -1;
    }
    size_t pos = 0;
    for (size_t i = 0; i < zeroes; i++) out[pos++] = '1';
    for (size_t i = offset; i < buflen; i++) out[pos++] = b58alpha[buf[i]];
    out[pos] = 0;
    free(buf);
    return 0;
}
