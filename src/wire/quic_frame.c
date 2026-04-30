#include "quic_frame.h"

#include "speer_internal.h"

#include <string.h>

#include "varint.h"

void speer_qf_writer_init(speer_qf_writer_t *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->pos = 0;
    w->err = 0;
}

int speer_qf_w_varint(speer_qf_writer_t *w, uint64_t v) {
    if (w->err) return -1;
    size_t n = speer_qvarint_encode(w->buf + w->pos, w->cap - w->pos, v);
    if (n == 0) {
        w->err = 1;
        return -1;
    }
    w->pos += n;
    return 0;
}

int speer_qf_w_u8(speer_qf_writer_t *w, uint8_t v) {
    if (w->err || w->pos + 1 > w->cap) {
        w->err = 1;
        return -1;
    }
    w->buf[w->pos++] = v;
    return 0;
}

int speer_qf_w_bytes(speer_qf_writer_t *w, const uint8_t *d, size_t n) {
    if (w->err || w->pos + n > w->cap) {
        w->err = 1;
        return -1;
    }
    if (n > 0) memcpy(w->buf + w->pos, d, n);
    w->pos += n;
    return 0;
}

void speer_qf_reader_init(speer_qf_reader_t *r, const uint8_t *buf, size_t len) {
    r->buf = buf;
    r->len = len;
    r->pos = 0;
    r->err = 0;
}

int speer_qf_r_varint(speer_qf_reader_t *r, uint64_t *v) {
    if (r->err) return -1;
    uint64_t out = 0;
    size_t n = speer_qvarint_decode(r->buf + r->pos, r->len - r->pos, &out);
    if (n == 0) {
        r->err = 1;
        return -1;
    }
    r->pos += n;
    if (v) *v = out;
    return 0;
}

int speer_qf_r_u8(speer_qf_reader_t *r, uint8_t *v) {
    if (r->err || r->pos + 1 > r->len) {
        r->err = 1;
        return -1;
    }
    if (v) *v = r->buf[r->pos];
    r->pos++;
    return 0;
}

int speer_qf_r_bytes(speer_qf_reader_t *r, const uint8_t **d, size_t n) {
    if (r->err || n > r->len - r->pos) {
        r->err = 1;
        return -1;
    }
    if (d) *d = r->buf + r->pos;
    r->pos += n;
    return 0;
}

int speer_qf_r_eof(const speer_qf_reader_t *r) {
    return r->pos >= r->len;
}

int speer_qf_encode_padding(speer_qf_writer_t *w, size_t n) {
    if (w->err || w->pos + n > w->cap) {
        w->err = 1;
        return -1;
    }
    memset(w->buf + w->pos, 0, n);
    w->pos += n;
    return 0;
}

int speer_qf_encode_ping(speer_qf_writer_t *w) {
    return speer_qf_w_u8(w, QF_PING);
}

int speer_qf_encode_crypto(speer_qf_writer_t *w, uint64_t offset, const uint8_t *data, size_t len) {
    if (speer_qf_w_u8(w, QF_CRYPTO) != 0) return -1;
    if (speer_qf_w_varint(w, offset) != 0) return -1;
    if (speer_qf_w_varint(w, len) != 0) return -1;
    return speer_qf_w_bytes(w, data, len);
}

int speer_qf_encode_ack(speer_qf_writer_t *w, uint64_t largest, uint64_t delay,
                        const uint64_t *gaps_lengths, size_t pairs) {
    if (pairs == 0) return -1;
    if (speer_qf_w_u8(w, QF_ACK) != 0) return -1;
    if (speer_qf_w_varint(w, largest) != 0) return -1;
    if (speer_qf_w_varint(w, delay) != 0) return -1;
    if (speer_qf_w_varint(w, (uint64_t)(pairs - 1)) != 0) return -1;
    if (speer_qf_w_varint(w, gaps_lengths[1]) != 0) return -1;
    for (size_t i = 1; i < pairs; i++) {
        if (speer_qf_w_varint(w, gaps_lengths[i * 2]) != 0) return -1;
        if (speer_qf_w_varint(w, gaps_lengths[i * 2 + 1]) != 0) return -1;
    }
    return 0;
}

int speer_qf_encode_stream(speer_qf_writer_t *w, uint64_t stream_id, uint64_t offset,
                           const uint8_t *data, size_t len, int fin) {
    if (offset > UINT64_MAX - (uint64_t)len) return -1;
    if (offset + (uint64_t)len > ((uint64_t)1 << 62) - 1) return -1;
    uint8_t type = QF_STREAM_BASE | 0x02;
    if (offset > 0) type |= 0x04;
    if (fin) type |= 0x01;
    if (speer_qf_w_u8(w, type) != 0) return -1;
    if (speer_qf_w_varint(w, stream_id) != 0) return -1;
    if (offset > 0 && speer_qf_w_varint(w, offset) != 0) return -1;
    if (speer_qf_w_varint(w, len) != 0) return -1;
    return speer_qf_w_bytes(w, data, len);
}

int speer_qf_encode_path_challenge(speer_qf_writer_t *w, const uint8_t data[8]) {
    if (speer_qf_w_u8(w, QF_PATH_CHALLENGE) != 0) return -1;
    return speer_qf_w_bytes(w, data, 8);
}

int speer_qf_encode_path_response(speer_qf_writer_t *w, const uint8_t data[8]) {
    if (speer_qf_w_u8(w, QF_PATH_RESPONSE) != 0) return -1;
    return speer_qf_w_bytes(w, data, 8);
}

int speer_qf_encode_handshake_done(speer_qf_writer_t *w) {
    return speer_qf_w_u8(w, QF_HANDSHAKE_DONE);
}

int speer_qf_encode_connection_close(speer_qf_writer_t *w, uint64_t error_code, uint64_t frame_type,
                                     const char *reason) {
    if (speer_qf_w_u8(w, QF_CONNECTION_CLOSE) != 0) return -1;
    if (speer_qf_w_varint(w, error_code) != 0) return -1;
    if (speer_qf_w_varint(w, frame_type) != 0) return -1;
    size_t r_len = reason ? strlen(reason) : 0;
    if (speer_qf_w_varint(w, r_len) != 0) return -1;
    return speer_qf_w_bytes(w, (const uint8_t *)reason, r_len);
}

int speer_qf_encode_new_connection_id(speer_qf_writer_t *w, uint64_t seq, uint64_t retire_prior_to,
                                      const uint8_t *cid, size_t cid_len,
                                      const uint8_t reset_token[16]) {
    if (cid_len < 1 || cid_len > 20) return -1;
    if (retire_prior_to > seq) return -1;
    if (speer_qf_w_u8(w, QF_NEW_CONNECTION_ID) != 0) return -1;
    if (speer_qf_w_varint(w, seq) != 0) return -1;
    if (speer_qf_w_varint(w, retire_prior_to) != 0) return -1;
    if (speer_qf_w_u8(w, (uint8_t)cid_len) != 0) return -1;
    if (speer_qf_w_bytes(w, cid, cid_len) != 0) return -1;
    return speer_qf_w_bytes(w, reset_token, 16);
}

int speer_qf_encode_max_data(speer_qf_writer_t *w, uint64_t max_data) {
    if (speer_qf_w_u8(w, QF_MAX_DATA) != 0) return -1;
    return speer_qf_w_varint(w, max_data);
}

int speer_qf_encode_max_stream_data(speer_qf_writer_t *w, uint64_t stream_id, uint64_t max_data) {
    if (speer_qf_w_u8(w, QF_MAX_STREAM_DATA) != 0) return -1;
    if (speer_qf_w_varint(w, stream_id) != 0) return -1;
    return speer_qf_w_varint(w, max_data);
}

int speer_qf_encode_max_streams(speer_qf_writer_t *w, uint64_t max_streams, int uni) {
    uint8_t type = uni ? QF_MAX_STREAMS_UNI : QF_MAX_STREAMS_BIDI;
    if (speer_qf_w_u8(w, type) != 0) return -1;
    return speer_qf_w_varint(w, max_streams);
}

int speer_qf_encode_data_blocked(speer_qf_writer_t *w, uint64_t limit) {
    if (speer_qf_w_u8(w, QF_DATA_BLOCKED) != 0) return -1;
    return speer_qf_w_varint(w, limit);
}

int speer_qf_encode_stream_data_blocked(speer_qf_writer_t *w, uint64_t stream_id, uint64_t limit) {
    if (speer_qf_w_u8(w, QF_STREAM_DATA_BLOCKED) != 0) return -1;
    if (speer_qf_w_varint(w, stream_id) != 0) return -1;
    return speer_qf_w_varint(w, limit);
}

int speer_qf_encode_streams_blocked(speer_qf_writer_t *w, uint64_t limit, int uni) {
    uint8_t type = uni ? QF_STREAMS_BLOCKED_UNI : QF_STREAMS_BLOCKED_BIDI;
    if (speer_qf_w_u8(w, type) != 0) return -1;
    return speer_qf_w_varint(w, limit);
}
