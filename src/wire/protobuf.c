#include "protobuf.h"

#include "speer_internal.h"

#include <string.h>

#include "varint.h"

void speer_pb_reader_init(speer_pb_reader_t *r, const uint8_t *buf, size_t len) {
    r->buf = buf;
    r->len = len;
    r->pos = 0;
    r->err = 0;
}

static int pb_avail(speer_pb_reader_t *r, size_t n) {
    return r->pos + n <= r->len;
}

int speer_pb_read_varint(speer_pb_reader_t *r, uint64_t *v) {
    if (r->err) return -1;
    uint64_t out = 0;
    size_t n = speer_uvarint_decode(r->buf + r->pos, r->len - r->pos, &out);
    if (n == 0) {
        r->err = 1;
        return -1;
    }
    r->pos += n;
    if (v) *v = out;
    return 0;
}

int speer_pb_read_tag(speer_pb_reader_t *r, uint32_t *field, uint32_t *wire) {
    uint64_t tag = 0;
    if (speer_pb_read_varint(r, &tag) != 0) return -1;
    if (field) *field = (uint32_t)(tag >> 3);
    if (wire) *wire = (uint32_t)(tag & 0x7);
    return 0;
}

int speer_pb_read_int32(speer_pb_reader_t *r, int32_t *v) {
    uint64_t u = 0;
    if (speer_pb_read_varint(r, &u) != 0) return -1;
    if (v) *v = (int32_t)u;
    return 0;
}

int speer_pb_read_int64(speer_pb_reader_t *r, int64_t *v) {
    uint64_t u = 0;
    if (speer_pb_read_varint(r, &u) != 0) return -1;
    if (v) *v = (int64_t)u;
    return 0;
}

int speer_pb_read_bool(speer_pb_reader_t *r, int *v) {
    uint64_t u = 0;
    if (speer_pb_read_varint(r, &u) != 0) return -1;
    if (v) *v = u != 0;
    return 0;
}

int speer_pb_read_bytes(speer_pb_reader_t *r, const uint8_t **data, size_t *len) {
    uint64_t l = 0;
    if (speer_pb_read_varint(r, &l) != 0) return -1;
    if (!pb_avail(r, (size_t)l)) {
        r->err = 1;
        return -1;
    }
    if (data) *data = r->buf + r->pos;
    if (len) *len = (size_t)l;
    r->pos += (size_t)l;
    return 0;
}

int speer_pb_read_string(speer_pb_reader_t *r, const char **s, size_t *len) {
    const uint8_t *d;
    size_t l;
    if (speer_pb_read_bytes(r, &d, &l) != 0) return -1;
    if (s) *s = (const char *)d;
    if (len) *len = l;
    return 0;
}

int speer_pb_skip(speer_pb_reader_t *r, uint32_t wire) {
    switch (wire) {
    case PB_WIRE_VARINT: {
        uint64_t v;
        return speer_pb_read_varint(r, &v);
    }
    case PB_WIRE_64BIT: {
        if (!pb_avail(r, 8)) {
            r->err = 1;
            return -1;
        }
        r->pos += 8;
        return 0;
    }
    case PB_WIRE_32BIT: {
        if (!pb_avail(r, 4)) {
            r->err = 1;
            return -1;
        }
        r->pos += 4;
        return 0;
    }
    case PB_WIRE_LEN: {
        const uint8_t *d;
        size_t l;
        return speer_pb_read_bytes(r, &d, &l);
    }
    default:
        r->err = 1;
        return -1;
    }
}

void speer_pb_writer_init(speer_pb_writer_t *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->pos = 0;
    w->err = 0;
}

int speer_pb_write_varint(speer_pb_writer_t *w, uint64_t v) {
    if (w->err) return -1;
    size_t n = speer_uvarint_encode(w->buf + w->pos, w->cap - w->pos, v);
    if (n == 0) {
        w->err = 1;
        return -1;
    }
    w->pos += n;
    return 0;
}

int speer_pb_write_tag(speer_pb_writer_t *w, uint32_t field, uint32_t wire) {
    return speer_pb_write_varint(w, ((uint64_t)field << 3) | (wire & 0x7));
}

int speer_pb_write_int32_field(speer_pb_writer_t *w, uint32_t field, int32_t v) {
    if (speer_pb_write_tag(w, field, PB_WIRE_VARINT) != 0) return -1;
    return speer_pb_write_varint(w, (uint64_t)(uint32_t)v);
}

int speer_pb_write_int64_field(speer_pb_writer_t *w, uint32_t field, int64_t v) {
    if (speer_pb_write_tag(w, field, PB_WIRE_VARINT) != 0) return -1;
    return speer_pb_write_varint(w, (uint64_t)v);
}

int speer_pb_write_bool_field(speer_pb_writer_t *w, uint32_t field, int v) {
    if (speer_pb_write_tag(w, field, PB_WIRE_VARINT) != 0) return -1;
    return speer_pb_write_varint(w, v ? 1 : 0);
}

int speer_pb_write_bytes_field(speer_pb_writer_t *w, uint32_t field, const uint8_t *data,
                               size_t len) {
    if (speer_pb_write_tag(w, field, PB_WIRE_LEN) != 0) return -1;
    if (speer_pb_write_varint(w, (uint64_t)len) != 0) return -1;
    if (w->pos + len > w->cap) {
        w->err = 1;
        return -1;
    }
    if (len > 0) memcpy(w->buf + w->pos, data, len);
    w->pos += len;
    return 0;
}

int speer_pb_write_string_field(speer_pb_writer_t *w, uint32_t field, const char *s) {
    return speer_pb_write_bytes_field(w, field, (const uint8_t *)s, strlen(s));
}
