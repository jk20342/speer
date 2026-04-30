#include "circuit_relay.h"

#include "speer_internal.h"

#include "protobuf.h"

static int encode_peer(speer_pb_writer_t *w, uint32_t field, const uint8_t *peer_id,
                       size_t peer_id_len) {
    if (speer_pb_write_tag(w, field, PB_WIRE_LEN) != 0) return -1;
    speer_pb_writer_t inner;
    uint8_t tmp[128];
    speer_pb_writer_init(&inner, tmp, sizeof(tmp));
    if (speer_pb_write_bytes_field(&inner, 1, peer_id, peer_id_len) != 0) return -1;
    if (speer_pb_write_varint(w, inner.pos) != 0) return -1;
    if (w->pos + inner.pos > w->cap) {
        w->err = 1;
        return -1;
    }
    COPY(w->buf + w->pos, tmp, inner.pos);
    w->pos += inner.pos;
    return 0;
}

int speer_relay_encode_hop_reserve(uint8_t *out, size_t cap, size_t *out_len) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, HOP_TYPE_RESERVE) != 0) return -1;
    if (out_len) *out_len = w.pos;
    return 0;
}

int speer_relay_encode_hop_connect(uint8_t *out, size_t cap, size_t *out_len,
                                   const uint8_t *peer_id, size_t peer_id_len) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, HOP_TYPE_CONNECT) != 0) return -1;
    if (encode_peer(&w, 2, peer_id, peer_id_len) != 0) return -1;
    if (out_len) *out_len = w.pos;
    return 0;
}

int speer_relay_encode_hop_status(uint8_t *out, size_t cap, size_t *out_len, int status,
                                  const speer_relay_reservation_t *res) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, 2) != 0) return -1;
    if (speer_pb_write_int32_field(&w, 4, status) != 0) return -1;
    if (res) {
        uint8_t inner[600];
        speer_pb_writer_t iw;
        speer_pb_writer_init(&iw, inner, sizeof(inner));
        if (speer_pb_write_int64_field(&iw, 1, (int64_t)res->expire) != 0) return -1;
        if (res->voucher_len > 0) {
            if (speer_pb_write_bytes_field(&iw, 3, res->voucher, res->voucher_len) != 0) return -1;
        }
        if (speer_pb_write_bytes_field(&w, 3, inner, iw.pos) != 0) return -1;
    }
    if (out_len) *out_len = w.pos;
    return 0;
}

int speer_relay_encode_stop_connect(uint8_t *out, size_t cap, size_t *out_len,
                                    const uint8_t *src_peer_id, size_t src_peer_id_len) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, STOP_TYPE_CONNECT) != 0) return -1;
    if (encode_peer(&w, 2, src_peer_id, src_peer_id_len) != 0) return -1;
    if (out_len) *out_len = w.pos;
    return 0;
}

int speer_relay_encode_stop_status(uint8_t *out, size_t cap, size_t *out_len, int status) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, 1) != 0) return -1;
    if (speer_pb_write_int32_field(&w, 2, status) != 0) return -1;
    if (out_len) *out_len = w.pos;
    return 0;
}

static int decode_inner_peer(const uint8_t *in, size_t in_len, uint8_t *peer_id,
                             size_t *peer_id_len) {
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, in, in_len);
    while (r.pos < r.len) {
        uint32_t f, wire;
        if (speer_pb_read_tag(&r, &f, &wire) != 0) return -1;
        if (f == 1 && wire == PB_WIRE_LEN) {
            const uint8_t *d;
            size_t l;
            if (speer_pb_read_bytes(&r, &d, &l) != 0) return -1;
            if (l > *peer_id_len) return -1;
            COPY(peer_id, d, l);
            *peer_id_len = l;
            return 0;
        }
        if (speer_pb_skip(&r, wire) != 0) return -1;
    }
    return -1;
}

int speer_relay_decode(const uint8_t *in, size_t in_len, speer_relay_msg_type_t *type, int *status,
                       speer_relay_reservation_t *opt_reservation, uint8_t *opt_peer_id,
                       size_t *opt_peer_id_len) {
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, in, in_len);
    if (status) *status = 0;
    while (r.pos < r.len) {
        uint32_t f, wire;
        if (speer_pb_read_tag(&r, &f, &wire) != 0) return -1;
        if (f == 1 && wire == PB_WIRE_VARINT) {
            int32_t v;
            if (speer_pb_read_int32(&r, &v) != 0) return -1;
            if (type) *type = (speer_relay_msg_type_t)v;
        } else if (f == 4 && wire == PB_WIRE_VARINT) {
            int32_t v;
            if (speer_pb_read_int32(&r, &v) != 0) return -1;
            if (status) *status = v;
        } else if (f == 2 && wire == PB_WIRE_LEN) {
            const uint8_t *d;
            size_t l;
            if (speer_pb_read_bytes(&r, &d, &l) != 0) return -1;
            if (opt_peer_id && opt_peer_id_len) {
                size_t cap = *opt_peer_id_len;
                if (decode_inner_peer(d, l, opt_peer_id, &cap) == 0) { *opt_peer_id_len = cap; }
            }
        } else if (f == 3 && wire == PB_WIRE_LEN && opt_reservation) {
            const uint8_t *d;
            size_t l;
            if (speer_pb_read_bytes(&r, &d, &l) != 0) return -1;
            speer_pb_reader_t ir;
            speer_pb_reader_init(&ir, d, l);
            while (ir.pos < ir.len) {
                uint32_t ff, ww;
                if (speer_pb_read_tag(&ir, &ff, &ww) != 0) return -1;
                if (ff == 1 && ww == PB_WIRE_VARINT) {
                    int64_t v;
                    if (speer_pb_read_int64(&ir, &v) != 0) return -1;
                    opt_reservation->expire = (uint64_t)v;
                } else if (ff == 3 && ww == PB_WIRE_LEN) {
                    const uint8_t *vd;
                    size_t vl;
                    if (speer_pb_read_bytes(&ir, &vd, &vl) != 0) return -1;
                    if (vl > sizeof(opt_reservation->voucher)) return -1;
                    COPY(opt_reservation->voucher, vd, vl);
                    opt_reservation->voucher_len = vl;
                } else {
                    if (speer_pb_skip(&ir, ww) != 0) return -1;
                }
            }
        } else {
            if (speer_pb_skip(&r, wire) != 0) return -1;
        }
    }
    return 0;
}
