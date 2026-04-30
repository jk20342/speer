#include "speer_internal.h"
#include "dcutr.h"
#include "protobuf.h"

int speer_dcutr_encode(const speer_dcutr_msg_t* m, uint8_t* out, size_t cap, size_t* out_len) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, (int32_t)m->type) != 0) return -1;
    for (size_t i = 0; i < m->num_addrs; i++) {
        if (speer_pb_write_bytes_field(&w, 2, m->addrs[i].bytes, m->addrs[i].len) != 0) return -1;
    }
    if (out_len) *out_len = w.pos;
    return 0;
}

int speer_dcutr_decode(speer_dcutr_msg_t* m, const uint8_t* in, size_t in_len) {
    ZERO(m, sizeof(*m));
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, in, in_len);
    while (r.pos < r.len) {
        uint32_t f, wire;
        if (speer_pb_read_tag(&r, &f, &wire) != 0) return -1;
        if (f == 1 && wire == PB_WIRE_VARINT) {
            int32_t v;
            if (speer_pb_read_int32(&r, &v) != 0) return -1;
            m->type = (speer_dcutr_type_t)v;
        } else if (f == 2 && wire == PB_WIRE_LEN) {
            const uint8_t* d; size_t l;
            if (speer_pb_read_bytes(&r, &d, &l) != 0) return -1;
            if (m->num_addrs < DCUTR_MAX_ADDRS && l <= sizeof(m->addrs[0].bytes)) {
                COPY(m->addrs[m->num_addrs].bytes, d, l);
                m->addrs[m->num_addrs].len = l;
                m->num_addrs++;
            }
        } else {
            if (speer_pb_skip(&r, wire) != 0) return -1;
        }
    }
    return 0;
}
