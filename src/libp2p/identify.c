#include "speer_internal.h"
#include "identify.h"
#include "protobuf.h"
#include <string.h>

int speer_identify_encode(const speer_identify_t* id, uint8_t* out, size_t cap, size_t* out_len) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);

    if (id->protocol_version[0])
        if (speer_pb_write_string_field(&w, 5, id->protocol_version) != 0) return -1;
    if (id->agent_version[0])
        if (speer_pb_write_string_field(&w, 6, id->agent_version) != 0) return -1;
    if (id->pubkey_proto_len > 0)
        if (speer_pb_write_bytes_field(&w, 1, id->pubkey_proto, id->pubkey_proto_len) != 0) return -1;
    for (size_t i = 0; i < id->num_listen_addrs; i++) {
        if (speer_pb_write_bytes_field(&w, 2, id->listen_addrs[i].bytes, id->listen_addrs[i].len) != 0) return -1;
    }
    for (size_t i = 0; i < id->num_protocols; i++) {
        if (speer_pb_write_string_field(&w, 3, id->protocols[i]) != 0) return -1;
    }
    if (id->has_observed)
        if (speer_pb_write_bytes_field(&w, 4, id->observed_addr.bytes, id->observed_addr.len) != 0) return -1;

    if (out_len) *out_len = w.pos;
    return 0;
}

int speer_identify_decode(speer_identify_t* id, const uint8_t* in, size_t in_len) {
    ZERO(id, sizeof(*id));
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, in, in_len);
    while (r.pos < r.len) {
        uint32_t f, wire;
        if (speer_pb_read_tag(&r, &f, &wire) != 0) return -1;
        if (wire != PB_WIRE_LEN) {
            if (speer_pb_skip(&r, wire) != 0) return -1;
            continue;
        }
        const uint8_t* d; size_t l;
        if (speer_pb_read_bytes(&r, &d, &l) != 0) return -1;
        switch (f) {
            case 1:
                if (l <= sizeof(id->pubkey_proto)) {
                    COPY(id->pubkey_proto, d, l);
                    id->pubkey_proto_len = l;
                }
                break;
            case 2:
                if (id->num_listen_addrs < IDENTIFY_MAX_LISTEN_ADDRS &&
                    l <= sizeof(id->listen_addrs[0].bytes)) {
                    COPY(id->listen_addrs[id->num_listen_addrs].bytes, d, l);
                    id->listen_addrs[id->num_listen_addrs].len = l;
                    id->num_listen_addrs++;
                }
                break;
            case 3:
                if (id->num_protocols < IDENTIFY_MAX_PROTOCOLS && l < 64) {
                    COPY(id->protocols[id->num_protocols], d, l);
                    id->protocols[id->num_protocols][l] = 0;
                    id->num_protocols++;
                }
                break;
            case 4:
                if (l <= sizeof(id->observed_addr.bytes)) {
                    COPY(id->observed_addr.bytes, d, l);
                    id->observed_addr.len = l;
                    id->has_observed = 1;
                }
                break;
            case 5:
                if (l < IDENTIFY_PROTOCOL_VERSION_MAX) {
                    COPY(id->protocol_version, d, l);
                    id->protocol_version[l] = 0;
                }
                break;
            case 6:
                if (l < IDENTIFY_AGENT_VERSION_MAX) {
                    COPY(id->agent_version, d, l);
                    id->agent_version[l] = 0;
                }
                break;
            default:
                break;
        }
    }
    return 0;
}
