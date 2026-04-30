#include "dht_libp2p.h"

#include "protobuf.h"

static int libp2p_type_to_rpc(uint8_t msg_type, uint8_t *out_rpc) {
    switch (msg_type) {
    case DHT_LIBP2P_PING:
        *out_rpc = DHT_RPC_PING;
        return 0;
    case DHT_LIBP2P_FIND_NODE:
        *out_rpc = DHT_RPC_FIND_NODE;
        return 0;
    case DHT_LIBP2P_GET_VALUE:
        *out_rpc = DHT_RPC_FIND_VALUE;
        return 0;
    case DHT_LIBP2P_PUT_VALUE:
        *out_rpc = DHT_RPC_STORE;
        return 0;
    default:
        return -1;
    }
}

int dht_libp2p_encode_query(uint8_t msg_type, const uint8_t *key, size_t key_len, uint8_t *out,
                            size_t cap, size_t *out_len) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, msg_type) != 0) return -1;
    if (key && key_len > 0 && speer_pb_write_bytes_field(&w, 2, key, key_len) != 0) return -1;
    if (out_len) *out_len = w.pos;
    return w.err ? -1 : 0;
}

int dht_libp2p_decode_query(const uint8_t *msg, size_t msg_len, uint8_t *out_rpc,
                            const uint8_t **out_key, size_t *out_key_len) {
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, msg, msg_len);
    uint8_t msg_type = 0xff;
    const uint8_t *key = NULL;
    size_t key_len = 0;
    while (r.pos < r.len) {
        uint32_t field;
        uint32_t wire;
        if (speer_pb_read_tag(&r, &field, &wire) != 0) return -1;
        if (field == 1 && wire == PB_WIRE_VARINT) {
            int32_t v;
            if (speer_pb_read_int32(&r, &v) != 0 || v < 0 || v > 255) return -1;
            msg_type = (uint8_t)v;
        } else if (field == 2 && wire == PB_WIRE_LEN) {
            if (speer_pb_read_bytes(&r, &key, &key_len) != 0) return -1;
        } else {
            if (speer_pb_skip(&r, wire) != 0) return -1;
        }
    }
    if (msg_type == 0xff || libp2p_type_to_rpc(msg_type, out_rpc) != 0) return -1;
    if (out_key) *out_key = key;
    if (out_key_len) *out_key_len = key_len;
    return 0;
}
