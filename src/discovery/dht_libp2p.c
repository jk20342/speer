#include "dht_libp2p.h"

#include "speer_internal.h"

#include "multistream.h"
#include "protobuf.h"
#include "varint.h"

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

static int encode_peer(const dht_libp2p_peer_t *peer, uint8_t *out, size_t cap, size_t *out_len) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_bytes_field(&w, 1, peer->id, DHT_ID_BYTES) != 0) return -1;
    if (speer_pb_write_string_field(&w, 2, peer->address) != 0) return -1;
    if (out_len) *out_len = w.pos;
    return w.err ? -1 : 0;
}

static int decode_peer(const uint8_t *buf, size_t len, dht_libp2p_peer_t *peer) {
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, buf, len);
    ZERO(peer, sizeof(*peer));
    while (r.pos < r.len) {
        uint32_t field, wire;
        if (speer_pb_read_tag(&r, &field, &wire) != 0) return -1;
        if (field == 1 && wire == PB_WIRE_LEN) {
            const uint8_t *id;
            size_t id_len;
            if (speer_pb_read_bytes(&r, &id, &id_len) != 0 || id_len != DHT_ID_BYTES) return -1;
            COPY(peer->id, id, DHT_ID_BYTES);
        } else if (field == 2 && wire == PB_WIRE_LEN) {
            const char *addr;
            size_t addr_len;
            if (speer_pb_read_string(&r, &addr, &addr_len) != 0 ||
                addr_len >= sizeof(peer->address))
                return -1;
            COPY(peer->address, addr, addr_len);
            peer->address[addr_len] = 0;
        } else {
            if (speer_pb_skip(&r, wire) != 0) return -1;
        }
    }
    return peer->address[0] ? 0 : -1;
}

int dht_libp2p_encode_message(const dht_libp2p_msg_t *msg, uint8_t *out, size_t cap,
                              size_t *out_len) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, msg->type) != 0) return -1;
    if (msg->key && msg->key_len > 0 &&
        speer_pb_write_bytes_field(&w, 2, msg->key, msg->key_len) != 0)
        return -1;
    if (msg->value && msg->value_len > 0 &&
        speer_pb_write_bytes_field(&w, 3, msg->value, msg->value_len) != 0)
        return -1;
    for (size_t i = 0; i < msg->num_closer_peers; i++) {
        uint8_t peer_buf[160];
        size_t peer_len;
        if (encode_peer(&msg->closer_peers[i], peer_buf, sizeof(peer_buf), &peer_len) != 0)
            return -1;
        if (speer_pb_write_bytes_field(&w, 8, peer_buf, peer_len) != 0) return -1;
    }
    if (out_len) *out_len = w.pos;
    return w.err ? -1 : 0;
}

int dht_libp2p_decode_message(const uint8_t *msg, size_t msg_len, dht_libp2p_msg_t *out,
                              dht_libp2p_peer_t *peers, size_t max_peers) {
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, msg, msg_len);
    ZERO(out, sizeof(*out));
    out->type = 0xff;
    out->closer_peers = peers;
    while (r.pos < r.len) {
        uint32_t field, wire;
        if (speer_pb_read_tag(&r, &field, &wire) != 0) return -1;
        if (field == 1 && wire == PB_WIRE_VARINT) {
            int32_t v;
            if (speer_pb_read_int32(&r, &v) != 0 || v < 0 || v > 255) return -1;
            out->type = (uint8_t)v;
        } else if (field == 2 && wire == PB_WIRE_LEN) {
            if (speer_pb_read_bytes(&r, &out->key, &out->key_len) != 0) return -1;
        } else if (field == 3 && wire == PB_WIRE_LEN) {
            if (speer_pb_read_bytes(&r, &out->value, &out->value_len) != 0) return -1;
        } else if (field == 8 && wire == PB_WIRE_LEN) {
            const uint8_t *peer_buf;
            size_t peer_len;
            if (out->num_closer_peers >= max_peers) return -1;
            if (speer_pb_read_bytes(&r, &peer_buf, &peer_len) != 0) return -1;
            if (decode_peer(peer_buf, peer_len, &peers[out->num_closer_peers]) != 0) return -1;
            out->num_closer_peers++;
        } else {
            if (speer_pb_skip(&r, wire) != 0) return -1;
        }
    }
    return out->type == 0xff ? -1 : 0;
}

int dht_libp2p_frame(const uint8_t *msg, size_t msg_len, uint8_t *out, size_t cap,
                     size_t *out_len) {
    uint8_t hdr[10];
    size_t hdr_len = speer_uvarint_encode(hdr, sizeof(hdr), msg_len);
    if (hdr_len == 0 || hdr_len + msg_len > cap) return -1;
    COPY(out, hdr, hdr_len);
    COPY(out + hdr_len, msg, msg_len);
    if (out_len) *out_len = hdr_len + msg_len;
    return 0;
}

int dht_libp2p_unframe(const uint8_t *frame, size_t frame_len, const uint8_t **msg, size_t *msg_len,
                       size_t *used) {
    uint64_t n;
    size_t hdr_len = speer_uvarint_decode(frame, frame_len, &n);
    if (hdr_len == 0 || n > (uint64_t)SIZE_MAX || hdr_len + (size_t)n > frame_len) return -1;
    if (msg) *msg = frame + hdr_len;
    if (msg_len) *msg_len = (size_t)n;
    if (used) *used = hdr_len + (size_t)n;
    return 0;
}

int dht_libp2p_dispatch(dht_t *dht, const uint8_t *request, size_t request_len, uint8_t *response,
                        size_t *response_len) {
    dht_libp2p_peer_t peers[DHT_K];
    dht_libp2p_msg_t msg;
    if (dht_libp2p_decode_message(request, request_len, &msg, peers, DHT_K) != 0) return -1;
    if (msg.type == DHT_LIBP2P_PING) {
        dht_libp2p_msg_t out = {.type = DHT_LIBP2P_PING};
        return dht_libp2p_encode_message(&out, response, *response_len, response_len);
    }
    if (msg.key_len != DHT_ID_BYTES) return -1;
    if (msg.type == DHT_LIBP2P_FIND_NODE) {
        dht_node_t nodes[DHT_K];
        int n = dht_get_closest_nodes(dht, msg.key, nodes, DHT_K);
        for (int i = 0; i < n; i++) {
            COPY(peers[i].id, nodes[i].id, DHT_ID_BYTES);
            COPY(peers[i].address, nodes[i].address, sizeof(peers[i].address));
        }
        dht_libp2p_msg_t out = {.type = DHT_LIBP2P_FIND_NODE,
                                .key = msg.key,
                                .key_len = msg.key_len,
                                .closer_peers = peers,
                                .num_closer_peers = (size_t)n};
        return dht_libp2p_encode_message(&out, response, *response_len, response_len);
    }
    if (msg.type == DHT_LIBP2P_GET_VALUE) {
        uint8_t core[2048];
        size_t core_len = sizeof(core);
        dht_value_t value;
        int r = dht_handle_find_value(dht, msg.key, core, &core_len, &value);
        if (r < 0) return -1;
        if (r == 1) {
            dht_libp2p_msg_t out = {.type = DHT_LIBP2P_GET_VALUE,
                                    .key = msg.key,
                                    .key_len = msg.key_len,
                                    .value = value.value,
                                    .value_len = value.value_len};
            return dht_libp2p_encode_message(&out, response, *response_len, response_len);
        }
        dht_libp2p_peer_t closer[DHT_K];
        size_t pos = 1;
        size_t num = core[0];
        for (size_t i = 0; i < num && i < DHT_K && pos < core_len; i++) {
            if (pos + DHT_ID_BYTES + 1 > core_len) return -1;
            COPY(closer[i].id, core + pos, DHT_ID_BYTES);
            pos += DHT_ID_BYTES;
            uint8_t addr_len = core[pos++];
            if (pos + addr_len > core_len || addr_len >= sizeof(closer[i].address)) return -1;
            COPY(closer[i].address, core + pos, addr_len);
            closer[i].address[addr_len] = 0;
            pos += addr_len;
        }
        dht_libp2p_msg_t out = {.type = DHT_LIBP2P_GET_VALUE,
                                .key = msg.key,
                                .key_len = msg.key_len,
                                .closer_peers = closer,
                                .num_closer_peers = num < DHT_K ? num : DHT_K};
        return dht_libp2p_encode_message(&out, response, *response_len, response_len);
    }
    return -1;
}

int dht_libp2p_stream_client(void *user, dht_libp2p_send_fn send_fn, dht_libp2p_recv_fn recv_fn,
                             const uint8_t *request, size_t request_len, uint8_t *response,
                             size_t *response_len) {
    if (speer_ms_negotiate_initiator(user, send_fn, recv_fn, SPEER_LIBP2P_KAD_PROTOCOL) != 0)
        return -1;
    uint8_t frame[2048];
    size_t frame_len;
    if (dht_libp2p_frame(request, request_len, frame, sizeof(frame), &frame_len) != 0) return -1;
    if (send_fn(user, frame, frame_len) != 0) return -1;
    uint8_t in[2048];
    size_t in_len;
    if (recv_fn(user, in, sizeof(in), &in_len) != 0) return -1;
    const uint8_t *msg;
    size_t msg_len;
    if (dht_libp2p_unframe(in, in_len, &msg, &msg_len, NULL) != 0 || msg_len > *response_len)
        return -1;
    COPY(response, msg, msg_len);
    *response_len = msg_len;
    return 0;
}

int dht_libp2p_stream_server(dht_t *dht, void *user, dht_libp2p_send_fn send_fn,
                             dht_libp2p_recv_fn recv_fn) {
    const char *protos[] = {SPEER_LIBP2P_KAD_PROTOCOL};
    if (speer_ms_negotiate_listener(user, send_fn, recv_fn, protos, 1, NULL) != 0) return -1;
    uint8_t in[2048];
    size_t in_len;
    if (recv_fn(user, in, sizeof(in), &in_len) != 0) return -1;
    const uint8_t *msg;
    size_t msg_len;
    if (dht_libp2p_unframe(in, in_len, &msg, &msg_len, NULL) != 0) return -1;
    uint8_t response[2048], frame[2048];
    size_t response_len = sizeof(response), frame_len;
    if (dht_libp2p_dispatch(dht, msg, msg_len, response, &response_len) != 0) return -1;
    if (dht_libp2p_frame(response, response_len, frame, sizeof(frame), &frame_len) != 0) return -1;
    return send_fn(user, frame, frame_len);
}

static int rpc_to_libp2p_type(uint8_t op, uint8_t *out_type) {
    switch (op) {
    case DHT_RPC_PING:
        *out_type = DHT_LIBP2P_PING;
        return 0;
    case DHT_RPC_FIND_NODE:
        *out_type = DHT_LIBP2P_FIND_NODE;
        return 0;
    case DHT_RPC_FIND_VALUE:
        *out_type = DHT_LIBP2P_GET_VALUE;
        return 0;
    default:
        return -1;
    }
}

static int kad_to_core_response(const dht_libp2p_msg_t *msg, uint8_t *response,
                                size_t *response_len) {
    if (msg->value && msg->value_len > 0) {
        if (*response_len < 3 + msg->value_len) return -1;
        response[0] = 0xff;
        response[1] = (uint8_t)(msg->value_len >> 8);
        response[2] = (uint8_t)msg->value_len;
        COPY(response + 3, msg->value, msg->value_len);
        *response_len = 3 + msg->value_len;
        return 0;
    }
    if (msg->num_closer_peers > 255) return -1;
    size_t pos = 1;
    response[0] = (uint8_t)msg->num_closer_peers;
    for (size_t i = 0; i < msg->num_closer_peers; i++) {
        size_t addr_len = strlen(msg->closer_peers[i].address);
        if (addr_len > 255 || pos + DHT_ID_BYTES + 1 + addr_len > *response_len) return -1;
        COPY(response + pos, msg->closer_peers[i].id, DHT_ID_BYTES);
        pos += DHT_ID_BYTES;
        response[pos++] = (uint8_t)addr_len;
        COPY(response + pos, msg->closer_peers[i].address, addr_len);
        pos += addr_len;
    }
    *response_len = pos;
    return 0;
}

int dht_libp2p_send_rpc(void *user, const char *addr, uint8_t op, const uint8_t *request,
                        size_t request_len, uint8_t *response, size_t *response_len) {
    dht_libp2p_rpc_t *rpc = (dht_libp2p_rpc_t *)user;
    if (!rpc || !rpc->roundtrip) return -1;
    uint8_t type;
    if (rpc_to_libp2p_type(op, &type) != 0) return -1;
    dht_libp2p_msg_t msg = {.type = type, .key = request, .key_len = request_len};
    uint8_t wire[1024], wire_resp[2048];
    size_t wire_len, wire_resp_len = sizeof(wire_resp);
    if (dht_libp2p_encode_message(&msg, wire, sizeof(wire), &wire_len) != 0) return -1;
    if (rpc->roundtrip(rpc->user, addr, wire, wire_len, wire_resp, &wire_resp_len) != 0) return -1;
    dht_libp2p_peer_t peers[DHT_K];
    dht_libp2p_msg_t out;
    if (dht_libp2p_decode_message(wire_resp, wire_resp_len, &out, peers, DHT_K) != 0) return -1;
    return kad_to_core_response(&out, response, response_len);
}
