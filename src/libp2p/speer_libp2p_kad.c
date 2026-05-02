#include "speer_libp2p_kad.h"

#include "speer_internal.h"

#include "dht_libp2p.h"

static void to_internal_peers(const speer_libp2p_kad_peer_t *src, dht_libp2p_peer_t *dst,
                              size_t count) {
    for (size_t i = 0; i < count; i++) {
        COPY(dst[i].id, src[i].id, DHT_ID_BYTES);
        COPY(dst[i].address, src[i].address, sizeof(dst[i].address));
        dst[i].address[sizeof(dst[i].address) - 1] = 0;
    }
}

static void from_internal_peers(const dht_libp2p_peer_t *src, speer_libp2p_kad_peer_t *dst,
                                size_t count) {
    for (size_t i = 0; i < count; i++) {
        COPY(dst[i].id, src[i].id, SPEER_LIBP2P_KAD_ID_BYTES);
        COPY(dst[i].address, src[i].address, sizeof(dst[i].address));
        dst[i].address[sizeof(dst[i].address) - 1] = 0;
    }
}

int speer_libp2p_kad_encode_query(uint8_t msg_type, const uint8_t *key, size_t key_len,
                                  uint8_t *out, size_t cap, size_t *out_len) {
    return dht_libp2p_encode_query(msg_type, key, key_len, out, cap, out_len);
}

int speer_libp2p_kad_encode_message(const speer_libp2p_kad_msg_t *msg, uint8_t *out, size_t cap,
                                    size_t *out_len) {
    if (!msg) return -1;
    dht_libp2p_peer_t peers[SPEER_LIBP2P_KAD_MAX_PEERS];
    if (msg->num_closer_peers > SPEER_LIBP2P_KAD_MAX_PEERS) return -1;
    if (msg->closer_peers && msg->num_closer_peers > 0)
        to_internal_peers(msg->closer_peers, peers, msg->num_closer_peers);
    dht_libp2p_msg_t internal = {.type = msg->type,
                                 .key = msg->key,
                                 .key_len = msg->key_len,
                                 .value = msg->value,
                                 .value_len = msg->value_len,
                                 .closer_peers = msg->num_closer_peers > 0 ? peers : NULL,
                                 .num_closer_peers = msg->num_closer_peers};
    return dht_libp2p_encode_message(&internal, out, cap, out_len);
}

int speer_libp2p_kad_decode_message(const uint8_t *msg, size_t msg_len, speer_libp2p_kad_msg_t *out,
                                    speer_libp2p_kad_peer_t *peers, size_t max_peers) {
    if (!out || (max_peers > 0 && !peers)) return -1;
    dht_libp2p_peer_t internal_peers[SPEER_LIBP2P_KAD_MAX_PEERS];
    if (max_peers > SPEER_LIBP2P_KAD_MAX_PEERS) max_peers = SPEER_LIBP2P_KAD_MAX_PEERS;
    dht_libp2p_msg_t internal;
    if (dht_libp2p_decode_message(msg, msg_len, &internal, internal_peers, max_peers) != 0)
        return -1;
    ZERO(out, sizeof(*out));
    out->type = internal.type;
    out->key = internal.key;
    out->key_len = internal.key_len;
    out->value = internal.value;
    out->value_len = internal.value_len;
    out->num_closer_peers = internal.num_closer_peers;
    out->closer_peers = peers;
    if (internal.num_closer_peers > 0)
        from_internal_peers(internal_peers, peers, internal.num_closer_peers);
    return 0;
}

int speer_libp2p_kad_stream_roundtrip(speer_libp2p_tcp_session_t *session, const uint8_t *request,
                                      size_t request_len, uint8_t *response, size_t *response_len) {
    if (!session || !request || request_len == 0 || !response || !response_len) return -1;
    speer_yamux_stream_t *stream = NULL;
    if (speer_libp2p_tcp_open_protocol_stream(session, SPEER_LIBP2P_KAD_PROTOCOL_STR, &stream) != 0)
        return -1;
    if (speer_libp2p_tcp_stream_send_frame(session, stream, request, request_len) != 0) return -1;
    return speer_libp2p_tcp_stream_recv_frame(session, stream, response, *response_len,
                                              response_len);
}
